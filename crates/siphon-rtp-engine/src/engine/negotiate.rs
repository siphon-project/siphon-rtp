//! SDP presentation, security, ICE, DTLS and codec-policy helpers shared by the negotiation verbs.

use siphon_rtp_codec::factory::{self, CodecSpec};
use siphon_rtp_datapath::{EndpointId, SourceFilter};
use siphon_rtp_media::wav::WavRecorder;
use siphon_rtp_proto::ProfileFlags;
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::CryptoAttribute;
use std::sync::{Arc, Mutex};

use crate::ice::IceCredentials;
use crate::media_pipeline::{DirectionConfig, RtcpRelay, SecureSide};
use crate::sdp::{self, EngineMedia, IceRewrite, SecurityAdvertisement, TextRewrite};

/// What the engine shows one party about the leg that faces it. Every SDP the engine hands a party is
/// built from one of these and [`present_leg`]: `offer` presents the far leg to B, `answer` the near
/// leg to A, and a re-offer or a reversed answer whichever leg faces the party it is *delivered to*.
/// The leg decides what is shown, not the verb — three hand-built presentations drifting apart is how
/// a re-offer came to hand B the offerer's own port.
pub(super) struct LegPresentation<'a> {
    /// The leg's engine endpoints (`c=`, `m=audio`, `a=rtcp`).
    pub(super) engine: EngineMedia,
    /// The leg's ICE posture (RFC 8839 §5).
    pub(super) ice: IceRewrite<'a>,
    /// The leg's audio transport security, or `None` to leave the input's transport as it is.
    pub(super) security: Option<SecurityAdvertisement>,
    /// The leg's bound RTCP mux state, when a `rtcp-mux` directive asked for it to be presented
    /// explicitly (RFC 5761); `None` mirrors the input.
    pub(super) mux_override: Option<bool>,
    /// The leg's RFC 4103 text stream.
    pub(super) text: TextRewrite,
    /// Which audio codecs the party is shown.
    pub(super) codec: CodecPresentation<'a>,
}

/// Which audio codecs a presented SDP lists.
pub(super) enum CodecPresentation<'a> {
    /// The input's own list, unchanged — a relay, where both parties share the codec.
    AsReceived,
    /// The offer-side codec policy (`codec-strip/mask/consume/offer/transcode/except`), as `offer`
    /// applies it to B.
    Policy(&'a sdp::CodecPolicy),
    /// Only the leg's own negotiated codec (plus its telephone-event PT). A transcoding call sends
    /// each party its own codec whatever the other one uses, so presenting the other party's list
    /// would offer a codec this leg never receives (RFC 3264 §6).
    Own {
        codec: &'a CodecSpec,
        telephone_event: Option<u8>,
    },
}

/// Rewrite `sdp` to present one leg, as described by `presentation`, and apply the profile's
/// rtpengine `replace` directives with that leg's advertised address. An unsupported `replace` token
/// is logged rather than silently ignored (pre-public-review B15).
pub(super) fn present_leg(
    sdp: &str,
    presentation: LegPresentation<'_>,
    replace: &[String],
    call_id: &str,
) -> Result<String, sdp::SdpError> {
    let advertised_ip = presentation.engine.advertised_ip;
    let mut presented = sdp::rewrite(
        sdp,
        presentation.engine,
        presentation.ice,
        presentation.security,
        presentation.mux_override,
        presentation.text,
    )?
    .sdp;
    match presentation.codec {
        CodecPresentation::AsReceived => {}
        CodecPresentation::Policy(policy) => {
            if !policy.is_noop() {
                presented = sdp::apply_codec_policy(&presented, policy);
            }
        }
        CodecPresentation::Own {
            codec,
            telephone_event,
        } => {
            presented = sdp::force_answer_codec(&presented, codec, telephone_event);
        }
    }
    // rtpengine `replace`: rewrite the o= line to the leg's advertised address (topology hiding) —
    // the interface's advertised IP, not the bound one.
    let (replaced, unsupported_replace) =
        apply_replace_directives(&presented, replace, advertised_ip);
    if !unsupported_replace.is_empty() {
        tracing::warn!(
            %call_id,
            tokens = ?unsupported_replace,
            "ignoring unsupported rtpengine `replace` directive(s); only `origin` is honoured",
        );
    }
    Ok(replaced)
}

/// The audio transport security the far leg presents to B. One rule for every SDP B is sent, so B is
/// never told two different things about one leg: a `dtls: off` downgrade forces plaintext
/// `RTP/AVP`; a DTLS-SRTP leg advertises the engine's fingerprint and `setup` (RFC 5764 / RFC 5763);
/// an SDES leg advertises the engine's own `a=crypto` (RFC 4568); anything else passes the input's
/// transport through.
pub(super) fn far_security(
    downgraded_to_plain: bool,
    dtls: Option<(sdp::Fingerprint, sdp::Setup)>,
    local_crypto: Option<CryptoAttribute>,
) -> Option<SecurityAdvertisement> {
    if downgraded_to_plain {
        Some(SecurityAdvertisement::Plain)
    } else if let Some((fingerprint, setup)) = dtls {
        Some(SecurityAdvertisement::Dtls { fingerprint, setup })
    } else {
        local_crypto.map(SecurityAdvertisement::Secure)
    }
}

/// The audio transport security the near leg presents to A. The mirror of [`far_security`], and it
/// had to become one: it could previously only ever say "plaintext" or "unchanged", which is why a
/// secure *offerer* was never terminated on this path.
///
/// * `near_local_crypto` set — the engine minted its own SDES key for A, so it **is** A's
///   cryptographic far side: advertise that key and strip A's own (RFC 4568).
/// * otherwise, a secure far leg means the engine terminates SRTP there and A's side is plaintext:
///   force `RTP/AVP` and strip the other party's keying.
/// * otherwise, leave the transport alone.
pub(super) fn near_security(
    near_local_crypto: Option<CryptoAttribute>,
    far_secure: bool,
) -> Option<SecurityAdvertisement> {
    match near_local_crypto {
        Some(local) => Some(SecurityAdvertisement::Secure(local)),
        None => far_secure.then_some(SecurityAdvertisement::Plain),
    }
}

/// The ICE posture an **offer** presents for a leg (RFC 8839 §5): ICE-lite re-originated with the
/// engine's credentials and the leg's gathered candidates when the call has credentials; otherwise
/// `a=ice-mismatch` when the offerer's SDP was altered in transit (§5.3, so it stops waiting for
/// checks that will never come), the offerer's ICE stripped on `ice: remove`, or passed through.
pub(super) fn offer_ice_rewrite<'a>(
    credentials: Option<&'a IceCredentials>,
    candidates: &'a [siphon_rtp_ice::Candidate],
    mismatch: bool,
    directive: Option<IceDirective>,
) -> IceRewrite<'a> {
    match (credentials, directive) {
        (Some(credentials), _) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
            ufrag: credentials.ufrag.as_str(),
            pwd: credentials.pwd.as_str(),
            candidates,
        }),
        (None, _) if mismatch => IceRewrite::Mismatch,
        (None, Some(IceDirective::Remove)) => IceRewrite::Strip,
        (None, _) => IceRewrite::Keep,
    }
}

/// The ICE posture `answer` presents for a leg, and so the one a leg re-presented as it was answered
/// keeps: ICE-lite re-originated with the engine's credentials and the leg's candidates when the call
/// has credentials (its ICE posture was decided at offer), the other party's ICE passed through
/// otherwise.
pub(super) fn answer_ice_rewrite<'a>(
    credentials: Option<&'a IceCredentials>,
    candidates: &'a [siphon_rtp_ice::Candidate],
) -> IceRewrite<'a> {
    match credentials {
        Some(credentials) => IceRewrite::Reoriginate(sdp::IceAdvertisement {
            ufrag: credentials.ufrag.as_str(),
            pwd: credentials.pwd.as_str(),
            candidates,
        }),
        None => IceRewrite::Keep,
    }
}

/// The `a=setup` the engine puts in an **offer** for a DTLS-SRTP leg: `actpass` (RFC 5763 §5), or
/// the role a control `dtls: passive|active|actpass` directive asks for (RFC 4145 §4). Subsequent
/// offers included — RFC 8842 §5.5 has an offerer that keeps the existing association still send
/// `actpass`; the unchanged fingerprint is what says "same association", not a pinned role.
pub(super) fn offered_dtls_setup(directive: Option<DtlsDirective>) -> sdp::Setup {
    match directive {
        Some(DtlsDirective::Role(role)) => role,
        _ => sdp::Setup::Actpass,
    }
}

/// Parse rtpengine codec-manipulation flags into a [`sdp::CodecPolicy`] for the SDP offered to the
/// far side. The NG/JSON front-ends flatten the `codec` dictionary
/// (`docs/ng_control_protocol.md`) into `codec-<op>-<NAME>` flag strings, which map as:
/// - `codec-strip-X` — remove X from the offer.
/// - `codec-mask-X` / `codec-consume-X` — remove X from the offer but keep it usable near-side for
///   transcoding. Removing A's own codec from what B is offered is read as exactly that request: the
///   answer-time adoption of B's selection is skipped and the near side keeps X, which engages the
///   transcoder because the near/far codecs then differ (see [`negotiated_near_codec`]). `strip`
///   shares this branch, so it behaves the same way — which is *not* rtpengine's "remove it, I do not
///   want it" and cannot be used to keep a codec off the near leg.
/// - `codec-transcode-X` — add X to the offer; the transcoder engages when the far side selects it.
/// - `codec-except-X` / `codec-accept-X` — a keep-list: X is never stripped (the exception to
///   `strip-all` / `mask-all`).
/// - `codec-offer-X` — a whitelist that sets the far offer's codec order (only the listed codecs, in
///   flag order; the first is preferred).
/// - the special value `all` / `full` on strip/mask removes every codec except the keep-list.
///
/// Unknown / not-yet-encodable `transcode` targets are skipped so a forced codec never fails the call
/// at answer. Names are matched case-insensitively (stored uppercased).
pub(super) fn parse_codec_flags(flags: &[String]) -> sdp::CodecPolicy {
    let mut policy = sdp::CodecPolicy::default();
    for flag in flags {
        if let Some(name) = flag
            .strip_prefix("codec-strip-")
            .or_else(|| flag.strip_prefix("codec-mask-"))
            .or_else(|| flag.strip_prefix("codec-consume-"))
        {
            // The special value `all` / `full` sweeps every codec (bar the keep-list).
            if name.eq_ignore_ascii_case("all") || name.eq_ignore_ascii_case("full") {
                policy.remove_all = true;
            } else {
                policy.remove.push(name.to_ascii_uppercase());
            }
        } else if let Some(name) = flag
            .strip_prefix("codec-except-")
            .or_else(|| flag.strip_prefix("codec-accept-"))
        {
            policy.keep.push(name.to_ascii_uppercase());
        } else if let Some(name) = flag.strip_prefix("codec-offer-") {
            policy.order.push(name.to_ascii_uppercase());
        } else if let Some(name) = flag.strip_prefix("codec-transcode-") {
            if let Some(spec) = transcode_codec_spec(name) {
                policy.add.push(spec);
            }
        }
    }
    policy
}

/// A conventional dynamic RTP payload type for Opus. Not registered — RFC 7587 §7 makes Opus a
/// dynamic payload type — but 111 is what WebRTC endpoints offer in practice, so using it keeps the
/// engine's offer familiar to the peers most likely to answer it. Distinct from the 96 the other
/// dynamic entries in [`transcode_codec_spec`] use, so an offer can carry both.
pub(super) const OPUS_DYNAMIC_PAYLOAD_TYPE: u8 = 111;

/// Map a `codec-transcode-<NAME>` target to a [`CodecSpec`] the engine can both advertise and
/// **encode** (so the forced transcode does not fail at answer). Static codecs use their RFC 3551
/// payload type; dynamic ones use a conventional number.
///
/// `None` for an unknown name, and — crucially — for a *known* name the codec factory cannot actually
/// build an encoder for. That is enforced by probing [`factory::encoder_for`] rather than by a
/// hand-maintained list, so this table can never drift into advertising a transcode target that fails
/// at answer: AMR-WB without the `amr` build feature simply drops out, and lights up on its own once
/// the factory can serve it (which is exactly how Opus arrived, with no edit here).
pub(super) fn transcode_codec_spec(name: &str) -> Option<CodecSpec> {
    let upper = name.to_ascii_uppercase();
    // (payload type, RTP clock, rtpmap channels, ptime): the last two are per-codec, not universal —
    // Opus signals `opus/48000/2` (RFC 7587 §7) even for a mono stream.
    let (payload_type, clock_rate_hz, channels, ptime_ms) = match upper.as_str() {
        "PCMU" => (0u8, 8000u32, 1u8, 20u8),
        "PCMA" => (8, 8000, 1, 20),
        "G722" => (9, 8000, 1, 20),
        "GSM" => (3, 8000, 1, 20),
        "G726-32" => (96, 8000, 1, 20),
        #[cfg(feature = "amr")]
        "AMR-WB" => (96, 16000, 1, 20),
        // RFC 7587: 48 kHz clock (§4.1), rtpmap channel count 2 (§7 — normalised by `CodecSpec::new`
        // regardless), 20 ms default ptime (§6.1). The engine's egress is mono, declared as
        // `sprop-stereo=0` by `sdp::egress_fmtp_line`.
        "OPUS" => (
            OPUS_DYNAMIC_PAYLOAD_TYPE,
            siphon_rtp_codec::factory::OPUS_CLOCK_RATE_HZ,
            siphon_rtp_codec::factory::OPUS_RTPMAP_CHANNELS,
            20,
        ),
        _ => return None,
    };
    let spec = CodecSpec::new(payload_type, &upper, clock_rate_hz, channels, ptime_ms);
    // Advertise only what we can genuinely encode — see the doc comment.
    factory::encoder_for(&spec).is_ok().then_some(spec)
}

/// The explicit ICE posture requested by the control `profile.ice` field (rtpengine `ICE=…`),
/// overriding the SDP-derived default (mirror the offer). `None` ⇒ no directive, mirror the offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IceDirective {
    /// `force` / `force-relay` — advertise engine ICE-lite regardless of whether the offer carried
    /// ICE (RFC 8445). `force-relay` (relay-only candidates) degrades to `force`: the engine has no
    /// TURN allocator, so only its host candidate is offered — documented in `docs/control/json.md`.
    Force,
    /// `remove` — strip the peer's ICE and advertise none (RFC 8839 §5).
    Remove,
}

/// Parse `profile.ice` (case/space-insensitive). An unknown token yields `None` (no override), so a
/// controller cannot silently disable ICE with a typo.
pub(super) fn ice_directive(profile: &ProfileFlags) -> Option<IceDirective> {
    match profile.ice.as_deref()?.trim().to_ascii_lowercase().as_str() {
        "force" | "force-relay" => Some(IceDirective::Force),
        "remove" => Some(IceDirective::Remove),
        _ => None,
    }
}

/// The candidates of one ICE component, for the checklist that component's agent forms.
pub(super) fn filter_component(
    candidates: &[siphon_rtp_ice::Candidate],
    component: u16,
) -> Vec<siphon_rtp_ice::Candidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.component == component)
        .cloned()
        .collect()
}

/// A fresh RFC 8445 §5.2 tie-breaker from the OS CSPRNG. Unlike the consent driver's derived value
/// this one really is security-relevant — it decides who wins a role conflict — so it must not be
/// predictable from the endpoint id. Falls back to a fixed value only if the RNG is unavailable, in
/// which case a conflict resolves deterministically rather than not at all.
pub(super) fn ice_tie_breaker() -> u64 {
    let mut bytes = [0u8; 8];
    match getrandom::fill(&mut bytes) {
        Ok(()) => u64::from_be_bytes(bytes),
        Err(_) => 1,
    }
}

/// The peer's own ICE credentials from a parsed offer/answer — what an outbound connectivity check
/// toward that peer is addressed with and signed by (RFC 8445 §7.1.2), as opposed to
/// [`Call::ice`], which is the engine's identity. Both attributes are mandatory together (RFC 8839
/// §5.4), so a peer that signalled only one of them has no usable credential and is treated as
/// having offered none — the leg keeps the responder and simply runs no consent.
pub(super) fn peer_ice_credentials(info: &sdp::MediaInfo) -> Option<IceCredentials> {
    match (info.ice_ufrag.as_ref(), info.ice_pwd.as_ref()) {
        (Some(ufrag), Some(pwd)) => Some(IceCredentials {
            ufrag: ufrag.clone(),
            pwd: pwd.clone(),
        }),
        _ => None,
    }
}

/// The explicit DTLS-SRTP posture requested by the control `profile.dtls` field (rtpengine `DTLS=…`)
/// for a secure (`UDP/TLS/RTP/SAVP[F]`) far leg, overriding the hardcoded offerer role. `None` ⇒ no
/// directive (the RFC 5763 §5 default, `a=setup:actpass`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DtlsDirective {
    /// `off` — no DTLS-SRTP; the far leg is advertised plaintext `RTP/AVP` (RFC 3264) even when a
    /// UDP/TLS transport was requested.
    Off,
    /// `passive` / `active` / `actpass` — advertise DTLS with this `a=setup` role (RFC 4145 §4).
    Role(sdp::Setup),
}

/// Parse `profile.dtls` (case/space-insensitive). An unknown token yields `None` (keep the default
/// `actpass` offerer role).
pub(super) fn dtls_directive(profile: &ProfileFlags) -> Option<DtlsDirective> {
    match profile
        .dtls
        .as_deref()?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "off" => Some(DtlsDirective::Off),
        "passive" => Some(DtlsDirective::Role(sdp::Setup::Passive)),
        "active" => Some(DtlsDirective::Role(sdp::Setup::Active)),
        "actpass" => Some(DtlsDirective::Role(sdp::Setup::Actpass)),
        _ => None,
    }
}

/// Decide how a call's media is carried once answered: an SRTP bridge (secure far leg), the
/// userspace media slow path (transcode requested or recording on), or the in-datapath plain relay.
/// Whether two specs name the same negotiated codec: the `a=rtpmap` encoding name (case-insensitive,
/// RFC 4566 §6), the RTP clock rate and the channel count. Deliberately **not** the payload type — the
/// two sides of a call may number the same codec differently, and it is the encoding, not the number,
/// that decides whether a transcoder is needed.
pub(super) fn same_codec(left: &CodecSpec, right: &CodecSpec) -> bool {
    left.encoding_name
        .eq_ignore_ascii_case(&right.encoding_name)
        && left.clock_rate_hz == right.clock_rate_hz
        && left.channels == right.channels
}

/// Build one transcode direction's config: decode the ingress codec, encode the egress codec, and
/// (when recording) capture the decoded ingress audio. Fails if either codec is unimplemented.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_direction(
    ingress_endpoint: EndpointId,
    accepted_source: SourceFilter,
    egress_endpoint: EndpointId,
    egress_dst: std::net::SocketAddr,
    ingress_codec: &CodecSpec,
    egress_codec: &CodecSpec,
    telephone_event_in: Option<u8>,
    telephone_event_out: Option<u8>,
    record_path: Option<&str>,
    noise_suppression: bool,
    echo: crate::media_pipeline::EchoProfile,
    beep_detection: bool,
    beep_cadence_guard_ms: Option<u32>,
) -> Result<DirectionConfig, String> {
    // Name the codec (and which half of the transcode wanted it) in the failure: the factory's error
    // holds a `&'static str`, so on its own it says only "unsupported", leaving an operator to guess
    // which leg's codec the engine could not build.
    let decoder = factory::decoder_for(ingress_codec).map_err(|error| {
        format!(
            "cannot decode the ingress codec {}/{} (payload type {}): {error}",
            ingress_codec.encoding_name, ingress_codec.clock_rate_hz, ingress_codec.payload_type
        )
    })?;
    let encoder = factory::encoder_for(egress_codec).map_err(|error| {
        format!(
            "cannot encode the egress codec {}/{} (payload type {}): {error}",
            egress_codec.encoding_name, egress_codec.clock_rate_hz, egress_codec.payload_type
        )
    })?;
    // Record at the codec's *native* PCM rate (what the decoder emits), not the RTP clock — they
    // differ for G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2), and a clock-rate WAV header
    // would replay the recording at the wrong pitch.
    //
    // One channel, and that stays right even for a stereo ingress: the media path folds a
    // multi-channel decoded frame to mono at the codec trait boundary (`downmix_to_mono`) *before*
    // the recorder sees it, so the PCM written here is always single-channel. Only a genuinely
    // multi-channel media path would change this, not a multi-channel codec.
    let recorder = record_path.map(|_| WavRecorder::new(decoder.params().sample_rate_hz, 1));
    Ok(DirectionConfig {
        ingress_endpoint,
        accepted_source,
        egress_endpoint,
        egress_dst,
        decoder,
        encoder,
        egress_ssrc: random_ssrc(),
        egress_payload_type: egress_codec.payload_type,
        telephone_event_in,
        telephone_event_out,
        recorder,
        // The suppressor is built (and rate-gated) inside `Direction::new` from the decoder's native
        // rate; carry only the request here. Inert unless the ingress rate is 8/16 kHz.
        noise_suppression,
        // Likewise the canceller: built and rate-gated in `Direction::new`, so only the request and
        // its posture (search window or long tail, residual post-filter) travel here.
        echo,
        // The detector is built (and rate-gated) inside `Direction::new` from the decoder's native
        // rate; carry only the request and the optional cadence-guard override here.
        beep_detection,
        beep_cadence_guard_ms,
        // A 2-party leg's echo cancellation is symmetric: both directions cancel, so each must also
        // produce the far-end reference the other reads (the audio it sends toward its party). Hence
        // `produce_echo_reference == echo.enabled` here — the two are only ever set apart for a
        // (future) single-leg asymmetric AEC or in the integration tests.
        produce_echo_reference: echo.enabled,
        // The G.107 codec class of the stream this direction decodes (the ingress codec), for the MOS
        // in its periodic quality report — mapped the same way as the HEP QoS / conference paths.
        ingress_mos_codec: crate::conference::hep_codec_for_name(&ingress_codec.encoding_name),
    })
}

/// The two directions of a two-party transcoding call, described once: A→B decodes the near leg's
/// codec and encodes the far leg's toward B, B→A the reverse. Each side's gate and destination are
/// resolved by the caller (the answer's effective addresses, or a snapshot's signalled ones).
pub(super) struct TranscodePair<'a> {
    pub(super) near_endpoint: EndpointId,
    pub(super) near_source: SourceFilter,
    pub(super) near_dst: std::net::SocketAddr,
    pub(super) far_endpoint: EndpointId,
    pub(super) far_source: SourceFilter,
    pub(super) far_dst: std::net::SocketAddr,
    pub(super) near_codec: &'a CodecSpec,
    pub(super) far_codec: &'a CodecSpec,
    pub(super) near_telephone_event: Option<u8>,
    pub(super) far_telephone_event: Option<u8>,
    pub(super) record_path: Option<&'a str>,
    pub(super) noise_suppression: bool,
    pub(super) echo: crate::media_pipeline::EchoProfile,
    pub(super) beep_detection: bool,
    pub(super) beep_cadence_guard_ms: Option<u32>,
}

/// Build both directions of `pair`, A→B first. A failure names the direction that could not be
/// built (`"A→B"` or `"B→A"`) alongside the reason, so the caller can put it in its own context.
pub(super) fn build_transcode_pair(
    pair: &TranscodePair<'_>,
) -> Result<(DirectionConfig, DirectionConfig), (&'static str, String)> {
    let a_to_b = build_direction(
        pair.near_endpoint,
        pair.near_source,
        pair.far_endpoint,
        pair.far_dst,
        pair.near_codec,
        pair.far_codec,
        pair.near_telephone_event,
        pair.far_telephone_event,
        pair.record_path,
        pair.noise_suppression,
        pair.echo,
        pair.beep_detection,
        pair.beep_cadence_guard_ms,
    )
    .map_err(|reason| ("A→B", reason))?;
    let b_to_a = build_direction(
        pair.far_endpoint,
        pair.far_source,
        pair.near_endpoint,
        pair.near_dst,
        pair.far_codec,
        pair.near_codec,
        pair.far_telephone_event,
        pair.near_telephone_event,
        pair.record_path,
        pair.noise_suppression,
        pair.echo,
        pair.beep_detection,
        pair.beep_cadence_guard_ms,
    )
    .map_err(|reason| ("B→A", reason))?;
    Ok((a_to_b, b_to_a))
}

/// How the companion RTCP relays of a transcoding call with a secure far (B) party are keyed.
pub(super) enum RtcpKeying {
    /// With the SDES leg the call already holds.
    Leg(Arc<Mutex<SecureLeg>>),
    /// Pending until the DTLS handshake delivers a leg; the relays drop until then (RFC 5764).
    Pending,
}

/// The two companion (non-muxed) RTCP relays of a transcoding call whose far (B) party is secure:
/// A's RTCP encrypted toward B, B's SRTCP decrypted toward A (RFC 3711; RFC 5761 keeps RTCP on its
/// own port). The caller redirects both endpoints to the actor.
#[allow(clippy::too_many_arguments)]
pub(super) fn secure_rtcp_relays(
    near_rtcp: EndpointId,
    near_source: SourceFilter,
    far_dst: std::net::SocketAddr,
    far_rtcp: EndpointId,
    far_source: SourceFilter,
    near_dst: std::net::SocketAddr,
    keying: &RtcpKeying,
) -> Vec<RtcpRelay> {
    let toward_far = RtcpRelay::new(near_rtcp, near_source, far_rtcp, far_dst);
    let toward_near = RtcpRelay::new(far_rtcp, far_source, near_rtcp, near_dst);
    match keying {
        RtcpKeying::Leg(leg) => vec![
            toward_far.with_secure_egress(leg.clone()),
            toward_near.with_secure_ingress(leg.clone()),
        ],
        RtcpKeying::Pending => vec![
            toward_far.with_pending_secure(SecureSide::Egress),
            toward_near.with_pending_secure(SecureSide::Ingress),
        ],
    }
}

/// Apply the supported rtpengine `replace` directives to `sdp`, returning the rewritten SDP and the
/// list of requested tokens that were **not** applied.
///
/// Only `origin` is implemented (rewrite the `o=` line's unicast-address to the engine's advertised
/// address for topology hiding, RFC 4566 §5.2). Every other rtpengine `replace` token
/// (`session-connection`, `session-name`, `zero-address`, `SDES`, `force-increment-sdp-ver`, …) is a
/// recognized directive we do not yet honour; rather than silently swallow it (pre-public-review B15)
/// it is returned so the caller surfaces it in a `warn!`. Token matching is ASCII-case-insensitive.
pub(super) fn apply_replace_directives(
    sdp: &str,
    replace: &[String],
    advertised_ip: std::net::IpAddr,
) -> (String, Vec<String>) {
    let mut rewrite_origin = false;
    let mut unsupported = Vec::new();
    for token in replace {
        if token.eq_ignore_ascii_case("origin") {
            rewrite_origin = true;
        } else {
            unsupported.push(token.clone());
        }
    }
    let sdp = if rewrite_origin {
        sdp::rewrite_origin(sdp, advertised_ip)
    } else {
        sdp.to_string()
    };
    (sdp, unsupported)
}

/// A fresh SSRC for a synthesized (transcoded) egress stream, from the OS CSPRNG (RFC 3550 §8 wants
/// a random SSRC). Falls back to a fixed value if the CSPRNG is unavailable — never panics.
pub(super) fn random_ssrc() -> u32 {
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return 0x5310_0000; // "SIP0" — a stable fallback when the CSPRNG is unavailable
    }
    u32::from_be_bytes(bytes)
}

/// Resolve the rtpengine `rtcp-mux` directive list into the `(near_mux, far_mux)` decision for a
/// call (RFC 5761). `offered` is whether the offer's SDP carried `a=rtcp-mux` (the near side's
/// intent). The first recognised directive wins; an empty/unknown list mirrors the offer.
///
/// - `offer` / `require`: force mux on the generated (far) SDP → 1 far port. The near side follows
///   the offer (mux iff it was offered).
/// - `demux`: present separate RTCP to the far side (2 far ports, strip `a=rtcp-mux`) while the near
///   side stays as offered — the engine bridges a muxed access leg to a non-muxed core.
/// - `reject` / `remove`: no mux either side → 2 ports both sides, `a=rtcp-mux` stripped.
/// - `accept` (or no directive): mirror the offer on both sides (the default behaviour).
pub(super) fn resolve_rtcp_mux(offered: bool, directives: &[String]) -> (bool, bool) {
    for directive in directives {
        match directive.as_str() {
            "offer" | "require" => return (offered, true),
            "demux" => return (offered, false),
            "reject" | "remove" => return (false, false),
            "accept" => return (offered, offered),
            _ => continue,
        }
    }
    (offered, offered)
}

/// Apply an rtpengine `received-from` source hint to a leg's SDP-signalled address: when `hint` is
/// set (the real post-NAT source IP the SIP proxy saw the request come from), return the signalled
/// **port** paired with the hint IP; otherwise the signalled address unchanged. Only the IP the
/// source gate keys on is overridden — never the port (the media port differs from the signalling
/// port), and never the gate *policy* (Exact/Subnet/Any is still chosen by `ingress_rule` /
/// `bridge_source_filter` from the profile flags). This tightens the NAT case: a UA whose `c=`
/// advertised a private (unusable) address is gated precisely to its NAT's public IP rather than
/// forced onto a symmetric/any gate (docs/security-and-nat.md §4 layer 2, RFC 3264).
pub(super) fn apply_received_from(
    signalled: Option<std::net::SocketAddr>,
    hint: Option<std::net::IpAddr>,
) -> Option<std::net::SocketAddr> {
    match (signalled, hint) {
        (Some(addr), Some(ip)) => Some(std::net::SocketAddr::new(ip, addr.port())),
        (addr, _) => addr,
    }
}

/// The source-address gate for an SRTP-bridge leg, mirroring [`ingress_rule`]'s policy: an exact
/// source-IP gate by default (the tightest RTPBleed defence), the signalled /24 (v4) or /64 (v6)
/// under `subnet-source`, or any source under `symmetric`. The bridge enforces this itself because
/// the `Redirect` path bypasses the datapath's Forward-path source gate (docs/security-and-nat.md
/// §4 layer 2).
pub(super) fn bridge_source_filter(
    profile: &ProfileFlags,
    addr: std::net::SocketAddr,
) -> SourceFilter {
    if profile.flags.iter().any(|flag| flag == "symmetric") {
        SourceFilter::Any
    } else if profile.flags.iter().any(|flag| flag == "subnet-source") {
        let prefix = if addr.is_ipv4() { 24 } else { 64 };
        SourceFilter::Subnet(addr.ip(), prefix)
    } else {
        SourceFilter::Exact(addr.ip())
    }
}
