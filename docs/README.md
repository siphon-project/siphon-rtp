# siphon-rtp

**A pure-Rust, kernel-accelerated media engine for [SIPhon](https://github.com/siphon-project/siphon-sip)
and for existing Kamailio / OpenSIPS deployments.**

siphon-rtp is the media plane SIPhon owns: an RTP/SRTP relay, a bit-exact VoLTE codec stack, a
transcoder, an N-party conferencing MCU, and a bidirectional RTP↔WebSocket bridge for voice-AI. It
speaks two control protocols onto one engine, so it drops in for SIPhon over native JSON and for
`mod_rtpengine` deployments over the rtpengine NG wire.

The design bets are deliberate:

- **Pure Rust, zero C library dependencies.** Every codec is hand-written Rust. No ffmpeg, no
  libopus, no spandsp, no libsrtp, no `-sys` codec crates. SRTP/DTLS ride RustCrypto, the XDP path
  rides `aya`. The payoff is one statically-linkable binary, clean licensing, and bit-exact AMR that
  ships in a single artifact.
- **IMS/VoLTE codecs first.** G.711 for PSTN interconnect, AMR-NB and AMR-WB for VoLTE, all bit-exact
  against the 3GPP and ITU reference vectors.
- **A gated latch, no RTPbleed.** The relay only adopts a media source consistent with the
  SDP-signalled address, never re-latches mid-stream, and drops packets from unexpected sources. NAT
  traversal is a first-class feature, not an afterthought.
- **Drop-in twice over.** A native JSON-over-TCP control protocol for SIPhon, and an optional
  rtpengine NG/bencode front-end so existing Kamailio / OpenSIPS deployments switch with no signalling
  change.

## New here? Start with the Cookbook

The **[Cookbook](cookbook/index.md)** has concrete starting points for the common jobs, each with the
control exchange and how to verify it:

[Plain relay](cookbook/relay.md) ·
[Transcoding](cookbook/transcoding.md) ·
[Secure media (SRTP)](cookbook/secure-srtp.md) ·
[WebRTC (DTLS/ICE/TURN)](cookbook/webrtc.md) ·
[Voice-AI (WebSocket)](cookbook/voice-ai.md) ·
[Conferencing](cookbook/conferencing.md) ·
[NAT & latching](cookbook/nat.md) ·
[Recording & forking](cookbook/recording.md) ·
[Monitoring](cookbook/monitoring.md)

## The control protocols

- **[Native JSON-over-TCP](control/json.md)**: length-prefixed JSON, request/response correlated by
  id, async events pushed back, optional shared-secret auth. The protocol SIPhon speaks.
- **[rtpengine NG / bencode](control/ng.md)**: the rtpengine wire protocol, so an existing
  Kamailio / OpenSIPS + `mod_rtpengine` stack points at siphon-rtp unchanged.

## Running it in production

- **[Deployment & operations](deployment.md)**: install, the CLI flags, container profiles, health
  and readiness probes, graceful drain, and the ops runbook.
- **[Scaling, clustering & HA](scaling-and-ha.md)**: how a single-node engine scales behind the SIP
  dispatcher, the load/drain surface for rolling upgrades, and warm-standby checkpoint/restore.
- **[Datapath](datapath.md)**: the UDP backend that runs today and the eBPF/XDP in-kernel path that
  is built but not yet wired in. An honest map of what forwards where.
- **[Supply chain & SBOM](supply-chain.md)**: the per-release SPDX + CycloneDX SBOM, the cargo-deny
  audit that enforces the zero-C rule, and how to report a vulnerability.
- **[Migrating from rtpengine](migrating-from-rtpengine.md)**: the NG parity table and what to
  validate after cutover.

## Reference

- **[Codec support matrix](codecs.md)**: what encodes, what decodes, what is bit-exact, and which
  Cargo feature gates it.
- **[Security & NAT design](security-and-nat.md)**: the threat model and the layered secure-latch
  design. The source of truth for why the relay accepts, latches, and forwards a packet.
- **[Observability & call quality](observability.md)**: Prometheus metrics, RTCP reception reports,
  G.107 MOS, and the `call_quality` events.
- **[Codec licensing & patents](codec-licensing.md)**: why passthrough is always free, and why AMR
  transcoding sits behind an opt-in feature.

## Also

- The main **[README](https://github.com/siphon-project/siphon-rtp/blob/main/README.md)**: overview,
  install, the performance baseline, and the full feature table.
- **[Commercial support & sponsorship](https://realtime-telecom.nl)** from
  **Real Time Telecom B.V.**, run by the maintainer.
