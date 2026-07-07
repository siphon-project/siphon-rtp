# siphon-rtp — Security & NAT design

> Design + threat model for the media plane. Status: **implemented and wired.** The gated latch, the
> source-consistency checks, symmetric-RTP NAT traversal, SDP address rewrite, ICE-lite + STUN, the
> built-in TURN server, SRTP-SDES (RFC 3711 / 4568), and DTLS-SRTP (RFC 5764) all ship today. The main
> remaining item is full ICE (state machine + consent freshness, RFC 8445 / 7675); ICE-lite is the
> current server posture. Crypto posture: secure legs stay secure end to end, and a plaintext leg can
> still run behind network-layer security (IPsec / SBC / private bearer) where a deployment prefers
> that. Order as built: **latch hardening, then SRTP/DTLS keying, then ICE/TURN, then DoS /
> control-plane hygiene.**
>
> This document is the source of truth for *why* the relay accepts, latches, and forwards a packet.
> Every enforcement point below cites the spec it implements; any deviation must say so and why.

---

## 1. Why security and NAT are one problem here

A relay learns where to send a party's media by **latching**: it forwards toward the source address
of the packets it actually receives, because the SDP-advertised address is often unusable for a UA
behind NAT (RFC 4961 symmetric RTP; rtpengine "latching"). That single mechanism is:

- the **NAT-traversal feature** — follow the peer to wherever its packets really come from; and
- the **primary attack surface** — whoever the relay latches to *is* the call.

So "do NAT correctly" and "don't get hijacked" are the same state machine seen from two sides. NAT
wants latching **flexible** (re-learn on a NAT rebind); security wants it **strict** (never follow an
attacker). This document defines the one policy that satisfies both.

---

## 2. RTPBleed: the original hole, and the fix

> **Status — M-S1 (landed):** layers 2–3 below are implemented. The blind first-source `or_insert`
> latch is gone; ingress is now **source-gated** and the latch is **SSRC-consistent** (`update_latch`
> in [`udp.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-datapath/src/udp.rs); rules built by `ingress_rule` in
> [`engine.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/src/engine.rs) from the parsed SDP + `ProfileFlags`).
> Layer 1 (RFC 7983 demux) is in too; only layer 6 (media-timeout) remains — see §8. The original
> hole, for the record:

[`crates/siphon-rtp-datapath/src/udp.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-datapath/src/udp.rs), `recv_loop`:

```rust
inner.latched.entry(endpoint).or_insert(source);
```

This latches the forward target to **the first source that sends any datagram to the port**, with:

- **no source check** against the SDP-signalled address (which the engine *does* know —
  `remote_near` / `remote_far`);
- **no packet classification** — it latches on STUN, DTLS, garbage, anything;
- **no gating on call state** — the per-endpoint receive loop starts at `alloc_endpoint`, i.e. from
  `offer`, *before* `answer` installs a flow, and it latches even on `Redirect` / `Drop` / no-flow
  endpoints.

This is the **RTPBleed** primitive (Enable Security / Sandro Gauci, 2017; the class rtpengine then
hardened against):

1. The engine's media UDP port range is scannable.
2. An attacker sprays RTP across it. On any live port, if their packet beats the real peer, the relay
   latches to **them**.
3. Result: the victim's media is forwarded to the attacker (**eavesdrop**) and the attacker's media
   is forwarded to the victim (**injection**).

`or_insert` (latch-once) blocks mid-call *re*-latch — but it is wrong on **both** ends:

- the **first-packet race is wide open** (security hole); and
- the latch **never expires or re-learns**, so a genuine **NAT rebind** mid-call is never followed
  (NAT correctness hole).

Today's logic is simultaneously too loose for security and too rigid for NAT. The fix is one
redesign of the latch lifecycle, below.

---

## 3. Threat model

### 3.1 Assets
- **Confidentiality** of in-progress call media (no eavesdrop).
- **Integrity** of call media (no injection / no stream takeover).
- **Availability** of the relay (no port/FD/CPU exhaustion; no wedged sessions).
- **Isolation** between calls and between control clients (one client cannot read/kill another's
  call).

### 3.2 Adversaries
- **A1 — Off-path blind attacker.** Can send UDP to the engine's public media ports; cannot see
  call media; does not know `call_id`/tags. The RTPBleed actor. *Primary threat.*
- **A2 — On-path observer.** Can see media (shared L2, mirror, compromised transit). Plaintext RTP
  is readable to A2 by definition — out of scope for the media plane in this posture; mitigated at
  the network layer (IPsec / private bearer). Documented, not solved here.
- **A3 — Malicious/compromised control client.** Speaks the JSON control protocol. Can it exhaust
  ports, or tear down / inspect calls it does not own?
- **A4 — Hostile peer / bitstream.** A legitimately-signalled peer that sends malformed RTP/RTCP or a
  hostile codec bitstream to crash or wedge the engine.

### 3.3 Trust boundaries
- **Media plane (untrusted):** every byte on a media socket is hostile until classified, source-
  gated, and (where applicable) ICE/SRTP-validated. §4.
- **Control plane (semi-trusted):** the SIPhon ↔ engine JSON-over-TCP channel. Authenticated,
  private-bound, per-client quota'd. §6.
- **Network layer (trusted by deployment):** IPsec / SBC / private bearer carries the confidentiality
  guarantee in this posture. The media plane must not *rely* on it for integrity/availability — those
  are enforced here regardless.

---

## 4. The media-plane design: layered secure symmetric RTP

Six layers, applied in order to every received datagram. Each names its spec and its enforcement
point. Layers 1–3 are the RTPBleed fix and the correct NAT latch; layer 4 (ICE) supersedes blind
latching where offered; layers 5–6 round out the surface.

### Layer 1 — Demultiplex before anything else
Classify each datagram by its first byte and route it; **only RTP/RTCP may touch the media latch.**

| First byte | Protocol | Action |
|---|---|---|
| 0–3 | STUN | ICE / consent path (§4.4) |
| 16–19 | ZRTP | drop (not supported) |
| 20–63 | DTLS | DTLS-SRTP handshake (§5) |
| 64–79 | TURN channel | drop |
| 128–191 | RTP / RTCP | media path (layers 2–3) |
| else | unknown | drop, count |

- **Spec:** RFC 7983 (multiplexing demux ranges), updating RFC 5764 §5.1.2.
- **Enforcement:** one `siphon_rtp_datapath::classify` → `PacketClass` table backs the whole demux —
  the datapath receive path (STUN answered in-datapath on an ICE endpoint, RTP/RTCP gated to the media
  latch, everything else dropped on the `Forward` path before any latch write) *and* the userspace
  split of a secure WebRTC leg's `Redirect` stream into its DTLS-handshake and SRTP-media sub-streams.
- **Effect on A1:** garbage and STUN sprays can no longer poison the media latch.

### Layer 2 — Signalled-source gate
Only **accept** (and only latch from) media whose source matches the address learned from SDP.

- Default policy `SignalledOnly`: source IP must equal the SDP `c=`/`m=` address (the engine already
  parses this into `remote_near` / `remote_far`). A `/24`-tolerant mode covers carriers that split
  RTP/RTCP across nearby addresses or re-NAT within a block.
- **`received-from` (the NAT-aware signalled source, rtpengine parity).** When a UA sits behind NAT
  it advertises its *private* `c=` address, which its media never actually comes from — the raw
  `SignalledOnly` gate would then be `Exact(private-ip)`, which never matches the real (public) media
  source, forcing the leg onto `Symmetric`/`Any` (a strictly weaker gate). The SIP proxy already knows
  the real post-NAT source: the address it saw the request *arrive* from. It passes that to the engine
  as rtpengine's `received-from` list (`["IP4"|"IP6", "<address>"]` → `ProfileFlags.received_from`).
  When present, the engine **overrides the gated source IP** with it — the offer's `received-from`
  tightens the near (A) leg, the answer's the far (B) leg — keeping the signalled media port and the
  chosen gate *policy* (`Exact`/`Subnet`/`Any`) untouched. This is a **tightening**, not a relaxation:
  a NATed UA is gated precisely to its NAT's public IP (`Exact(public-ip)`) instead of falling back to
  an open latch. Only the IP is carried (the media port differs from the signalling port, so the port
  is never gated — consistent with `SourceFilter` gating on IP only). Threaded into **every** gate
  path — the datapath Forward relay, the redirect-dispatched media/transcode actor's `accepted_source`,
  the SRTP bridge (`bridge_source_filter`), and the WS bridge — so no path silently keeps the private
  address.
- Relax to `Symmetric` (accept any source, latch the first) **only** when the control plane sets it —
  for UAs behind symmetric NAT where the signalled address is genuinely unusable. This is opt-in per
  leg, never a global default.
- **Spec:** RFC 3264 (the offer/answer address *is* the contract); mirrors rtpengine
  `trust-address` / `strict-source` / `received-from`.
- **Enforcement:** new accepted-source constraint on the forward rule (§4.7); engine fills it from
  parsed SDP + `ProfileFlags.received_from` + `ProfileFlags.flags` (`trust-address`, `strict-source`,
  `port-latching`, `symmetric`).
- **Effect on A1:** with `SignalledOnly`, a blind attacker must *also* spoof the signalled source IP
  to land a packet — collapses the off-path attack for non-NAT and full-cone-NAT peers.

### Layer 3 — Sticky, SSRC-consistent latch (the NAT-rebind vs hijack reconciliation)
Replace the permanent `or_insert` with a lifecycle that follows a real rebind but resists a spray.

Latch state machine, per direction:

```
            first accepted+classified RTP
 Unlatched ───────────────────────────────▶ Latched{addr, ssrc, last_seen}
                                                 │
        new source, SAME ssrc (RFC 3550 §8)      │   new source, DIFFERENT ssrc
        = NAT rebind  ──────re-latch────────────▶│◀────────── = hijack attempt: REJECT, count
                                                 │
                       no accepted packet for T  │
                       ──────────────────────────▶ Dead → teardown + Event (§4.6)
```

- First accepted packet (passing layers 1–2) latches `addr` and records the RTP **SSRC**.
- A packet from a **new** source re-latches **only if it carries the same SSRC** — a genuine NAT
  rebind keeps its SSRC; an attacker spraying a fresh stream does not. (With SRTP later, gate re-latch
  on a valid auth tag instead — strictly stronger.)
- **Spec:** RFC 3550 §8 (SSRC identity/collision), RFC 4961 (symmetric RTP/RTCP).
- **Enforcement:** datapath latch state carries `ssrc`; needs the RTP header parse already in
  `siphon-rtp-media`.
- **In-kernel enforcement (XDP_TX fast path).** For a plain `Forward` (`rtp_passthrough`) leg these
  same three layers run **in the kernel** before the relay: the eBPF classifier demuxes (layer 1,
  RFC 7983), re-checks the signalled-source gate (layer 2), and applies this SSRC-consistent latch —
  learning the peer's real source into the flow's kernel latch state and re-latching a new source
  only on a matching SSRC (RFC 3550 §8). It then rewrites L3/L4 with an RFC 1624 incremental checksum
  fixup and `XDP_TX`s. The kernel latch is the **source anchor** (the RTPBleed / strict-source check,
  rtpengine `expected_src`); the forward **destination** stays the userspace-maintained `out_dst`
  (rtpengine `dst_addr`), never a flow's own ingress latch (which would echo). Consequently the
  symmetric reply to an as-yet-unlearned peer — which the loopback backend resolves via the *peer*
  leg's latch — stays on the userspace/`Redirect` path, since the per-flow kernel ABI carries no
  cross-leg latch reference; a FIB miss / unresolved neighbour likewise falls back to `Redirect`.
- **Effect on A1:** even inside the learning window, a hijack must reproduce the victim's live SSRC,
  which the blind attacker does not know.

### Layer 4 — ICE supersedes blind latching where offered
When SDP carries ICE, **connectivity checks replace latching** as the address-learning mechanism.

> **Status (responder landed):** the **STUN codec** (`siphon-rtp-stun` — pure Rust, hand-rolled
> SHA-1 / HMAC / CRC-32, validated against the SHA-1, HMAC (RFC 2202), and CRC-32 known-answer
> vectors) **plus the datapath connectivity-check responder**: on an ICE endpoint
> (`Datapath::set_ice`), a STUN Binding check whose `USERNAME` addresses us and whose
> `MESSAGE-INTEGRITY` verifies with our local password is answered with a signed Binding success
> response and **adopts the validated source as the media path** (superseding blind latching); a
> forged check is dropped. **Engine wiring (landed):** `sdp::parse`/`rewrite` carry ICE, `engine::ice`
> mints credentials from the OS CSPRNG, and at offer/answer the engine re-originates ICE as
> **ICE-lite** — advertising `a=ice-lite` + its own ufrag/pwd + a host candidate and calling
> `set_ice` on the ICE legs, which then answer checks and adopt the validated source; end-to-end
> tested. **Remaining:** full (non-lite) ICE for cases where the engine must *send* connectivity
> checks (the engine as ICE controlling agent). Consent loss is handled — a valid check stamps
> activity, so the media-timeout sweep reaps an ICE path that stops receiving checks — and RTCP-port
> ICE under non-mux is wired.

- The peer proves reachability with a STUN Binding request authenticated by the negotiated
  `ice-ufrag`/`ice-pwd` (MESSAGE-INTEGRITY) — a challenge/response A1 cannot forge without the SDP it
  never saw. The validated candidate pair, not "first packet wins", becomes the path.
- **Consent freshness** (RFC 7675): periodic STUN keepalives; on consent loss, stop forwarding and
  tear down. This is also the anti-hijack *and* the dead-path detector.
- **Spec:** RFC 8445 (ICE), RFC 8839 (SDP for ICE), RFC 8489 (STUN), RFC 7675 (consent).
- **Enforcement:** `profile.ice` (`force` / `remove`; `force-relay` degrades to `force`) now
  overrides the SDP-derived ICE posture; STUN served on the media socket via the layer-1 demux.
- **Note:** for non-ICE legacy VoLTE/PSTN UAs (the common case), layers 1–3 are the whole story; ICE
  applies to ICE-capable peers (RCS, WebRTC bridges, modern clients).

### Layer 5 — SRTP / DTLS-SRTP
The cryptographic fix: authenticated media cannot be injected or silently hijacked even if the latch
is wrong, and encryption defeats A2 eavesdrop.

> **Status (landed — SDES bridge):** SRTP over **SDES** (RFC 4568 `a=crypto`) is implemented and
> wired for the `RTP/AVP` ↔ `RTP/SAVP` **bridge** topology (Scenario 1). The crypto core is the
> isolated [`siphon-rtp-srtp`](https://github.com/siphon-project/siphon-rtp/tree/main/crates/siphon-rtp-srtp) crate: AES-CM + HMAC-SHA1 key derivation
> validated bit-exact against the RFC 3711 §4.3.2 vectors, SRTP (§3.3) and SRTCP (§3.4)
> protect/unprotect for `AES_CM_128_HMAC_SHA1_80` with §3.3.2 anti-replay on the receive path, and
> `SecureLeg` (the directional in/out contexts +
> RFC 5761 RTP/RTCP demux). Pure-Rust RustCrypto (`aes`/`ctr`/`hmac`/`sha1`) — **not** ring, which has
> no AES-CM; still zero-C. The engine generates its SDES key on a secure leg, parses the peer's, and
> bridges plaintext ↔ SRTP via the userspace `Redirect` path (`engine/src/srtp_bridge.rs`).
>
> **DTLS-SRTP is implemented** (the WebRTC keying path, RFC 5764) via `siphon-rtp-dtls` +
> `engine/src/dtls_bridge.rs`: the offer advertises `a=fingerprint` + `a=setup:actpass`, and the
> handshake keys the same `SecureLeg` through the same profile flags below.

- **Source gate on the bridge path (RTPBleed, restated for `Redirect`).** The SRTP bridge runs on the
  `FlowAction::Redirect` slow path, which **bypasses** the datapath's Forward-path layer-2 gate. The
  bridge therefore **re-enforces** the signalled-source gate itself (`bridge_source_filter`, the same
  `Exact`/`Subnet`/`Any` policy as `ingress_rule`) before any crypto — an off-path spray is dropped at
  the bridge, not decrypted. SRTP auth (HMAC-SHA1-80) is the second line: a forged packet from the
  gated address still fails authentication and is dropped (the rollover counter advances only after
  auth succeeds). **Anti-replay is the third line** (RFC 3711 §3.3.2, enforced in
  `SrtpContext::unprotect` / `SrtcpContext::unprotect`): a per-SSRC 64-packet sliding window over the
  SRTP packet index — and over the explicit SRTCP index — rejects a duplicated or too-old packet, so a
  captured but still-valid packet re-injected by an on-path attacker is dropped as a replay rather than
  re-forwarded. The window is recorded only *after* authentication, so a forged packet can never
  advance or poison it; on an HA takeover the standby anchors the window at the checkpointed rollover
  index and keeps rejecting the primary's last-seen packet.
- **Key direction (the footgun `SecureLeg` pins down).** Outbound (engine→peer) encrypts with the
  engine's *own* offered key (the `a=crypto` it advertised); inbound (peer→engine) decrypts with the
  *peer's* answered key. The peer's `a=crypto` is always re-originated (dropped and replaced), like
  ICE — a secure leg's key never leaks onto the plaintext leg's rewritten SDP.
- **Seam (present):** `ProfileFlags.transport_protocol` (`RTP/SAVP[F]`, `UDP/TLS/RTP/SAVPF`) selects a
  secure leg; `profile.dtls` (`off`/`passive`/`active`/`actpass`) is now honoured and overrides the
SDP-derived DTLS posture.
- **Spec:** RFC 3711 (SRTP/SRTCP), RFC 4568 (SDES — keys in SDP, so the signalling path must be TLS),
  RFC 5764 (DTLS-SRTP, implemented). Pure-Rust only, per the zero-C hard rule. **SDES key material must
  never transit a plaintext control channel** — keys in `a=crypto` are only as safe as the signalling.

### Layer 5b — The media (transcode / record / DTMF) Redirect path
The transcode/record/DTMF-extraction slow path (`engine/src/media_pipeline.rs`) shares the SRTP
bridge's posture because it runs on the **same `FlowAction::Redirect`** seam, which bypasses the
datapath's Forward-path layer-2 gate.

> **Status (landed — media slow path):** when the two legs' negotiated codecs differ, or recording is
> requested, the call is resolved to `PipelineKind::Media` and both RTP legs are set to `Redirect`.
> The redirect dispatcher (`run_redirect_dispatcher`) routes each datagram by `EndpointId` —
> SRTP-bridge endpoints to the bridge, media endpoints to the owning per-call `MediaCall` actor,
> everything else to TURN. Each `MediaCall` decodes the ingress codec, optionally records/silences,
> re-encodes the peer's codec, and transmits via `Datapath::send`. RFC 4733 telephone-events are
> extracted to `Event::Dtmf` (the control plane) and repacketized onto the egress stream.

- **Source gate (RTPBleed, restated for `Redirect`).** Each direction re-enforces the signalled-source
  gate (`MediaCall::process` checks `SourceFilter::accepts` before any decode, using the same
  `Exact`/`Subnet`/`Any` policy as the relay and the SRTP bridge). An off-path spray is dropped before
  it can be transcoded or latched.
- **Symmetric latch.** When a party's gated packet is accepted, the reverse direction's egress
  destination is latched to that observed source (RFC 3550 symmetric RTP), so a NATed peer is replied
  to where its media actually originates — consistent with the Forward-path latch, but enforced in the
  actor because `Redirect` skips it.
- **RTCP & unknown packets** are relayed verbatim (RFC 5761 demux on the payload-type byte); only audio
  RTP is transcoded. On the plaintext `Media` path, companion (non-mux) RTCP stays on the in-datapath
  Forward fast path. On the **secure** transcode (`SrtpMedia`) path it cannot ride the datapath (it is
  encrypted): non-mux RTCP endpoints are redirected into the same `MediaCall` actor and SRTCP-(de)crypted
  through the call's shared `SecureLeg` — A's RTCP encrypted toward the secure B, B's SRTCP decrypted
  toward plaintext A (RFC 3711) — with the RTPBleed source gate re-enforced on each RTCP endpoint.
  (Muxed RTCP rides the RTP endpoint and is (de)crypted inline in `Direction::handle`.) RTCP is
  forwarded to the peer's signalled RTCP address; dynamic RTCP-follows-RTP latching is a follow-up.
- **Injected media** (PlayMedia prompts, PlayDtmf bursts) is emitted on the engine's *own* egress SSRC
  and sequence space, never echoing an attacker-supplied stream.

### Layer 5c — The conference (MCU) Redirect path
The N-party conference mixer (`engine/src/conference.rs`) is another `FlowAction::Redirect` consumer,
so it carries the **same** RTPBleed posture as Layers 5a/5b — and, unlike the send-only SIPREC tee,
**every participant endpoint is a full inbound surface**, so the gate matters on each one.

> **Status (landed — conference MCU):** `conference_join` allocates one engine endpoint per
> participant, sets it to `Redirect`, and seats the participant in a per-room `Conference` actor; the
> redirect dispatcher gains a `conference.owns(ep)` arm (order: bridge → media → ws → conference →
> TURN). The room is **clock-driven** — a 20 ms tick pops one frame per participant, mixes
> mixed-minus-self (`saturate(Σ others)`), and transmits each participant its mix via `Datapath::send`.

- **Source gate (RTPBleed, restated for `Redirect`).** `Conference::ingest` checks
  `SourceFilter::accepts` for the participant's endpoint **before** the packet enters the jitter buffer
  (same `Exact`/`Subnet`/`Any` policy). A spoofed source never reaches the mix — proven by
  `unsignalled_source_is_dropped_from_the_mix`.
- **Constrained latch.** An accepted participant's egress destination is latched to its observed
  source (symmetric RTP), so a NATed leg is replied to where its media originates.
- **SDES-SRTP secure legs.** A participant offering `RTP/SAVP` + `a=crypto` gets a per-participant
  `SecureLeg` (the same primitive Layer 5a uses): `conference_join` mints the engine's key, answers
  `RTP/SAVP` + its own `a=crypto`, and the room **decrypts each inbound packet before it enters the
  mix** (the auth tag also proves authenticity — a forged/replayed packet fails and is dropped) and
  **encrypts the mix (and the SR) back out** as SRTP/SRTCP. DTLS-SRTP / ICE (WebRTC) conference legs
  remain a follow-up — `conference_join` rejects an ICE offer rather than half-securing it.
- **Never into the void.** A participant whose destination is not yet resolved is **not transmitted
  to** (`destination_usable` gate) — the room drops that egress rather than guessing.
- **Idle reap.** A gated-in packet stamps the endpoint's activity (`Datapath::note_activity` — the
  `Redirect` arm does not stamp `last_seen` itself); a spoofed source that fails the gate does **not**,
  so it cannot keep a dead path alive. The daemon sweep reaps participants idle past the media timeout
  and tears down a room once empty (the conference analogue of Layer 6).
- **RTCP & telephone-events** are split off before the jitter buffer (RFC 5761 demux + RFC 4733 PT
  match) so they cannot corrupt the decoder: the conference path now consumes inbound reception
  reports (RRs) to derive RTT for MOS, and only non-report RTCP is dropped/not consumed; a
  telephone-event is detected and surfaced as `Event::Dtmf` on the control channel.
  Each participant's mix is stamped with the engine's **own** per-leg egress SSRC, and a periodic RTCP
  Sender Report is emitted per participant (lip-sync + liveness) carrying a **reception report** on that
  participant's inbound stream (cumulative loss from its jitter buffer + extended highest sequence).
- **Room bridging** crosses the only actor boundary in the design: a bounded, drop-oldest `flume`
  channel carries one room's *participant-only* mix (never its full mix, so a bridge cannot echo a
  room back to itself) to another room — no shared state between room actors (single-owner rule).

### Layer 6 — Media timeout & dead-path teardown
A flow that has received no *accepted* packet for `T` ticks is torn down and reported.

> **Status (landed):** the **reaper + event delivery** — `Engine::reap_idle(idle_ticks)` frees calls
> whose media has been idle (returning their ports/FDs and registry/quota slots) and pushes
> `Event::MediaTimeout` to the owning control connection over the server's per-connection event
> channel (`Engine::register_client` + the connection `select!`-loop; bounded, drop-on-backpressure).
> Activity is stamped on every accepted packet against the datapath's logical clock (`now_ticks` /
> `advance_clock` / `last_activity`); the daemon advances it ~1 tick/s and sweeps.

- Frees ports/FDs (availability), surfaces one-way-audio and failed-NAT cases, and is the non-ICE
  analogue of consent loss.
- **Determinism:** the sweep clock is an injected tick source — `tokio::time` advances it in
  production, tests advance it explicitly via `advance_clock` (project rule: never `Instant::now()`).

### 4.7 Data-model changes implied
> **Landed in M-S1:** `SourceFilter` (`Exact`/`Subnet`/`Any`) and `LatchPolicy`
> (`Off`/`SignalledOnly`/`Symmetric`) on `ForwardRule`, and an SSRC-aware latch state. The
> `last_seen` field and the timeout sweep arrive with layer 6.

Concrete, minimal, additive to the existing datapath seam:

- **`ForwardRule`** ([datapath/src/lib.rs](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-datapath/src/lib.rs)) gains:
  - `accepted_source: SourceFilter` — `Exact(IpAddr)` | `Subnet(IpAddr, prefix)` | `Any`.
  - `latch: LatchPolicy` — `Off` | `SignalledOnly` | `Symmetric`.
  (`out_dst` stays the send target; `allow_latch: bool` is subsumed by `latch`.)
- **Latch state** becomes `DashMap<EndpointId, LatchState { addr, ssrc: Option<u32>, last_seen }>`
  instead of a bare `SocketAddr`.
- **`recv_loop`** gains the pipeline: demux byte0 → source-gate → SSRC-consistent latch/relatch →
  dispatch. The unconditional `or_insert` is removed.
- **Engine** ([engine/src/engine.rs](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/src/engine.rs)) fills
  `accepted_source` / `latch` from the parsed SDP remote address and `ProfileFlags.flags` at
  `answer` time, and starts the timeout sweep.
- **`siphon-rtp-media`** supplies the RTP header parse (version, PT, SSRC) the latch needs — already
  the right home.

---

## 5. Control-plane & DoS hardening (A3, availability)

Distinct from the media latch but part of the same security surface.

- **Port/FD exhaustion.** **Landed:** `alloc_endpoint` is now bounded — `UdpLoopbackDatapath`
  caps concurrent endpoints (`with_max_endpoints`, strict atomic reservation) and returns
  `PoolExhausted`, so `offer` fails cleanly and frees the ports on `delete` instead of exhausting
  host FDs. **Remaining:** a **per-client quota** (needs control-client identity) and wiring the cap
  to daemon config.
- **Control authz.** **Landed:** every call is owned by the `ClientId` of the control connection
  that created it via `offer`; `answer` / `query` / `delete` from any other client see the call as
  unknown (so a client cannot tear down, inspect, or even probe for a call it does not own). The
  engine threads `ClientId` from the server, which assigns one per accepted connection. **Caveat:**
  this binds identity to the *connection*; it assumes one persistent control connection per SIPhon
  instance. A shared identity across a connection pool needs the deferred control-channel auth.
- **Channel security.** **Landed:** optional shared-secret authentication — when
  `$SIPHON_RTP_CONTROL_SECRET` is set, a control connection must send `Authenticate` with the
  matching token (constant-time compared) before any other verb is honoured (`serve_with_auth`).
  **Remaining:** TLS on the control socket (mandatory the day SDES key material rides it) and binding
  it to a private interface by config.
- **Reflector/amplifier hygiene.** Do not forward toward a destination until it is validated (the
  layer-2 gate + "no forward before `answer`" already cover most of this); never echo to an
  unvalidated source.
- **Frame limits.** The control framing already caps at `MAX_FRAME_LEN` (1 MiB) — keep it; add a
  per-connection request rate limit.

---

## 6. Parser robustness (A4)

Every parser that eats untrusted bytes must **decode-or-error, never panic / never spin / never read
out of bounds** — already a project hard rule; restated as part of this surface:

- RTP/RTCP parser (`siphon-rtp-media`) — malformed/truncated packets.
- Codec frame decoders (AMR NB/WB, Opus, IuUP framing) — hostile bitstreams.
- SDP parser ([engine/src/sdp.rs](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/src/sdp.rs)) and the JSON / (future)
  NG-bencode control parser.
- **Method:** `cargo-fuzz` (libFuzzer) targets in CI + `proptest` structural invariants
  (`parse(serialize(x)) == x`, bounded output under arbitrary input). **Landed (proptest, on
  stable / in `cargo test`+CI):** no-panic over arbitrary input for the RTP & RTCP parsers, the SDP
  parser, and the JSON control frame decoder, plus RTP write→parse and control encode→decode
  round-trips. **Remaining:** `cargo-fuzz` libFuzzer targets for continuous fuzzing (need the
  nightly toolchain, like the ebpf crates).

---

## 7. Test & acceptance plan (TDD, tests-first)

Security behavior is validated by adversarial tests on the NIC-free UDP-loopback datapath, not by
inspection:

- **RTPBleed regression:** attacker socket sends to a live engine port *before* the real peer; assert
  the engine does **not** latch to the attacker and the real peer still establishes. The headline
  test — it must fail against today's `or_insert` and pass after layer 2–3.
- **Mid-call hijack:** mid-stream spray from a new source with a *wrong* SSRC is rejected; a new source
  with the *correct* SSRC (simulated NAT rebind) re-latches. Two tests, opposite verdicts.
- **Demux:** STUN/DTLS/garbage to a media port never moves the media latch (layer 1).
- **Source gate:** `SignalledOnly` rejects an off-address source; `Symmetric` (opt-in) accepts it.
- **Media timeout:** a flow goes silent → teardown + `Event::MediaTimeout`, driven by a logical clock.
- **Control authz:** client B cannot `Delete`/`Query` a call created by client A.
- **Port pool:** exhausting the pool fails `offer` cleanly and frees on `Delete`.
- **Fuzz:** RTP/RTCP/SDP/control corpora in CI (§6).

---

## 8. Milestones (priority order for this posture)

**M-S1 — Secure latch (RTPBleed fix + correct NAT).**
- **Landed:** layer 1 (RFC 7983 demux) + layer 2 (signalled-source gate) + layer 3 (SSRC-consistent
  latch) + the §4.7 `SourceFilter` / `LatchPolicy` / `ForwardRule` / SSRC latch-state change, wired
  through `engine::answer` (`ingress_rule`), plus **layer 6 media-timeout reaping** (`reap_idle`, on
  the deterministic logical clock). Tests on the UDP-loopback datapath: RTPBleed off-path regression
  (datapath + engine end-to-end), mid-call wrong-SSRC hijack rejected, same-SSRC NAT rebind followed,
  non-RTP (STUN) demux drop, and idle-call reaping.
- **Remaining:** the `/24` source-gate option (§9) — a tuning knob, not a gap. **M-S1 is otherwise
  complete**: layers 1–3 + media-timeout reaping with `Event::MediaTimeout` delivered to SIPhon over
  the new per-connection event channel.

**M-S2 — Control-plane & DoS hardening.** §5. **Landed:** the bounded media-port pool (clean `offer`
failure on exhaustion, freed on `delete`); the **per-client call quota**; **per-verb authz** (calls
private to their creating `ClientId`); and optional shared-secret **control-channel auth**
(`serve_with_auth`). **Remaining:** TLS + private-interface bind on the control socket, and
`cargo-fuzz` continuous targets (proptest robustness already landed, §6).

**M-S3 — ICE + consent.** Layer 4. **Landed:** the pure-Rust STUN codec (`siphon-rtp-stun`,
vector-validated), the datapath connectivity-check responder (`set_ice` + STUN-validated source
adoption; forged checks dropped), and the engine **ICE-lite** wiring — credential generation (OS
CSPRNG), SDP parse + ICE-lite re-origination (`a=ice-lite` + ufrag/pwd + host candidate), and
`set_ice` on every endpoint of an ICE leg (RTP + non-mux RTCP) at answer time; end-to-end tested.
Consent loss is handled via the media-timeout sweep (a valid check stamps activity). **Remaining:**
full (non-lite) ICE where the engine must *send* checks — the strongest NAT + anti-hijack story for
ICE-capable peers.

**M-S4 — SRTP / DTLS-SRTP (implemented).** Layer 5. SRTP-SDES ships in `siphon-rtp-srtp` +
`engine/src/srtp_bridge.rs`; DTLS-SRTP (RFC 5764) ships in `siphon-rtp-dtls` +
`engine/src/dtls_bridge.rs`. Both key the same `SecureLeg`; pure RustCrypto (no C), per the zero-C
hard rule.

**M-T — Built-in TURN server (RFC 5766), a coturn replacement.** §11. **Landed (M-T1–M-T7):** the
`siphon-rtp-turn` crate — the allocation actor, the coturn REST credential + stateless nonce, the
permission/channel/refresh state machine, the anti-abuse controls, and the **UDP + TCP + TLS**
listeners — drawing relay ports from the shared bounded datapath pool; wired into the daemon
(`--turn-udp/tcp/tls`, realm+secret from env) and the compose profiles, with a criterion relay bench
and a jemalloc allocation-churn soak. The codec lives in `siphon-rtp-stun::turn`. End-to-end tested on
the loopback datapath over every transport. **M-T8 (XDP channel-relay fast path) — foundation landed,
kernel TX remaining:** the map ABI (`TurnPeerKey`/`TurnChannelKey` etc. in `siphon-rtp-ebpf-common`,
ABI-tested) and the userspace `TurnFastPath` seam (installed on ChannelBind, withdrawn on teardown;
mock-tested) are in; the in-kernel ChannelData rewrite + `XDP_TX` is specified in the eBPF program's
docs and lands with the generic `XDP_TX` path it shares.

---

## 9. Open decisions
- **Source-gate strictness** — **resolved:** the default is **exact** source-IP (the tightest
  RTPBleed defence); the per-leg `subnet-source` `ProfileFlags` flag loosens it to the signalled IP's
  `/24` (v4) / `/64` (v6) for carriers that re-NAT or split RTP/RTCP within a block. (Security-first
  default — the reverse of rtpengine's looser default.)
- **Symmetric/`port-latching` policy** — when SIPhon should set `Symmetric` for a leg (which NAT
  classes warrant abandoning the source gate). Needs the SIPhon-side signalling rule.
- **Media-timeout `T`** — default seconds before dead-path teardown, and whether RTCP-only traffic
  keeps a flow alive.
- **Control-channel auth mechanism** — shared secret vs mTLS for the SIPhon ↔ engine link.

---

## 10. Spec index
RFC 3264 (offer/answer) · RFC 3550 §5,§8 / 3551 (RTP/RTCP) · RFC 4961 (symmetric RTP/RTCP) ·
RFC 6263 (RTP NAT keepalives) · RFC 7983 (STUN/DTLS/RTP demux) · RFC 8445 / 8839 / 8489 (ICE / SDP-for-ICE / STUN) ·
RFC 7675 (ICE consent freshness) · RFC 3711 (SRTP) · RFC 5764 (DTLS-SRTP) · RFC 4568 (SDES) ·
RFC 4566 (SDP) · RFC 5761 / 3605 (rtcp-mux / a=rtcp) · RFC 5766 / 8656 (TURN) · RFC 6062 (TURN-over-TCP) ·
RFC 1321 (MD5) · RFC 4648 (base64) · RFC 2104 / 2202 (HMAC). RTPBleed: Enable Security advisory, 2017.

---

## 11. Built-in TURN server (RFC 5766) — the open-relay threat model

The engine ships its own TURN relay (`siphon-rtp-turn`), a drop-in for coturn on the WebRTC voice-AI
legs, so the deployment runs no external relay. A TURN server hands an authenticated client a public
relay address and forwards traffic between that address and arbitrary peers — i.e. it is, by
construction, **the open-relay / reflection primitive the rest of this document defends against**.
The same discipline applies: authenticate before relaying, gate every packet, never forward into the
void, and bound the resources.

### 11.1 Relay model
- **Standalone listeners, shared relay pool.** Clients reach the server directly on its own ports
  (UDP `turn:`, TCP, TLS `turns:`), independent of the JSON control plane. Each allocation's **relay**
  endpoint is drawn from the **same bounded [`Datapath`] pool** the media plane uses, so the
  port/FD-exhaustion guard (§5) and the future XDP/AF_XDP acceleration both apply unchanged.
- **Relay bind posture.** The relay socket binds the datapath's configured IP (`UdpLoopbackDatapath::
  with_bind_ip`): **loopback in CI / NIC-free runs**, a **routable IP in production** so real peers can
  reach the relay. Prefer a *specific* public IP — the transmitted source then matches what the client
  was told — and use the TURN server's `relay_address` (`--turn-relay-ip`) to advertise the reachable
  address in XOR-RELAYED-ADDRESS when the bound IP differs (e.g. a `0.0.0.0` bind or a NAT'd host). A
  loopback bind relays only loopback peers, so a production relay needs a routable bind (or the XDP/
  public datapath).
- **Single-owner actor.** All allocation state lives in one task (`AllocationManager`) reached only
  through a bounded `flume` mailbox — no shared lock over allocation state, no lock across an `.await`
  (the concurrency rules). Peer datagrams arrive on the relay endpoint via `FlowAction::Redirect`
  and are routed to the actor by a single dispatcher that owns the shared `Datapath::rx()` stream.
- **Datapath relaxation (cited at the enforcement point).** A relay endpoint must forward *whatever*
  the peer sends, including STUN/TURN-shaped bytes a media socket would drop at layer 1. So `recv_loop`
  delivers raw datagrams to a non-ICE `Redirect` endpoint instead of swallowing first-byte ≤3
  (`udp.rs`). This **never** weakens the media plane: the layer-1 demux still drops ChannelData/STUN on
  *media* (`Forward`) sockets; ChannelData is only ever expected on the TURN server's **own** listener
  sockets, and a `Redirect` endpoint never writes the media latch (the TURN permission model is its
  source gate — see R2).

### 11.2 Enforcement (each cited where it runs, in `siphon-rtp-turn`)
| # | Control | Spec | Enforcement |
|---|---|---|---|
| R1 | **Mandatory auth on Allocate** — no anonymous allocations; a missing/invalid credential gets a 401 challenge with REALM + a fresh NONCE. Credentials are the coturn REST profile (`username = <unix-expiry>[:id]`, `password = base64(HMAC-SHA1(secret, username))`, key = `MD5(username:realm:password)`); the server recomputes the password and **enforces the embedded expiry**, so it stores no per-user secrets. | RFC 5766 §4, RFC 5389 §10.2 | `credentials::CredentialVerifier`; `manager::require_auth` |
| R2 | **Permission-gate every relayed packet, both directions** — a peer datagram with no live permission for its IP is dropped; a Send/ChannelData to an unpermitted peer is dropped. This *is* the relay's source gate; there is **no blind latch** (contrast layers 2–3). | RFC 5766 §8/§9/§10 | `handle_relay_inbound`, `handle_send_indication`, `handle_channel_data` |
| R3 | **Peer-IP denylist** (anti-SSRF / anti-reflection): loopback / link-local / multicast / private ranges / the server's own IPs are refused at CreatePermission and ChannelBind with 403, and re-checked on every relayed packet. | (coturn `denied-peer-ip`) | `PeerIpPolicy::permits` |
| R4 | **Resource bounds:** relay ports come from the bounded pool → 508 on exhaustion; a per-credential allocation quota → 486. | §5, RFC 5766 §6.2 | `AllocationManager` quota; `Datapath::alloc_endpoint` |
| R5 | **Lifetimes + explicit teardown:** allocation (600 s), permission (300 s), channel (600 s) all expire on the **logical clock**, swept by the TURN reaper (the analogue of the media-timeout sweep — *not* `Engine::reap_idle`, which would mistake a relay for an idle call); a Refresh with LIFETIME 0 deletes and frees the relay port. | RFC 5766 §6.2/§7/§8/§11 | `reap`, `delete_allocation` |
| R6 | **Per-allocation bandwidth cap** (optional) bounds a single allocation's relayed bytes. | — | `within_budget` |
| R7 | **Stateless nonce** = `base64(issued_tick ‖ HMAC(secret, issued_tick ‖ client_ip))`, bound to the client and validated by an age check against the logical clock → 438 Stale Nonce. No per-nonce map to exhaust. | RFC 5389 §10.2 | `credentials::NonceFactory` |
| R8 | **Allocation isolation** — 437 Allocation Mismatch for a second Allocate on a live 5-tuple or a non-Allocate verb without one; an Allocate retransmission (same transaction id) replays the cached response, never a 437. The 5-tuple includes the server transport + protocol, so a client's UDP/TCP/TLS allocations never collide. | RFC 5766 §6.2 | `handle_allocate` |

### 11.3 Scope / deviations
- **Credentials:** the RFC 5766 long-term mechanism (MESSAGE-INTEGRITY = HMAC-SHA1, key =
  `MD5(username:realm:password)`). RFC 8656 MESSAGE-INTEGRITY-SHA256 is a deferred seam.
- **EVEN-PORT / RESERVATION-TOKEN** are rejected with 508 (cited deviation): the ephemeral `:0` relay
  pool gives no port-number control, and WebRTC never requests them.
- **Peer transport** is always UDP, even for TURN-over-TCP/TLS clients (browser posture); RFC 6062
  TCP-relay-*to-peer* is out of scope.
- The **acceptance tests** (`crates/siphon-rtp-turn/tests/turn_server.rs`) drive a real client over the
  loopback datapath: the full Allocate → CreatePermission → ChannelBind → relay round-trip both ways,
  plus 401 / 437 / 438 / 403, relay-without-permission drop, idempotent retransmit, and Refresh(0)
  teardown — the §7-style adversarial validation, applied to the relay.
