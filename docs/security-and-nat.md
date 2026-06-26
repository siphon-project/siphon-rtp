# siphon-rtp — Security & NAT Roadmap

> Design + threat model for the media plane. Status: **design, pre-implementation.**
> Crypto posture for the target deployments: **plaintext RTP, secured at the network layer**
> (IPsec / SBC / private bearer). SRTP / DTLS-SRTP is designed-but-deferred — the control seam is
> reserved, the work is not scheduled. Priority order therefore: **latch hardening → ICE → DoS/
> control-plane hygiene → (deferred) SRTP/DTLS**.
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
> in [`udp.rs`](../crates/siphon-rtp-datapath/src/udp.rs); rules built by `ingress_rule` in
> [`engine.rs`](../crates/siphon-rtp-engine/src/engine.rs) from the parsed SDP + `ProfileFlags`).
> Layer 1 (RFC 7983 demux) is in too; only layer 6 (media-timeout) remains — see §8. The original
> hole, for the record:

[`crates/siphon-rtp-datapath/src/udp.rs`](../crates/siphon-rtp-datapath/src/udp.rs), `recv_loop`:

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
| 20–63 | DTLS | DTLS-SRTP handshake (deferred, §5) |
| 64–79 | TURN channel | drop |
| 128–191 | RTP / RTCP | media path (layers 2–3) |
| else | unknown | drop, count |

- **Spec:** RFC 7983 (multiplexing demux ranges), updating RFC 5764 §5.1.2.
- **Enforcement:** datapath receive path, before any latch write.
- **Effect on A1:** garbage and STUN sprays can no longer poison the media latch.

### Layer 2 — Signalled-source gate
Only **accept** (and only latch from) media whose source matches the address learned from SDP.

- Default policy `SignalledOnly`: source IP must equal the SDP `c=`/`m=` address (the engine already
  parses this into `remote_near` / `remote_far`). A `/24`-tolerant mode covers carriers that split
  RTP/RTCP across nearby addresses or re-NAT within a block.
- Relax to `Symmetric` (accept any source, latch the first) **only** when the control plane sets it —
  for UAs behind symmetric NAT where the signalled address is genuinely unusable. This is opt-in per
  leg, never a global default.
- **Spec:** RFC 3264 (the offer/answer address *is* the contract); mirrors rtpengine
  `trust-address` / `strict-source`.
- **Enforcement:** new accepted-source constraint on the forward rule (§4.7); engine fills it from
  parsed SDP + `ProfileFlags.flags` (`trust-address`, `strict-source`, `port-latching`, `symmetric`).
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
- **Effect on A1:** even inside the learning window, a hijack must reproduce the victim's live SSRC,
  which the blind attacker does not know.

### Layer 4 — ICE supersedes blind latching where offered
When SDP carries ICE, **connectivity checks replace latching** as the address-learning mechanism.

- The peer proves reachability with a STUN Binding request authenticated by the negotiated
  `ice-ufrag`/`ice-pwd` (MESSAGE-INTEGRITY) — a challenge/response A1 cannot forge without the SDP it
  never saw. The validated candidate pair, not "first packet wins", becomes the path.
- **Consent freshness** (RFC 7675): periodic STUN keepalives; on consent loss, stop forwarding and
  tear down. This is also the anti-hijack *and* the dead-path detector.
- **Spec:** RFC 8445 (ICE), RFC 8839 (SDP for ICE), RFC 8489 (STUN), RFC 7675 (consent).
- **Enforcement:** `ProfileFlags.ice` (`remove` | `force` | `force-relay`) already reserved; STUN
  served on the media socket via the layer-1 demux.
- **Note:** for non-ICE legacy VoLTE/PSTN UAs (the common case), layers 1–3 are the whole story; ICE
  applies to ICE-capable peers (RCS, WebRTC bridges, modern clients).

### Layer 5 — SRTP / DTLS-SRTP (DEFERRED in this posture)
The cryptographic fix: authenticated media cannot be injected or silently hijacked even if the latch
is wrong, and encryption defeats A2 eavesdrop.

- **Status:** deferred. Target deployments carry confidentiality at the network layer (IPsec / private
  bearer), so layers 1–3 + ICE meet the *integrity/availability* goals without crypto. We design the
  seam now and schedule the work when an SRTP/DTLS-SRTP deployment is on the roadmap.
- **Seam (already present):** `ProfileFlags.transport_protocol` (`RTP/SAVP[F]`,
  `UDP/TLS/RTP/SAVPF`), `ProfileFlags.dtls` (`passive`/`active`/`off`).
- **Spec when built:** RFC 3711 (SRTP), RFC 5764 (DTLS-SRTP), RFC 4568 (SDES — keys in SDP, so
  requires TLS on the signalling path). Pure-Rust only: ring / rustls / webrtc-rs, per the project's
  zero-C hard rule. SDES key material must never transit a plaintext control channel.

### Layer 6 — Media timeout & dead-path teardown
A flow that has received no *accepted* packet for `T` seconds is torn down and reported.

- Frees ports/FDs (availability), surfaces one-way-audio and failed-NAT cases, and is the non-ICE
  analogue of consent loss.
- **Enforcement:** a periodic sweep over latch `last_seen`; new `Event::MediaTimeout` pushed to
  SIPhon (the `Event` enum's `#[serde(other)] Unknown` arm keeps SIPhon forward-compatible).
- **Determinism:** the sweep clock is an injected tick source — `tokio::time` in production, a logical
  sample-clock in tests (project rule: never `Instant::now()` in deterministic tests).

### 4.7 Data-model changes implied
> **Landed in M-S1:** `SourceFilter` (`Exact`/`Subnet`/`Any`) and `LatchPolicy`
> (`Off`/`SignalledOnly`/`Symmetric`) on `ForwardRule`, and an SSRC-aware latch state. The
> `last_seen` field and the timeout sweep arrive with layer 6.

Concrete, minimal, additive to the existing datapath seam:

- **`ForwardRule`** ([datapath/src/lib.rs](../crates/siphon-rtp-datapath/src/lib.rs)) gains:
  - `accepted_source: SourceFilter` — `Exact(IpAddr)` | `Subnet(IpAddr, prefix)` | `Any`.
  - `latch: LatchPolicy` — `Off` | `SignalledOnly` | `Symmetric`.
  (`out_dst` stays the send target; `allow_latch: bool` is subsumed by `latch`.)
- **Latch state** becomes `DashMap<EndpointId, LatchState { addr, ssrc: Option<u32>, last_seen }>`
  instead of a bare `SocketAddr`.
- **`recv_loop`** gains the pipeline: demux byte0 → source-gate → SSRC-consistent latch/relatch →
  dispatch. The unconditional `or_insert` is removed.
- **Engine** ([engine/src/engine.rs](../crates/siphon-rtp-engine/src/engine.rs)) fills
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
- **Channel security.** Authenticate the JSON-over-TCP control socket, bind it to a private
  interface, and add TLS (and it becomes mandatory the day SDES key material rides it — §5).
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
- SDP parser ([engine/src/sdp.rs](../crates/siphon-rtp-engine/src/sdp.rs)) and the JSON / (future)
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
  through `engine::answer` (`ingress_rule`). Tests on the UDP-loopback datapath: RTPBleed off-path
  regression (datapath + engine end-to-end), mid-call wrong-SSRC hijack rejected, same-SSRC NAT
  rebind followed, and non-RTP (STUN) demux drop.
- **Remaining:** layer 6 (media-timeout + `last_seen` + the dead-path `Event`) and the `/24`
  source-gate option (§9). Neither blocks the safe `SignalledOnly` default; this is the next
  datapath increment.

**M-S2 — Control-plane & DoS hardening.** §5. **Landed:** the bounded media-port pool (clean `offer`
failure on exhaustion, freed on `delete`); the **per-client call quota**; and **per-verb authz** —
calls are private to their creating `ClientId`. **Remaining:** control-channel auth + private bind
(and, once a server→SIPhon event-push channel exists, surfacing rejections), plus the fuzz/proptest
targets from §6 wired into CI.

**M-S3 — ICE + consent.** Layer 4: STUN over the layer-1 demux, ICE connectivity checks, consent
freshness, the `ProfileFlags.ice` modes. Brings the strongest NAT + anti-hijack story for ICE-capable
peers.

**M-S4 — SRTP / DTLS-SRTP (deferred).** Layer 5, scheduled when an SRTP/DTLS deployment lands. Seam
(`transport_protocol`, `dtls`) is already reserved; build with ring/rustls/webrtc-rs only.

---

## 9. Open decisions
- **Source-gate strictness default** — exact IP vs `/24` for `SignalledOnly`. Carrier NAT and split
  RTP/RTCP argue for `/24`; tighter is safer. Likely a per-leg `ProfileFlags` choice with a `/24`
  default and an exact-match opt-in.
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
RFC 4566 (SDP) · RFC 5761 / 3605 (rtcp-mux / a=rtcp). RTPBleed: Enable Security advisory, 2017.
