# siphon-rtp — Security & NAT design

> Design + threat model for the media plane. Status: **implemented and wired.** The gated latch, the
> source-consistency checks, symmetric-RTP NAT traversal, SDP address rewrite, ICE-lite + STUN, the
> built-in TURN server, SRTP-SDES (RFC 3711 / 4568), and DTLS-SRTP (RFC 5764) all ship today, as does
> RFC 7675 consent freshness (opt-in, `--ice-consent` — §4.4). Candidate gathering, the full RFC 8445
> agent (`--ice-full`), ICE restart (the `reoffer` verb, RFC 8445 §9), trickle-receive (RFC 8838), and
> a TURN **client** (wired at the engine API, `Engine::with_turn_server`, not a daemon flag) all ship
> too; ICE-lite is the **default** responder posture, not the only one. Crypto posture: secure legs
> stay secure end to end, and a plaintext leg can
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
- **This table is the `Forward` path's, and is deliberately *not* replayed on `Redirect`.** A
  redirected endpoint is entitled to non-RTP: a DTLS-SRTP leg's handshake records must reach the
  bridge (RFC 5764), and a TURN allocation's own STUN must reach its client (RFC 5766 §11, §11.1).
  Dropping everything outside 128–191 there would deadlock both. The demux therefore stays where the
  consumer is — the DTLS bridge splits its own stream, the TURN client reads its own responses — and
  what the datapath applies on the redirected path instead is the **source** gate (layer 4 for an ICE
  endpoint; see the `Redirect` bullet there).
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
- **In-kernel enforcement (XDP_TX fast path) — shipped in the separate `siphon-rtp-xdp-daemon`.** The
  default `siphon-rtp` binary runs the userspace UDP datapath, which enforces layers 1–3 in
  [`udp.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-datapath/src/udp.rs). The in-kernel `XDP_TX` fast path, with the same
  layer-1..4 checks, ships in the separate `siphon-rtp-xdp-daemon` binary —
  [`docs/datapath.md`](datapath.md) is the authority on the two-binary split. When attached: for a
  plain `Forward` (`rtp_passthrough`) leg these
  same three layers run **in the kernel** before the relay: the eBPF classifier demuxes (layer 1,
  RFC 7983), re-checks the signalled-source gate (layer 2), and applies this SSRC-consistent latch —
  learning the peer's real source into the flow's kernel latch state and re-latching a new source
  only on a matching SSRC (RFC 3550 §8). It then rewrites L3/L4 with an RFC 1624 incremental checksum
  fixup and `XDP_TX`s. The kernel latch is the **source anchor** (the RTPBleed / strict-source check,
  rtpengine `expected_src`); the forward **destination** stays the userspace-maintained `out_dst`
  (rtpengine `dst_addr`), never a flow's *own* ingress latch (which would echo). To reach a NATed peer
  whose real source differs from the signalled `out_dst`, userspace closes the loop out-of-band: the
  kernel exposes each flow's learned source over the trait (`Datapath::learned_source`), and on its
  1 Hz sweep the engine (`Engine::refresh_latched_destinations`) reads the *peer* leg's kernel latch
  and, when it has learned a new source, reprograms the **sibling** flow's `out_dst` to it (rtpengine's
  "userspace learns → reprograms the kernel rule" model) — so the in-kernel fast path then relays to
  the peer's real post-latch source with no cross-leg reference in the per-flow kernel ABI. The engine
  mirrors **only** a source the kernel *already* validated (its own source-gate + SSRC re-latch), so no
  new trust is introduced. A FIB miss / unresolved neighbour still falls back to `Redirect`.
- **Known divergence — the userspace latch declines, it does not drop.** On the `Forward` path a
  latch rejection is a **drop**: `Inner::update_latch` returns `Reject` and `dispatch` discards the
  packet, so under `symmetric` (`SourceFilter::Any` + `LatchPolicy::Symmetric`) the first source
  latches and a later different-SSRC spray is thrown away. The `Redirect` consumers mirror the state
  machine but not that consequence: `SymmetricLatch::observe` returning `None` only means "keep the
  current reply address", and the packet is still decoded, mixed or relayed
  (`MediaCall::process`, `Conference::ingest`, the text pipeline). For the default `Exact` gate this
  is immaterial — layer 2 already pinned the source. It matters **only** under the opt-in
  `symmetric` flag, where layer 2 is open and the latch is the sole remaining constraint: such a
  redirected leg accepts injected media from any source (it cannot be *stolen* — egress stays pinned
  to the latched source). Tracked as a deliberate, named gap rather than a silent one; closing it
  means giving the userspace latch the same drop-on-reject semantics across all three consumers,
  which is a behaviour change to an operator-selected rtpengine-parity flag and belongs in its own
  change.
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
> tested. **Consent freshness (RFC 7675) is now wired and runnable** — see the bullet below.
> **Candidate gathering (RFC 8445 §5.1.1) is wired**: the advertised candidate list is gathered per
> leg and per component rather than being one hardcoded host line — host always, plus a
> server-reflexive candidate per `--stun-server` that answers. **The full RFC 8445 agent is wired too**
> (`--ice-full`, off by default): checklists, connectivity checks, both roles with 487 conflict
> resolution, peer-reflexive discovery, and regular nomination — with media gated on the selected
> pair. **ICE restart (§9) and trickle-receive (RFC 8838) are wired**, and the **XDP kernel datapath
> now enforces the same layer-4 gate** as the userspace one (see the bullet below).
> **Relayed candidates are wired too** (via a TURN *client* at the engine API,
> `Engine::with_turn_server`, not a daemon flag): the engine can act as a TURN client as well as a
> server, and a relayed candidate is advertised only when the allocation actually came up and the
> datapath can relay through it. RTCP-port ICE under non-mux is wired.

- The peer proves reachability with a STUN Binding request authenticated by the negotiated
  `ice-ufrag`/`ice-pwd` (MESSAGE-INTEGRITY) — a challenge/response A1 cannot forge without the SDP it
  never saw. The validated candidate pair, not "first packet wins", becomes the path.
- **Candidate gathering** (RFC 8445 §5.1.1) decides what we advertise as reachable, so it is part of
  the same story:
  - **Host** candidates come from the leg's own endpoints — one per component (RTP, plus RTCP when the
    leg is not muxed, RFC 8445 §4.1.1.1) — and carry the leg's *advertised* address, so a 1:1-NAT
    deployment offers the routable IP rather than the bound private one.
  - **Server-reflexive** candidates are gathered by probing each `--stun-server` from the media
    endpoint itself. A reflexive address equal to the base (or to the advertised address) is pruned as
    redundant (RFC 8445 §5.1.3), which is exactly what a directly-addressable engine sees — so the
    default deployment gathers host-only and pays **no** round trip at call setup. The built-in TURN
    server answers plain Binding requests (RFC 8656 §12), so it can be its own STUN server.
  - A gathering response is accepted only when its transaction id matches an outstanding probe **and**
    it came from the server that probe was sent to. Without the source check, anyone able to guess a
    transaction id could plant a reflexive candidate in our offer.
  - Gathering is **bounded**: it runs on the offer/answer control path, retransmits per RFC 8489
    §6.2.1, and gives up at a deadline, advertising what it has and logging which servers went quiet.
    A dead STUN server costs one bounded delay and a host-only list — never a failed call. Components
    gather concurrently, so that delay is paid once per leg, not once per component.
  - We still gather fully before answering and mark the list `a=end-of-candidates` (RFC 8838 §14),
    but we now **accept** trickled remote candidates (`a=ice-options:trickle`) even though we do not
    send our own.
  - **Enforcement:** `siphon-rtp-ice/src/gather.rs` (the pure plan), `Engine::gather_leg_candidates` /
    `run_gatherer` (its I/O), `sdp::IceAdvertisement` (emission).
- **The full agent (`--ice-full`) changes who decides the media path**, which is why it belongs in this
  document rather than only in the cookbook:
  - **The datapath stops answering checks on a full-agent leg** (`IceAgentMode::ForwardOnly`). It
    forwards STUN to the engine and answers nothing, because answering correctly needs state the
    datapath does not have: the role and tie-breaker for the §7.3.1.1 conflict check, the checklist for
    §7.3.1.3 peer-reflexive discovery, and the nomination flag for §7.3.1.5.
  - **The agent becomes the only writer of the latch**, through the new `Datapath::adopt_source`. It
    is called when ICE selects a pair (§8.1.1), and only for a pair whose check the agent
    authenticated with the negotiated credentials — the same authority the responder had, relocated
    to the component that owns the checklist.
  - **Media therefore does not start until ICE has chosen.** Under the layer-4 gate an ICE endpoint
    forwards media only from the adopted source, so with nothing adopted, nothing flows. An early
    media sender cannot pre-empt the choice, and neither can an attacker who simply sends first.
  - **The forward rule follows for free.** The datapath already prefers an endpoint's adopted source
    over the signalled `out_dst`, so adopting both gates ingress and re-points the sibling's egress.
    RFC 7675 consent, which resolves its target from the same adopted source each tick, follows the
    selection without being told.
  - **A DTLS-SRTP leg keys the selected pair, not the signalled address** (RFC 8445 §12). Its
    handshake is held until ICE selects, then released and pointed at the chosen pair; records and
    media follow it. Gated only when a full agent is actually running on that leg — otherwise no
    selection is coming and waiting would hang a working leg.
  - **A failed checklist tears the call down** (§8.1.2, CDR reason `ice_failed`): if no pair works,
    there is no path, and holding the call open would only wait for a timeout.
  - **Enforcement:** `siphon-rtp-ice/src/{checklist,agent}.rs` (the pure state machine),
    `ice/driver.rs` `AgentSupervisor` + `Engine::drive_ice_agents` (its I/O), `IceAgentMode` and
    `adopt_source` in `datapath`.
- **No blind pre-check latch on a plaintext-RTP + ICE relay leg.** On the `Forward` fast path an ICE
  endpoint's media is gated to the STUN-validated latch: the connectivity-check responder
  (`handle_stun`) is the **only** writer of an ICE endpoint's latch, so media arriving *before* any
  valid check is dropped, media from a source other than the adopted one is dropped, and media never
  itself creates or moves the latch (a genuine rebind comes via a fresh validated check, not a media
  spray). The engine builds the ICE `Forward` rule with `SourceFilter::Any` + `LatchPolicy::Off` (no
  rule-level latch) and calls `set_ice` **before** installing the flow, so an ICE leg is check-gated
  from its first packet — no first-source race. Enforcement: `Inner::dispatch` (the Forward-path ICE
  branch) in [`udp.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-datapath/src/udp.rs); the rule + `set_ice` ordering in `engine::answer`.
- **The same gate runs on the `Redirect` path, and it has to.** Every userspace consumer — a
  conference seat, a promoted transcode/record/echo call, a WebSocket takeover leg, the SRTP and DTLS
  bridges — receives its media as `FlowAction::Redirect`, and each re-enforces the **layer-2**
  signalled-source gate itself (Layers 5a–5d). That is not enough for an ICE endpoint, because an ICE
  leg deliberately runs layer 2 **open** (`SourceFilter::Any`): the signalled address is not the
  discriminator when a peer-reflexive check legitimately arrives from a transport the SDP never
  carried (RFC 8445 §7.3.1.3). On a `Forward` leg layer 4 takes over from layer 2 — so on a
  `Redirect` leg it must too, or an ICE endpoint ends up with *no* source gate at all. The
  `Redirect` arm therefore consults the identical verdict (`Inner::ice_gate`, the one definition both
  arms call, so the two paths cannot drift): an endpoint carrying ICE credentials hands the consumer
  only the source a connectivity check validated — nothing before one has, nothing from another
  source after. Only the source is gated, never the packet class: a redirected endpoint is entitled
  to non-RTP (Layer 1), and STUN never reaches the arm at all because `recv_loop` routes it to the
  responder or the full agent first, which is what lets a check through and lets the latch form. A
  non-ICE `Redirect` endpoint is untouched — the TURN relay path in particular still receives
  everything raw. Enforcement: `Inner::{ice_gate, dispatch}` in `udp.rs`.
  - **What this closed.** Before it, an **ice-lite** conference seat had no source gate whatsoever:
    `conference_join` opened layer 2 for the ICE case, the room's `ice_pending` gate is only set for a
    *full* agent (an ice-lite seat has no agent that would ever call `ice_selected` to narrow it), and
    the `Redirect` arm applied nothing — so anyone able to reach the seat's port injected audio into
    the mix every other participant heard. The same gap covered every other redirected ICE consumer:
    a promoted ICE call inherits `SourceFilter::Any` from the `Forward` rule `ingress_rule` built for
    it, and neither `MediaCall::process` nor the SRTP/DTLS bridges have an ICE gate of their own.
- **The kernel datapath enforces the same gate** (XDP `Forward` fast path). An ICE endpoint sets the
  flow's `ice` byte, which changes two things in the classifier:
  - **STUN is redirected to userspace instead of dropped.** The layer-1 demux drops everything that
    is not RTP/RTCP on a `Forward` leg, which on an ICE leg would silently swallow every connectivity
    check and leave it unable to connect. The source gate is deliberately *not* applied first: a
    peer-reflexive check legitimately arrives from a transport the SDP never carried (RFC 8445
    §7.3.1.3), and MESSAGE-INTEGRITY — which the agent verifies — is a stronger gate than the address.
  - **Layers 2 and 3 are replaced by the adopted-source gate** (`rewrite::ice_media_allowed`): media
    is forwarded only from the source ICE adopted, and nothing at all before a check has validated
    one. Without this an ICE leg on XDP would blind-latch the first RTP sender through
    `LatchPolicy::Symmetric` — exactly the RTPbleed hole ICE exists to close. The same-SSRC re-latch
    escape hatch layer 3 grants a plain relay is absent here on purpose: only an authenticated check
    may move an ICE path.
  - The adopted source is written into the kernel flow by `Datapath::adopt_source` (full agent) or by
    the userspace ice-lite responder on the datapath thread, and is **re-stamped on every flow
    install** — a rebuilt rule would otherwise drop the flag mid-call and quietly revert the leg to
    the signalled-source gate.
  - **The classifier's `REDIRECT` arm applies the same gate**, for the same reason the loopback
    backend's does: a redirected ICE endpoint's consumer gates by address, and an ICE leg's address
    gate is open. `apply_ice_posture` already stamped the flag and the adopted source onto a Redirect
    action, so the arm has everything it needs; before it consulted them, an ICE conference seat or
    promoted call on XDP reached userspace ungated. STUN is exempt there too, so a check still
    reaches the datapath thread's `IceDemux`.
  - **Enforcement:** `rewrite::{is_stun, ice_media_allowed}` (the pure, host-tested decisions),
    `forward_in_kernel` **and the `action::REDIRECT` arm of `try_classify`** in the eBPF classifier,
    `IceDemux` + `apply_ice_posture` in `siphon-rtp-xdp`. Both backends share one responder
    (`datapath::respond_to_stun_check`), so what authenticates a check cannot drift between them.
- **Relayed candidates carry traffic, they are not just advertised** (RFC 5766). A relayed candidate's
  transport address lives on the TURN server, so nothing sent from the endpoint reaches the peer
  directly. The datapath therefore wraps egress to a **bound** peer in ChannelData and addresses it to
  the server, and unwraps inbound ChannelData **rewriting the source back to the peer** — so the ICE
  responder, the source gate, the latch and the relay all keep working in terms of the peer's own
  address and never learn a relay is in the path (`Datapath::set_turn_relay`, `TurnRelay`).
  - **Only the allocation's own server is trusted for de-encapsulation.** ChannelData-shaped bytes
    from any other source are left untouched, so the seam cannot be used to forge a peer address; a
    message on a channel this allocation never bound is dropped rather than passed up as if it came
    from the server.
  - **A destination with no channel is sent directly and untouched** — that is what keeps the
    allocation's own requests (addressed to the server) and any peer reached over a host or
    server-reflexive candidate on the direct path.
  - **The candidate is not advertised unless it can be carried.** Gathering consults
    `Datapath::supports_turn_relay` and the allocation's actual state; a backend without the seam, or
    a TURN server that never answers, yields no relayed candidate at all. An advertised relay the peer
    nominates and we then cannot carry is worse than never offering one — it turns a call that would
    have failed over into one that connects and has no audio.
  - **The allocation is kept alive for the life of the leg**, not just long enough to gather: it is
    refreshed before its lifetime lapses, and every remote candidate the checklist may probe (including
    peer-reflexive ones discovered mid-session) gets a permission and a channel, because the server
    drops traffic from a peer it holds no permission for (§9). An allocation that dies is torn out and
    the datapath's relay cleared, so the leg falls back to its direct candidates.
  - **Enforcement:** `siphon-rtp-stun/src/turn_client.rs` (the pure allocation state machine),
    `Engine::gather_relayed_candidate` + `Engine::drive_turn_allocations` (its I/O), `set_turn_relay`
    and the `relay_unwrap` ingress hook in `udp.rs`.
- **Consent freshness** (RFC 7675): periodic STUN checks on the established pair; on consent loss the
  call is torn down. This is also the anti-hijack *and* the dead-path detector.
  - **Responder half (always on).** A valid inbound check stamps the endpoint's activity, so the
    media-timeout sweep (layer 6) already reaps an ICE path whose peer stops checking. Nothing to
    enable; this is what an ICE-lite agent is required to do.
  - **Initiator half (`--ice-consent`, off by default).** With it enabled, every ICE leg is promoted
    to the datapath's **full-agent seam** (`Datapath::set_ice_agent`: the responder plus forwarding of
    every STUN datagram — crucially the Binding *responses* the responder drops) and gets a
    `ConsentChecker` driven once per sweep tick by `Engine::drive_consent`. A check is addressed
    `<peer-ufrag>:<our-ufrag>` and signed with the **peer's** password (RFC 8445 §7.1.2), so each leg
    of a call is probed with the credentials of the peer *it* faces. After
    `--consent-timeout-secs` (30 s per RFC 7675 §5.1) with no correlated, MI-verified response, the
    call is torn down: CDR reason `consent_failed`, `Event::MediaTimeout` to the owner.
  - **Where the check is sent is the security-relevant part.** It goes to
    `Datapath::ice_validated_source` — the address the peer proved it can receive on by answering a
    signed check — **never** the signalled `c=`. For a NATed peer the `c=` address is its private
    address, so probing it would fail consent on healthy calls and reap them. An endpoint on which no
    check has validated a source yet is not probed at all (there is no pair to keep alive, and layer 6
    still covers a leg that never comes up). A *media* latch on a non-ICE endpoint is never reported
    as validated — only an authenticated check moves that source.
  - **Off by default, deliberately.** RFC 7675 §4 states that an ICE-lite agent does not generate
    consent checks, only responds to them, and `a=ice-lite` is what the engine advertises today.
    Initiating them while claiming lite is a deviation, so it is an operator opt-in; the full-agent
    work turns it on for legs that no longer claim lite.
  - **Backend support.** Both datapaths implement the seam — the UDP one in its `recv_loop`, the XDP
    one in the datapath thread's ICE demux, on STUN the kernel redirects up for exactly this purpose.
    A backend that did not would take the defaulted `set_ice_agent`, which **logs a warning per
    endpoint** and keeps responder-only behaviour — the degradation stays loud, never silent, for any
    future backend. An HA-restored ICE call likewise runs no
    consent and says so: the snapshot carries the engine's own credentials but not the peer's, so a
    check cannot be addressed.
  - **Enforcement:** `ice/driver.rs` (`ConsentSupervisor`), `ice/consent.rs` (`ConsentChecker`),
    `Engine::drive_consent` + the daemon sweeper, `ice_validated_source` in `udp.rs` and
    `siphon-rtp-xdp`.
- **Spec:** RFC 8445 (ICE), RFC 8839 (SDP for ICE), RFC 8489 (STUN), RFC 7675 (consent).
- **Enforcement:** `profile.ice` (`force` / `remove`; `force-relay` degrades to `force`) now
  overrides the SDP-derived ICE posture; STUN served on the media socket via the layer-1 demux.
- **Note:** for non-ICE legacy VoLTE/PSTN UAs (the common case), layers 1–3 are the whole story; ICE
  applies to ICE-capable peers (RCS, WebRTC bridges, modern clients).

- **ICE restart (RFC 8445 §9) rides the `reoffer` verb, and does not interrupt media.** A re-offer
  renegotiates on the *existing* ports (unlike a repeated `offer`, which replaces the call on fresh
  ones), so there is a session to restart in the first place. A re-offer whose `a=ice-ufrag`/`a=ice-pwd`
  differ from the current ones is a restart (§9.1.1.1): the engine mints fresh credentials of its own,
  re-gathers, and rebuilds the leg's agent against the new session — while **leaving the adopted
  source untouched**, so under the layer-4 gate media keeps flowing on the previously selected pair
  until the new session selects one (§9.3). Clearing it instead would silence every call for the
  length of a fresh ICE exchange. Owner-only; a re-offer that changes the negotiated codec is
  *rejected* rather than accepted-and-ignored, because rebuilding a live transcode pipeline is not
  done here.
- **A repeated `offer` on a live call-id is owner-only, and replaces cleanly.** Another client
  offering an existing call-id gets `unknown_call` and the live call is untouched — it cannot be
  destroyed, and its existence is not disclosed (A3, §5). For the owner the offer *replaces* the call:
  the previous one is torn down through the same path as `delete` (CDR emitted, endpoints, pipelines,
  subscriptions and the quota slot all released) before the replacement is built. Previously the
  registry entry was simply overwritten and the old `Call` dropped unfreed, leaking its media ports
  and its quota slot on every repeat — a client re-offering in a loop could exhaust both. Note this is
  replacement, not re-negotiation: the replacement binds fresh ports, so the peer must be told the new
  address. That in-place re-offer on the existing ports (a SIP re-INVITE, and the trigger an RFC 8445
  §9 ICE restart needs) is the `reoffer` verb (see the ICE-restart bullet above).

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
>
> **A DTLS leg reaches the media pipeline** (`PipelineKind::DtlsMedia`) and can be seated in a
> conference, so a WebRTC leg can be transcoded, recorded, noise-suppressed, WS-teed or mixed rather
> than only relayed — see Layer 5d.

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

### Layer 5b — The media (transcode / record / DTMF / echo) Redirect path
The transcode/record/DTMF-extraction/echo slow path (`engine/src/media_pipeline.rs`) shares the SRTP
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
- **Symmetric, SSRC-consistent latch (after auth).** When a party's gated packet is accepted, the
  reverse direction's egress destination is latched to that observed source (RFC 3550 symmetric RTP),
  so a NATed peer is replied to where its media actually originates. This mirrors the Forward-path
  latch (the same SSRC gate, `SymmetricLatch`): the reply follows a genuine NAT rebind (a new source
  keeping the stream's SSRC, RFC 3550 §8) but a spray from a new source with a *different* SSRC cannot
  steal it. Crucially the re-latch runs **only after** the SRTP `unprotect` succeeds on a secure leg —
  a forged, auth-failing packet from the gated address is dropped before it can move the reply
  direction (it never reaches the latch). Enforced in the actor because `Redirect` skips the datapath
  latch (`MediaCall::process` → `Direction::source_latch`).
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
- **Echo reflect (self-test).** `echo enabled=true` promotes a plain relay into a **processing**
  `MediaCall` that decodes each party's ingress and re-encodes it back to the sender (on the engine's
  own egress SSRC/sequence, RFC 3550 §5.1 — never the sender's). A **single-leg** echo — an offer-only
  UAS IVR with no answered B leg — reflects on the one caller-facing endpoint the offer's rewritten SDP
  advertised (the socket the UAS put in its 200 OK), gating ingress to the caller's signalled /
  `received-from` source (RTPBleed, layer 2) and looping back to it; the never-advertised sibling socket
  stays idle. Disabling echo demotes the relay — a single-leg promotion returns its lone endpoint to the
  inbound-drop state it had before (an offer-only endpoint has no negotiated peer).
- **Idle reap.** A gated-in packet stamps the endpoint's activity (`Datapath::note_activity` — the
  `Redirect` arm does not stamp `last_seen` itself, so the `MediaCall` actor stamps it on each accepted
  packet, exactly as the conference actor does); a spoofed source that fails the gate does **not**, so
  it cannot keep a dead path alive. The daemon sweep (Layer 6) then reaps a media call idle past the
  media timeout — an actively-transcoding/echoing call is kept alive, a silent one is torn down.

### Layer 5d — A DTLS-SRTP leg on the media Redirect path
A DTLS leg whose media must actually be *decoded* — a different codec per side, recording, noise
suppression, echo cancellation — resolves to `PipelineKind::DtlsMedia`, the DTLS analogue of
`SrtpMedia`. It is the path that makes a WebRTC leg more than a relay.

**Split of responsibility.** The DTLS endpoint stays owned by `dtls_bridge.rs`, because only it can
do the two things that are genuinely DTLS-specific: the RFC 7983 demux (Layer 1) and the handshake.
Everything after that belongs to the per-call `MediaCall` actor:

| Sub-stream (RFC 7983) | Handled by |
|---|---|
| STUN | the ICE responder / agent (Layer 4) |
| DTLS | the handshake task in `dtls_bridge.rs` |
| SRTP / SRTCP media | forwarded **still encrypted** to the `MediaCall` actor, which decrypts on its own `secure_ingress` |

Forwarding media encrypted — rather than decrypting in the bridge and passing plaintext on — keeps a
single owner for the `SecureLeg`. Its SRTP contexts, the decode/re-encode, and the reverse
direction's `protect` all sit behind one actor mailbox, so no crypto state straddles two tasks. This
is the same shape SDES secure-transcode (`SrtpMedia`) already had; DTLS now joins it.

- **Keying is asynchronous, and the gap is closed by dropping, not by trusting.** SDES delivers its
  key in the answer; DTLS produces one only when the handshake finishes, which is after the control
  command has returned. The actor is therefore built **pending** (`with_far_secure_pending`), and
  every direction facing the secure peer drops media until
  `MediaControl::AttachSecureLeg` delivers the key. This is a security property, not a nicety:
  - an unkeyed secure **ingress** must not be decoded as if it were plaintext (SRTP payload decoded
    as G.711 is noise at the far end, and it would put ciphertext-derived audio on the wire);
  - an unkeyed secure **egress** must not emit the other party's cleartext toward a peer that
    negotiated encryption.
  The egress guard sits in `Direction::push_egress`, the single choke point every emitted datagram
  passes through — transcode, injected prompt, comfort noise, relayed telephone-event and echo
  reflect alike — so a new egress caller cannot bypass it by construction. Non-muxed SRTCP relays
  carry the same gate (`RtcpRelay::with_pending_secure`).
- **No unkeyed window.** On handshake success the key is handed to the actor *first* and only then
  published to the bridge. Because the actor's mailbox is FIFO and the bridge releases no media until
  that flag is set, the key is always already queued ahead of the first media packet. A handshake
  that completes after the call is gone leaves the leg unkeyed, so media keeps being dropped.
- **Source gate and latch (RTPBleed, restated).** Unchanged and applied twice: the bridge re-enforces
  the signalled-source gate before the demux (`Redirect` bypasses the datapath's Forward-path gate),
  and the actor re-enforces it again per direction before any decode. The SSRC-consistent latch still
  only ever follows an **authenticated** packet — on this path the SRTP `unprotect` inside the actor
  is what authenticates, so a forged packet cannot move the reply direction (Layer 3).
- **Conference (MCU) seats take the same shape.** A DTLS participant is seated **pending**
  (`ParticipantConfig::secure_pending`) and keyed by `ConferenceControl::AttachSecureLeg` when its
  handshake completes. Until then the room drops its ingress — unkeyed SRTP decoded as plaintext would
  mix noise into the room for *every other* participant — and sends it nothing, because the mix going
  out in the clear would leak every other participant to a peer that negotiated encryption. Both the
  mix egress (`Conference::emit`) and the periodic RTCP SR carry the gate. The room, not the bridge,
  owns the seat's `SecureLeg`, exactly as the 2-party actor does.
- **Full ICE on a conference seat takes the same pending shape.** A seat whose agent has not yet
  selected a pair is seated `ice_pending` and is treated exactly like an unkeyed DTLS one: the room
  drops its ingress and sends it nothing (both `Conference::emit` and the periodic RTCP SR carry the
  gate). The difference from a 2-party leg is *who* must be told when ICE chooses. A relay leg needs
  only `Datapath::adopt_source`, because the datapath's forward rule already prefers an adopted source
  over the signalled `out_dst`. A conference seat has no forward rule — the **room** owns its egress —
  so the selection is additionally routed to the room actor as `ConferenceControl::IceSelected`
  (`ConferenceRegistry::ice_selected`, driven from `Engine::drive_ice_agents`), which re-points
  `egress_dst` at the selected pair and narrows the source gate to it. Without that second half the
  seat would keep sending the mix to the signalled `c=` address, which for a NATed ICE peer is one it
  cannot receive on.
  - **The pre-selection window is not a permissive one.** An ICE seat starts with
    `SourceFilter::Any`, because a peer-reflexive check legitimately arrives from a transport the SDP
    never carried (RFC 8445 §7.3.1.3). Nothing is mixed or transmitted during that window — the
    `ice_pending` gate drops all media — and selection replaces the open gate with
    `SourceFilter::Exact` on the chosen remote. The symmetric latch is re-armed at the same moment, so
    a stale pre-ICE observation cannot move the reply back off the selected pair.
  - **`ice_pending` is the *full-agent* half of that, and only that.** An **ice-lite** seat never sets
    it: the datapath's own responder answers checks and adopts the validated source, no selection is
    coming, and a seat left pending forever would never be mixed at all. What covers an ice-lite seat
    — and, before its selection, a full-agent one — is the **datapath's layer-4 gate on the redirected
    path** (`Inner::ice_gate`, Layer 4): the room is handed only the source a check authenticated with
    the engine's own password. The seat's own `SourceFilter::Any` is therefore not the gate on an ICE
    seat, and must not be read as one; it is deliberately open so the *datapath* gate can be the
    discriminator. Both halves are armed by the credentials `conference_join` installs
    (`set_ice` / `set_ice_agent`) — without them an ICE seat would fall back to that open filter alone.
  - **A failed checklist removes the seat** (§8.1.2). A participant has no `MediaCall` for the
    2-party `ice_failed` teardown to reap, so `drive_ice_agents` drops it from the room (and tears the
    room down if it was the last member) rather than leaving it seated behind a gate that can never
    open.
  - **A DTLS-SRTP seat under full ICE holds its handshake for the selection** (RFC 8445 §12,
    `gate_on_ice`) — but only when an agent is actually running on it, since otherwise no selection is
    coming and waiting would hang a working seat.

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
  `unsignalled_source_is_dropped_from_the_mix`. **Two seats set that filter to `Any` and are therefore
  gated elsewhere, not here:** an **ICE** seat, which is covered by the datapath's layer-4 gate on the
  redirected path (Layer 4, and the `ice_pending` note in Layer 5d) — proven by
  `an_ice_lite_conference_seat_mixes_only_a_stun_validated_source`; and a **`symmetric`** seat, whose
  only remaining constraint is the reply latch, which declines rather than drops (see the known
  divergence in Layer 3).
- **Constrained, SSRC-consistent latch (after auth).** An accepted participant's egress destination
  is latched to its observed source (symmetric RTP), so a NATed leg is replied to where its media
  originates — but only for an authenticated, SSRC-consistent stream: the re-latch runs **after** the
  SRTP `unprotect` and only when the source is SSRC-consistent (`SymmetricLatch`, RFC 3550 §8), so a
  forged/auth-failing or wrong-SSRC packet from the gated address never moves the reply
  (`Conference::ingest` → the participant's `reverse_latch`).
- **SDES-SRTP secure legs.** A participant offering `RTP/SAVP` + `a=crypto` gets a per-participant
  `SecureLeg` (the same primitive Layer 5a uses): `conference_join` mints the engine's key, answers
  `RTP/SAVP` + its own `a=crypto`, and the room **decrypts each inbound packet before it enters the
  mix** (the auth tag also proves authenticity — a forged/replayed packet fails and is dropped) and
  **encrypts the mix (and the SR) back out** as SRTP/SRTCP. DTLS-SRTP and full-ICE conference legs are
  wired too — see Layer 5d for the pending-seat shape both use.
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
- **RFC 9071 multiparty text (plaintext and secure).** A participant that offers an `m=text` (RFC 4103)
  stream — `RTP/AVP` **or** secure `RTP/SAVP` — gets a **second** redirected engine endpoint (its own,
  distinct from audio), seated in the same room actor. That text endpoint is a full inbound surface and
  carries its **own** copy of Layers 1–3: `Conference::ingest_text` runs the per-stream `SourceFilter`
  gate on the wire source before anything else and moves the text reply address only for an
  SSRC-consistent stream (`ParticipantText::reverse_latch`) — a spoofed text packet neither enters the
  room's text mix nor moves the text latch, and the audio and text gates are wholly independent. The
  room mixes each participant's T.140 across the others **mix-minus-self** (`TextMixer`, a sibling to the
  audio `Mixer` — text is tagged, never summed), labelling every emitted packet with the contributing
  source's identity in the RTP **CSRC** list (RFC 9071 §4.2) so a receiver presents each source
  separately, on a **second, ~300 ms cadence** independent of the 20 ms audio tick.
- **SDES-SRTP secure conference text — per-participant, independently keyed.** A participant offering a
  secure (`RTP/SAVP` + `a=crypto`) `m=text` section gets a per-participant text `SecureLeg`, keyed
  exactly like its secure audio leg: `conference_join` mints the engine's own text SDES key, answers
  `RTP/SAVP` + its own text `a=crypto` (`TextRewrite::AnchorSecure`), and stores the `SecureLeg` on the
  participant's text config. On ingress (`Conference::ingest_text`) the SRTP text packet is **decrypted
  first — fail-closed**: a packet failing SRTP auth/replay is dropped before it is reassembled, mixed,
  observed, or allowed to move the latch (the auth tag proves authenticity, so a forged/replayed packet
  never steers the reply), so the whole reassembly/mix/latch runs on plaintext — the same order the
  secure **audio** leg uses. On egress (`Conference::text_tick`) each distributed increment is
  **re-encrypted with the receiving participant's own key** (a plaintext receiver gets it in the clear);
  the room's text mix itself stays **internal plaintext**, exactly as the audio mix does in a room that
  mixes secure and plaintext legs together. A secure text section the engine cannot key/anchor (no usable
  `t140`, or no usable `a=crypto`) is **declined** (`m=text 0`, RFC 3264 §6), never downgraded. DTLS-SRTP
  conference text (like DTLS conference audio) remains a follow-up. The text endpoint is part of the
  room's endpoint set for the idle reap (text activity keeps the seat) and is freed with the participant
  on leave/teardown.

### Layer 5d — The RFC 4103 Real-Time Text (RTT) relay path
A VoLTE/IMS call may carry a second media stream: an `m=text` line (RFC 4103, T.140 over RTP, usually
RFC 2198 RED-wrapped) alongside the audio. The engine parses it (section-aware SDP), anchors it to a
**separate** engine endpoint per leg, and relays it. **RTPBleed is per-stream**, so the text stream is
not a special case of the audio gate — it is a full inbound surface in its own right and gets its own
copy of Layers 1–3.

> **Status (landed — plaintext RTT relay):** `sdp::parse` yields `MediaInfo.text`
> (`TextMediaInfo`: remote RTP/RTCP, `secure`, `t140`/`red` payload types, and the text section's own
> `crypto` for a secure stream); the section-scoped `sdp::rewrite` takes a `TextRewrite` directive
> (`None` / `Anchor` / `AnchorSecure` (SDES text) / `Decline`). `offer`/`answer`
> allocate one text RTP endpoint per leg and install the in-datapath `FlowAction::Forward` flows
> `near.text ↔ far.text` — independent of the audio pipeline kind (the text endpoints are distinct, so
> text relays whether audio is a plain relay, a transcode, or an SRTP bridge). The T.140/RED payload is
> **not parsed** in this iteration — the stream is forwarded byte-for-byte.

- **Per-stream source gate + symmetric latch.** Each text direction is an ordinary `Forward` rule built
  by the same `ingress_rule` the audio relay uses: an `Exact`/`Subnet`/`Symmetric` `accepted_source`
  and the SSRC-consistent `LatchPolicy` (Layers 1–3). A spoofed source on the text port is dropped
  before it can move the text latch, exactly as on the audio port, and the two streams' gates/latches
  are wholly independent (a hijack of one cannot move the other). The `received-from` public-IP hint
  (Layer 2) tightens the text gate too.
- **Secure text (SDES-SRTP) is anchored, never downgraded or mixed.** An `m=text` offered over a
  secure profile (`RTP/SAVP` + `a=crypto`, RFC 4568) is anchored as a **per-leg `SecureLeg` bridge**
  (mirroring the Layer 5a audio SDES bridge): the engine mints its own SDES key for each text leg,
  answers `RTP/SAVP` + its own `a=crypto`, and decrypts each side's ingress / re-encrypts each side's
  egress with that leg's own key — text is re-keyed A↔B, and no plaintext ever crosses to a secure
  peer (RFC 3711). A **secure text stream cannot relay in-kernel** (SRTP must be terminated in
  userspace), so it runs in the text processor from the start — both text endpoints `Redirect`ed, held
  there for the call's life (a permanent `Secure` promotion hold, never demoted). Decrypt is
  **fail-closed**: a text packet that fails SRTP auth/replay is dropped — never forwarded, observed, or
  latched. A secure text stream with no usable `a=crypto`, or a **mixed** secure/plaintext text bridge
  (one side `RTP/SAVP`, the other `RTP/AVP`), is refused (`m=text 0`, RFC 3264 §6) rather than bridged
  or downgraded — the same "never silently bridge secure↔insecure" rule as Layer 5. DTLS-SRTP text
  (like DTLS conference legs) remains a follow-up; only SDES text is anchored here.
- **Section scoping fixes two latent multi-`m=` bugs.** The audio-plane strips (ICE / crypto /
  fingerprint / `rtcp-mux`, Layers 4–5) are scoped to the session region and the audio section only, so
  a secure-audio rewrite can no longer strip a text (or video) section's own keying/ICE, and a text
  section that relies on the session `c=` is anchored to the engine address rather than leaking the
  UE's (often private) one.
- **Idle reap + teardown.** The text endpoints are part of the call's endpoint set (`all_endpoint_ids`)
  for the media-timeout sweep (text activity keeps the call alive) and teardown (their ports are freed
  with the call). HA checkpoint/restore of the text stream is deferred (consistent with the deferred
  `SrtpMedia`/`Ws` restore) — a restored call is audio-only.

> **Status (landed — text observability):** when a text-observability feature is active for a call
> — control-plane `ProfileFlags.text_events`, or a runtime recording — the engine promotes **only** the
> low-rate text endpoints off the in-kernel `Forward` relay onto the userspace text processor
> (`engine/src/text_pipeline.rs`), switching them from `Forward` to `Redirect`. The audio
> relay/transcode/SRTP path is **never** promoted for text observability — it stays byte-for-byte on its
> own fast path. The text processor RED/T.140-reassembles the stream (`siphon-rtp-media::t140`) to
> surface `Event::Text` + per-leg content QoS in the `CallSummary` CDR, then forwards the packet
> **verbatim** (observe, don't transform). When no such feature is active, text stays on the PR-1
> in-kernel relay unchanged — text observation is never always-on.

- **The userspace text path keeps the exact same gate/latch as the in-kernel relay (RTPBleed, restated
  for `Redirect`).** Promotion reconstructs each text direction's `accepted_source` (`Exact`/`Subnet`/
  `Any`) and SSRC-consistent symmetric latch from the *same* stored text `Forward` rules the in-kernel
  relay used (via `relay_layout_from_flows`), so switching to `Redirect` — which **bypasses** the
  datapath's Forward-path layer-2 gate, exactly like Layers 5a–5c — loses no protection: `TextCall::process`
  re-enforces the signalled-source gate before it forwards, records, observes, or moves the latch, and
  only an authentic, SSRC-consistent packet re-points the reverse egress (Layer 3). A spoofed source on
  the promoted text port is dropped with no forward, no `Event::Text`, and no latch movement — identical
  to the in-kernel posture. Demotion (the last feature clears) reinstalls the same `Forward` rules.
- **Secure (SDES-SRTP) text observability rides the same processor.** A secure text stream is already
  running in the text processor (it has to — SRTP is terminated in userspace), so `Event::Text`, the
  per-leg content QoS, and the raw-RTP recording all attach to it exactly as they do for a promoted
  plaintext stream. Everything observed is **decrypted** (observe after decrypt, before encrypt); the
  pcap recording tees the on-the-wire **ciphertext** (matching the audio pcap recorder, which also
  captures pre-decrypt). The one difference from the plaintext path: a secure text stream is never
  demoted back to the kernel (it holds a permanent `Secure` promotion reason).

### Layer 5e — The WebSocket-takeover Redirect path
A **takeover** call (`ProfileFlags.ws_uri`, `PipelineKind::Ws`) points leg A's RTP endpoint at
`FlowAction::Redirect` and makes an external WebSocket media server A's far side; the A↔B
relay/transcode path is deliberately not wired. That makes the engine A's *only* peer — and therefore,
when A negotiated SRTP, A's cryptographic peer. It is a full inbound surface, so it carries its own
copy of Layers 1–4.

> **Status (landed — secure takeover):** a takeover leg on a secure offerer terminates SRTP on its own
> `WsSecureLeg` (`engine/src/ws_bridge.rs`), keyed by SDES (RFC 4568) in the answer or by the RFC 5764
> handshake. Only `answer_local` supports it; `offer`/`answer` refuse it (see "Where a secure takeover
> is refused" below).

- **Source gate (RTPBleed, restated for `Redirect`).** `WsRegistry::dispatch` re-enforces the
  signalled-source gate (`Exact`/`Subnet`/`Any`, tightened by the `received-from` public-IP hint)
  before anything reaches the bridge — `Redirect` bypasses the datapath's Forward-path gate, exactly as
  on Layers 5a–5d.
- **Only `answer_local` can be a secure offerer's far side, and that is a structural fact, not a
  policy.** The engine has to advertise *its own* keying (`a=crypto`, or `a=fingerprint` + the
  complement `a=setup` per RFC 5763 §5) in the answer that goes back to A. `answer_local` writes that
  answer itself. `offer`/`answer` do not: the answer delivered to A there is rewritten from **B's**
  SDP, and on a takeover call B does not exist. Advertising nothing (the pre-change behaviour) left A
  encrypting to an engine that had no key, and the downlink leaving in the clear.
- **The leg owns its crypto, and the crypto lives in one module.** `WsSecureLeg` holds the RFC 3711
  inbound and outbound contexts for the leg; the registry decrypts ingress on the way to the bridge and
  the bridge's drain task encrypts egress on the way out, both through that one type. The bridge itself
  never sees ciphertext and never sees the key — the same single-owner rule Layers 5b–5d follow.
- **Fail-closed in both directions.** An unkeyed leg (a DTLS handshake that has not finished), an SRTP
  authentication failure, or a crypto error drops the packet:
  - **ingress** — unkeyed or unauthenticated SRTP is never handed to the decoder, so ciphertext cannot
    be decoded as G.711 and streamed to the WS server as if it were audio (RFC 3711 §3.3);
  - **egress** — the downlink is *dropped*, never emitted in the clear. This is the half that matters
    most, and it is not hypothetical: the takeover bridge's ticker produces a downlink frame every
    ptime whether or not the leg is keyed, so a fail-open drain would spray plaintext RTP at a peer
    that negotiated encryption for the whole duration of the handshake.
  A takeover call has exactly **one** egress site — the bridge's drain task — because every other
  emitter (`play_media`, `play_dtmf`, pcap recording, SIPREC, the WS tee) already refuses a
  `PipelineKind::Ws` call and a takeover call has neither a media actor nor a forward rule. That is
  what makes a single encrypt point sufficient here, where Layer 5b needed a `push_egress` choke point.
- **SRTCP has no consumer and is dropped.** The bridge speaks PCM to the WS server, not RTCP, so an
  SRTCP packet on a muxed takeover port is discarded at the RFC 5761 §4 demux rather than decrypted and
  thrown away.
- **DTLS-SRTP reuses the existing bridge, unchanged.** The endpoint stays owned by `dtls_bridge.rs` for
  the two DTLS-specific jobs (the RFC 7983 demux and the handshake); accepted media is forwarded to the
  WS leg **still encrypted** via `PipelineTarget::Ws`, and the handshake's key is installed into the
  leg's `WsSecureLeg` before media is released — the same "key first, then publish" ordering
  `PipelineTarget::Call` and `PipelineTarget::Conference` use, with one fewer hop (the registry write
  is synchronous, so there is no mailbox to race).
- **Full ICE on a takeover leg, and why ice-lite is refused.** A takeover leg's egress belongs to the
  bridge's drain task, not to a datapath forward rule, so `Datapath::adopt_source` alone never reaches
  it — the selection is additionally routed to `WsRegistry::ice_selected` (driven from
  `Engine::drive_ice_agents`, exactly as a conference seat is), which re-points the drain's destination
  at the selected pair and narrows the source gate to it.
  - The pre-selection window is **not** permissive: the gate starts `Any` because a peer-reflexive
    check legitimately arrives from a transport the SDP never carried (RFC 8445 §7.3.1.3), and that is
    only safe because the `ice_pending` flag drops **all** media until the agent selects.
  - An ICE offerer with **no full agent** available (`--ice-full` off, or a peer that supplied no
    credentials/candidates) is **refused**, not downgraded to the ice-lite responder. The responder
    adopts the validated source into the datapath's own latch, which gates a `Forward` rule — and a
    takeover leg is `Redirect`, so that gate never runs. Accepting would produce a leg that is open at
    Layer 2 and deaf at Layer 4: wide to the world on ingress and sending its downlink to an address a
    NATed peer cannot receive on. `ICE=remove` remains the explicit escape hatch.
  - A DTLS takeover leg under full ICE holds its handshake for the selection (RFC 8445 §12,
    `gate_on_ice`), and only when an agent is actually running.
- **Where a secure takeover is refused.** Each refusal is returned at **offer** time (or at
  `answer_local`, which *is* the offer-time decision for a single-leg call) with a stable leading
  token, so a controller learns it before it commits to the dialog rather than discovering silent
  one-way audio afterwards:

  | Shape | Verb | Reason token |
  |---|---|---|
  | Secure (SDES or DTLS) offerer + `ws_uri` | `offer` / `answer` | `ws-takeover-secure-offerer` |
  | ICE offerer + `ws_uri` | `offer` / `answer` | `ws-takeover-ice-offerer` |
  | Secure offerer, **no** `ws_uri` (single-leg IVR/echo) | `answer_local` | `secure-offerer-unsupported` |
  | `RTP/SAVP` with no usable `a=crypto`; `UDP/TLS/RTP/SAVPF` with no `a=fingerprint`; no engine certificate | `answer_local` | `ws-takeover-unkeyable` |
  | ICE offerer with no full agent available | `answer_local` | `ws-takeover-ice-unsupported` |

  The class of bug being closed is "accepted silently", not "DTLS specifically": every one of these
  used to return `ok` on a call whose media went nowhere.
- **HA.** A takeover call is not restorable — the external WebSocket session is not replicable state —
  so `checkpoint` refuses a single-leg call outright and `restore` rejects a `Ws` snapshot. Securing
  the leg does not change that; it is refused for the same reason it was before.

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
RFC 1321 (MD5) · RFC 4648 (base64) · RFC 2104 / 2202 (HMAC) · ETSI TS 103 221-2 (lawful-interception
X2/X3 delivery). RTPBleed: Enable Security advisory, 2017.

---

## 10a. Consumers of the accepted-packet path

Everything that copies media out of the engine hangs off the same acceptance decision this document
describes, and each one sits at a deliberately chosen point on it. The differences are not
incidental — they are the security property of each consumer:

| Consumer | Tap point | Sees |
|---|---|---|
| pcap recording (`start recording`) | before `Direction::handle` | the **verbatim wire bytes**, so on a secure leg it records ciphertext — correct for debugging, since the point is to capture what was on the wire |
| SIPREC raw tee (`subscribe_*`) | in `handle`, after decrypt | plaintext, pre-transcode |
| WebSocket tee (`attach_ws_tee`) | post-decode fan-out | decoded PCM |
| **Lawful interception (`attach_x3`)** | in `handle` after decrypt **and** after the authentication decision; plus both crypto bridges | plaintext RTP the engine **accepted** |

The X3 tap is the strictest, and deliberately so. It must never deliver ciphertext (the agency has
no key) and must never deliver a packet the engine refused — a failed SRTP `unprotect`, a replay, or
media arriving before a DTLS handshake keys the leg — because forged traffic presented to an agency
as the target's media is worse than no delivery at all. It also runs on the SDES and DTLS **crypto
bridges**, which relay without ever entering the media pipeline: without that, a same-codec WebRTC
call would be silently uninterceptable.

The source gate (layer 2) runs before all of them, so no consumer ever sees a packet from an
unsignalled source. See [Lawful interception](lawful-interception.md).

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
- **Two-binary datapath model (the same relay-bind posture, kernel-accelerated).** The kernel fast
  path ships as a **separate binary**, not a Cargo feature. The default `siphon-rtp` binary is
  **UDP-only** and never links the eBPF/aya toolchain (the stable workspace and `cargo test` stay
  nightly-free); the `siphon-rtp-xdp-daemon` binary lives in the excluded `crates/siphon-rtp-xdp`
  workspace, depends **up into** the engine, and hands an `XdpDatapath` to the *same*
  `siphon_rtp_engine::run_with_datapath` runner. It attaches the kernel datapath only when
  `--xdp-interface` names a NIC **and** `--relay-bind-ip` is a **routable IPv4** (the fast path is
  IPv4-only and keys/advertises flows on that address — the reachability rule above); on any missing
  capability or attach/bind failure it logs and falls back to the UDP-loopback datapath, never a hard
  failure (the rtpengine posture). The relay-bind, source-gate, latch, and TURN rules in this document
  are enforced identically over either datapath — selection is the only difference between the two
  binaries.
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

---

## 12. Media interfaces and advertised address (egress topology)

A real carrier/SBC deploy separates two IPs the bare bind address conflates: the IP the engine's socket
**binds** (and sources media from) and the IP it **advertises** in the rewritten SDP. It also fronts more
than one network — a private `internal` side toward the core and a public `external` side toward the
access network. Both are policy the engine applies at SDP-rewrite time; neither weakens the ingress
posture of §4.

### 12.1 Advertised address ≠ bound address
The rewritten SDP (`c=`, `o=` on `replace: [origin]`, the ICE host `a=candidate`) advertises the
interface's **advertised** IP, while the socket binds the interface's **bind** IP and the advertised
**port** is always the bound one. This is what lets the engine bind a private or wildcard address yet
hand peers a routable one (1:1 NAT / a floating public IP), the SDP-layer analogue of the TURN
`--turn-relay-ip` split (§11). The single-homed case is `--advertise-ip <public>` (an AWS Elastic IP:
bind the private VPC address, advertise the EIP — same port, family-matched); the XDP fast path keeps
binding the private routable IP, so it is unaffected. With no override the advertised IP equals the
bound IP, so the default posture is unchanged.

- **Security invariant (no RTPbleed regression):** the advertised IP is **presentation-only**. It never
  feeds the layer-2 signalled-source gate, the layer-3 latch, or the forward/relay path — those key on
  the peer's *real* source (the SDP `c=`/`received-from`, §4.2) and on the engine's *bound* socket. An
  attacker learning the advertised IP from the SDP gains nothing the `c=` line did not already give
  them; the gate still requires the real signalled source. Enforcement: the advertised IP is carried as
  `EngineMedia.advertised_ip` / `Leg.advertised_ip` (presentation), entirely disjoint from
  `accepted_source` / `SourceFilter` (gate) and the bound `Endpoint.local_addr` (relay).

### 12.2 Named interfaces + `direction` (per-leg interface selection)
Operators define named interfaces (config `[[interface]] name / address / advertised`, repeating a name
for a second family). The control `direction` pair selects them per call: `direction[0]` → the near
(caller-facing / A) leg, `direction[1]` → the far (callee-facing / B) leg — so an inbound leg lands on
`internal` and the outbound leg on `external`, mirroring rtpengine. An absent or unknown name falls back
to the default interface (logged, never fatal — a stale `direction` from the proxy keeps the call
flowing). The single-interface advertised-IP override (§12.1) is the degenerate case: one synthesised
`default` interface from `relay_bind_ip` + `advertise_ip` (the `--advertise-ip` single-homed
Elastic-IP case: bind private, advertise the public IP, same port, family-matched).

- **Enforcement:** `siphon_rtp_engine::interface::InterfaceTable` (pure policy) resolves the pair to each
  leg's bind + advertised address; `Engine::leg_binding` maps it to a datapath bind IP and an advertised
  IP; the leg allocates via `Datapath::alloc_endpoint_on(bind_ip)`. A leg whose interface serves no
  address of the call's family falls back to the datapath's family default (never a cross-family bind —
  a v4 address in a `c=IN IP6` line is invalid SDP).
- **Datapath reach:** the UDP backend binds any source IP directly. The XDP fast path carries a per-flow
  source IP end-to-end already (`FlowAction.out_local_ipv4`, no eBPF change), so per-leg source IPs work
  for addresses on its **one attached NIC**; a second source IP on a *different* NIC needs a second
  AF_XDP socket and is a follow-up (the advertised-IP override still works there).
- **HA:** the checkpoint records each leg's advertised IP and its full bound `ip:port`, and restore
  re-binds the exact source IP (`Datapath::alloc_endpoint_on_port_at`), so a call pinned to a named
  interface resumes on the same source and re-advertises the same public IP on a standby.
