# siphon-rtp — Security & NAT design

> Design + threat model for the media plane. Status: **implemented and wired.** The gated latch, the
> source-consistency checks, symmetric-RTP NAT traversal, SDP address rewrite, ICE-lite + STUN, the
> built-in TURN server, SRTP-SDES (RFC 3711 / 4568), and DTLS-SRTP (RFC 5764) all ship today, as does
> RFC 7675 consent freshness (opt-in, `--ice-consent` — §4.4). Candidate gathering, the full RFC 8445
> agent (`--ice-full`), ICE restart (the `reoffer` verb, RFC 8445 §9), trickle-receive (RFC 8838), and
> a TURN **client** (`--turn-client`, which requires `--ice-full`) all ship
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
> [`engine/answer.rs`](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/src/engine/answer.rs) from the parsed SDP + `ProfileFlags`).
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
- **The hint belongs to a party, and moves with it on a renegotiation.** Each leg keeps its own
  stored hint: A's from its offer, B's from its answer. A later SDP from that party that carries a
  `received-from` replaces it — a re-offer from A or B (an app that switched from Wi-Fi to mobile data
  re-INVITEs from a new public address), or A's answer to a re-offer from B — and one that carries none
  keeps it, so a renegotiation that omits the hint keeps gating a NATed party on its public address
  instead of falling back to the private `c=` it signalled. Without the refresh the re-wired gate would
  be *(old public IP, new port)* and drop every packet from the new address; without the keep, a
  re-answer from B with no hint gated B on its RFC 1918 `c=`. Neither case widens what the engine
  accepts: one proxy-observed address replaces another, and the latch still governs from the first
  accepted packet.
- **A re-offer presents the leg facing its recipient, never the offerer's.** A re-offer from A is
  delivered to B, so it carries the far leg's endpoints, candidates and keying exactly as the original
  offer did; one from B is delivered to A and carries the near leg (RFC 3264 §8 — a subsequent offer
  modifies the SDP its recipient last received). Presenting the offerer's own leg tells the recipient to
  send into the offerer's socket, from an address the gate there correctly refuses — so the call goes
  one-way while every counter looks healthy. The gate dropping that media is this layer doing its job;
  the fix is in what the SDP says, never in loosening the gate. For the same reason a secure text
  stream re-presents the recipient's own engine key: the other leg's key protects the engine's stream
  toward the *other* party.
- **The hint also aims the relay, not just the gate.** The same `(hint IP, signalled port)` pair is
  the destination each direction transmits to **until that peer's own first accepted packet moves the
  latch**. Gating on the hint while still *sending* to the private `c=` left the whole pre-latch
  window — every packet the other party speaks before this one does, ~400 ms on a NATed call at 20 ms
  ptime — addressed to an unroutable RFC 1918 destination, so the audio was lost and the node emitted
  bogons. It applies wherever a peer's initial destination is derived from its signalled address: the
  in-kernel Forward relay (RTP and companion RTCP), the SDES and DTLS bridges, all three transcoding
  pipelines, the RFC 4103 text relay in both its plaintext and secure forms, and the
  WebSocket-takeover leg (§5e).

  This is an **opening guess, and only that**. Behind a symmetric NAT the public media port need not
  be the signalled one, so the seeded destination can still be wrong — never *more* wrong than an
  unroutable address, but it does mean aiming at a port on the NAT that may belong to another device
  behind it. Two properties keep that bounded, and both are load-bearing:
  - it is confined to the pre-latch window and is **never a latch substitute** — the latch still
    governs from the first accepted packet onward, and it is fed only by packets that passed the
    gate, so nothing here widens what the engine accepts (§4.7 is untouched). That bound is only
    real where a latch actually exists, which is why the WebSocket-takeover leg had to grow one of
    its own (§5e): it has no reverse relay direction, so no `ForwardRule` faces it and the datapath
    latch never runs. On that path a wrong seed was not a 400 ms window, it was the whole call;
  - it uses **control-plane** data — an address the SIP proxy observed the signalling arrive from —
    not anything asserted by an unauthenticated media packet, which is the distinction between this
    and the RTPBleed class of blind adoption.
- Relax to `Symmetric` (accept any source, latch the first) **only** when the control plane sets it —
  for UAs behind symmetric NAT where the signalled address is genuinely unusable. This is opt-in per
  leg, never a global default.
- **Spec:** RFC 3264 (the offer/answer address *is* the contract); mirrors rtpengine
  `trust-address` / `strict-source` / `received-from`.
- **Enforcement:** new accepted-source constraint on the forward rule (§4.7); engine fills it from
  parsed SDP + `ProfileFlags.received_from` + `ProfileFlags.flags` (`trust-address`, `strict-source`,
  `port-latching`, `symmetric`).
- **The single-leg anchor honours the same flags.** A leg the engine answers itself (`answer_local`,
  or an offer nobody answered) is carried by a pipeline `promote_to_processing` builds from the call
  after the command has returned, so the posture the flags asked for (`negotiate::SourcePosture`) is
  stored on the call and applied there. It used to gate on the exact signalled IP whatever the
  flags said, which made `symmetric` and `subnet-source` inert on exactly the leg shape a NATed
  caller reaching an IVR or a mailbox uses: every packet refused, a recording with no audio, and
  nothing the controller could set to fix it but `received_from`.
- **Effect on A1:** with `SignalledOnly`, a blind attacker must *also* spoof the signalled source IP
  to land a packet — collapses the off-path attack for non-NAT and full-cone-NAT peers.

- **An engine offer has no signalled source until its answer (`offer_local`).** The engine binds the
  leg and writes the offer (RFC 3264 §5) before the caller has said where it sends from, so there is
  nothing to gate on. Until the answer the call is *pending* and holds its endpoints and nothing
  else: the endpoints carry the `Drop` flow, and no pipeline, bridge, DTLS driver or ICE agent is
  registered. A datagram from anywhere is dropped (never forwarded into the void, never latched),
  and nothing is sent. Gathering against a STUN server leaves the datapath's ICE-lite responder on
  the endpoint, which would latch the source of an authenticated nominating check and stamp the call
  alive; the engine therefore clears the endpoint's datapath ICE state as soon as gathering ends, so
  a holder of the offered credentials can neither latch before the answer nor keep the call out of
  the setup reap. The full agent is armed from the answer's credentials, and an answer without ICE
  (RFC 8839 §5.1) leaves no ICE state behind to gate the legitimate caller. The answer is validated
  against the offer first (the RFC 3264 §6.1 codec, the offered transport, the SDES line by tag and suite, the DTLS fingerprint and `a=setup`
  role, ICE credentials with candidates) and a refused answer leaves the call pending, so a spoofed
  or malformed answer cannot open a path, and an answer consumes only the exact offer it was
  validated against (`offer-local-superseded` otherwise), so a call-id deleted and offered again
  meanwhile is never completed with the old validation. Only then is the gate drawn: on the address the answer
  signalled, with the same `received-from`, `subnet-source` and `symmetric` postures as every other
  leg, or on the pair ICE selects (Layer 4) with DTLS or SDES keying the path (Layer 5). The
  answering source is the controller's, so the engine trusts it as it trusts an `answer_local`
  offer. A repeated answer is refused (`offer-local-already-answered`), so a second SDP cannot move
  the gate of a live call; only a re-answer through `answer_local`, which replaces the call on fresh
  ports, can.

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
- **Enforcement:** one state machine, `source_latch_verdict` in `siphon-rtp-ebpf-common::rewrite`,
  decides every latch: the UDP backend's `Inner::update_latch`, the `Redirect` consumers'
  `SymmetricLatch` (through the `siphon-rtp-datapath` re-export) and the kernel program through the
  `latch_decision` adapter, so none of them can drift on what counts as a rebind. Two rules belong to
  the state machine rather than to any consumer. A first datagram with no readable SSRC (RTCP) latches
  its source without one, which is what lets a non-muxed RTCP port reply symmetrically behind NAT;
  such a latch is confirmed by its own source but never moved. And an SSRC change on the latched
  source keeps the first SSRC as the rebind key rather than re-pinning, so a transport carrying
  several SSRCs cannot rewrite the latch packet by packet. The kernel's latch map has no room for a
  latch without an SSRC, so the adapter forwards that first SSRC-less datagram without latching and
  learns from the first RTP instead, which only narrows the gate.
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
- **The `Redirect` consumers drop on reject, as the `Forward` path does.** On the `Forward` path a
  latch rejection is a **drop**: `Inner::update_latch` returns `Reject` and `dispatch` discards the
  packet. The userspace consumers (`SrtpBridge::handle`, `MediaCall::process`, `Conference::ingest`
  and its text path, `ForwardRoom::ingest`, the text pipeline, and the WebSocket takeover's `WsEgress`) do the same through
  `SymmetricLatch::admit`: they decide the latch after SRTP authentication and **before** the packet
  is teed, intercepted, relayed, decoded, mixed or forwarded, and a rejected packet is dropped without
  counting as media activity. They used to only decline to move the reply address and still consume
  the packet, which under the opt-in `symmetric` flag (`SourceFilter::Any`, where the latch is the
  only constraint left) let such a leg accept injected media from any source. The userspace latch
  shares the kernel adapter's one restriction: a datagram with no SSRC (RTCP) never aims the reply
  before a stream is latched, and once one is, such a datagram is accepted only from the latched
  source.
- **A re-answer that moves the peer forgets the replaced peer's latch.** An early answer (183) from
  one transport and a final answer, or a re-offer, that moves the far party to another (early media
  from one media server, the answer from another) reinstalls the call's rules. The latch the first
  peer taught belongs to the party the signalling just replaced: kept, it rejects every packet the new
  peer sends (a new source with a new SSRC is exactly what this layer refuses), and it keeps steering
  the reply to the old transport, so audio dies at the answer. The reinstall drops it, by one rule set
  shared through `signalled_peer_moved` in `siphon-rtp-datapath`: an endpoint's latch goes when the
  new rule's source gate (layer 2) no longer admits it, and a peer endpoint's latch goes when the rule
  toward it moved to a **different** signalled destination, which also catches a move to another port
  on the same address that an address-only gate cannot see. The UDP backend applies it in
  `install_flow` (`Inner::forget_stale_latches`), the SRTP bridge in `SrtpBridge::register`. This is
  never a blind re-latch: the new peer latches only through the new rule's gate, so the replaced peer
  and an off-path source carrying the new stream's SSRC both stay out. A reinstall that names the same
  destination (a hold or refresh re-INVITE), or a first destination after an unanswered offer, is not a
  move, so a NATed peer's learned source survives it. An ICE endpoint is exempt: its latch is the
  check-validated path, which only a connectivity check moves (layer 4). The XDP backend has no stale
  state to drop: `install_flow` writes a freshly built kernel action whose latch is empty, and the
  kernel re-learns through the new gate.
- **Effect on A1:** even inside the learning window, a hijack must reproduce the victim's live SSRC,
  which the blind attacker does not know.

### Layer 4 — ICE supersedes blind latching where offered
When SDP carries ICE, **connectivity checks replace latching** as the address-learning mechanism.

> **Status (responder landed):** the **STUN codec** (`siphon-rtp-stun` — pure Rust, hand-rolled
> SHA-1 / HMAC / CRC-32, validated against the SHA-1, HMAC (RFC 2202), and CRC-32 known-answer
> vectors) **plus the datapath connectivity-check responder**: on an ICE endpoint
> (`Datapath::set_ice`), a STUN Binding check whose `USERNAME` addresses us and whose
> `MESSAGE-INTEGRITY` verifies with our local password is answered with a signed Binding success
> response, and the source of a check that carries **USE-CANDIDATE** (a nomination, RFC 8445
> §7.3.1.5) becomes the media path (superseding blind latching); a plain check is answered but
> selects nothing, and a forged check is dropped. **Engine wiring (landed):** `sdp::parse`/`rewrite` carry ICE, `engine::ice`
> mints credentials from the OS CSPRNG, and at offer/answer the engine re-originates ICE as
> **ICE-lite** — advertising `a=ice-lite` + its own ufrag/pwd + a host candidate and calling
> `set_ice` on the ICE legs, which then answer checks and adopt the nominated source; end-to-end
> tested. **`a=ice-lite` is only ever advertised for a leg the lite responder serves**
> (RFC 8445 §5.1.1, RFC 8839 §5.3): under `--ice-full` the engine writes the same credentials and
> candidates without it, because a peer that reads `a=ice-lite` takes the controlling role against a
> "lite" engine (§6.1.1) and the full agent, controlling as the offerer, then contends with it for the
> role. The emitters take the fact as data (`IceAdvertisement::lite`, `WebrtcOffer::lite`) from
> `Engine::advertises_ice_lite`, and a full-agent seat the engine offered to controls
> (`arm_seat_ice`). **Consent freshness (RFC 7675) is now wired and runnable** — see the bullet below.
> **Candidate gathering (RFC 8445 §5.1.1) is wired**: the advertised candidate list is gathered per
> leg and per component rather than being one hardcoded host line — host always, plus a
> server-reflexive candidate per `--stun-server` that answers. **The full RFC 8445 agent is wired too**
> (`--ice-full`, off by default): checklists, connectivity checks, both roles with 487 conflict
> resolution, peer-reflexive discovery, and regular nomination — with media gated on the selected
> pair. **ICE restart (§9) and trickle-receive (RFC 8838) are wired**, and the **XDP kernel datapath
> now enforces the same layer-4 gate** as the userspace one (see the bullet below).
> **Relayed candidates are wired too** (a TURN *client*, `--turn-client`, which requires `--ice-full`
> because only the full agent's checklist knows which remote candidates need a permission, and an
> ICE-lite agent advertises host candidates only, RFC 8445 §2.5): the engine can act as a TURN client
> as well as a server, and a relayed candidate is advertised only when the allocation actually came up
> and the datapath can relay through it. Each allocation is refreshed for the life of the leg, gets a
> permission and channel for every remote candidate, and is deleted (Refresh with lifetime 0) when
> its endpoint is released. RTCP-port ICE under non-mux is wired.

- The peer proves reachability with a STUN Binding request authenticated by the negotiated
  `ice-ufrag`/`ice-pwd` (MESSAGE-INTEGRITY) — a challenge/response A1 cannot forge without the SDP it
  never saw. The **nominated** candidate pair, not "first packet wins" and not "the last check", becomes
  the path.
- **An ice-lite leg selects only the nominated pair** (RFC 8445 §7.3.1.5, §6.1.3.2). A lite agent
  answers every authenticated Binding request (§7.3) but a request moves the path only when it carries
  `USE-CANDIDATE`. A browser with several interfaces checks from every local address and nominates one;
  following each check sent the DTLS handshake and the seat egress to whichever address checked last,
  often one the engine cannot reach. When several pairs are nominated the highest pair priority wins
  (§8.1.1); a lite agent has one host candidate per component, so the request's `PRIORITY` orders them.
  A lower-priority later nomination never moves an established path, an equal-or-higher one may (RFC
  5245 aggressive nomination sets `USE-CANDIDATE` on every check, and keeps working). A peer that never
  nominates gets no path: nothing is forwarded to or accepted from it and the DTLS handshake stays
  held, which is strict per RFC and what every browser's controlling agent does. An ICE restart (new
  local credentials through `set_ice`) clears the stored nomination, so the new session's first
  nomination is taken whatever its priority, while the old path keeps carrying media until then (§9.3).
  **Enforcement:** `datapath::respond_to_stun_check` reads the attribute and returns the priority as
  `StunCheckOutcome::Respond { nomination }`, `datapath::nomination_supersedes` is the one ordering
  rule, `handle_stun` (UDP) and `IceDemux::classify` (XDP) are the only callers that move the latch
  or the adopted source, and both keep the per-endpoint nominated priority.
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
    send our own. The same line carries `ice2`, which RFC 8839 §4.2.1.5 requires of an RFC 8445 agent
    in every offer and answer.
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
    media follow it. Gated on any ICE leg, full agent or ice-lite: under ice-lite the selection is the
    peer's USE-CANDIDATE check, published through `Datapath::watch_ice_validated`. A leg without ICE
    is not gated, since no selection is coming and waiting would hang a working leg.
  - **The engine's own pipeline follows the selection too.** A call `answer_local` terminates itself
    (IVR, announcement, echo, voicemail) runs the agent on its one leg when the engine runs agents.
    Its pipeline starts with the layer-2 gate open (the datapath's layer-4 gate admits only the
    validated pair) and its egress **held**: comfort noise, prompts and echo go nowhere until the
    agent selects, then to the selected pair, never to the signalled `c=` (§12). The selection
    narrows the pipeline's own gate to the pair as well. Without `--ice-full` the answer strips ICE
    (RFC 8839 §5.1) instead of echoing the caller's credentials back with no agent behind them.
    Enforcement: `MediaCall::{with_egress_awaiting_ice, ice_selected}`, `SourcePosture::Ice`,
    `MediaRegistry::ice_selected` from the sweep's `Selected` arm.
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
  conference seat, a forwarding-room seat, a promoted transcode/record/echo call, a WebSocket takeover leg, the SRTP and DTLS
  bridges — receives its media as `FlowAction::Redirect`, and each re-enforces the **layer-2**
  signalled-source gate itself (Layers 5a–5d). That is not enough for an ICE endpoint, because an ICE
  leg deliberately runs layer 2 **open** (`SourceFilter::Any`): the signalled address is not the
  discriminator when a peer-reflexive check legitimately arrives from a transport the SDP never
  carried (RFC 8445 §7.3.1.3). On a `Forward` leg layer 4 takes over from layer 2 — so on a
  `Redirect` leg it must too, or an ICE endpoint ends up with *no* source gate at all. The
  `Redirect` arm therefore consults the identical verdict (`Inner::ice_gate`, the one definition both
  arms call, so the two paths cannot drift): an endpoint carrying ICE credentials hands the consumer
  only the source a nominating connectivity check selected — nothing before one has, nothing from another
  source after. Only the source is gated, never the packet class: a redirected endpoint is entitled
  to non-RTP (Layer 1), and STUN never reaches the arm at all because `recv_loop` (`Inner::receive`) routes it to the
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
    is forwarded only from the source ICE adopted, and nothing at all before a check has nominated
    one. Without this an ICE leg on XDP would blind-latch the first RTP sender through
    `LatchPolicy::Symmetric` — exactly the RTPbleed hole ICE exists to close. The same-SSRC re-latch
    escape hatch layer 3 grants a plain relay is absent here on purpose: only an authenticated check
    may move an ICE path.
  - The adopted source is written into the kernel flow by `Datapath::adopt_source` (full agent) or by
    the userspace ice-lite responder on the datapath thread, and is **re-stamped on every flow
    install** — a rebuilt rule would otherwise drop the flag mid-call and quietly revert the leg to
    the signalled-source gate. It is also published per endpoint (`Datapath::watch_ice_validated`) to a
    userspace consumer that owns a leg's egress, which is how the DTLS bridge learns where an ice-lite
    peer is.
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
  - **Both egress paths wrap.** `Datapath::send` and the `Forward` relay path share one framing
    decision, so media forwarded toward a peer behind the allocation never leaves unwrapped. A
    permitted peer with no channel yet (bind in flight or failed) is reached with a Send indication
    (RFC 8656 §11.1); the check costs one relaxed atomic load when no allocation is installed.
  - **Data indications are accepted only for a permitted peer** (RFC 8656 §11.4, §9): an indication
    from the server naming a peer the allocation holds no permission for is dropped, never attributed.
  - **A destination with no channel and no permission is sent directly and untouched** — that is
    what keeps the allocation's own requests (addressed to the server) and any peer reached over a
    host or server-reflexive candidate on the direct path.
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
  - **The client-to-server leg can be a TCP or TLS stream** (RFC 8656 §3.1; the leg to peers is UDP
    either way). The engine owns one connection per allocation. Its bytes are framed with the one
    shared `siphon_rtp_stun::turn::stream_frame_len` (ChannelData padded to four bytes, §12.5), and a
    framing desync closes the connection. A `turns:` server is verified against the hostname in its
    URI with the public web roots, or only against `--turn-client-ca-file` when that is set; there is
    no option to skip verification, and `turns:` with `transport=udp` (DTLS) is refused rather than
    downgraded. Inbound ChannelData and Data indications reach the datapath through
    `Datapath::ingest_relayed`, which unwraps them against the installed `TurnRelay` (unbound
    channels and unpermitted peers dropped) and then runs the same ICE gate, source gate, latch and
    flows as a datagram off the socket; egress is queued on a bounded stream queue that sheds on
    full. A losing server's connection never delivers relayed data (the relay is not active for it).
    The end of the stream, or a write error, fails the allocation and clears the relay.
  - **Enforcement:** `siphon-rtp-stun/src/turn_client.rs` (the pure allocation state machine),
    `Engine::gather_relayed_candidate` + `Engine::drive_turn_allocations` (its I/O, in
    `engine/turn_gather.rs` and `engine/turn_stream.rs`), `set_turn_relay` and the relay seam in
    `udp_relay.rs`.
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
    consent checks, only responds to them, and `a=ice-lite` is what the engine advertises without
    `--ice-full`. Initiating them while claiming lite is a deviation, so it is an operator opt-in;
    under `--ice-full` the legs no longer claim lite.
  - **Backend support.** Both datapaths implement the seam — the UDP one in its `recv_loop` (`Inner::receive`), the XDP
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
  differ from the current ones is a restart (§9.1.1.1): the engine mints fresh credentials of its own
  and rebuilds the **re-offering party's** leg agent against the new session — while **leaving the
  adopted source untouched**, so under the layer-4 gate media keeps flowing on the previously selected
  pair until the new session selects one (§9.3). Clearing it instead would silence every call for the
  length of a fresh ICE exchange. Either party may re-offer (resolved by tag: the call's `from_tag` is
  A, its `to_tag` B); the SDP returned presents the *other* party's leg with the candidates that leg
  already advertised (layer 2, "A re-offer presents the leg facing its recipient"). A re-offer from B
  is completed by A's answer, which arrives with the tags reversed and is accepted only while that
  re-offer is outstanding. Owner-only; a re-offer that changes the negotiated codec is *rejected*
  rather than accepted-and-ignored, because rebuilding a live transcode pipeline is not done here —
  and so is a re-offer from B that drops the far leg's SRTP keying (layer 5), which would otherwise
  have to be bridged in the clear. The engine's credentials are one set for both legs, so a restart
  on one leg re-presents the other with the new set too (per-leg credentials are a known follow-up).
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
- **A repeated `answer_local` on a live call-id is owner-only, and never replaces a two-party
  call.** Another client gets `unknown_call` and the call is untouched (A3, §5). A call with a far leg
  (a relay, or an offer awaiting its answer) is refused with `answer_local: call-has-a-far-leg`: this
  verb writes a single-leg call, so replacing a relay would cut the far party off mid-call. For the
  owner's own single-leg call (the in-dialog re-offer on an IVR or controller-anchored leg) the
  answer replaces it the same way a repeated `offer` does, torn down through the `delete` path, but
  only after the replacement has validated and bound its ports, so a refused re-answer leaves the live
  call alone. The replacement is admitted at a full quota, since it adds no session. Previously the
  registry entry was overwritten whatever it held, orphaning the old call's ports, endpoint index and
  flows and counting its quota slot twice.

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
>
> **A DTLS-SRTP offerer is terminated on the two-party relay** (`PipelineKind::DtlsOfferer`) when its
> offer asks for a plaintext far leg (`dtls: off`, or a transport without `SAVP`). It is the same
> `DtlsBridge` with the sides swapped: the secure endpoint faces the caller, the plain one the callee,
> and the callee's separate RTCP port rides the plain side. Because the caller multiplexes, the callee
> is offered `a=rtcp-mux` with a separate RTCP port bound beside it (RFC 5761 §5.1.1): the first answer
> keeps that port when the callee declines multiplexing (`Call.far_rtcp_fallback` marks it until then)
> and frees it when the callee multiplexes. The port is gated like any plain RTCP endpoint, from the
> callee's answered `a=rtcp` or RTP port + 1. The caller's `a=fingerprint`, `a=setup`
> and `a=tls-id` are kept on the call from the offer (`Call.near_dtls`) and never presented to the
> callee; the answer settles the engine's role (RFC 4145 §4.1) and its own `a=tls-id` (RFC 8842 §5.3)
> and records them for a renegotiation. Both bridge endpoints re-enforce `bridge_source_filter` before
> any crypto, exactly as on the far-leg bridge, except that an ICE-gated caller's endpoint runs that
> filter open and leaves the discrimination to the datapath's layer-4 gate (see the source gate below).
> The handshake, and the records and SRTP toward the caller, go to the pair ICE selected (nominated) rather than
> to the caller's `c=`. A DTLS far leg (a second association), a caller that does not multiplex
> RTCP, and a call that needs the decoded audio are refused (`secure-offerer-unsupported`), and a
> caller with no `a=fingerprint` is refused as unkeyable, rather than any of them being relayed in
> the clear. A renegotiation from either party restates the caller's keying on `Call.near_dtls`: the
> same fingerprint and `a=tls-id` keep the running association and its roles (RFC 8842 §5.5), a changed
> one is a new association the bridge handshakes afresh (RFC 8842 §3.1), and a re-offer or answer from
> the caller without a fingerprint is refused. Neither the offer, the answer nor either direction of a
> renegotiation ever presents the caller's keying to the callee.
>
> **Both parties on SDES is a transcrypt bridge** (`PipelineKind::SrtpTranscrypt`), which is what two
> SRTP-only desk phones calling each other negotiate. The engine is the cryptographic far side of
> *each*: it minted its own key toward A and its own toward B, so it holds two `SecureLeg`s — four
> SRTP/SRTCP contexts — and every datagram is `unprotect`ed under the sending party's key and
> `protect`ed under the receiving party's. **Neither party's key is ever presented to the other**,
> which is the same property the one-sided bridge has and the reason passing the offerer's `a=crypto`
> through was a defect rather than a shortcut.
>
> It is a *crypto* bridge, not a transcode: the payload is never decoded, so any codec crosses,
> including ones the engine has no decoder for, and the cost is one decrypt plus one encrypt
> (~507 ns per packet on the reference box, against ~261/~266 ns for a one-sided leg — exactly the
> sum, the intermediate never being copied anywhere else). Each flow names *which party's* leg sits
> on each side (`BridgeFlowPlan::ingress_leg` / `egress_leg`) rather than deriving it from a crypto
> op, because on a transcrypt the direction no longer implies the key. A flow naming a leg its call
> plan does not carry installs **nothing** for the whole call and logs an `error!`: an unkeyed side
> would either relay one party's ciphertext onward verbatim or put the other's plaintext on a wire
> that negotiated encryption, and a partially installed bridge is worse than an absent one.
>
> Two consequences worth stating. **Interception** (Layer 5g / `engine/src/engine/intercept.rs`) taps
> the plaintext *between* the two transforms, which on a transcrypt is the only plaintext the call
> ever has — both sides of the wire are ciphertext under different keys, so without that tap a
> secure-to-secure call would be uninterceptable. And **HA `checkpoint` refuses a transcrypt call**:
> `SecureSnapshot` carries one peer key, one rollover and a one-sided crypto op per flow, all of
> which a two-legged call has two of, so replicating it would restore a far-secure bridge with the
> caller silently demoted to plaintext. The call keeps running; only replication is unavailable.
> A renegotiation reads **both** rollovers (RFC 3711 §3.3.1) from A's RTP endpoint, whose one flow
> faces A on ingress and B on egress and so names both parties — seeding two legs from one snapshot
> would cross-seed one party's counters into the other's, which authenticates for a while and then
> stops.
>
> **An SDES-SRTP offerer toward a *DTLS* far leg is refused on the `offer`, not the `answer`**
> (`engine/src/engine/offer.rs`, `offer_security`), and stays refused: bridging SDES to DTLS is two
> keying *mechanisms* rather than two keys. Where it is decided is part of the posture rather than an
> ergonomic detail. `Call.far_dtls` is settled from the **offer's** own `transport_protocol` and
> merely read back at the answer, so the predicate an answer would test is already true when the
> offer is handled. Deciding it at the answer meant the engine handed out an SDP, the callee rang and
> picked up, and only then was the call torn down — a refusal that arrives after both parties are in
> conversation is worse than the same refusal before either is disturbed, and it tempts a controller
> into passing the media through unanchored to make the symptom go away. The answer's
> `settle_secure_offerer` keeps the cases only the answer can know: the two legs' codecs differing, a
> decode-forcing flag (`record_call`, `noise_suppression`, `echo_cancellation`, `beep_detection`)
> first named on the answer profile, and a renegotiation that changes the posture.
>
> **An SDES caller toward a plain callee is transcoded too** (`PipelineKind::SrtpOffererMedia`):
> `MediaCall::with_near_secure_leg` puts the caller's leg on the A→B ingress and the B→A egress, and
> the callee's side is plaintext — the mirror of `with_far_secure_leg`. The caller never receives a
> packet in the clear, and its key is never presented to the callee, exactly as on the offerer
> bridge. **A DTLS caller in the same position is transcoded as well** (`PipelineKind::
> DtlsOffererMedia`): the bridge keeps A's endpoint for the RFC 7983 demux and the handshake, and
> keys the actor through `KeyedParty::Caller` (`MediaCall::attach_caller_secure_leg`, the same two
> directions). Both directions start pending (`with_caller_secure_pending`), so nothing from A is
> decoded and nothing reaches A in the clear before the handshake completes.
>
> **A secure pair that asks for any of those is transcoded, not refused** (`PipelineKind::
> SrtpTranscryptMedia`). No crypto *bridge* yields decoded audio, but the media pipeline does, and it
> can hold the same two legs: `MediaCall::with_both_secure_legs` puts A's leg on the A→B ingress and
> the B→A egress and B's leg on the mirror image, so each direction decrypts under the party it faces
> and encrypts under the party it forwards to. The security posture is identical to the bridge's —
> the engine is the cryptographic far side of both parties and neither key is ever presented to the
> other — and what changes is only where the intermediate plaintext goes: to the pipeline, which is
> the point, since that is what a recording, a prompt, the DSP and a codec change attach to.
> Consequently **interception taps this shape in the pipeline, not on the bridge** (a tap installed on
> a bridge the call does not have would deliver nothing), and **`checkpoint` refuses it** for the same
> reason it refuses the bridge form: two secure legs, one snapshot record. A renegotiation reads both
> parties' rollovers (`MediaRegistry::rollover_snapshot` and `::near_rollover_snapshot`) for the same
> reason the bridge does — seeding one and restarting the other leaves that party's ROC at 0 on every
> re-INVITE, which its peer cannot verify (RFC 3711 §3.3.1).
>
> **A DTLS-SRTP caller toward an SDES-SRTP callee is a transcrypt between a handshake and a key**
> (`PipelineKind::DtlsOffererTranscrypt`, and `DtlsOffererTranscryptMedia` when the call needs the
> decoded audio). A browser (RFC 5764, `UDP/TLS/RTP/SAVPF`) calling a desk phone that must stay on
> `RTP/SAVP` (RFC 4568) is asked for with `transport_protocol: RTP/SAVP` on the offer. The engine is
> the caller's DTLS peer exactly as for a plain callee, and the callee's SDES peer: it offers the
> callee its **own** `a=crypto` (minted at the offer, never the caller's keying, which has none to
> give) and answers the caller with its own fingerprint, so neither party's keying reaches the other.
> The bridge's plain side carries the callee's `SecureLeg` (`DtlsBridge::set_plain_leg`, installed
> after `register` and before the endpoints are redirected): what the caller sends is unprotected
> under the handshake's keys and protected under the callee's key (RFC 3711 §3.1, §3.4), and the
> reverse, both through the bridge's own scratch buffers, so the second transform allocates nothing.
> The plaintext between the two transforms is the only plaintext the call has, and it is what an X3
> tap, a tee or a recording reads. Every refusal the bridge makes on a plain peer holds here: nothing
> crosses in either direction until the handshake has keyed the caller (never plaintext, and never
> SDES-protected media toward an unkeyed caller), a callee packet that fails SRTP authentication or
> replay (RFC 3711 §3.3.2) is dropped before the DTLS protect and counted as a failed unprotect, and
> both endpoints re-enforce `bridge_source_filter` before any crypto. The callee's separate RTCP
> port, when it declines `a=rtcp-mux`, rides the plain side as SRTCP under the callee's key
> (RFC 5761 §5.1.1). A renegotiation keeps the DTLS association as before (RFC 8842 §5.5), and keeps
> the callee's SDES leg across it: an answer that repeats the callee's keys keeps the live leg and its
> send window, a changed key is replaced in place with the stream's rollover carried over (RFC 3711
> §3.3.1, §9.1), and a changed fingerprint runs a new handshake under the same SDES leg. The transcode
> twin holds the callee's leg in the media actor from the start and the caller's once the handshake
> delivers it; both directions are pending until then, and the callee's separate RTCP port is relayed
> by the actor (callee's SRTCP opened and sealed for the caller, caller's multiplexed RTCP sent to
> the port). **Bundled video is declined** on such a call (audio only), a **hold or split** and a
> **conference seat** are refused with `secure-transcrypt-hold-unsupported` and
> `secure-transcrypt-seat-unsupported` until the bridge can move both keyings, and `checkpoint`
> refuses it like every DTLS kind. A re-answer that would move a live call between the bridge and its
> transcode twin (say, `noise_suppression` named on the answer) is refused before anything changes with
> `secure-transcrypt-renegotiation-unsupported`: the kept association's flows and the callee's SDES leg
> cannot yet move together. What is still refused is a DTLS caller toward a DTLS callee (two
> associations) and an SDES caller toward a DTLS callee, which needs the mirror of this bridge; both
> are `secure-offerer-unsupported`.

- **Source gate on the bridge path (RTPBleed, restated for `Redirect`).** The SRTP bridge runs on the
  `FlowAction::Redirect` slow path, which **bypasses** the datapath's Forward-path layer-2 gate. The
  bridge therefore **re-enforces** the signalled-source gate itself (`bridge_source_filter`, the same
  `Exact`/`Subnet`/`Any` policy as `ingress_rule`) before any crypto — an off-path spray is dropped at
  the bridge, not decrypted. **On an ICE-gated DTLS leg the filter on the secure endpoint is
  `SourceFilter::Any`**, as on an ICE conference seat (Layer 5c): the peer's checks, records and media
  legitimately come from a transport the SDP never carried (RFC 8445 §7.3.1.3), and the datapath's
  layer-4 gate on the redirected path already admits only the source a MESSAGE-INTEGRITY-authenticated
  check adopted, so an address gate as well would drop a NATed peer's handshake. Which posture applies
  is read from the datapath (`Datapath::watch_ice_validated` is `Some` only for an endpoint carrying ICE
  credentials), never from the SDP, so a leg whose ICE the answer cleared (a non-ICE or
  `a=ice-mismatch` peer, `ice: remove`) keeps its signalled-source gate. SRTP auth (HMAC-SHA1-80) is
  the second line: a forged packet from the
  gated address still fails authentication and is dropped (the rollover counter advances only after
  auth succeeds). **Anti-replay is the third line** (RFC 3711 §3.3.2, enforced in
  `SrtpContext::unprotect` / `SrtcpContext::unprotect`): a per-SSRC 64-packet sliding window over the
  SRTP packet index — and over the explicit SRTCP index — rejects a duplicated or too-old packet, so a
  captured but still-valid packet re-injected by an on-path attacker is dropped as a replay rather than
  re-forwarded. The window is recorded only *after* authentication, so a forged packet can never
  advance or poison it; on an HA takeover the standby anchors the window at the checkpointed rollover
  index and keeps rejecting the primary's last-seen packet.
- **An ICE DTLS leg keys the path ICE selected** (RFC 8445 §12, §12.1.1; `DtlsCallPlan::gate_on_ice`).
  The handshake is held until ICE has chosen the peer's transport: a full agent's selection, or on the
  ICE-lite responder the source of the check that nominates a pair (`USE-CANDIDATE`). The datapath publishes that source
  per endpoint (`Datapath::watch_ice_validated`), from the same writes that set the adopted source:
  `handle_stun` and `adopt_source` on UDP, `IceDemux` and `adopt_source` on XDP. The bridge follows it
  for the life of the association, so records and SRTP never go to a NATed peer's unusable `c=`, and a
  later equal-or-higher-priority nomination re-points them. A backend without the seam starts at the signalled address as
  before, since nothing would release the wait. Proven by
  `a_full_ice_dtls_offerer_is_keyed_on_the_pair_ice_selected_not_its_connection_address` and
  `an_ice_lite_dtls_offerer_is_keyed_on_the_source_its_check_validated`.
- **A plain peer's separate RTCP port on the DTLS bridge.** When the plain party does not multiplex
  RTCP (RFC 5761 §5.1.1), its RTCP endpoint is redirected into the DTLS bridge as a third flow and
  gated exactly like its RTP endpoint, to the plain party's signalled RTCP source
  (`bridge_source_filter`). That flow relays RTCP only: anything the RFC 5761 §4 packet-type demux
  does not classify as RTCP is dropped before the crypto, so the port cannot carry RTP toward the DTLS
  peer. SRTCP from the DTLS peer reaches that port only after the same gate, key and authentication as
  SRTP. The DTLS leg itself always multiplexes: RFC 5764 §4.1 keys each component with its own
  association, and WebRTC requires multiplexing.
- **Idle reap.** A packet that clears the gate *and* the crypto stamps the endpoint's activity
  (`Datapath::note_activity`); one that fails either does **not**, so neither an off-path spray nor a
  forged packet can hold a dead call open. This has to be done by the bridge itself, and the reason is
  worth stating because it is easy to assume otherwise: the `Redirect` arm never touches `last_seen`,
  and **both** legs of a bridged call are `Redirect`, so there is no `Forward` rule stamping anywhere
  on the call. Without it the Layer 6 sweep reaps a secure bridge at the media timeout however much
  audio is crossing it. The same applies to the DTLS bridge's two relaying directions; its
  `Pipeline`-mode media is stamped by the per-call actor it is handed to.
- **Key direction (the footgun `SecureLeg` pins down).** Outbound (engine→peer) encrypts with the
  engine's *own* offered key (the `a=crypto` it advertised); inbound (peer→engine) decrypts with the
  *peer's* answered key. The peer's `a=crypto` is always re-originated (dropped and replaced), like
  ICE — a secure leg's key never leaks onto the plaintext leg's rewritten SDP.
- **Which offered line is accepted, and how the answer names it.** An offerer may list several
  `a=crypto` lines. The engine accepts the first one it can key: lines in a suite the SRTP context does
  not run (AEAD, 256-bit, and `_32`, since the context authenticates with the 80-bit tag only) are
  dropped at SDP parse (RFC 4568 §7.1.1), so the inbound context is always keyed from the accepted line.
  The engine's own key is then answered under **that line's tag and suite** (RFC 4568 §5.1.2), at every
  answerer: the offer/answer bridge (audio and text), `answer_local`, and a conference seat (audio and
  text). Numbering the answer from one is a silent one-way-audio bug: an offerer whose first line is a
  suite the engine skipped reads tag 1 as "my first line was accepted", encrypts under that context,
  and every one of its packets fails authentication without appearing as a drop anywhere.
- **A renegotiation keeps the crypto, and keeps it continuous.** Completing an offer/answer on a live
  call re-runs the answer path, which rebuilds the leg's wiring; two things have to survive that, and
  both are enforced rather than left to chance. A **DTLS association** is kept and re-pointed (each
  side's gate, the plain peer's address, and the DTLS peer's: the signalled one on a non-ICE leg, and on
  an ICE leg the validated source of the ICE session the renegotiation settled on, including one it has
  just added, since no handshake runs to move it) whenever the peer's
  fingerprint and the engine's role are unchanged: RFC 8842 §5.5 has the peer keep its own association
  in exactly that case, so tearing ours down leaves the leg waiting for a handshake that never comes.
  A change to either **is** a new association (§3.1) and re-handshakes. The **SRTP rollover** is
  carried into every rebuilt leg (RFC 3711 §3.3.1): the counter is estimated per stream rather than
  derived from the key, so restarting it at 0 while the peer keeps counting fails authentication on
  everything after the first sequence wrap — about 21 minutes of a 20 ms-ptime call. That holds on the
  SDES bridge, the secure transcode actor and both legs of a secure text stream, and across a re-key,
  which does not restart the stream's packet index either. Neither carry-over widens what the engine
  accepts: the gate and SRTP authentication are unchanged, and a kept association is still bound to
  the certificate it authenticated.
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
| DTLS | the leg's **session driver** (`dtls_session.rs`) — one task per leg, not two |
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
- **The association outlives its handshake, because RFC 6347 §4.2.4 requires it.** The sender of the
  last flight cannot know it arrived, so when the peer repeats its own final flight, ours has to be
  sent again. The previous stack could not: its handshake future returned at completion and took with
  it the only thing that could have re-sent that flight, so a lost flight 6 left a DTLS **server**
  keyed while the peer retransmitted until it gave up — a call that is up, carries no media, and logs
  nothing. The leg's driver now holds the association for 60 s after keying, restarted whenever a
  repeat is answered, and post-handshake records still reach it. Answers are limited to one flight per
  200 ms per leg. That limit is a CPU guard, **not** an anti-amplification one: the source is already
  gated twice (Layer 4, then the bridge's own `accepted_source`) and our last flight is *smaller* than
  the certificate-bearing flight that triggers it, so the factor is below one. It sits on the response
  side rather than on intake, because throttling intake would starve the retransmission we owe.
- **One association, whatever the source.** The driver addresses its association by a fixed internal
  key rather than by the peer's address, so an ICE re-point moves where records are *sent* without
  starting a second handshake — and a second handshake is exactly what a silent, healthy-looking call
  is made of. Feeding it a moved-but-already-gated source is safe because the record MAC and epoch
  authenticate the records themselves; the corollary is that the source gate and the RFC 7983 demux
  must run **before** the driver sees a datagram, which is where the bridge applies them.
- **Completion keys once.** Answering a retransmitted last flight can report completion a second time.
  Re-deriving would install fresh SRTP contexts and restart their rollover counters mid-call
  (RFC 3711 §3.3.1), so the session keys exactly once and any later completion is ignored.
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
  - **An ice-lite seat's egress follows the nominated source too** (RFC 8445 §12.1.1: data goes to the
    valid pair's remote candidate; §7.3.1.5: only a `USE-CANDIDATE` check selects it). It has no agent to call `ice_selected`, so the daemon subscribes to
    `Datapath::watch_ice_validated` when it seats the participant and hands the room the same
    `ConferenceControl::IceSelected` a full agent's selection would — re-pointing `egress_dst` and
    narrowing the gate to the validated transport. Before that the room aimed the mix at the signalled
    `c=` until the seat's own first packet moved the reply latch, so a seat that listens before it
    talks (a webinar attendee, a muted participant) heard nothing at all while its mix went to an
    address that never asked for it. The follower is aborted on every path that drops the seat —
    `conference_leave`, a failed checklist, and the idle reap — so it never outlives it. Proven by
    `an_ice_lite_conference_seat_is_sent_the_mix_at_the_source_its_check_validated`.
  - **A live call's leg seated in place (`conference_seat`) keeps the gate it already had.** The
    seat is taken **pending** (`secure_pending`), so the room neither mixes nor sends while the call's
    previous owner — the in-kernel `Forward` rule, the SRTP/DTLS bridge, or the media actor — is still
    carrying it. Once that owner has stopped, `ConferenceControl::Activate` hands the room the gate
    that owner had **in force** (the `Forward` rule's `accepted_source`, the bridge flow's, or the
    actor's per-direction gate as an ICE selection may have narrowed it), the destination it had
    latched, and the leg's own `SecureLeg` with its rollover and replay state (RFC 3711 §3.3.1). Only
    then is the endpoint routed to the room. The gate is never re-derived from the signalling and
    never widened by the move, the room's symmetric latch starts afresh, and two owners never send
    toward the party at once. A DTLS leg's association stays with its bridge, now feeding the room,
    so the handshake is not repeated. A call whose SRTP the engine relays end to end without a key
    is refused rather than mixed as ciphertext.
  - **A seat the room dials out gets the same gate from the answer.** `conference_offer` allocates the
    endpoint but installs no redirect and seats nothing, so a datagram reaching it before the answer
    enters no room. `conference_answer` then seats the participant through the same
    `Engine::seat_participant` a join uses, with the gate built from the **answer's** `c=`/`m=`
    (`SourceFilter::Exact`, or `Any` only for an offer whose profile carried `symmetric`) and the same
    constrained latch. An offered seat is never ICE or SRTP (the verb refuses a profile asking for
    either), so the plain RTPBleed gate is the whole of its layer 2.
  - **A failed checklist removes the seat** (§8.1.2). A participant has no `MediaCall` for the
    2-party `ice_failed` teardown to reap, so `drive_ice_agents` drops it from the room (and tears the
    room down if it was the last member) rather than leaving it seated behind a gate that can never
    open.
  - **A DTLS-SRTP seat holds its handshake for ICE** (RFC 8445 §12, §12.1.1, `gate_on_ice`): a full
    agent's selection, or on an ice-lite seat the source of the check that nominated a pair, both
    published through `Datapath::watch_ice_validated`, and the handshake records follow that source. A
    seat without ICE starts at once, since nothing would release the wait. A secure WS takeover runs
    ICE only under a full agent, so its handshake always waits for the selection. Proven by
    `an_ice_lite_dtls_conference_seat_is_keyed_on_the_source_its_check_validated`.
  - **Dropping a seat retires its bridge registration.** A DTLS seat registers a bridge flow when it
    joins, carrying its association, its destination watch and the tasks driving its handshake. Call
    teardown reaches those through `finish_call`, but a seat can be dropped while the room lives on —
    `conference_leave`, a failed checklist, the idle reap — and those paths freed the datapath endpoint
    and stopped the ICE follower while leaving the bridge registration behind, so a seat's handshake
    and drain tasks outlived the participant and the room accumulated them. Each of those paths now
    also retires the endpoint from the bridge, beside the follower it already stopped. Proven by
    `a_conference_leave_retires_the_seats_dtls_bridge` and
    `reaping_an_idle_conference_seat_retires_its_dtls_bridge`.

### Layer 5d-ii — Holding a crypto-bridged call in the decoding actor, and releasing it

> **Status (landed — `PromotionReason::WsSplit`, no control verb yet):** a call on a crypto bridge
> (`Srtp`, `SrtpOfferer`, `SrtpTranscrypt`, `Dtls`, `DtlsOfferer`; not yet `DtlsOffererTranscrypt`,
> which is refused with `secure-transcrypt-hold-unsupported`) can be moved at runtime into the
> decoding `MediaCall` actor and moved back, **with no re-INVITE and no rebuilt crypto state**. It is
> the foundation a split bridge (both legs to one stereo stream) stands on; this change adds no wire
> verb, only the engine's `hold_in_userspace(WsSplit, Processing)` and `release_userspace_hold`.
> Code: `engine/promote/secure_hold.rs`, `srtp_bridge/hold.rs`, `dtls_bridge/hold.rs`,
> `media_pipeline/secure_hold.rs`, `egress_track.rs`.

A bridge relays ciphertext it never decodes, so nothing that needs the audio can attach to such a call.
Holding moves the two legs' media into an actor that decodes it. What changes owner, and what must not:

| What | On hold | On release |
|---|---|---|
| The `SecureLeg`s (master key, per-SSRC rollover, replay window, SRTCP index) | the **same objects** go to the actor (SDES: the bridge flows' shared handles; DTLS: the leg moves out of the relaying flow, the bridge keeping a retained copy for a renegotiation) | the same objects go back (`surrender` hands them over, the flows are rebuilt around them) |
| The DTLS association (handshake driver, retransmission answers, ICE destination watch) | never leaves the bridge; the secure flow becomes a *pipeline flow*, which keeps the RFC 7983 demux and hands media on still encrypted | the flow turns back into the relaying flow |
| Each party's egress RTP stream | the actor continues the **SSRC** the bridge was sending, with `sequence + 1` and a timestamp advanced by the elapsed clock in whole frames (RFC 3550 §5.1) | the rebuilt flow numbers the peer's stream so it continues the actor's, by a constant sequence/timestamp offset for the rest of the call |
| The taps a flow carried (X3, a tee's or a recording's plaintext tap) | the same senders move to the actor's direction | and back |

**Why continuity, and not a new SSRC.** On an SRTP leg the receiver estimates the rollover counter
from the sequence numbers of one SSRC (RFC 3711 §3.3.1). Continuing the SSRC with a contiguous sequence
keeps that estimate right; a restarted sequence under the same SSRC would make every packet past it
fail authentication at the receiver. A *different* SSRC is legitimate (RFC 3550 §8.2) and is what the
plain `Passthrough` relay does, because a kernel `Forward` cannot renumber a stream: its actor sends
under a fresh SSRC and the release returns the carrier's own, verbatim. The bridge flows record the
position of what they forward (`EgressTrack`: one short mutex per packet, no allocation, proven by
`tests/egress_track_zero_alloc.rs`) and are **sealed** when the hold takes them: a packet a flow had
already begun forwarding is either recorded (and so included in the position the actor continues from)
or refused, never sent twice. The offset applies only to the SSRC the actor was sending; any other SSRC
is a new source and numbers itself.

**No handler-less window (§4 layer 2), in either direction.** On hold the actor is registered **first**,
inert (both directions gated until it has the final stream position, so it cannot emit under the
wrong SSRC), and only then do the flows let go. On release it is mirrored: the bridge's flows are
registered **first**, refusing everything (`EgressTrack::awaiting`) until they know where each stream
stands; the dispatcher checks the bridge before the media registry, so the endpoints are never
ownerless. Only then is the actor stopped, its final positions, gates, destinations and taps read, and
the flows told, which starts them. If the actor cannot report (a wedged mailbox), the flows start under a
**fresh random SSRC** per peer stream (peer sequence and timestamp kept) rather than leave the call
without a media path: the actor sends on a clock of its own, so under the old SSRC it may be past the
peer's numbering and resuming that numbering could reuse an SRTP index. A new SSRC is a new SRTP
context at ROC 0 on both ends (RFC 3711 §3.2.1, §3.3.1) and a legitimate change (RFC 3550 §8.2). A DTLS key is taken out of its shared handle by swapping, never by unwrapping the
`Arc`, so a straggling holder cannot make the release fail.

**No index is ever used twice (RFC 3711 §3.3.1, §9.1) — by construction.** The sender context of every
`SecureLeg` (`siphon-rtp-srtp`) keeps, per SSRC, the highest index it sent and a 64-wide bitmap below
it (the §3.3.2 replay list applied outbound), and `protect` refuses with `SrtpError::IndexReused`
anything already sent or older than the window; a reordered packet whose index was never sent still
goes. It also refuses (`SequenceJump`, nothing recorded) a sequence number that a receiver would place
in a rollover that never was: at rollover counter 0 an estimate below 0 would wrap to 2^32-1 and anchor
the window there for good. It is one fixed-size record per SSRC (allocated when the SSRC first
appears), it lives in the one leg every owner shares, and so it survives hold, release and re-offer
without anyone cooperating. A re-offer that changes only the peer's key keeps the leg and its send
window (`SecureLeg::rekey` replaces only the side whose key changed, carrying that side's counters). The
SRTCP index never wraps either: used up (2^31), `protect` refuses (`IndexExhausted`) until a new key
(§3.4, §9.2). Refusals are counted (`SecureLeg::reuse_refusals`) and logged at `error!` with their
context. It is the safety net, never the way a stream is meant to behave: **a refusal must not become
an outage**, so each flow that feeds an SRTP leg also numbers its stream correctly.

- A flow records the **high-water** mark of each of its last eight SSRCs, committed only once the
  packet was protected (a refused packet leaves no mark, and the stream that advanced least recently is
  the one given up), keeps the position it was to resume until **its own** SSRC shows up, and after a
  release refuses any packet of the continued SSRC from before the first it took over.
- A **discontinuity** in what a plain peer sends (its sequence jumps back beyond reordering, or forward
  by half the space or more, which a receiver reads as a jump back: a restart after a re-INVITE to
  another media server, an SSRC reused after a gap) is renumbered: the flow carries on from its own
  high-water mark + 1 with a timestamp moved on by the quiet in whole frames, for that stream epoch. A
  translator may renumber a stream (RFC 3550 §7.1, §8.2). Normal loss and reordering keep the peer's
  numbering verbatim, and the no-discontinuity path allocates nothing.
- The record and the offset follow the flow across a re-registration for as long as its key is
  unchanged.
- **The SRTP sender is the authority on where a stream stands.** A stream the flow is not following
  (its epoch given up, a restart renumbered earlier, a leg restored with its window closed) whose first
  packet is at or below what the leg has sent under that SSRC is renumbered from the leg's position at
  once, not from the peer's numbering, so a peer resuming below a restored mark is heard immediately; epochs that renumber are the last to be given up; and a packet
  the sender refuses as a reused index or an unplaceable jump, far from where it stands, renumbers the
  stream from the sender's position (a duplicate inside the send window is the window's to refuse).
  The timestamp step is learned only from consecutive packets less than a second apart and may change
  by a few frames at a time, so a suppressed silence is never mistaken for a frame.
- **A renegotiation that repeats a key keeps the live leg** (a key is its master key and salt: an MKI
  that alone changes only changes the MKI emitted; SDES audio, video, text, a decoded
  call's re-answer): only a side whose key changed is re-keyed, in place, so the send window survives.
  A leg that has to be rebuilt (an HA restore, a seat whose leg is still shared) closes every index at
  or below the restored mark, so nothing sent before may be sent again under the same key (RFC 3711
  §9.1).
- A NACK is answered with **the datagram that was sent**, from a bounded, preallocated per-receiver
  history keyed on the packet's extended index (rollover and sequence number, RFC 3711 §3.3.1)
  (RFC 4585 §6.2.1); a packet that has left it is not answered, and the history is emptied when the
  seat's key is replaced. The sender never encrypts a second time at an index it has used.

**The latch is carried, so a stranger does not win a race (RTPBleed).** On a symmetric plain leg
(`SourceFilter::Any`, no ICE) the learned source and SSRC are all that keep a stranger from becoming the
reply destination. The latch of each party's ingress moves with the call, bridge flow to actor on
hold, actor to bridge flow on release and actor to replacement on a re-offer carry. A bridge flow that
is registered awaiting its stream forwards nothing and learns nothing (checked before the latch), and
the actor starts gated, so no first-packet race exists in a hand-over. A latch is carried only while the
address the peer signalled is the same: a re-offer that moves the peer starts from the gate its new SDP
draws, as any re-offer does, so the moved peer is served and nothing is opened. Proven by
`a_stranger_who_sends_first_after_a_hold_or_a_release_meets_the_established_latch`.

**RTPBleed.** The actor re-enforces exactly the gate the flow carried (the signalled source, or open on
an ICE leg whose gate the datapath's layer 4 owns, narrowed to the selected pair by `IceSelected`), and
latches symmetrically only on an authenticated packet. A stranger is dropped while held as it is on the
bridge (`secure_hold::*` tests send a valid-looking packet of another SSRC from another address while
held). Packets that arrive before the actor is keyed are dropped, never decoded as plaintext.

**Re-offer while held.** The answer keeps the actor's kind (`settle_held_pipeline`), so it rebuilds
the *actor* the way every transcoding call's re-answer does, but the old actor is **stopped first**
(`carry_held_actor`, right before the install) and its live `SecureLeg`s, final stream positions,
taps and plain-RTCP route go to the replacement: the same SDES leg objects when the keys did not
change (a new key gets a new leg that carries the old counters), the DTLS leg re-keying the replacement
from the bridge's retained handle. Snapshotting counters off a running actor and rebuilding would let
two contexts under one key number the same SRTCP index, and would restart the replay window. An install
that fails restores the old actor from what it left (`restore_held_actor`). A DTLS re-handshake (a
changed peer certificate, RFC 8842 §3.1) cannot be kept: the hold is released first, back onto the
bridge, and the answer then installs the new association the ordinary way, so there is never a
half-keyed leg. The release returns `HeldAnswer::ReleasedForRekey`, which a later change turns into an
event.

**Refusals.** `ws-split-seated`, `ws-split-answer-local`, `ws-split-already-bridged` (a WebSocket
takeover or a hold already on the call) and `ws-split-not-answered`; a DTLS leg that is not keyed yet,
or that carries bundled video (RFC 8843), is refused with its reason rather than half-moved. A
plain peer's separate RTCP port on a DTLS leg is carried while held: its RTCP goes out as SRTCP on the leg's key, and the DTLS peer's decrypted RTCP goes to that port. A re-offer takes that routing from its new answer, so a plain peer that moved its RTCP port is followed.


### Layer 5d-iii — The split bridge: two parties and a bot, nothing between them

`attach_ws_split` holds a call in the decoding actor (5d-ii) and plays each party a bot instead of
the other party. What it adds to the media path is an *isolation*, and the rule is that it fails
closed:

- **Isolation is a property of the direction, set before the direction is fed.** An isolated
  direction still goes through every ingress check (source gate, reply latch, SRTP authentication,
  replay window) and still decodes, which is what feeds the uplink to the bot, the recordings and
  the interception taps, but what it decoded is never encoded toward the other party
  (RFC 3550 §5.1: the party's egress stream is the engine's own, so nothing of the other party's
  audio is in it). DTMF telephone-events are detected and reported and not relayed.
- **A replacement actor starts isolated.** A re-offer, a promotion or a rebuild registers a new
  actor for the call; `MediaRegistry::mark_split` makes `register` begin every actor registered for
  a split call isolated and silent, before it takes a packet, and the split's queues are attached
  afterwards. There is no interval in which one party's audio reaches the other because the
  actor that carried the isolation was replaced.
- **Interception follows the wires.** The target's own voice is still the ingress tap (taken after
  the gate and the SRTP authentication, so a refused packet is never delivered). What the target
  *hears* is no longer the other party's ingress, which is isolated, so the `to_target` stream comes
  from the egress of the direction facing the target, on the plaintext just sent and only once the
  datagram is really going out. The switch rides the same per-direction state as the isolation, read
  by one actor at both tap sites, so a packet reaches the interception from exactly one of the two
  and the other party's original voice is never delivered as what the target heard.
- **The gate does not move.** The bot is not a media source: it has no flow, no endpoint and no
  address on the datapath, only a WebSocket the engine dialled. A stranger is refused by the same
  gate and latch as on a held call (layers 1 to 3; no RTPbleed: a split never latches to whatever
  sends first), and a stranger's packet reaches neither the other party nor the bot.
- **The playout is the engine's own egress.** What the bot sends is rendered on the actor's tick as
  the direction's egress stream, protected by the leg's own SRTP context (the sender refuses an
  `(SSRC, index)` it already sent, RFC 3711 §9.1), so a secure leg stays secure and the receiver
  sees one SSRC with contiguous sequence numbers across attach and detach.
- **Nothing but a detach lifts it, once the attach has succeeded.** Until then a refused or failed
  attach puts the previous path back (and, if the actor does not answer the undo, leaves the call
  isolated for a detach to clean up). After it, a bot that goes away, a re-offer the split cannot be
  re-attached to, a failure, a failover and a delete all leave the parties apart. The end is
  reported once (`ws_split_ended`) and the controller detaches; the engine never reconnects two
  people who were relying on an intermediary. A detach is confirmed by the actor before anything
  changes, and one the engine gave up on is never applied late: the split's generation moves on
  first, and the actor ignores a control issued under an earlier one.
- **A checkpoint carries it.** A snapshot of a split call has its own version and a
  `split_isolated` flag, and restores only onto the decoding actor, registered isolated and silent
  (an actor registered for a marked call always starts so); a standby that does not know splits
  refuses the version rather than reconnect the parties.
- **A delete lifts nothing.** The transport and the registry entry go; the actor keeps the parties
  apart until it stops, however long recordings and interception take to finish, and the mark is
  cleared once it has, so the call-id can be used again.
- **A DTLS re-handshake is refused while split.** A new certificate is a new association the actor
  does not have, and releasing the hold would put it on a bridge that relays one party to the
  other (RFC 8842 §3.1), so the answer fails and the call keeps its association and isolation.

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
  only remaining constraint is the reply latch, which drops a rejected source before it reaches the
  mix (Layer 3).
- **Constrained, SSRC-consistent latch (after auth).** An accepted participant's egress destination
  is latched to its observed source (symmetric RTP), so a NATed leg is replied to where its media
  originates — but only for an authenticated, SSRC-consistent stream: the latch is decided **after**
  the SRTP `unprotect` (`SymmetricLatch`, RFC 3550 §8), so a forged/auth-failing packet never reaches
  it, and a wrong-SSRC packet from a new source is dropped before it is mixed or counted as activity
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

### Layer 5c-ii: The forwarding room (push-to-talk) Redirect path
A forwarding room (`engine/src/forward/`, verbs `forward_join` / `forward_leave` /
`forward_set_source`) is a `FlowAction::Redirect` consumer with the **same** RTPBleed posture as the
conference seat, because it runs the same code: the per-seat ingress chain lives in
`engine/src/seat_gate.rs` and both `Conference::ingest` and `ForwardRoom::ingest` call it, so the two
cannot drift. The redirect dispatcher reaches it through the conference registry's slot
(`ConferenceRegistry::owns` / `dispatch` / `ice_selected` fall through to the forward registry), so
the routing order is unchanged: bridge → media → text → udptl → ws → conference (and forward) → TURN.

- **Same gates, same order.** Layer-2 signalled-source gate (exact source, or the `received-from`
  hint, or `Any` for an ICE or `symmetric` seat); a DTLS seat not yet keyed and a full-ICE seat not
  yet selected are refused (`secure_pending`, `ice_pending`); SRTP `unprotect` (RFC 3711 §3.3);
  the constrained SSRC-consistent latch (RFC 3550 §8). A refused datagram never reaches the translator
  and is not liveness. `forward_join` opens the seat's transport with the helper `conference_join`
  uses (`Engine::open_seat_transport`), so ICE, DTLS-SRTP and SDES seats are supported identically.
- **Never into the void, never in the clear.** A receiver is sent a packet only when it has a resolved
  destination, is keyed (DTLS) and has had its pair selected (ICE); a secure receiver gets SRTP under
  its own key, one `protect` per receiver. The source never receives its own audio.
- **RTCP is terminated.** A seat's RTCP is read (SR to LSR/DLSR, reception report blocks to RTT) and
  dropped, never relayed to the other seats (RFC 3550 §7.3: a translator rewrites reports, it does not
  echo them). The room sends each reachable seat its own SR every 5 s about the stream it is sent.
- **Liveness, not reaping.** Any accepted RTP or RTCP stamps the seat's endpoint; RTP from a seat that
  is not the source is dropped after the gate and counts in the endpoint's `packets_dropped` while
  still stamping liveness. A seat is never freed for silence (a listener sends nothing while others
  talk): the sweep raises `forward_seat_inactive` once per quiet spell
  (`ForwardRegistry::scan_inactive`) and the controller decides. It is freed by `forward_leave`, by a
  failed ICE checklist, and with its room.
- **Whole-room backstop.** A room in which *every* seat has received nothing at all (RTP, RTCP or floor
  packet, which is what the endpoint's activity stamp reads) for `--forward-room-idle-secs` (default
  3600, `0` off) is freed by `ForwardRegistry::reap_silent_rooms`: each seat's client gets a
  `media_timeout` (`no_media`), then the room and its endpoints go. Receivers send RTCP receiver reports
  (RFC 3550 §6.2), so a live group never trips it; seats pending their answer are not measured.
- **Dial-out seats** (`forward_offer` / `forward_answer`) are plain RTP/AVP with no ICE: the pending seat
  holds its endpoints outside the room, the answer's `c=` (or `received_from`) is the signalled-source
  gate, a `symmetric` profile opens it as on a join, and the Redirect flow is installed only when the
  answer is accepted. Every path out of the pending state frees its endpoints (answer, refusal,
  `forward_leave`, setup-timeout sweep). A dial-out seat whose profile asks for
  `transport_protocol: "UDP/TLS/RTP/SAVPF"` is the engine-offers form of the DTLS-SRTP join: the offer is
  ICE-lite (RFC 8445 §2.5, the browser controls; under `--ice-full` no `a=ice-lite` and the engine controls as the offerer) with `a=setup:actpass` and the engine's fingerprint
  (RFC 5763 §5), and the pending seat keeps the certificate and ICE credentials it advertised. The answer
  is accepted only as `UDP/TLS/RTP/SAVPF` with an `a=fingerprint` (the handshake is trusted against it,
  RFC 5763 §5) and an `active`/`passive` `a=setup` (the engine's DTLS role is its complement); a plain
  answer, a DTLS answer to a plain offer, a missing fingerprint and an `actpass` answer free the seat.
  The seat then takes exactly the join gates: `secure_pending` (nothing forwarded either way until keyed),
  the ICE gate left open on the signalled address and narrowed by the first authenticated check or the
  full agent's selection, and the DTLS handshake held until ICE validates the peer (RFC 8445 §12). A
  preserve room refuses it, because the engine would have to terminate SRTP the room forwards end to end.
- **The video endpoint is gated like the audio.** A seat's `m=video` (3GPP TS 24.281 §6.2) is an
  endpoint of its own, a `Redirect` consumer routed to the same room actor, and `ForwardRoom::ingest_video`
  runs the same `seat_gate::admit` chain on it: the layer-2 signalled-source gate (the video `c=` and
  port, the `received-from` hint, or `Any` for a `symmetric` seat), the pending refusals, and the
  constrained SSRC-consistent latch (RFC 3550 §8) with its own reverse latch per video stream, so a
  hijacker's packet from another address with another SSRC is refused and never moves the reply address.
  Only then is RTCP consumed (never relayed, RFC 3550 §7.3) or RTP armed for the fan-out, and only from the
  chosen source of a seat that offered to send video (`sendrecv`, `sendonly`); a receive-only uplink and a
  non-source are counted and dropped. A receiver is sent video only on its own video endpoint with a
  resolved destination (never into the void), under its own SSRC and payload type. The payload is
  never decoded; only its H.264 framing is read, after the gate and only from the chosen source (and
  the SPS and PPS of any seat, kept to start a receiver on a keyframe), by `siphon-rtp-media::h264`,
  which reads no further than the packet (fuzzed). Video is plain RTP: a seat whose media is SDES or DTLS
  SRTP and a browser video on a transport of its own have their video declined at port 0 with a stated
  reason, because a plain video answer to a secure offer would send the seat video it cannot decrypt. A
  browser seat's video is bundled; a preserve room has its own rules (Layer 5c-iii).
  Leaving, a room's end and the inactivity scan treat the video endpoint as one of the seat's.
- **What the room sends a video seat, and only there.** A source change holds each receiver's video
  until a keyframe (RFC 6184 §5.8), so a seat never receives a stream it cannot start; the packets held
  back are dropped, never queued. The room originates RTCP toward a seat in two cases, both on the seat's
  video endpoint and only to the destination its video gate latched (the signalled address or the
  SSRC-consistent latch above, never an address a datagram merely claims): the Sender Reports above,
  and, to the **source** only, a keyframe request (RFC 4585 PLI, RFC 5104 FIR, in a compound that opens
  with an empty report and the source description, RFC 4585 §3.1) built from the stream the room sends
  that seat. A request goes only to a source that accepted that feedback in its SDP, is bounded (a
  repeat every 500 ms, three repeats, one request a second however many receivers ask), and is never
  sent for a source whose SSRC the room has not yet seen. A receiver's feedback is read only after the
  gate, only about the stream the room sends *that* receiver (a PLI, FIR or NACK naming another SSRC is
  ignored), and a NACK is answered to the receiver that sent it alone, from a fixed history of the
  current source's packets that is emptied at every source change (a retransmission is the packet the
  receiver was already sent, through its own translator, so it can never carry another source's bytes or
  a sequence number outside the receiver's own run). Nothing here allocates per packet.
- **Cross-codec seats put a decoder behind the gate.** A seat whose codec is not the room's has its
  payload decoded (when it is the source) and re-encoded. That is a new consumer of untrusted bytes, but
  it sits strictly after the gate above (signalled source, SRTP, the SSRC latch, source selected by the
  controller), reads only the packet of the one chosen source, and uses the same codec decoders the
  mixing conference and the transcoding relay already run on peer bytes (all fuzzed). A payload the
  decoder refuses, or a frame of an unexpected length, is dropped and counted (`transcode_dropped`); it
  never reaches another seat. Nothing is allocated per packet, so a hostile source cannot grow memory.

#### Bundled video of a browser seat (RFC 8843)

A browser seat's video shares the seat's one endpoint, so it has no gate, latch, key or destination of its
own: every datagram passes the seat's layers 2 to 4 and its `SecureLeg` unprotect (a forged packet never
reaches the demux), then is told from the audio by payload type (RFC 8843 §9.2: a payload type is
unique across the bundle) and, for RTCP, by the streams it speaks of (report blocks or feedback about the
video egress SSRC, or the seat's video sender). The latch is the seat's: it pins the first SSRC the
endpoint saw, audio or video, and a same-source SSRC change is accepted as before; nothing is loosened. Egress goes
to the seat's latched or ICE-selected destination, protected under the seat's key (one SRTP context per
SSRC under one key, RFC 3711 §3.2.3); a bundled video is never sent in the clear and not at all before the
seat is keyed and its ICE pair selected. A video section outside the audio's BUNDLE group is declined,
since the room runs no second transport.

### Layer 5c-iii: Preserve rooms (end-to-end SRTP, hop-by-hop SRTCP)
A forwarding room created with `"media": "preserve"` forwards the talker's media untouched, so it
runs the layer-2 gate, the pending-seat refusals and the constrained SSRC latch of 5c-ii and then
stops short of the translator. Two different things are protected, on two different hops
(3GPP TS 33.180):

- **The media is end to end** (§5.2.1, §7.5.2 NOTE 3). The UEs key their own SRTP and SRTP
  authenticates the SSRC and sequence number (RFC 3711 §3.3), so the engine, which holds no key,
  hands the talker's datagram on byte for byte and cannot verify its tag. What bounds who can feed the
  room is therefore the source gate and the controller's choice of source, nothing cryptographic: a
  seat that offers `a=crypto` or DTLS-SRTP is refused, because the engine would have to terminate
  what the room forwards end to end. Only the cleartext RTP header (RFC 3711 §3.1) is read, to demux
  (RFC 5761 §4) and to check the payload type. The engine writes no SR, RR or BYE toward a seat: a
  report under an SSRC the receivers never saw would describe a stream that does not exist (RFC 3550
  §7.3).
- **The RTCP is hop by hop** (§9.4.1: all RTCP, media RTCP included, is protected between each
  client and the server under that client's own key; §9.4.2 whose key, §9.4.6 how it is derived,
  §9.4.8 the profile: `AEAD_AES_128_GCM` SRTCP, RFC 7714, 32-bit MKI). A seat given
  `profile.media_srtcp_keys` (or `set_floor_keys` with `stream: audio`) is a hop of this kind:
  - **Authenticate first.** Its audio RTCP is opened under a held key before anything is read. A
    plaintext datagram, an unknown MKI, a failed tag and a replay (RFC 3711 §3.3.2, recorded only
    after the tag verified) are dropped, counted per seat (`media_srtcp_refused`) and logged through
    the rate-limited refusal log (a replay at `debug` only). Nothing unauthenticated reaches the
    controller or another seat, and a refused datagram is not liveness.
  - **Then read, as a translating room does.** What authenticated feeds the seat's report
    statistics, and an APP part is surfaced to the controller (`rtcp_app`, stream `audio`).
  - **A keyed talker's RTCP is resealed, never relayed as it came.** It is sealed again for each
    receiver under that receiver's own newest key (E=1, RFC 7714 §9.2), each with its own index, so no
    GCM IV is reused (§9.4). A receiver holding no media key is sent nothing of it, never the
    plaintext (`media_srtcp_unkeyed_receiver`). The plaintext lives in the room's own buffer for the
    duration of one fan-out and is never allocated per packet.
  - **A keyed receiver's RTCP is consumed**, not forwarded (`receiver_rtcp_dropped` still counts it).
  - **An unkeyed seat is unchanged.** An unkeyed talker's audio SRTCP is still forwarded byte for
    byte and never parsed (its body is encrypted, and a receiver's report would describe a stream the
    others never saw); an unkeyed receiver's RTCP is dropped.
  - **Only the preserve room has this.** A translate room, a mixing room and a two-party call write
    their own RTCP, so a key there would silently protect nothing: `media_srtcp_keys` is refused
    with a reason before anything is allocated. `send_rtcp_app` with `stream: audio` to a keyed
    preserve seat is sealed under that seat's media key.
  - **The keys are the controller's.** The engine applies them (newest two accepted, the last
    protects outbound; a rekey keeps an unchanged key's replay state and the send index never moves
    back); the MIKEY exchange (§9.4.6) belongs to the controller. The floor keys of
    `profile.floor_keys` protect the floor stream only and are never used here, and these never
    protect the floor stream.

- **Video in a preserve room is the same two hops.** A seat's `m=video` is an endpoint of its own,
  gated by the same `seat_gate::admit` chain as in 5c-ii (layer 2 signalled source, pending refusals,
  the SSRC-consistent latch), and is accepted as `RTP/SAVP[F]` or plain only with no `a=crypto`, no
  `a=fingerprint` and no BUNDLE with the audio: any of those would make the engine terminate or key
  what the room forwards end to end, so the video is declined with the reason. Never bundled, so the
  room never holds a key for it.
  - **The media is verbatim, from the source only.** Only the cleartext RTP header (RFC 3711 §3.1) is
    read: the direction the seat offered (RFC 3264 §6.1), the payload type (the room's one, RFC 3550
    §7.1) and the SSRC, which is what a request names. The source's datagram is lent to every reachable
    receiver whose video reception is on (`forward_set_reception`, counted
    `reception_off_dropped_video`), unrewritten and never for another seat's packet. The room keeps
    the last 256 datagrams of the source in a fixed ring, emptied at every source change, for NACK.
  - **No keyframe gate.** The payload is encrypted, so an IDR is invisible: nothing is held back, no
    parameter set is replayed and no `forward_keyframe` or timeout is raised. A source change and a
    late joiner are sent one PLI (RFC 4585 §6.3.1; one FIR, RFC 5104 §4.3.1, when only that was
    accepted), at most once a second, and the room then stops: it cannot see whether it was answered.
  - **RTCP is hop by hop (§9.4.1), on the seat's one key.** A keyed seat's video RTCP is opened in
    the same context as its audio RTCP, with a replay window per sender SSRC (RFC 3711 §3.2.3, §3.3.2:
    the index and the replay list belong to the SSRC), so audio and video each count their own index
    and a datagram of one stream replayed onto the other's endpoint is still a replay. The windows sit
    in a fixed table of 8 slots per key, claimed only by a datagram that authenticated; a ninth sender
    SSRC is refused rather than given a shared window. Replay state belongs to the key material, not to
    its MKI (RFC 3711 §3.2.1: the MKI selects a key and is not authenticated), so a key renamed by a
    rekey keeps it, and a key set listing one key and salt under two MKIs is refused. Everything is counted in
    `media_srtcp_refused` (plaintext, an unknown MKI, a failed tag, a replay, a full table). A keyed source's is
    sealed again for each keyed receiver under that receiver's key, on the receiver's one outgoing
    index shared with its audio RTCP (RFC 7714 §9.2: no IV is reused). A keyed receiver's PLI, FIR and
    Generic NACK are read only after authentication and only for the source's stream; a request toward
    the source is sealed under the source's key, and is never made toward a source with no media key,
    because a plaintext request would be refused and TS 33.180 §9.4.1 allows no other kind. A NACK is
    answered to the receiver that sent it with the stored original SRTP bytes, which the receiver
    never saw, so its replay check passes.
  - **An unkeyed seat is outside the hop protection**, as for audio: its RTCP is neither read nor
    answered. An unkeyed source's video RTCP is forwarded as it came (opaque), an unkeyed receiver's is
    dropped and counted, and no request is ever sent to an unkeyed source. A deployment that wants the
    hop protected gives every seat `media_srtcp_keys`.

### Layer 5c-iv: The SRTCP send-index ledger (no GCM IV is ever reused)
`AEAD_AES_128_GCM` SRTCP (3GPP TS 33.180 §9.4.8, RFC 7714) encrypts under the IV `salt XOR (SSRC, index)`
(§9.1). A repeated (key, SSRC, index) breaks both confidentiality and integrity (§8), and the
index is a counter the engine owns on every packet it seals: a keyed forward seat's resealed
talker RTCP (which keeps the talker's SSRC), its video and audio requests, floor control and APP, and
two-party floor legs.

- **The counter belongs to the key.** A counter per seat, leg or room restarts at 0 whenever its owner does,
  and the SSRC cannot be relied on to differ: resealed RTCP carries the talker's own, and a controller may
  name one. So the engine keeps one `SendIndex` per key in an engine-wide ledger
  (`srtcp_ledger.rs`), keyed by `HMAC(master_key, label || master_salt)`: one-way (it names the key
  without revealing it), identical on every node (so a checkpoint is recognised by a standby with no secret
  distributed), and independent of the MKI because the IV is. Every protection sending under a key draws
  from its counter: a seat that rejoins, a client key in two rooms or in a room and a call, one key under both
  the floor and the media keys of a seat (TS 33.180 §9.4.2: one key per client), a key unset and set again.
- **Per packet it is one atomic load and one add**: lock-free, no allocation (the zero-allocation tests cover
  it), never decreasing, and at index 2^31 - 1 it refuses (`IndexExhausted`, logged at `error`, RFC 7714 §9.4:
  never wrap) until the controller replaces the key. A new key starts at its own counter (0): its IV space
  is its own.
- **Retention: never, by default.** An entry is the key's high-water mark, and a key that comes back after
  its entry was dropped restarts at index 0 and repeats nonces (RFC 7714 §8); the engine cannot see a
  controller replace a key. So nothing is dropped unless the operator opts in with
  `srtcp_ledger_retention_secs` (config file) / `--srtcp-ledger-retention-secs`, which drops an entry nothing
  has held for that long. That is only safe at or above the lifetime the controller enforces on a client
  key (TS 33.180 §9.4.2). A held entry and an exhausted one are never dropped. Memory is one small
  entry per distinct key material seen; `siphon_rtp_srtcp_ledger_entries` is the gauge.
- **Entry cap: refuse the new key, never evict.** Without retention nothing bounds the entry count, so
  `srtcp_ledger_max_entries` (config file) / `--srtcp-ledger-max-entries` caps it (default 100000, about 15 MB).
  At the cap the install of a **new** key is refused under the ledger's install mutex (control path only,
  never the per-packet take): the verb that carried it fails with a clear reason, an `error!` is logged on
  `siphon_rtp::media` and `siphon_rtp_srtcp_ledger_install_refused_total` counts it. A key already in the
  ledger adds no entry and still installs. A live or retained entry is never evicted to make room, since
  its counter is the only record of how far the key has sent and evicting it would let the key restart at
  0 (RFC 7714 §8). A key that reaches the counter without having been admitted gets an already-exhausted,
  unstored counter: it can never seal. `restore_srtcp_indices` refuses a blob whose new keys would pass the
  cap whole and imports nothing, since a partial import would leave the rest of its keys with no floor.
- **Failover is fail-closed.** `checkpoint_srtcp_indices` exports every counter (a key that is installed and
  has sent nothing included) and `restore_srtcp_indices` seeds a standby 65536 past each (the floor
  checkpoint margin), never lowering. A margin only holds if the primary never sends that far, so once a
  checkpoint has been taken **each counter has a lease**: the index in the last *confirmed* checkpoint plus
  the margin. The first checkpoint's lease takes effect at export (a standby holds that blob or nothing, and
  nothing is the fresh-keys case). A later export extends no lease: only `confirm_srtcp_indices`, which the
  controller sends after it has durably stored that generation's blob, does, and a confirmation older than
  the last confirmed one is ignored. Otherwise a reply lost on its way to the controller would let the
  primary send past what the standby holds: the standby restores g1 (index 0), the primary was extended by
  an unstored g2 and sent index 65536, the standby sends 65536 again. A standby may restore the last
  confirmed blob or a newer unconfirmed one: a newer blob's indices are at or above the confirmed one's
  (counters only move forward), and the primary is capped at the confirmed one plus the margin, so a
  standby seeded from either starts above anything the primary sent. A key
  installed after the first checkpoint is leased from index 0 plus the margin (no checkpoint knows it). At
  half its window a counter raises the `srtcp_checkpoint_due` event, once per crossing, to the client that
  took the checkpoint (it names only a count); at the lease the seal is refused (`error`, once per
  protection, counted in `siphon_rtp_srtcp_lease_refused_total`) until the next confirmed checkpoint extends the
  lease. Before any checkpoint there is no lease and nothing is refused. A standby that imports a ledger
  leases from the counter it seeded. **Keys the blob does not list** are safe too: the primary leases every
  key installed after its first checkpoint from creation, capping it at index 0 plus the margin, so a
  key absent from a blob has sent below the blob's `unlisted_ceiling` (the margin on a primary; what the
  last standby seeded after a chain of failovers). A standby that restores a blob raises every key it
  already holds that the blob does not list to at least that ceiling, and seeds every key installed later
  at it, so such a key never restarts at 0 under an index the primary used. The
  counter holds the index and the lease in one atomic word and a checkpoint reads the one and sets the
  other in a single compare-and-swap, so a send that raced a checkpoint cannot be handed the standby's
  first index; installing a key and taking or restoring a checkpoint are serialised by one ledger-wide
  `std::sync::Mutex` (control path only, never held across an `.await`, never taken by the per-packet
  take), so a key installed during a checkpoint is in the blob or leased from its first index. A two-party floor
  call restored from `checkpoint` also raises the ledger through its resumed send index.
  **A restore of the engine's own blob is a no-op; any other restore gates every key.** A controller
  restores its stored blob on every connection, a reconnect to an engine that never restarted included, so
  that must not stop the keys the engine serves. Every exported blob carries an origin tag,
  `HMAC-SHA1(secret, canonical bytes)` (SHA-1 because `hmac` and `sha1` are already dependencies, and an HMAC
  does not rest on collision resistance), under a random 32-byte secret generated when the ledger is built
  and never exported. A blob whose tag verifies (constant time) under this ledger's secret was exported by this
  very ledger, whose counters only rise and are already at or above it: the restore changes nothing. The epoch
  in the generation token is not proof, since any blob shows it: a blob that names this epoch without a
  verifying tag (forged, edited, from an earlier process whose epoch collided, or from before the tag existed,
  blob version 1) is another engine's and is gated like any other, with a warning. A blob whose whole bytes
  (tag included) were imported here before is skipped as well: the first import raised everything it could,
  counters never lower, and re-closing the window would stop keys installed since. The last 8 are remembered.
  Any other blob closes the send window of **every** key (the lease is set to the counter, so the per-packet
  take gains no flag) until one of this engine's own exports, taken after the restore, is confirmed: each
  listed key is seeded a margin past its index, each key the engine held that the blob does not list is raised
  to at least the ceiling, and each key installed afterwards starts at the ceiling. An export taken before
  the restore can no longer be confirmed. **Why a held, unlisted key must be gated too (RFC 7714 §8):** A
  exports a checkpoint without K; B holds K and has sent nothing under it. B restores A's blob and raises K to
  the ceiling M. Were K left open, B could seal M and fail before its own checkpoint is durably stored; a
  standby C restoring the still-current A blob installs K at M too and seals M again, one nonce twice. Only a
  confirmed checkpoint of B bounds what B sends after a restore, so until one is, B sends nothing under any
  key. Raising a counter never repeats a nonce; it is the sending that needs a durable bound. The epoch and
  the secret come from the operating system with no fallback: a daemon that cannot get them refuses to start,
  and an embedder that builds an engine without the daemon gets a **poisoned** ledger that refuses every key
  install (counted in `siphon_rtp_srtcp_ledger_install_refused_total`), seals nothing, and refuses export,
  confirm and restore. What no restore can repair is one key live on two engines at once before the failure:
  that is the controller issuing the same key twice. A standby that
  restores no ledger knows nothing of what the primary sent, so the controller must issue **fresh keys**
  (RFC 7714 §8). Forward rooms are not checkpointed; rejoining seats on a seeded ledger is what is safe.
- **The MKI is a label, not a context.** Send counters and replay state are keyed by the key material
  (RFC 3711 §3.2.1: the MKI selects a master key and is not authenticated), so a captured packet re-sent
  under an alias MKI is a replay, and a key set listing one key under two MKIs is refused.
- **The receive side is the SSRC's too.** Replay windows are per sender SSRC under each key (RFC 3711 §3.2.3,
  §3.3.2), in a fixed table of 8 slots claimed only by authenticated packets; a ninth SSRC is refused.

### Layer 5f — The RFC 4103 Real-Time Text (RTT) relay path
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

### Layer 5i: The video stream of a two-party call

With `video_relay: anchor` a two-party call's `m=video` stream is relayed on engine endpoints of its own
(an RTP pair per leg, one endpoint under `a=rtcp-mux`, RFC 5761), beside the audio. It is a stream with its own
inbound surface, so it has its own gate and latch and none is inherited from the audio.

- **Gate.** Each video RTP endpoint's rule is built by the same `ingress_rule` as audio: only the SDP-signalled
  address (RFC 3264) is accepted, tightened to the `received-from` public IP when the proxy supplied one, and
  loosened only by the documented `subnet-source` and `symmetric` flags. The companion RTCP endpoint is gated
  on the signalled RTCP address. A stranger's datagram is dropped and counted, never latched
  (`video_from_an_unexpected_source_is_dropped_not_latched`). Video does not use ICE here.
- **Latch.** `SignalledOnly`, as audio. The 1 Hz latch refresh sweep reprograms the forward destination of
  the video flows from the validated learned source exactly as for audio (RFC 3550 §8); it also walks the
  text flows, which it previously skipped.
- **Direction.** Only the directions the two parties' own attributes allow get a forward rule (RFC 3264 §6.1,
  §8.4); the other ingress is a drop. RTCP flows both ways whenever the stream flows at all, because receiver
  feedback travels against the media. Under `a=rtcp-mux` the RTP direction rule yields to RTCP, since one
  endpoint receives both and a kernel rule cannot split them: a `recvonly` party's stray RTP is then
  forwarded. This is the one place the direction is not enforced, and the reason it is not.
- **Re-offer.** A moved address or changed direction is recorded when the re-offer arrives and the relay is
  re-gated on it by the answer that completes the exchange; the old source is dropped from then on.
- **Never into the void, never a leak.** A section the engine does not anchor is declined with port 0, so the
  other party is never shown a party's own private video address. A stream that cannot be keyed is declined,
  never relayed unkeyed.
- **SDES-SRTP per stream** (RFC 4568, RFC 3711). Each video section carries its own `a=crypto`, parsed like the
  text stream's. The engine mints its own key toward each secure party, the answer echoes the offered tag
  (RFC 4568 §5.1.2), and one party's key is never written into the other's SDP. A secure answer to a plain
  offer, a plain answer to a secure offer and a section with no usable key are declined: there
  is no downgrade and no unkeyed relay. A secure leg cannot ride the kernel relay, so every video endpoint
  that carries media is `Redirect`ed and a second bridge plan, over the video endpoints and video
  `SecureLeg`s only, goes to the SRTP bridge. Plain to SDES, SDES to plain and SDES to SDES (a transcrypt)
  are the audio bridge's one mechanism. The gated latch is the bridge's, unchanged: the signalled-source gate
  runs before any crypto, and the symmetric latch adopts a source only after the packet authenticated under
  the party's key (`a_stranger_is_dropped_by_the_gated_latch_even_with_a_well_formed_packet`). RTCP is SRTCP
  per stream. A re-offer carries each secure leg's rollover into the rebuilt one (RFC 3711 §3.3.1), as audio's
  does, so a stream past a sequence wrap keeps authenticating. The bridge's crypto buffers are reused across
  datagrams, so the secure path allocates nothing per packet (`srtp_bridge_video_zero_alloc`); this holds for
  audio's bridge flows too.
- **DTLS-SRTP per stream** (RFC 5764, RFC 5763, RFC 8843). The engine terminates one party's DTLS; the other is
  plain. A **bundled** video (the group names the video mid and the audio's) shares the leg's endpoint, source
  gate and association: no second handshake, one SRTP context per SSRC under the leg's keys. After unprotect the
  bridge tells it from the audio by payload type (unique across a bundle, RFC 8843 §9.2; a video section that
  shares one with the audio is declined) and, for RTCP, by the streams it speaks of (the shared
  `rtcp_is_about_video`); nothing is decided before the signalled-source gate and the crypto, so a stranger
  or a forged packet is never routed. The far party's video endpoint is its own redirected, gated endpoint,
  and what it sends leaves the leg's audio 5-tuple as SRTP, never in the clear. **Unbundled, no ICE**: a
  second association on the video endpoint, registered like the audio's, with the same certificate and the
  role of its own `a=setup` (the kept association survives a re-offer, RFC 8842 §3.1). Unbundled with ICE,
  without `a=rtcp-mux`, toward an SDES leg, on a passed-through DTLS audio leg, or bundled on an audio leg the
  media pipeline owns, the stream is declined. The latch is the audio's: the DTLS bridge gates on the
  signalled source and has no symmetric latch for either stream. Interception, tees and recordings take the
  audio only. The bridge's crypto buffers are reused, so the DTLS path allocates nothing per packet
  (`dtls_bridge_video_zero_alloc`). A DTLS call is not checkpointed, so neither is its video.
- **Through `answer_local`.** The caller's video is answered on endpoints of its own before any far party
  exists, because its answer is frozen (RFC 3264 §8). Those endpoints carry a `Drop` flow until the far party's
  answer installs the ordinary relay above, built by the same `ingress_rule`: nothing is forwarded, and nothing is
  sent toward the caller (an answerer may send nothing, RFC 3264 §6.1), before a signalled far address exists, and
  a stranger is dropped and never latched in either phase (`the_callers_video_is_dropped_and_nothing_is_sent_before_a_far_party_answers`,
  `a_far_answer_with_the_offered_payload_relays_video_both_ways_and_counts_it`). The caller is answered one video format and the far party offered only it; the far party's answer
  must carry exactly that format, with a meaning and format parameters (H.264 sub-profile and level) both sides can decode, and a stream that does not is declined alone. Only a
  plain RTP caller is accepted: a secure, ICE or WebSocket-bridged caller is refused, since the answer cannot be
  revised once sent. The keyframe request sent when the relay goes live names a media SSRC the party declared in its own SDP or the relay latched from
  its admitted packets, never one the engine guessed, and goes to the address the relay forwards to.
  - **The far party's `sprop-parameter-sets` (RFC 6184 §8.1).** The caller cannot be told them in its frozen
    answer, so a far answer that carries a usable list in packetization mode 0 or 1 arms a first-IDR injector
    (`video_injector`) on the far-to-caller flow. The flow is a plain `SrtpBridge` flow registered **before**
    the far endpoint is redirected, so the first redirected datagram already finds its owner
    (`an_injected_far_video_leg_owns_its_endpoint_before_it_is_redirected`) and the gate below runs first: the
    bridge re-enforces the signalled-source gate and the latch, and a stranger is dropped before the injector
    sees it, so it can neither start the injection nor reach the caller
    (`a_stranger_cannot_drive_the_injector_or_reach_the_caller`). Order inside the bridge: source gate, latch,
    liveness stamp, injector, send; the injector never relaxes a gate, only withholds. Before the first IDR it
    drops every far RTP packet that does not begin one (RTCP, muxed on the port, passes); at the IDR it sends the
    sets that packet lacks under the two sequence numbers before it, so nothing is renumbered. While the flow is
    in userspace every packet at or before the number before the IDR is dropped (wrap-aware), and it stays there
    until the sequence is 64 packets past the IDR (RFC 3550 §A.1 reordering tolerance) or the timeout, so a late
    original cannot reach the caller under a number the sets used. The far endpoint is never given a `Forward`
    rule first: it goes from parked straight to the redirect the bridge owns, so no packet is relayed ahead of
    the injector. A set that cannot be sent holds the whole IDR back and the far party is asked for another.
    Each sweep acts on an injector only while it is still the call's, under the call's map entry, so a
    renegotiation or park that replaced the flow is never overwritten. Where the
    flow forwards to is the signalled caller address, the bridge's own latch for the caller's endpoint, or the
    datapath's latched source for it, in that order, so a NATed caller is still reached (an XDP backend keeps
    no latched source, and the signalled address is used). Once settled (or, when no IDR comes, three sweeps after arming, the stream then
    forwarding unchanged) the sweep returns the endpoint to the recorded
    `Forward` rule and a sweep later removes the bridge flow. The injection is cancelled by a renegotiation,
    by parking the video, by deleting the far leg and by teardown. Not covered: packetization mode 2, and a
    secure caller (refused on this path anyway).
- **HA.** The video sockets re-bind on their ports at restore, with the same gate and latch policy and the
  same directions. A secure stream also records its keys and each secure leg's rollover, so the standby's
  first packet past a wrap authenticates; its snapshot has a version of its own, so an older standby refuses
  it rather than restoring an unencrypted picture on a secure leg. A key that cannot be rebuilt refuses the
  restore.

### Layer 5g — The T.38 fax (UDPTL) relay path
A call may switch to fax: an `m=image <port> udptl t38` section (ITU-T T.38 Annex D, RFC 3362),
either alongside the audio or — the usual T.30 switchover — replacing it, in a re-INVITE that carries
no `m=audio` line at all. The engine anchors it to a **separate** endpoint per leg and relays it.
**RTPBleed is per-stream**, so the fax stream is a full inbound surface in its own right and gets its
own copy of Layers 2–3. Layer 1 is where it differs, and that difference is the whole design.

- **It is not RTP, so it does not ride the `Forward` path — at all.** A UDPTL datagram has no RTP
  header: its first two octets are a 16-bit sequence number, so its leading byte walks the whole
  `0..=255` range as the fax progresses and *aliases every RFC 7983 demux class* (Layer 1). Installed
  as a `FlowAction::Forward` flow it would be dropped in the datapath for roughly three datagrams in
  four, and the quarter landing in `128..=191` would be worse than dropped: `rtp_media_ssrc` reads
  bytes 8..12 and returns `Some(garbage)` rather than `None` for a datagram that merely looks like
  RTP, so the Layer-3 latch would pin a value that changes every packet. The stream is therefore
  installed as `FlowAction::Redirect` on both endpoints and relayed by `udptl_pipeline`. This is the
  arm Layer 1 already sanctions for non-RTP ("a redirected endpoint is entitled to non-RTP") and it
  leaves the `Forward` path's RTP-only rule — the RTPBleed fix — exactly as it was. No eBPF ABI
  change, and the XDP backend's own `Redirect` arm gates Layer 2 in-kernel before handing the
  datagram up.
- **The consumer re-enforces Layer 2 itself,** because on a non-ICE `Redirect` endpoint the UDP
  backend applies no source gate of its own (see the Layer 4 `Redirect` bullet). Each direction is
  gated to its peer's signalled address, tightened to the `received-from` public IP when the proxy
  supplied one, through the same `bridge_source_filter` the audio and text relays use — so the
  `symmetric` and `subnet-source` postures mean the same thing on a fax leg as anywhere else.
- **The latch is address-only and learns exactly once.** There is no SSRC to key a re-latch on, so
  there is no evidence a new source could ever offer that it is the same stream. `OpaqueLatch` runs
  the same `source_latch_verdict` state machine with `ssrc: None`, which already yields precisely
  this: learn the first accepted source, reject every later one. It is the posture Layer 3 already
  describes for an SSRC-less latch — *confirmed by its own source but never moved*. The consequence
  is deliberate and worth stating plainly: a genuine mid-call NAT rebind **kills** a fax rather than
  following it. A fax that stops is retried; a fax that follows an attacker is not a fax.
  - `SymmetricLatch` could **not** be reused. It deliberately does not store an SSRC-less learn (the
    carve-out that stops RTCP-before-RTP from aiming the reply), so on a stream that never carries an
    SSRC it accepts every source forever. Under the opt-in `symmetric` flag, where `SourceFilter::Any`
    makes the latch the only constraint left, that is no gate at all — the same hole Layer 3 records
    as already fixed once for RTP. The two latches share one state machine so they cannot drift.
- **The stream is never parsed.** A relay does not need the sequence number, the primary IFP packet
  or the redundancy — those are a contract between the two fax endpoints. The bytes that arrive are
  the bytes that leave, so this path adds no parser for untrusted input, and therefore no new attack
  surface and no new fuzz target.
- **Never forward into the void.** A direction with no resolved destination drops the datagram rather
  than guessing, exactly as the `Forward` path does.
- **A transport the engine cannot relay is declined, not passed through.** T.38 over TCP (Annex E)
  and over DTLS are legal and unsupported here; both are answered with `m=image 0` (RFC 3264 §6). An
  untouched section would advertise the UE's own address, so passing one through is not a no-op — it
  is a silent topology change that takes the media off the engine.
- **Idle reap + teardown.** The image endpoints are part of the call's endpoint set
  (`all_endpoint_ids`) for the media-timeout sweep and teardown, and the relay stamps datapath
  activity only for a datagram that cleared both gates — so a spoofed spray cannot extend a call's
  life, and a fax-only call (which by then carries no audio at all) is not reaped mid-transmission.

### Layer 5h — The MCPTT floor-control stream of a forwarding-room seat
A forwarding-room seat may offer `m=application <port> udp MCPTT` (3GPP TS 24.380 §14, SDP per
TS 24.379), or the MCVideo transmission control stream, `m=application <port> udp MCVideo` (3GPP TS 24.581
§4.3.3.1), which is the same surface under another token; everything below holds for both. Both tokens
are always *recognised*, and `profile.transmission_control_formats` picks which are *accepted*
(default `MCPTT`). A recognised section that is not accepted is declined with port 0 (RFC 3264 §6), so
neither token is ever passed through to the other party with the offerer's own address. The engine
anchors it on a **separate** `Redirect` endpoint per seat, because RTPBleed is
per-stream and the floor stream is a full inbound surface that reaches the controller. The stream
carries only RTCP APP packets (RFC 3550 §6.7). It is plain unless the controller keyed it (the SRTCP
rule below); SRTP for the media control channel (TS 24.380 §13) is not implemented, so the answer
never offers it.

- **Layer 2, the same source gate as the seat's audio.** The floor endpoint is gated to the address
  the floor m-line signalled (its own `c=`, else the session one), tightened to the `received-from`
  hint exactly as the audio is, or open under the opt-in `symmetric` flag. An ICE seat holds it open
  until its pair is selected and the room then narrows it to the selected address. A datagram from any
  other source never produces an event.
- **The floor opens when the audio path does.** A DTLS seat before its handshake and an ICE seat
  before its pair is selected have their floor datagrams refused, and `send_rtcp_app` to them is an
  error naming the seat, so floor control cannot race the decisions that gate the media.
- **Layer 3 is the learn-once `OpaqueLatch`, not the SSRC latch.** The stream has no RTP, and
  `rtp_media_ssrc` returns nothing for RTCP, so there is no SSRC to prove a new source is the same
  stream. The first gated source is learned as the reply address and every later source is refused,
  the posture Layer 5g describes for UDPTL. A NAT rebind therefore stops floor control rather than
  following it; the controller sees `forward_seat_inactive` for a seat that has gone quiet. An SSRC
  inside an APP packet is the sender's claim and is never used to move the latch.
- **Keyed floor is SRTCP, and nothing else is accepted.** A stream keyed by `profile.floor_keys` or
  `set_floor_keys` is `AEAD_AES_128_GCM` SRTCP (RFC 7714 §9; 3GPP TS 33.180 §9.4.1 requires RTCP
  protection between the UE and the server, §9.4.8 fixes the profile, §9.4.7 the 4-octet MKI that
  is the KFC-ID). A datagram is first checked by layer 2, then **authenticated**, then latched, then
  parsed. A plaintext packet, an unknown MKI, a failed tag and a replay (RFC 3711 §3.3.2, recorded
  only after the tag verified) are dropped, counted per seat or leg (`floor_refused`) and logged
  through the rate-limited refusal log (a replay at `debug` only). No APP packet from an
  unauthenticated datagram reaches the controller. The reply latch is committed only from an
  authenticated packet, and a datagram from a source other than the pinned one is refused before it
  is opened, so a forged datagram from the signalled host can neither pin the stream's destination
  nor spend an anti-replay slot. Outbound floor control on a keyed stream is always protected
  (E=1) under the newest key, never in the clear. The newest two keys are accepted
  (`set_floor_keys` replaces the set; an unchanged key keeps its replay state and the send index
  never moves back, because a reused (key, index) pair reuses the GCM IV, RFC 7714 §9.4). An
  unkeyed stream behaves exactly as before. The floor keys are never used on the audio stream's
  RTCP (a preserve seat's audio RTCP has keys of its own, `media_srtcp_keys`, Layer 5c-iii), and a
  floor data channel is protected by its DTLS association instead. The engine applies keys; the MIKEY-SAKKE exchange (§9.4.6) belongs to the
  controller.
- **Never forward into the void.** `send_rtcp_app` to a seat whose floor destination is not yet known
  (no address, or the seat not open yet) is refused for that seat, never guessed.
- **Floor messages are terminated, never relayed.** An APP packet from a seat becomes a control
  event for the controller that seated it and is not sent to any other seat. The controller decides
  what the room hears. The same holds for APP parts inside a seat's audio RTCP: they are surfaced,
  the reports in the same compound are read as before, and nothing is relayed.
- **A malformed datagram is counted and dropped.** `rtcp::app_packets` reads at most what the
  datagram's own length fields describe, never allocates and never panics; a datagram it cannot read
  to the end is counted per seat and logged at `debug`, and raises no event.
- **Events are not shed silently.** `rtcp_app` events use their own per-controller queue (4096),
  drained by the same connection loop. When it fills the *oldest* event is dropped, with an `error!`
  naming the room and seat, and `siphon_rtp_rtcp_app_dropped_total` / `statistics.rtcp_app_dropped_total`
  count it, so a floor message lost to a stuck controller is visible and never a surprise.
- **Liveness.** Datagrams that clear the gate stamp the floor endpoint's activity, and the inactivity
  scan takes the newer of a seat's audio and floor activity, so a seat that only sends floor traffic is
  not reported as quiet.
- **Teardown.** The floor endpoint is part of the seat's endpoints for `forward_leave`, a room's end,
  and an ICE failure, so it is freed with the seat and its route removed.
- **Two-party calls run the same gate.** A call's floor endpoints (`Leg::floor`) are `Redirect`ed and
  routed to `call_floor`, which applies layer 2 (the signalled floor address, tightened by the
  `received-from` hint, or the `symmetric` posture) and the learn-once latch per leg, and terminates the
  stream: nothing a party sends on it reaches the other party. They are part of the leg's endpoint set,
  so call teardown, the idle sweep's liveness reading and re-offers treat them like any other stream's
  endpoint, and a re-offer never moves a floor leg's gate. APP parts in a party's audio RTCP are read
  after the pipeline's own gate, decrypt and latch, and the compound is relayed as before. Each
  party's floor keys are its own: the offerer's from its `offer` profile, the answerer's from its
  `answer` profile (`answer_local` keys its one leg); one party may be keyed and the other not.
- **Audio RTCP of a floor call on the in-kernel relay leaves the kernel, behind the same gate.** A
  plain-relay call that carries a floor stream installs its relay rules with `rtcp_to_userspace`: RTP
  keeps forwarding in the backend, while an RTCP datagram (RFC 5761 §4 demux, muxed or on its own port)
  is handed to the `Redirect` stream **only after** layers 1 to 4 admitted it, in the UDP backend's
  `Forward` arm and in the XDP classifier alike. An unadmitted source is dropped there and never reaches
  userspace. The consumer (`rtcp_relay`) re-checks the rule's signalled-source filter, reads the APP
  parts (RFC 3550 §6.7), offers the datagram to the telemetry tap and relays it unchanged toward the
  peer's latched source, else its signalled RTCP address, as the backend's own arm does. It owns no
  latch of its own: the backend's is the one latch of the stream. The relay is registered with the call
  and removed at its teardown, and a re-answer that drops the floor stream removes it. Secure calls are
  not affected: their RTCP is already userspace.
- **A floor stream survives an HA failover without reopening learning or reusing an IV.** `checkpoint`
  reads the stream from the actor that owns it and records its gate, its reply address, its SSRC and, if
  keyed, its keys with the outgoing SRTCP index and the highest index received per key. `restore`
  re-binds the floor port, redirects it to the call-floor actor and registers the leg with the learn-once
  latch **already pinned** to the recorded source: a standby never lets the first sender win the stream
  (the RTPbleed rule), and a stream that had learned nothing learns once, as a new one does. The outgoing
  index resumes 2^16 past the recorded one (`SEND_INDEX_MARGIN`): the primary keeps sending between the
  checkpoint and its failure, and RFC 7714 §9.4 forbids protecting two packets under one key with one
  index. A margin that would leave the 31-bit index space refuses the restore; the index never wraps. The
  replay state of each key comes back closed at the highest received index (RFC 3711 §3.3.2), so the
  phone's last packets are not accepted twice; only packets the primary consumed after the checkpoint can
  be, once. The snapshot of a floor call carries its own version so a standby that predates this refuses
  it instead of resuming without the stream. A DTLS or data-channel floor stream is not carried (its keys
  come from the handshake) and the call is refused at `checkpoint`.

### WebRTC data channel (floor control for a browser seat)

A browser seat that bundles `m=application <port> UDP/DTLS/SCTP webrtc-datachannel` with its audio
(RFC 8841, RFC 8843) carries its MCPTT floor control on a data channel (`mcptt-floor`, 3GPP TS 24.380
has no WebRTC binding; the convention is siphon-rtp's own, docs/control/json.md). **This adds no UDP
ingress.** The SCTP association is carried as DTLS application data (RFC 8261 §5) inside the DTLS
association the seat's audio already runs, on the same `Redirect` endpoint:

- **Layers 1 to 4 are unchanged and come first.** The datagram is demultiplexed (RFC 7983), gated on
  the signalled or ICE-validated source and, on an ICE seat, held until the pair is validated, exactly
  as a DTLS handshake record is. A data channel record from any other source never reaches the driver.
- **Authenticated before parsed.** SCTP bytes are only handed to the SCTP stack after the DTLS record
  layer has decrypted them, and the DTLS association only completes after the peer's certificate has
  matched the `a=fingerprint` it signalled (RFC 5763 §5). Application data cannot arrive before that
  (`DtlsSession::write_application_data` refuses to send until then, and the driver feeds SCTP only
  from keyed-session events). An impersonator that cannot complete the handshake cannot reach the
  SCTP parser, the DCEP parser or the floor parser.
- **One owner.** The DTLS driver task of the seat's endpoint owns the DTLS session, the SCTP association
  and the channel state; it is the single task that reads them. The controller reaches it only through
  a bounded (64) mailbox, so a controller that outpaces the association gets `floor data channel
  congested` rather than a growing queue.
- **Bounded.** The advertised and enforced `a=max-message-size` is 65536, the receive window is twice
  that, and a larger message is dropped and counted. A floor message is parsed by the same
  `rtcp::app_packets` the UDP floor stream uses, which reads at most the message's own length fields.
  A string message, a malformed binary one, a message on a channel that is not `mcptt-floor`, and a
  message on a stream that never completed its DATA_CHANNEL_OPEN are counted and dropped with no event.
- **Teardown.** The channel lives and dies with the leg's endpoint: `forward_leave`, `delete` and a
  room's end drop the driver (and with it the association) and the channel plan together.
- **What is relaxed.** A leg with a data channel keeps its DTLS driver for the life of the leg, not for
  the 60 s last-flight retention window, and does not throttle its post-handshake DTLS output to the
  200 ms retransmission guard, which would otherwise drop SCTP packets. The guard was a CPU and
  bandwidth bound on a source that is already gated twice; SCTP's own congestion control bounds the
  channel traffic.

### Layer 5e — The WebSocket-takeover Redirect path
A **takeover** call (`ProfileFlags.ws_uri`, `PipelineKind::Ws`) points leg A's RTP endpoint at
`FlowAction::Redirect` and makes an external WebSocket media server A's far side; the A↔B
relay/transcode path is deliberately not wired. That makes the engine A's *only* peer — and therefore,
when A negotiated SRTP, A's cryptographic peer. It is a full inbound surface, so it carries its own
copy of Layers 1–4.

**Order of installation.** The bridge is registered (route, source gate and latch) before leg A's
`Redirect` lands, because a redirected datagram that finds no owner is dropped; the displaced relay is
switched off back to back with that redirect; and `ws_bridge_started` is announced only once the
redirect has succeeded. A refused redirect deregisters the bridge, aborts its tasks without any
lifecycle event, puts the displaced relay back, and fails the verb, so the call keeps relaying on its
old path.

> **Status (landed — secure takeover):** a takeover leg on a secure offerer terminates SRTP on its own
> `WsSecureLeg` (`engine/src/ws_bridge.rs`), keyed by SDES (RFC 4568) in the answer or by the RFC 5764
> handshake. Only `answer_local` supports it; `offer`/`answer` refuse it (see "Where a secure takeover
> is refused" below).

- **Source gate (RTPBleed, restated for `Redirect`).** `WsRegistry::dispatch` re-enforces the
  signalled-source gate (`Exact`/`Subnet`/`Any`, tightened by the `received-from` public-IP hint)
  before anything reaches the bridge — `Redirect` bypasses the datapath's Forward-path gate, exactly as
  on Layers 5a–5d.
- **Idle reap.** `WsRegistry::dispatch` stamps the endpoint's activity on each packet that clears the
  gate and, on a secure leg, SRTP authentication — before the bridge's mailbox, so a bridge that is
  momentarily behind is not mistaken for a dead call, and after both checks, so an off-source or
  forged packet cannot hold one open. A takeover leg is the one userspace `Redirect` consumer with no
  per-call actor to stamp from (the media pipeline, the conference room and the text relay each stamp
  from an actor that owns a datapath; a takeover leg's bridge task lives in `siphon-rtp-media` and
  never sees one), so the registry carries the datapath itself as a narrow `MediaActivity` handle on
  the route. Without it the endpoint's `last_seen` never leaves the call's `created_tick` and Layer 6
  tears the call down at the media timeout mid-conversation — indistinguishable, from the outside,
  from the caller hanging up.
- **The downlink runs on the engine's clock, not the server's, and never stops.** The bridge core
  drains its playout by *samples* — exactly one ptime per tick — rather than by whole WS frames, so
  the RTP cadence is the engine's whatever framing the server chose. This is a NAT property as much
  as a correctness one: the leg now emits continuously (a low-level comfort floor between turns
  rather than nothing), which is what keeps the pinhole toward a NATed caller open for the whole
  call. A takeover leg has no second party whose media would hold that pinhole open for it — it is
  the caller's only far side — so a leg that emitted only while the bot spoke left the return path to
  expire between turns, on top of reading as dead air.
- **The hint aims the downlink too, and the leg latches its own egress (§4 layers 2 and 3).** The
  same `(hint IP, signalled port)` pair the gate keys on is where the bridge's drain task starts
  sending, at every setup site — the two-leg `offer`, the single-leg `answer_local`, a `ws_uri` that
  arrives first at `answer`, and the runtime attach's fallback when the relay it displaced had not
  latched anything yet. From there `WsRegistry::dispatch` applies the same SSRC-consistent
  symmetric-RTP latch the relay and transcode paths use (`WsEgress`, sharing `SymmetricLatch` with
  `media_pipeline` so the two userspace `Redirect` paths cannot drift): the first packet to pass the
  gate — and, on a secure leg, SRTP authentication — re-points the downlink at the source it actually
  arrived from, a new source keeping the stream's SSRC follows a genuine NAT rebind, and a new source
  carrying a different SSRC never moves it. Only RTP media is offered to the latch, so a STUN or DTLS
  record on a muxed takeover port cannot steer the call's audio.
  - Gating on the hint while still *sending* to the private `c=` is the general defect §4 layer 2
    describes, but it is worse here than on a relay leg and it is worth being explicit about why:
    a relay leg is corrected by the datapath's latch on the peer's first accepted packet, whereas a
    takeover leg has no reverse relay direction and so no forward rule and no datapath latch behind
    it. Nothing corrected it, so a NATed caller's downlink went to an RFC 1918 address for the life
    of the call — signalling clean, uplink arriving and decoding perfectly, and silence back.
  - The `symmetric` profile flag was never the fix for this and is not one now. It widens the
    ingress *gate* to `Any`, a strictly weaker Layer 2, and before the latch existed it did nothing
    whatever about where the downlink was aimed — a takeover leg with it set still sent to the
    private `c=`. With the latch in place a `symmetric` takeover leg does now follow the first source
    that reaches it, exactly as a `symmetric` relay leg has always done; that width is what the flag
    asks for, and it is still the wrong tool here, because the `received-from` hint reaches the same
    destination while leaving the gate `Exact`.
  - On an **ICE** leg the latch is off entirely (`WsEgress::ice_managed`). The agent's selection is
    the only thing that may adopt a transport (Layer 4, RFC 8445 §7.3.1.3) — the same posture the
    datapath takes by installing `LatchPolicy::Off` on an ICE relay leg — so media from an unselected
    port on the selected address is forwarded but never re-points the downlink.
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
  | **SDES** offerer, no `ws_uri` (single-leg IVR/echo/voicemail) | `answer_local` | terminated on the single-leg media pipeline — the engine answers its own `a=crypto` and holds the `SecureLeg` |
  | **DTLS** offerer, no `ws_uri` (single-leg IVR/echo/voicemail) | `answer_local` | terminated on the single-leg media pipeline — the handshake runs in front of the endpoint (held for the ICE selection when an agent runs) and keys both directions, which send nothing until then |
  | `RTP/SAVP` with no usable `a=crypto`; `UDP/TLS/RTP/SAVPF` with no `a=fingerprint`; no engine certificate | `answer_local` | `ws-takeover-unkeyable` |
  | ICE offerer with no full agent available | `answer_local` | `ws-takeover-ice-unsupported` |

  The class of bug being closed is "accepted silently", not "DTLS specifically": every one of these
  used to return `ok` on a call whose media went nowhere.
- **HA.** A takeover call is not restorable — the external WebSocket session is not replicable state —
  so `checkpoint` refuses a single-leg call outright and `restore` rejects a `Ws` snapshot. Securing
  the leg does not change that; it is refused for the same reason it was before.
- **Runtime lifecycle (`attach_ws_bridge` / `detach_ws_bridge`) inherits every layer above, and adds
  no new way in.** A bridge can now be attached to a call already up, moved to a different server, and
  removed again. None of that touches how a packet is accepted:
  - **An attach's `profile` is read for the wire rate and uplink processing only.** The symmetric /
    subnet-source flags that shape the gate at negotiation are not read from it, so a runtime attach
    cannot widen the gate the negotiation installed.
  - **A re-point carries the gate, the keying and the egress across; it never re-derives them.** The
    replacement bridge is handed the *live* `SourceFilter` — already narrowed to the selected pair if
    ICE has chosen one — the same `WsSecureLeg`, and the same egress watch. Rebuilding any of the
    three from the signalling would silently widen the Layer 2 gate back to the `c=` address, drop a
    secure leg's keys, and aim the downlink at an address a NATed peer cannot receive on. (The watch is
    also written with `send_replace` rather than `send`, so a selection landing while no drain task
    holds a receiver is still recorded for the bridge that follows.)
  - **Taking over a live relay keeps that relay's own gate, and follows its latch.** The bridge inherits
    the `accepted_source` from the `Forward` rule it displaces, so the leg is gated exactly as it was a
    packet earlier. Its downlink goes to the address the relay had **latched** (Layer 3) rather than the
    signalled `c=`, read through `Datapath::latched_source` — a symmetric-RTP peer's real port is
    routinely not the one its SDP advertised, so re-deriving the destination from the signalling would
    break precisely the calls the latch exists for. That read is for **continuity only**: it reports the
    media path as it stands and makes no claim that a connectivity check authenticated it, which is why
    it is a separate method from `ice_validated_source` and never feeds a trust decision.
  - **The two negotiation-time refusals now also run at runtime.** A runtime attach that would *create*
    a takeover on a secure or ICE leg is refused with the same `ws-takeover-secure-offerer` /
    `ws-takeover-ice-offerer` tokens, for the identical structural reasons: on a two-leg call the engine
    is not A's cryptographic far side, and no agent is armed to re-point a takeover leg's egress.
    Re-pointing an *existing* bridge is unaffected — that leg was keyed and armed when it was
    negotiated, and the state is carried, not rebuilt.
  - **A bot can take over the engine's own leg.** On a single-leg call running on the engine's pipeline
    the attach stops the pipeline and **awaits** its exit before the bridge is installed, so the two
    never send on one endpoint together (RFC 3550 §5.1) and never share one SDES context (RFC 3711
    §9.1: one index, two senders, is a two-time pad). The context then *moves* to the bridge — the
    call's handle is the last one left, so it is unwrapped rather than cloned — and the gate is drawn
    from the call's stored posture exactly as the pipeline's was. Everything that can refuse does so
    before the pipeline stops; anything that fails after it puts the call back on a pipeline rather
    than leaving it with no media path.
  - **A detach restores exactly what the attach displaced.** The stored `Forward` rules are reinstalled
    verbatim, gate and latch policy included; the datapath keeps the latch in separate state, so a flow
    install does not disturb it and a NATed leg keeps the path it had. A bridge that was *negotiated*
    (`ws_uri`) on a single-leg call displaced nothing; its detach promotes the leg onto the engine's
    own pipeline, whose source gate is drawn from the call's stored posture and `received-from` hint —
    the same inputs the bridge's gate was drawn from, so the gate does not widen across the
    hand-over. An SDES leg's `SecureLeg` is moved, not re-derived, so the peer's rollover counter and
    replay window carry over (RFC 3711 §3.3.1). A DTLS leg keeps its association: the bridge's flow
    is retargeted from one owner to the other (`DtlsBridge::retarget`) and the key moves with it,
    so the peer sees no new handshake (RFC 8842 §5.5); a flow whose handshake is still running is
    not moved, since its session would key the owner being torn down. An ICE leg keeps its agent:
    each new owner starts on the pair already selected, and a selection that landed while neither
    owner had a route is read again once the new one exists. A two-leg negotiated takeover is
    refused before anything stops.
  - **An ICE takeover leg's downlink has no destination until its agent selects.** `WsEgress` holds
    `None` rather than the signalled address, so the drain sends nothing before the selection (RFC
    8445 §12), as a conference seat and the engine's own pipeline already did.
  - **`block_media` / `unblock_media` are refused on a takeover call.** A taken-over call still holds
    the displaced relay's `Forward` rules so its detach can reinstall them, and `unblock` walks exactly
    that list — it would have pulled leg A back off the bridge silently. This joins the existing
    refusals (`play_media`, `play_dtmf`, recording, SIPREC, the tee, `block_dtmf`), so the "one egress
    site" property above still holds.

### Layer 6 — Media timeout & dead-path teardown
A flow that has received no *accepted* packet for `T` ticks is torn down and reported.

> **Status (landed):** the **reaper + event delivery** — `Engine::reap_idle(idle_ticks,
> held_idle_ticks, setup_ticks)` frees calls whose media has been idle (returning their ports/FDs and
> registry/quota slots) and pushes `Event::MediaTimeout` to the owning control connection over the
> server's per-connection event channel (`Engine::register_client` + the connection `select!`-loop;
> bounded, drop-on-backpressure). Activity is stamped on every accepted packet against the datapath's
> logical clock (`now_ticks` / `advance_clock` / `last_activity`); the daemon advances it ~1 tick/s
> and sweeps.

- Frees ports/FDs (availability), surfaces one-way-audio and failed-NAT cases, and is the non-ICE
  analogue of consent loss.
- **Determinism:** the sweep clock is an injected tick source — `tokio::time` advances it in
  production, tests advance it explicitly via `advance_clock` (project rule: never `Instant::now()`).
- **Silence is only evidence while someone was expected to speak.** A dead media path and a call on
  hold are *identical* at the packet layer, and only the SDP distinguishes them. RFC 3264 §8.4 defines
  hold as an offer marked `sendonly` (answered `recvonly`), or `inactive` when both ends hold it, and
  is explicit that the holding party *"MAY send media (e.g., music on hold) or MAY send nothing"* — so
  `sendonly` guarantees a packet no more than `recvonly` does. Hold, park and queue are all this state
  and they last minutes, so a rule that reads "no packets from anyone" tears the call down while the
  user is still holding the handset.

  The engine therefore parses the direction attribute (RFC 4566 §6 / RFC 8866 §6.7, media-level
  winning over session-level — `sdp::MediaDirection`) on every offer, answer and `reoffer`, records it
  per party (`Call::near_direction` / `far_direction`), and treats a call where **either** party has
  taken the stream off `sendrecv` as *held* (`Call::is_held`). A held call is measured against
  `--held-media-timeout-secs` (default 7200, `0` = never) rather than `--media-timeout-secs`; an
  unhold re-offer re-arms the short timer, and the `Event::MediaTimeout` `reason`
  (`no_media` / `held_too_long`) reports which rule fired. Everything else is unchanged, down to the
  endpoint set read — a held call carrying music-on-hold refreshes its own ceiling like any other.

  **This does not weaken the gate.** The direction attribute only selects *which ceiling* applies; it
  never makes a packet acceptable. Liveness is still claimed only for media that cleared the source
  gate and, where there is crypto, SRTP authentication, so an attacker cannot extend a call's life by
  spraying it — and cannot shorten one either, since the attribute comes from the signalling path the
  controller already owns, not from the media path.
- **Silence that was never due is not evidence at all.** A controller anchors media when it *builds
  the offer*, before it dials, so a call that is still ringing has no media by definition — its
  activity sits at `Call::created_tick` because nothing was ever asked for, not because something
  stopped. Measured against `--media-timeout-secs` the anchor's budget races the controller's own ring
  budget and wins it (the anchor was created a fraction of a second before the ring deadline was
  armed), so a call that merely rang out is reported as a media fault and the controller's ring-timeout
  path — where its failure response and route-failure hook live — never runs.

  A call anchored by `offer` (`Call::anchored_before_answer`) that has carried **no** accepted packet
  on any endpoint is therefore measured against `--setup-timeout-secs` (default 300, `0` = never) and
  reported as `setup_timeout`. `answer_local` is excluded — that command *is* the answer, so media is
  due one round trip later — as is a call restored from an HA checkpoint, which was answered on the
  node that checkpointed it and whose media path the standby adopts live. The three ceilings are tried
  held → setup → dead path: the setup rule is the narrower claim, and the first accepted packet on any
  leg moves the call onto the dead-path rule for the rest of its life (`last_activity` is sticky), so a
  mid-call failure is still reaped at `--media-timeout-secs` unchanged. This is the split rtpengine
  makes between its `timeout` and its `silent-timeout`.

  **This does not weaken the gate either.** The ceiling is selected from how the call was *signalled*
  and from whether a packet has ever cleared the gate — never from the contents of an unaccepted one.
  An off-path attacker spraying a ringing call's port therefore moves nothing: its packets are dropped
  before they are stamped, and a dropped packet is neither liveness nor a first packet. A source that
  *does* pass the gate would move the call onto the shorter dead-path ceiling — but a source that
  passes the gate is, by construction, indistinguishable from the signalled peer, and it can already
  inject media, which is the larger problem the earlier layers exist to prevent. Note the direction:
  the setup ceiling is the longer one, so the only thing a gate-passing source can do here is shorten
  a budget, never extend one.
- **Conference seats follow the same rule** (`ConferenceRegistry::reap_idle`): a participant that
  joined `recvonly` or `inactive` — a listen-only webinar attendee — owes the room no media, so it is
  measured against the held ceiling instead of the media timeout. Seats have no *setup* ceiling: a
  controller only seats a leg it has already answered, so a seat is never in setup.

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
- **Engine** ([engine/src/engine/answer.rs](https://github.com/siphon-project/siphon-rtp/blob/main/crates/siphon-rtp-engine/src/engine/answer.rs)) fills
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
- **Control authz.** **Landed:** every call is owned by the `ClientId` of the control client that
  created it via `offer`; `answer` / `query` / `delete` from any other client see the call as
  unknown (so a client cannot tear down, inspect, or even probe for a call it does not own), and
  `list` returns only the caller's own calls.
- **Call scope relaxes ownership, on purpose.** **Landed:** a control frame may name a `scope`,
  and the engine keys the call by `(scope, call_id)` so that several functions on one call path
  can share an engine. An unscoped call is owned exactly as above. A scoped call is reachable by
  **every** client that names its scope, because two instances of one function have to be able
  to answer and release each other's offers. `list` stays the creating client's own calls, in one
  scope per request, so a controller's orphan reap still cannot delete a peer's calls. A scope is
  a name, not a credential: it is bounded (64 bytes of ASCII letters, digits, `-`, `_`) and
  validated on every verb, but any authenticated client may name any scope. **Remaining:**
  restricting scopes per connection, which needs a credential per controller before it means
  anything (one shared secret cannot tell controllers apart).
- **Control-client identity survives a reconnect.** **Landed:** `Authenticate` carries an optional
  `controller_id`, the stable identity of the controller *process*. The server resolves it to a
  `ClientId` — minted from the connection's own ordinal on first sight, returned unchanged on every
  later connection — so a reconnect re-attaches to the calls, the event sink and the quota row it
  already owned. A connection that presents no id keeps connection-scoped identity, which is the
  previous behaviour exactly.
  This is not a restart-only concern: the controller reconnects with backoff for the life of its
  process, and identity bound to the socket meant a TCP blip stranded every call that was live at
  that moment — `delete` answered `unknown call` so signalling could never tear the call down, a
  re-INVITE could not be renegotiated, the call-id was poisoned for the life of the dialog, and the
  `CallSummary` media CDR was pushed to a client that had gone. Ports, FDs and pipelines then stayed
  held until the idle reaper found them, and an orphan whose media still flowed was never idle.
  **Every scope is unchanged:** `list` and `delete` stay owner-scoped, and no all-scope variant of
  either exists — widening them would let one node delete another node's live calls on a shared
  engine. Once identity is stable the existing owner-scoped `list` is exactly the enumeration a
  controller's startup orphan reap needs, and it is safe on a shared engine by construction.
  A controller id is an **identity claim, not a credential**: where a secret is configured it is
  honoured only on a connection that presented the matching token; where none is configured any
  client can claim any id, which is the posture the whole control plane already has without a
  secret (see *Channel security* below for what closes that). It is claimed once per connection,
  never over live calls or joined conference seats, and is bounded in length — the engine retains a
  row per identity for as long as that identity owns calls or seats that joined a room, and drops it
  as soon as no connection is attached and none is left under it. **Remaining:** one live connection per identity — a second closes the first, newest
  wins, logged at `warn`. A genuine controller *pool* sharing one identity needs the event sink to
  become a set.
- **Channel security.** **Landed:** optional shared-secret authentication — when
  `$SIPHON_RTP_CONTROL_SECRET` is set, or `--control-secret-file` /
  `$SIPHON_RTP_CONTROL_SECRET_FILE` names a file holding the secret, a control connection must send
  `Authenticate` with the matching token (constant-time compared) before any other verb is honoured
  (`serve_with_auth`). Neither form reaches argv. Setting both is a fatal startup error and an empty
  secret file is refused, so a provisioning mistake cannot silently leave the control plane
  unauthenticated on a node configured to require a secret.
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
  with the *correct* SSRC (simulated NAT rebind) re-latches. One check, opposite verdicts.
- **Demux:** STUN/DTLS/garbage to a media port never moves the media latch (layer 1).
- **Re-answer:** an early answer latches one far peer, the final answer moves it to another address
  with a new SSRC; the new peer's media flows, the near party's goes to the new peer, and the replaced
  peer and an off-path source spoofing the new SSRC stay gated out (layer 3, "re-answer").
- **Every backend, not only UDP-loopback:** the RTPBleed race, the hijack-versus-rebind check, the
  re-answer check and the demux check are written against the `Datapath` trait (`siphon_rtp_datapath::conformance`, behind
  the `conformance` feature), so another backend runs the same adversarial tests instead of
  inheriting none of their cover.
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
| WebSocket tee (`attach_ws_tee`) | post-decode fan-out; on a crypto bridge, between the bridge's transforms | decoded PCM — on a bridge, decoded by the tee's own task from the plaintext RTP the engine **accepted** (after the gate, the latch and the crypto), exactly where the X3 tap sits |
| Decoded recording (`start_recording`, `wav`) | the same two points as the tee | decoded PCM, written to disk. On a bridge it shares the tee's tap: an endpoint carries a set of plaintext taps keyed by consumer, so a tee and a recording coexist and each is removed without disturbing the other. The set moves with the endpoint when a renegotiation re-registers the bridge's flows |
| **Lawful interception (`attach_x3`)** | in `handle` after decrypt **and** after the authentication decision; plus both crypto bridges; in a conference room, on the seat's ingress right after the shared ingress chain accepted it and on the stream the room sends the seat, built and protected successfully, before it is queued; on a WebSocket-takeover leg, in `WsRegistry::dispatch` after the gate, the SRTP authentication and the latch, and in the bridge's drain task on the plaintext packet it sent, after it was protected and before the datagram goes out | plaintext RTP the engine **accepted**, and what the engine **sent** the seat |

The X3 tap is the strictest, and deliberately so. It must never deliver ciphertext (the agency has
no key) and must never deliver a packet the engine refused — a failed SRTP `unprotect`, a replay, or
media arriving before a DTLS handshake keys the leg — because forged traffic presented to an agency
as the target's media is worse than no delivery at all. It also runs on the SDES and DTLS **crypto
bridges**, which relay without ever entering the media pipeline: without that, a same-codec WebRTC
call would be silently uninterceptable. A bridge's taps belong to the endpoint, not to one
negotiation of the call: when a re-INVITE re-registers the bridge's flows, or replaces a DTLS
association, the rebuilt flow keeps the interception tap and the plaintext taps the old one carried.
A flow rebuilt without them would keep relaying while the delivery stopped, with nothing reporting it.

The source gate (layer 2) runs before all of them, so no consumer ever sees a packet from an
unsignalled source. See [Lawful interception](lawful-interception.md).

## 10b. Every refusal is counted, on every path

The `Forward` fast path counts its own drops. A `Redirect` endpoint does not: the datapath counts the
datagram as received and hands it on, and admission is decided by the consumer. So every consumer —
the media pipeline and its companion RTCP relays, the SDES and DTLS bridges, the conference (audio
and text), the text relay, the fax relay and the WebSocket takeover — reports each datagram through
`ingress::Ingress::record`, and `packets_dropped` means the same thing whichever path a leg is on.
Before this, only the SDES bridge counted, so a locally answered leg whose peer signalled an address
it never sent from ended with `packets_in` climbing, nothing sent and `packets_dropped: 0` — a number
that read as evidence of absence precisely when it was not.

The outcome has three values because two questions are being answered, not one:

| `Ingress` | Liveness (layer 6) | `packets_dropped` | When |
|---|---|---|---|
| `Accepted` | yes | no | past every gate |
| `DroppedFromPeer` | yes | yes | passed the source gate, then dropped: a failed SRTP authentication on the media or text pipeline, an unkeyed DTLS leg on the media pipeline, a fax datagram with no destination yet |
| `Refused` | no | yes | an unsignalled source, a latch rejection, ICE not yet selected, an unowned endpoint |

`DroppedFromPeer` keeps the liveness the media and text pipelines already gave an authentication
failure from the signalled source (a rekey or reorder must not reap a live call). Counting it does not
change what keeps a call alive; it only stops the drop being invisible. The conference and the
WebSocket takeover never counted an authentication failure as liveness and still do not.

A refusal is also logged once per flow and kind at `warn` (`ingress::RefusalLog`), naming the source
the datagram came from and the gate it failed — the signal that a NATed peer is signalling its private
address. Every later refusal of the same kind is `debug`, so a hostile stream cannot flood the log.
A datagram from the signalled peer that SRTP `unprotect` refuses is logged by *reason*, each with
its own first warning: failed authentication (the peer is not sending under the key its `a=crypto`
carried), an MKI the key does not carry, and a datagram that is not SRTP at all. The last is usually
a NAT keepalive on the media port and says nothing about the key, so it must not take the warning a
real key mismatch gets. The warning carries the datagram's size and the SSRC and sequence number its
header carries in the clear (RFC 3550 §5.1), which is what tells the causes apart without a capture.
SRTCP on a takeover leg is not counted: it has no consumer there and is discarded by design, and
counting it would give every healthy secure call a drop every few seconds.

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
  the peer sends, including STUN/TURN-shaped bytes a media socket would drop at layer 1. So `recv_loop` (`Inner::receive`)
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
| R3 | **Peer-IP denylist** (anti-SSRF / anti-reflection): loopback / link-local / multicast / private ranges / the server's own IPs are refused at CreatePermission and ChannelBind with 403, and re-checked on every relayed packet. The one exemption is the engine's own live media endpoints (below). | RFC 8656 §21 (coturn `denied-peer-ip`) | `PeerIpPolicy::permits`, `PeerIpPolicy::denied_only_by_range`, `manager::peer_access`, `manager::relay_peer_allowed` |
| R4 | **Resource bounds:** relay ports come from the bounded pool → 508 on exhaustion; a per-credential allocation quota → 486. | §5, RFC 5766 §6.2 | `AllocationManager` quota; `Datapath::alloc_endpoint` |
| R5 | **Lifetimes + explicit teardown:** allocation (600 s), permission (300 s), channel (600 s) all expire on the **logical clock**, swept by the TURN reaper (the analogue of the media-timeout sweep — *not* `Engine::reap_idle`, which would mistake a relay for an idle call); a Refresh with LIFETIME 0 deletes and frees the relay port. | RFC 5766 §6.2/§7/§8/§11 | `reap`, `delete_allocation` |
| R6 | **Per-allocation bandwidth cap** (optional) bounds a single allocation's relayed bytes. | — | `within_budget` |
| R7 | **Stateless nonce** = `base64(issued_tick ‖ HMAC(secret, issued_tick ‖ client_ip))`, bound to the client and validated by an age check against the logical clock → 438 Stale Nonce. No per-nonce map to exhaust. | RFC 5389 §10.2 | `credentials::NonceFactory` |
| R8 | **Allocation isolation** — 437 Allocation Mismatch for a second Allocate on a live 5-tuple or a non-Allocate verb without one; an Allocate retransmission (same transaction id) replays the cached response, never a 437. The 5-tuple includes the server transport + protocol, so a client's UDP/TCP/TLS allocations never collide. | RFC 5766 §6.2 | `handle_allocate` |


**R3 opt-out.** `--turn-permit-private-peers` (config key `turn_permit_private_peers`) lifts only the loopback and private-range (RFC 1918 / unique-local) denials, for a lab or CI run where the peers genuinely live on a private network (the browser-in-CI relay-only scenario is one). Link-local and multicast stay refused, and the daemon logs a warning at startup because the flag weakens the default. It is off unless set, and must not be set on a server untrusted clients can reach.

**R3 exemption: the engine's own media endpoints.** A TURN-only client on the engine's own network (a LAN deployment, or an RFC 1918 engine address behind 1:1 NAT) is handed a relayed candidate, and the engine's media port that candidate has to reach is on an address the denylist refuses, so without an exemption no media flows. `--turn-permit-private-peers` fixes that by opening every loopback and private peer, far more than the port needs. The rule is narrower, and it is two checks because a TURN permission names an IP only (RFC 8656 §9), so the IP alone cannot say which ports are meant:

- At **CreatePermission and ChannelBind**, an IP the policy denies *only* as loopback or private (`PeerIpPolicy::denied_only_by_range`) is accepted when the engine has a live media endpoint bound on it (`OwnMediaEndpoints::hosts_media_on`). Any other private IP is still 403. An address in `denied`, the unspecified address, and link-local and multicast stay 403 even when the engine is bound there, since RFC 8656 §21 gives no reason to relay to them.
- On **every relayed packet toward or from such a peer** (Send indication, ChannelData, and the peer-to-client direction) the `(IP, port)` pair must be a live engine media endpoint at that moment (`OwnMediaEndpoints::is_live_media_endpoint`, the engine's `MediaEndpointRegistry`, a sharded-map read that takes a shard read lock for the lookup and allocates nothing, about 26 ns). A packet for any other port of the host, including the TURN listeners and the relay sockets of every allocation (relay-to-relay hairpin), is dropped and logged at debug. A call that ends drops out of the registry on the release funnel, before its socket closes, so the permission a client still holds (it lasts 300 s) never reaches whatever binds that port next.
- Every peer address is canonicalised (`IpAddr::to_canonical`) on arrival, before the policy, the permission and channel tables, the registry lookup and the fast-path offer, so an IPv4-mapped IPv6 spelling (`::ffff:127.0.0.1`) gets exactly the rule of the plain IPv4 form: it cannot slip past the loopback, private or explicit `denied` checks, and a mapped engine endpoint gets the same per-port rule, no wider. Canonical rather than refused, because the relay socket is IPv4 and could not send to the mapped form anyway.
- A channel to such a peer is never offered to the kernel fast path: the in-kernel rewrite is fixed at bind time and cannot check liveness per packet.
- Peers the policy already permits skip all of this. With no registry configured the denylist is exactly as before.

**Residual window.** The liveness check and the send are not one atomic step across tasks. On the client-to-peer path (Send indication, ChannelData) there is no `.await` between `relay_peer_allowed` and the call to `datapath.send`, so the window is the time between the check and the datagram being handed to the kernel; a call torn down on another thread inside it can still have one packet addressed to a port that something else has meanwhile bound. The peer-to-client path checks the peer before the packet is delivered to the client and sends nothing to the peer, so it has no such window. The registry entry is removed before the socket is closed (`release_endpoint`), which keeps the window to that one in-flight packet.

What this does **not** do: the relayed packet arrives at the media endpoint from the engine's own relay address, so it passes that endpoint's own source gate (§4) only if the call signalled that address. A call whose leg accepts any source (`symmetric` latching) accepts a packet from any TURN client that holds a valid credential and a permission on the engine's IP, which is the same exposure that leg has from the open network. The registry holds endpoints by their bound address, so an endpoint bound to a wildcard address is never matched; bind media to a concrete address (`--relay-bind-ip`, or a named interface) to use this. The in-kernel XDP datapath is not covered: a packet the relay sends to a local address is delivered by the host's loopback path, which the XDP program does not see, and this has only been exercised on the UDP datapath.

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
  address of the call's family falls back to the datapath's own address when that is of the family,
  and is otherwise refused (`no IPv6 media address configured`). There is never a cross-family bind
  (a v4 address in a `c=IN IP6` line is invalid SDP) and never a loopback one on a routable relay
  (a peer told to send to `::1` sends to itself).
- **Datapath reach:** the UDP backend binds any source IP directly. The XDP fast path carries a per-flow
  source IP end-to-end already (`FlowAction.out_local_ipv4`, no eBPF change), so per-leg source IPs work
  for addresses on its **one attached NIC**; a second source IP on a *different* NIC needs a second
  AF_XDP socket and is a follow-up (the advertised-IP override still works there).
- **HA:** the checkpoint records each leg's advertised IP and its full bound `ip:port`, and restore
  re-binds the exact source IP (`Datapath::alloc_endpoint_on_port_at`), so a call pinned to a named
  interface resumes on the same source and re-advertises the same public IP on a standby.
