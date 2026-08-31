# siphon-rtp-li

ETSI TS 103 221-2 X2/X3 PDU framing, for delivering lawfully-intercepted content from the media
plane straight to a Mediation Function.

Pure Rust, std only, `#![forbid(unsafe_code)]`. The crate owns the clause 5 wire format and nothing
else — no sockets, no engine types, and no interpretation of the identifiers it carries. The XID and
Correlation ID are provisioned over X1 in the signalling plane and are copied through opaquely.

```rust
use siphon_rtp_li::attributes::{AttributeWriter, IP_PROTOCOL_UDP};
use siphon_rtp_li::clock::WallClockAnchor;
use siphon_rtp_li::{encode, PayloadDirection, PduHeader};

// Anchored once per delivery session, on its first packet.
let anchor = WallClockAnchor::anchored_now(arrival_micros);
let (seconds, nanoseconds) = anchor.timestamp(arrival_micros);

let mut attributes = Vec::new();
AttributeWriter::new(&mut attributes)
    .network_function_id("sbc-01")
    .sequence_number(sequence)
    .timestamp(seconds, nanoseconds)
    .source(peer)
    .destination(local)
    .ip_protocol(IP_PROTOCOL_UDP);

let mut pdu = Vec::new();
encode(
    &PduHeader::x3_rtp(xid, correlation_id, PayloadDirection::FromTarget),
    &attributes,
    rtp_packet,
    &mut pdu,
)?;
```

Both buffers are caller-owned so a delivery path recycles one allocation per session rather than
allocating per intercepted frame.

## Two things that are easy to get wrong

**The version field is `00 05`.** The PDU format carries its own version (0.5); it is *not* the
version of the specification document (V1.4.1). Reading it the other way round and emitting `05 00`
produces PDUs a conformant Mediation Function rejects. See `VERSION_MAJOR` for the evidence,
including a real captured PDU from an unrelated implementation.

**The timestamp is absolute.** Conditional attribute 9 is Unix seconds plus nanoseconds, not an NTP
timestamp and not a capture-relative one. The engine's per-datagram arrival stamp is a *logical*
clock on the loopback datapath and a *monotonic* clock on XDP, so it cannot be handed through
unchanged — `WallClockAnchor` reads the wall clock once per session and derives the rest from the
receive-clock delta, keeping inter-packet spacing exact while anchoring to absolute time.

## Direction is target-relative

`PayloadDirection::ToTarget` (2) and `FromTarget` (3) are defined against the intercept *target*,
not against a call leg. The engine knows which leg is which; only the warrant knows which one is the
target, so that is a required input rather than something inferred.

## Conformance

Written against **ETSI TS 103 221-2 V1.4.1 (2021-04)**. Every constant carries its clause citation
at the point it is enforced.

The framing has an authoritative external definition, so round-trips prove nothing — a shared
encode/decode bug passes one. It is checked three ways:

- **byte-exact fixtures** built by hand from the specification, never by reading our own encoder
  back;
- a **known-answer test** against the header of a PDU captured from a different implementation
  (`sipgate/li-lib-x1x2x3`), which is what caught the version field being reversed;
- an **independent decoder** — a third-party Wireshark dissector driven through `tshark` — asserting
  every header field and conditional attribute reads back as intended, and that the RTP payload
  hands off to Wireshark's own RTP dissector. See `reference/x2x3-dissector/`. Fetch it with
  `reference/x2x3-dissector/fetch.sh`; those tests skip when it is absent.

The inbound header parser eats untrusted bytes from a network peer and has a libFuzzer target
(`fuzz/fuzz_targets/li_pdu_fuzz.rs`).

### Credit where it is owed

The independent checks above exist because of other people's work: **Wireshark** and *hyavari*'s
[`x2x3PduDissector`](https://github.com/hyavari/x2x3PduDissector) provide the decoder, and
**sipgate**'s [`li-lib-x1x2x3`](https://github.com/sipgate/li-lib-x1x2x3) ships the captured PDU that
proved our version field was the wrong way round. See
[THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md) — none of it is redistributed here.

## Benchmarks

`cargo bench -p siphon-rtp-li` — per-packet framing cost, split into the TLV writer and the header
encode so a regression can be attributed rather than guessed at.
