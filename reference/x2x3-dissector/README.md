# X2/X3 PDU dissector — independent decoder for the TS 103 221-2 framing

`siphon-rtp-li` emits ETSI TS 103 221-2 X2/X3 PDUs. A round-trip against our own reader would prove
nothing: a shared encode/decode bug passes one. So the framing is checked against a **third-party**
decoder that does not share our bugs, the same way the project's other encoders are checked with
Wireshark.

The decoder is a Lua dissector for Wireshark by *hyavari*, fetched rather than vendored.
`crates/siphon-rtp-li/tests/dissector.rs` drives it through `tshark` and asserts that every header
field and conditional attribute reads back as intended, and that the RTP payload hands off to
Wireshark's own RTP dissector.

## Licence — why this is fetched and never committed

**The upstream repository carries no licence file, so default copyright applies: all rights
reserved.** That is the reason for the fetch-don't-vendor arrangement rather than a stylistic
preference. The file is downloaded into this directory against a pinned hash, is gitignored, is
never committed or redistributed as part of siphon-rtp, and nothing in the build or the shipped
artifacts depends on it. Running the check means fetching your own copy from upstream, under
whatever terms the author offers.

Wireshark itself (GPL-2.0-or-later) is likewise a development tool invoked as an external process —
not linked, not bundled, not required to build or run siphon-rtp.

See [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md) for the full acknowledgement, including
sipgate's LI reference implementation, whose captured demo PDU is what established the PDU-format
version this crate emits.

## Fetching

```sh
reference/x2x3-dissector/fetch.sh
```

This writes `x2x3PduDissector.lua` next to the script and verifies its SHA-256 against the pin
below. The file is gitignored. The test **skips when it is absent**, matching how the codec
reference vectors behave, so a checkout without it still runs green — it just runs one fewer
independent check.

Requires `tshark` (built with Lua) and `text2pcap`, both from Wireshark. The test also skips if
either is missing.

## Pinned source

- Upstream: <https://github.com/hyavari/x2x3PduDissector>
- File: `x2x3PduDissector.lua`
- SHA-256: `431ef56da4c6753c349cc1c0824eabec322effd3865e8e23fce6de30cb49a545`

Re-pin deliberately: a new hash means the decoder we validate against changed, which is exactly the
kind of thing that should be a visible commit rather than a silent drift.

## Why this decoder

It is independent of our implementation and it reads the fields we care about by name
(`x2x3.version`, `x2x3.pduType`, `x2x3.headerLength`, `x2x3.payloadLength`, `x2x3.payloadFormat`,
`x2x3.payloadDirection`, `x2x3.xid`, `x2x3.correlationId`), so assertions can be specific rather
than "it did not crash". It walks conditional attributes strictly as `4 + length` with no alignment
padding, which is the property most likely to be got wrong silently.

## Note on the PDU version field

The version field is `00 05` on the wire — PDU format major 0, minor 5, which is **not** the version
of the specification document. See `VERSION_MAJOR` in `crates/siphon-rtp-li/src/lib.rs` for the
evidence, including a real captured PDU from an unrelated implementation.
