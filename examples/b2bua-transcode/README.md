# B2BUA transcode: VoLTE (AMR-WB) ↔ PSTN (G.711)

`driver.py` drives siphon-rtp the way a back-to-back user agent (SIPhon, or any controller speaking
the native JSON-over-TCP protocol) would, to set up a transcoding call. Leg A is a VoLTE UE offering
AMR-WB; leg B is a PSTN gateway that only speaks G.711 A-law. The engine anchors both legs and
transcodes between them, per direction.

It maps to the B2BUA signalling flow:

1. Inbound INVITE from A (AMR-WB offer) → `offer` to the engine with `codec-transcode-PCMA` → send
   the rewritten SDP (now advertising PCMA) toward B.
2. B's 200 OK (PCMA answer) → `answer` to the engine → send the rewritten SDP (advertising A's own
   AMR-WB) back to A. Because A's primary codec now differs from B's, the transcoder engages.
3. Media flows: A↔engine in AMR-WB, engine↔B in PCMA.

## Run

AMR is a build feature, so start a daemon built with it, then run the driver:

```sh
cargo run -p siphon-rtp --features amr -- --control 127.0.0.1:8080
python3 driver.py                          # no dependencies; standard library only
```

The driver prints the rewritten SDP for each leg (check that B's advertises `PCMA` and A's advertises
`AMR-WB`), runs a `query`, and tears the call down with `delete` on exit. Point real RTP at the
answered ports to hear transcoded audio both ways.

## Notes

- **`--features amr` is required** for AMR-WB transcode; without it the offer is refused. G.711,
  G.722, G.726, GSM-FR are always available. See the [codec matrix](../../docs/codecs.md).
- **Forceable `codec-transcode` targets** are `PCMU`, `PCMA`, `G722`, `GSM`, `G726-32`, and (with
  `amr`) `AMR-WB`. AMR-NB is not a forceable target; AMR-NB transcode happens only when a leg
  itself offers AMR.
- **AMR-WB egress mode** defaults to mode 2 (12.65 kbit/s) and is clamped to the peer's `mode-set`
  and per-frame CMR.
- For a **secure** VoLTE access leg, set `profile.transport_protocol` to `RTP/SAVP` on the offer:
  the engine decrypts, transcodes, and re-encrypts (SDES-SRTP ↔ plaintext PSTN).

The framing is a 4-byte big-endian length prefix + JSON body; see
[docs/control/json.md](../../docs/control/json.md) for the full protocol.
