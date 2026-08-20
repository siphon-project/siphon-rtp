# siphon-rtp-media

The media plane for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): the RTP/RTCP packet
model, jitter buffer + PLC, resampling, the per-leg pipeline, fan-out / fork, the mixer, DTMF
(RFC 4733) and T.140 real-time text, media playback/capture, and the stream bridges.

Pure, sync, allocation-light, and NIC-free, with criterion benches on the per-channel relay and
media hot paths. The packet parsers are fuzzed so a hostile bitstream off the network decodes-or-
errors — never panics.

```toml
[dependencies]
siphon-rtp-media = "0.2"
```

## License

MIT
