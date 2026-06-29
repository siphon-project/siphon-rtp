# siphon-rtp-media

The media plane for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): the RTP/RTCP packet
model, jitter buffer + PLC, resampling, the per-leg pipeline, fan-out / fork, the mixer, and the
stream bridges.

Pure, sync, allocation-light, and NIC-free, with criterion benches on the per-channel relay and
media hot paths. The packet parsers are fuzzed so a hostile bitstream off the network decodes-or-
errors — never panics.

```toml
[dependencies]
siphon-rtp-media = "0.1"
```

## License

MIT
