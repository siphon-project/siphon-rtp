# siphon-rtp-hep

HEP3 (Homer Encapsulation Protocol v3) packet encoding for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp) — exports RTCP / QoS telemetry (with a
MOS estimate) to a Homer / VoIPmonitor capture node over UDP.

Pure Rust, `std` only, zero dependencies, matching the HEP3 wire format byte-for-byte.

```toml
[dependencies]
siphon-rtp-hep = "0.1"
```

## License

MIT
