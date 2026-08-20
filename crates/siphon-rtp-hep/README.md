# siphon-rtp-hep

HEP3 (Homer Encapsulation Protocol v3) packet encoding for
[siphon-rtp](https://github.com/siphon-project/siphon-rtp) — exports RTCP / QoS telemetry (with a
MOS estimate) to a Homer / VoIPmonitor capture node over UDP.

Pure Rust, zero C, matching the HEP3 wire format byte-for-byte. The encoder is dependency-free; the
optional async UDP exporter uses `tokio`.

```toml
[dependencies]
siphon-rtp-hep = "0.2"
```

## License

MIT
