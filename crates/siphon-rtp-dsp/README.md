# siphon-rtp-dsp

Pure-Rust audio DSP for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): a resampler
today, with VAD / NS / AEC to follow.

Sync, allocation-light, and **deterministic** — driven by a logical sample-clock, never
`Instant::now()` — so its tests never flake. Zero C dependencies.

```toml
[dependencies]
siphon-rtp-dsp = "0.1"
```

## License

MIT
