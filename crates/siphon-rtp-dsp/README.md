# siphon-rtp-dsp

Pure-Rust audio DSP for [siphon-rtp](https://github.com/siphon-project/siphon-rtp): resampling,
energy VAD, noise suppression, and acoustic + residual echo cancellation, built on a self-contained
radix-2 real FFT and √Hann WOLA framing.

Sync, allocation-light, and **deterministic** — driven by a logical sample-clock, never
`Instant::now()` — so its tests never flake. Zero C dependencies.

```toml
[dependencies]
siphon-rtp-dsp = "0.2"
```

## License

MIT
