# siphon-rtp-simd

Pure-Rust SIMD DSP primitives for [siphon-rtp](https://github.com/siphon-project/siphon-rtp) —
**runtime-detected AVX2 with a portable scalar fallback**, zero C dependencies.

Hand-vectorized hot-path kernels (FIR / dot-product, resampler, VAD, and the AMR-WB decode kernels)
shared by `siphon-rtp-codec` and `siphon-rtp-dsp`. Each kernel is bit-exact against its scalar
reference and criterion-benched.

```toml
[dependencies]
siphon-rtp-simd = "0.1"
```

## License

MIT
