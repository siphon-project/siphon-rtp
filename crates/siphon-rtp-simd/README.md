# siphon-rtp-simd

Pure-Rust SIMD DSP primitives for [siphon-rtp](https://github.com/siphon-project/siphon-rtp) —
**runtime-detected AVX2 with a portable scalar fallback**, zero C dependencies.

Hand-vectorized dot-product (i16/f32) and sum-of-squares primitives used by the resampler, VAD, and
AMR-WB decode paths, shared by `siphon-rtp-codec` and `siphon-rtp-dsp`. Each kernel is bit-exact against its scalar
reference and criterion-benched.

```toml
[dependencies]
siphon-rtp-simd = "0.2"
```

## License

MIT
