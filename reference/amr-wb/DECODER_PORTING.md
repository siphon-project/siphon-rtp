# AMR-WB decoder port — roadmap (TS 26.173 fixed-point C → bit-exact Rust)

Working notes for porting the AMR-WB **decoder** to pure Rust, validated bit-exact against the
official vectors. Reference C is in `c-code/` (gitignored), vectors in `testv/` (gitignored).
Decode is the Scenario-2 priority (AMR-WB → G.711a transcode needs decode first).

## Acceptance test (the gate)
Decode `testv/tst_mN.cod` → must byte-equal `testv/tst_mN.out`, for each mode N = 0..8 (+ `tst_md`
for DTX). 200 frames each (`tst.inp` = 128000 B = 64000 samples / 320 = 200 frames @ 16 kHz).

### `.cod` format (G.192 "default", confirmed from file sizes)
Per 20 ms frame, little-endian `Word16`: `[TXRXFLAG, FrameType, Mode, bit_0 … bit_{N-1}]`.
- `TXRXFLAG`: 0x6B21 (from encoder) / 0x6B20 (bad frame). `Mode` = 0..8. `N` = speech bits for the
  mode (`AMRWB_SPEECH_BITS`: m0→132, m2→253, m8→477).
- Each databit word: `+127` = bit 1, `-127` = bit 0. (Frame size check: m0 cod = 200·(3+132)·2 =
  54000 B ✓; m2 = 200·(3+253)·2 = 102400 ✓; m8 = 200·(3+477)·2 = 192000 ✓.)
- `.inp`/`.out`: headerless 16-bit signed LE PCM @16 kHz, 320 samples/frame.
- These vectors do NOT start with a homing frame — decode regular speech from frame 0. First frame
  is not otherwise special (state inits to fixed `isp_init[]`; `first_frame` just copies ispnew→ispold).

The decoder's bit input order is the **encoder output order** (what `Bits2prm`/`Serial_parm` expect),
which is the bit order in `.cod` directly — NOT the RTP sorted order. The RTP payload (payload.rs)
needs the RFC 4867 sorting/`reorder` step before feeding the core decoder; the `.cod` harness feeds
the bits straight in.

## Progress
- ✅ **basic_ops.rs** — ITU-T 16/32-bit operators (pre-existing) + `l_shr_r` (this port).
- ✅ **math_op.rs** — isqrt/isqrt_n, pow2, log2/log2_norm, dot_product12, random (bit-exact, tested).
- ⬜ everything below.

## Tier order (leaf-first; unit-test each tier)
1. **Constants** (`cnst.h`): L_FRAME=256 (12.8 k internal), L_SUBFR=64, M=16, M16k=20, PIT_MIN/MAX,
   L_INTERPOL=16, PREEMPH_FAC, NB modes table `nb_of_bits[]`, `isp_init[]`. → `wb/constants.rs`
2. **Extended 32-bit ops** (`oper_32b.c`): `L_Extract`, `Mpy_32_16`, `Mpy_32`, `L_Comp`, `Div_32`.
   → add to basic_ops (math_op already covers the math layer).
3. **DSP filters**: `syn_filt.c` (Syn_filt_32, the order-16 LPC synthesis @12.8k, hi/lo split),
   `deemph.c` (Deemph_32), `hp50.c`/`hp400.c`, `decim54.c` (Oversamp_16k, 5/4 polyphase, L_FILT=12),
   `hp6k.c`/`hp7k.c` (HF band-pass). → `wb/filters.rs`
4. **LPC/ISP**: `isp_isf.c` (Isf_isp/Isp_isf), `isp_az.c` (Isp_Az → LPC coeffs), `int_lpc.c`
   (Int_isp interpolation to 4 subframes). → `wb/lpc.rs`
5. **Pitch**: `pred_lt4.c` (Pred_lt4, 1/4-sample interp via inter4_2[]), `pit_shrp.c` (Pit_shrp),
   `lagconc.c`. → `wb/pitch.rs`
6. **Algebraic codebook**: `q_pulse.c` (dec_1p_N1 … dec_6p_6N_2), `d2t64fx.c` (DEC_ACELP_2t64_fx),
   `d4t64fx.c` (DEC_ACELP_4t64_fx). → `wb/codebook.rs`
7. **ISF dequant**: `qpisf_2s.c` (Dpisf_2s_36b / Dpisf_2s_46b), `qisf_ns.c` (Disf_ns, DTX).
   → `wb/isf_dequant.rs` (+ the big `.tab` codebooks)
8. **Gains**: `d_gain2.c` (D_gain2 + t_qua_gain6b/7b tables, the gain-predictor state). → `wb/gains.rs`
9. **Enhancers**: `ph_disp.c` (Phase_dispersion), `voicefac.c` (voice_factor), the noise/pitch
   enhancer math inside dec_main. → `wb/enhance.rs`
10. **DTX/CNG**: `dtx.c` (rx_dtx_handler, dtx_dec, comfort noise). → `wb/dtx.rs` (after speech path works)
11. **Bitstream**: `bits.c` (Serial_parm, Bits2prm per-mode bit-allocation). → `wb/bitstream.rs`
12. **dec_main**: `dec_main.c` `decoder()` — the per-frame orchestration + `synthesis()`; the
    `Decoder_State` struct; Init/Reset. → `wb/dec_main.rs`; wire into `AmrWb::decode`.

## Decoder_State fields (frame-to-frame) — see subagent map / dec_main.h
ispold[M], isfold[M], isf_buf[3*M], past_isfq[M]; old_exc[PIT_MAX+L_INTERPOL]; old_T0, old_T0_frac,
lag_hist[5]; dec_gain[23] (gain-predictor mem incl. CNG seed); mem_syn_hi[M], mem_syn_lo[M],
mem_syn_hf[M16k]; mem_deemph, mem_sig_out[6], mem_hp400[6], mem_oversamp[2*L_FILT], mem_hf*[…];
Q_old, Qsubfr[4], L_gc_thres, tilt_code; seed/seed2/seed3, prev_bfi, state (BFI machine);
dtx_decSt, vad_hist; first_frame.

## Per-frame pipeline (dec_main `decoder()`), see subagent map for the full step list
DTX handler → ISF dequant (36b ≤7k / 46b >7k) → Isf_isp → Int_isp → per-subframe ×4 { pitch lag
decode, Pred_lt4, [LP filter select], algebraic codebook decode, Preemph+Pit_shrp, D_gain2, excitation
scaling (Q_new), voice_factor/tilt, build exc = code·gcode + adapt·gpit, Phase_dispersion, noise/pitch
enhance, synthesis(Syn_filt_32 → Deemph_32 → HP50 → Oversamp_16k → HF synth add) } → save exc history.

## Smallest first milestone
Decode mode-0 (7.5 k, 132 bits, DEC_ACELP_2t64_fx — the simplest codebook) frame 0 and match the first
320 samples of `tst_m0.out`; then all 200 frames (proves state mgmt). Mode 0 needs tiers 1-5,6(2t64),
7(36b),8,9,11,12 — the 46b ISF and 4t64 codebook (modes 1-8) come after.
