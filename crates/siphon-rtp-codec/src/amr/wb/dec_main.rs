//! AMR-WB main decoder orchestration (3GPP TS 26.173 `dec_main.c`), ported bit-exact for the
//! speech path. Currently wires the **mode-0** (6.60 kbit/s, 7.5 k ISF / 2-pulse codebook) decode
//! end to end: `Bits2prm`-order parameter read → ISF dequant → ISP interpolation → per-subframe
//! adaptive + algebraic excitation → gain decode → enhancers → 12.8 kHz synthesis → 16 kHz HF
//! synthesis, producing 320 Q0 samples per 20 ms frame.
//!
//! The higher modes (4t64 codebook, 46-bit ISF) and the DTX/CNG and bad-frame concealment paths
//! are deliberately out of scope here; [`Decoder::decode`](crate::Decoder) reports
//! [`CodecError::Unsupported`](crate::CodecError) for them rather than guessing.

use super::bitstream::SerialBits;
use super::codebook::dec_acelp_2t64;
use super::constants::{
    L_FRAME, L_FRAME16K, L_INTERPOL, L_SUBFR, L_SUBFR16K, M, M16K, PIT_MAX, PIT_SHARP, PREEMPH_FAC,
};
use super::enhance::{
    agc2, filt_6k_7k, hp400_12k8, isf_extrapolation, phase_dispersion, preemph, scale_sig, syn_filt,
    voice_factor, weight_a,
};
use super::filters::{deemph_32, hp50_12k8, oversamp_16k, syn_filt_32};
use super::gains::{d_gain2, init_d_gain2, DEC_GAIN_LEN};
use super::isf_dequant::dpisf_2s_36b;
use super::lpc::{int_isp, isf_isp};
use super::pitch::{pit_shrp, pred_lt4};
use crate::amr::basic_ops::{
    abs_s, add, div_s, extract_h, l_add, l_deposit_h, l_mac, l_msu, l_mult, l_shl, l_shr, l_sub,
    mult, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::amr::math_op::{dot_product12, isqrt_n, random};
use crate::amr::oper_32b::{l_extract, mpy_32_16};

/// L_MEANBUF (ISF mean-buffer depth), shared with the ISF dequantizer.
const L_MEANBUF: usize = 3;
/// 6.60 kbit/s speech bits (mode 0).
const NBBITS_7K: usize = 132;
/// Scaling cap for the excitation (`Q_MAX`).
const Q_MAX: i16 = 8;

/// LPC interpolation fractions `{0.45, 0.8, 0.96, 1.0}` (Q15) — only `[0..3]` feed `Int_isp`.
const INTERPOL_FRAC: [i16; 4] = [14746, 26214, 31457, 32767];

/// HF correction-gain table (`HP_gain`); only nb_bits ≥ 23.85k reads it (kept for parity).
const HP_GAIN: [i16; 16] = [
    3624, 4673, 5597, 6479, 7425, 8378, 9324, 10264, 11210, 12206, 13391, 14844, 16770, 19655,
    24289, 32728,
];

/// Initial ISP set (`isp_init`, the decoder Reset state).
const ISP_INIT: [i16; M] = [
    32138, 30274, 27246, 23170, 18205, 12540, 6393, 0, -6393, -12540, -18205, -23170, -27246,
    -30274, -32138, 1475,
];

/// Initial ISF set (`isf_init`).
const ISF_INIT: [i16; M] = [
    1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192, 9216, 10240, 11264, 12288, 13312, 14336, 15360,
    3840,
];

/// Frame-to-frame decoder state (`Decoder_State`). Mode-0 subset — DTX history and the parts only
/// the higher modes touch are omitted; the laid-out fields are bit-exact with the reference.
///
/// A few fields (`seed`/`seed3`/`old_t0`/`old_t0_frac`/`mem_hf3`) are only read by the bad-frame
/// concealment and ≥ 23.85k paths, which are not yet wired here; they are carried for parity so the
/// state struct matches the reference and so those paths can be added without a layout change.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DecoderState {
    /// Old excitation history (`old_exc[PIT_MAX + L_INTERPOL]`).
    old_exc: [i16; PIT_MAX + L_INTERPOL],
    /// Old ISP (`ispold[M]`).
    ispold: [i16; M],
    /// Old ISF (`isfold[M]`).
    isfold: [i16; M],
    /// ISF history buffer (`isf_buf[L_MEANBUF * M]`).
    isf_buf: [i16; L_MEANBUF * M],
    /// Past ISF quantizer residual (`past_isfq[M]`).
    past_isfq: [i16; M],
    /// Tilt of code (`tilt_code`).
    tilt_code: i16,
    /// Old excitation scaling (`Q_old`).
    q_old: i16,
    /// Per-subframe max scaling memory (`Qsubfr[4]`).
    qsubfr: [i16; 4],
    /// Noise-enhancer gain threshold (`L_gc_thres`).
    l_gc_thres: i32,
    /// Synthesis memory MSB / LSB (`mem_syn_hi[M]`, `mem_syn_lo[M]`).
    mem_syn_hi: [i16; M],
    mem_syn_lo: [i16; M],
    /// De-emphasis memory (`mem_deemph`).
    mem_deemph: i16,
    /// HP50 synthesis memory (`mem_sig_out[6]`).
    mem_sig_out: [i16; 6],
    /// 12.8 → 16 kHz oversampling memory (`mem_oversamp[2*L_FILT]`).
    mem_oversamp: [i16; 24],
    /// HF synthesis memory (`mem_syn_hf[M16k]`).
    mem_syn_hf: [i16; M16K],
    /// HF band-pass filter memory (`mem_hf[2*L_FILT16k]` → 30).
    mem_hf: [i16; 30],
    /// HF low-pass filter memory (`mem_hf3[2*L_FILT16k]` → 30), nb_bits ≥ 24k only.
    mem_hf3: [i16; 30],
    /// Random memory for frame erasure (`seed`).
    seed: i16,
    /// Random memory for HF generation (`seed2`).
    seed2: i16,
    /// Old pitch lag / fraction (`old_T0`, `old_T0_frac`).
    old_t0: i16,
    old_t0_frac: i16,
    /// LTP lag history (`lag_hist[5]`).
    lag_hist: [i16; 5],
    /// Gain decoder memory (`dec_gain[23]`).
    dec_gain: [i16; DEC_GAIN_LEN],
    /// Random memory for lag concealment (`seed3`).
    seed3: i16,
    /// Phase dispersion memory (`disp_mem[8]`).
    disp_mem: [i16; 8],
    /// HP400 synthesis memory (`mem_hp400[6]`).
    mem_hp400: [i16; 6],
    /// Previous bad-frame indicator (`prev_bfi`).
    prev_bfi: bool,
    /// Bad-frame-handler state (`state`).
    state: i16,
    /// First-frame flag (`first_frame`).
    first_frame: bool,
    /// Non-speech frame counter (`vad_hist`).
    vad_hist: i16,
    /// Decoder-homing driver state (`reset_flag_old` in `decoder.c`); starts homed (`true`).
    reset_flag_old: bool,
}

impl Default for DecoderState {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderState {
    /// Fresh decoder state, matching `Init_decoder` / `Reset_decoder(reset_all=1)`.
    #[must_use]
    pub fn new() -> Self {
        let mut isf_buf = [0i16; L_MEANBUF * M];
        for chunk in isf_buf.chunks_exact_mut(M) {
            chunk.copy_from_slice(&ISF_INIT);
        }
        let mut dec_gain = [0i16; DEC_GAIN_LEN];
        init_d_gain2(&mut dec_gain);
        Self {
            old_exc: [0; PIT_MAX + L_INTERPOL],
            ispold: ISP_INIT,
            isfold: ISF_INIT,
            isf_buf,
            past_isfq: [0; M],
            tilt_code: 0,
            q_old: Q_MAX,
            qsubfr: [Q_MAX; 4],
            l_gc_thres: 0,
            mem_syn_hi: [0; M],
            mem_syn_lo: [0; M],
            mem_deemph: 0,
            mem_sig_out: [0; 6],
            mem_oversamp: [0; 24],
            mem_syn_hf: [0; M16K],
            mem_hf: [0; 30],
            mem_hf3: [0; 30],
            seed: 21845,
            seed2: 21845,
            old_t0: 64,
            old_t0_frac: 0,
            lag_hist: [64; 5],
            dec_gain,
            seed3: 21845,
            disp_mem: [0; 8],
            mem_hp400: [0; 6],
            prev_bfi: false,
            state: 0,
            first_frame: true,
            vad_hist: 0,
            reset_flag_old: true,
        }
    }

    /// Reset the decoder core to its init state (`Reset_decoder(reset_all=1)`), preserving the
    /// homing driver flag so the per-frame homing protocol stays consistent across the reset.
    fn reset_core(&mut self) {
        let reset_flag_old = self.reset_flag_old;
        *self = Self::new();
        self.reset_flag_old = reset_flag_old;
    }
}

/// Decode one mode-0 frame including the decoder-homing protocol (`decoder.c` per-frame flow):
/// emit the constant `EHF_MASK` while homed and receiving a homing frame, reset the core after a
/// homing frame, and mask the output to 14 bits. `bits` are the 132 speech bits in encoder order.
/// Returns `L_FRAME16K`.
pub fn decode_frame(state: &mut DecoderState, bits: &[i16], synth16k: &mut [i16]) -> usize {
    use super::homing::{homing_frame_test, homing_frame_test_first, EHF_MASK};

    // While homed, test only the first subframe of the incoming frame.
    let mut reset_flag = if state.reset_flag_old {
        homing_frame_test_first(bits)
    } else {
        false
    };

    if reset_flag && state.reset_flag_old {
        // Homed and receiving a homing frame: emit the homing mask, no synthesis.
        synth16k[..L_FRAME16K].fill(EHF_MASK);
    } else {
        decode_mode0(state, bits, synth16k);
    }

    // 14-bit output (drop the 2 LSBs).
    for sample in synth16k.iter_mut().take(L_FRAME16K) {
        *sample &= 0xfffcu16 as i16;
    }

    // If not previously homed, test the whole frame for homing.
    if !state.reset_flag_old {
        reset_flag = homing_frame_test(bits);
    }
    if reset_flag {
        state.reset_core();
    }
    state.reset_flag_old = reset_flag;

    L_FRAME16K
}

/// Decode one mode-0 speech frame from its 132 serial bits into `synth16k[0..L_FRAME16K]` (Q0).
///
/// `bits` are the speech bits in encoder/`Bits2prm` order (the `.cod` order), starting *after* the
/// frame header. Returns the number of output samples (`L_FRAME16K`). This is the raw synthesis;
/// most callers want [`decode_frame`], which also runs the decoder-homing protocol.
#[allow(clippy::needless_range_loop)]
pub fn decode_mode0(state: &mut DecoderState, bits: &[i16], synth16k: &mut [i16]) -> usize {
    let nb_bits = NBBITS_7K;
    let bfi = false;
    let unusable_frame = false;
    let mut prms = SerialBits::new(bits);

    // BFH state machine: good frame → state >> 1.
    state.state = shr(state.state, 1);

    // vad_flag is the first speech bit; update vad_hist (good frame).
    let vad_flag = prms.read(1);
    if vad_flag == 0 {
        state.vad_hist = add(state.vad_hist, 1);
    } else {
        state.vad_hist = 0;
    }

    // Working excitation buffer: old_exc[(L_FRAME+1) + PIT_MAX + L_INTERPOL]; exc starts after the
    // PIT_MAX+L_INTERPOL history.
    const HIST: usize = PIT_MAX + L_INTERPOL;
    let mut old_exc = [0i16; (L_FRAME + 1) + PIT_MAX + L_INTERPOL];
    old_exc[..HIST].copy_from_slice(&state.old_exc);
    // `exc[i]` ≡ `old_exc[HIST + i]`; negative `i` reaches the history.

    // Decode the ISFs (36-bit, 5 indices).
    let ind = [
        prms.read(8),
        prms.read(8),
        prms.read(7),
        prms.read(7),
        prms.read(6),
    ];
    let mut isf = [0i16; M];
    dpisf_2s_36b(
        &ind,
        &mut isf,
        &mut state.past_isfq,
        &state.isfold,
        &mut state.isf_buf,
        bfi,
        true,
    );

    // ISF → ISP; on the first frame seed ispold with the current ISPs.
    let mut ispnew = [0i16; M];
    isf_isp(&isf, &mut ispnew, M);
    if state.first_frame {
        state.first_frame = false;
        state.ispold = ispnew;
    }

    // Interpolate ISPs across the 4 subframes → Aq[4*(M+1)].
    let mut aq = [0i16; 4 * (M + 1)];
    int_isp(&state.ispold, &ispnew, &INTERPOL_FRAC[..3], &mut aq);
    state.ispold = ispnew;

    // Stability factor from the ISF distance.
    let mut l_tmp = 0i32;
    for i in 0..(M - 1) {
        let tmp = sub(isf[i], state.isfold[i]);
        l_tmp = l_mac(l_tmp, tmp, tmp);
    }
    let mut tmp = extract_h(l_shl(l_tmp, 8));
    tmp = mult(tmp, 26214); // L_tmp*0.8/256
    tmp = sub(20480, tmp); // 1.25 - tmp
    let mut stab_fac = shl(tmp, 1); // Q14 → Q15 sat
    if stab_fac < 0 {
        stab_fac = 0;
    }
    let isf_tmp = state.isfold; // saved old ISF for HF ISF interpolation
    state.isfold = isf;

    // T0_min carries from subframe 0 (which decodes the absolute lag) into 1..4 (relative lag),
    // exactly as the reference's function-local `T0_min`.
    let mut t0_min = 0i16;

    for sf in 0..4 {
        let i_subfr = sf * L_SUBFR;
        let pit_flag = i_subfr; // 7k: no special-case for subframe 2

        // ---- Pitch lag decode (nb_bits ≤ 9k path) ----
        const PIT_FR1_8B: i16 = 92;
        const PIT_MIN: i16 = 34;
        let t0;
        let t0_frac;
        if pit_flag == 0 {
            let index = prms.read(8);
            if sub(index, (PIT_FR1_8B - PIT_MIN) * 2) < 0 {
                let t = add(PIT_MIN, shr(index, 1));
                let mut tf = sub(index, shl(sub(t, PIT_MIN), 1));
                tf = shl(tf, 1);
                t0 = t;
                t0_frac = tf;
            } else {
                t0 = add(index, PIT_FR1_8B - ((PIT_FR1_8B - PIT_MIN) * 2));
                t0_frac = 0;
            }
            t0_min = sub(t0, 8);
            if sub(t0_min, PIT_MIN) < 0 {
                t0_min = PIT_MIN;
            }
            let mut t0_max = add(t0_min, 15);
            if sub(t0_max, PIT_MAX as i16) > 0 {
                t0_max = PIT_MAX as i16;
                t0_min = sub(t0_max, 15);
            }
        } else {
            let index = prms.read(5);
            let t = add(t0_min, shr(index, 1));
            let mut tf = sub(index, shl(sub(t, t0_min), 1));
            tf = shl(tf, 1);
            t0 = t;
            t0_frac = tf;
        }

        // ---- Adaptive codebook (pitch) excitation ----
        pred_lt4(&mut old_exc, HIST + i_subfr, t0, t0_frac, L_SUBFR + 1);

        // select = 0 (nb_bits ≤ 9k): LP filter the pitch excitation.
        let mut code = [0i16; L_SUBFR];
        for i in 0..L_SUBFR {
            let base = HIST + i_subfr + i;
            let mut acc = l_mult(5898, old_exc[base - 1]);
            acc = l_mac(acc, 20972, old_exc[base]);
            acc = l_mac(acc, 5898, old_exc[base + 1]);
            code[i] = round_word(acc);
        }
        old_exc[HIST + i_subfr..HIST + i_subfr + L_SUBFR].copy_from_slice(&code);

        // ---- Algebraic codebook (2-pulse for mode 0) ----
        let idx = prms.read(12);
        dec_acelp_2t64(idx, &mut code);

        // Preemph + pitch sharpening on the code.
        let mut tmp_mem = 0i16;
        preemph(&mut code, state.tilt_code, L_SUBFR, &mut tmp_mem);
        let mut sharp_lag = t0;
        if sub(t0_frac, 2) > 0 {
            sharp_lag = add(sharp_lag, 1);
        }
        pit_shrp(&mut code, sharp_lag as usize, PIT_SHARP, L_SUBFR);

        // ---- Gain decode (6-bit for mode 0) ----
        let gindex = prms.read(6);
        let (gain_pit, mut l_gain_code) = d_gain2(
            gindex,
            6,
            &code,
            L_SUBFR,
            bfi,
            state.prev_bfi,
            state.state,
            unusable_frame,
            state.vad_hist,
            &mut state.dec_gain,
        );

        // ---- Find Q_new and scale the excitation history ----
        let mut tmp = state.qsubfr[0];
        for i in 1..4 {
            if sub(state.qsubfr[i], tmp) < 0 {
                tmp = state.qsubfr[i];
            }
        }
        if sub(tmp, Q_MAX) > 0 {
            tmp = Q_MAX;
        }
        let mut q_new = 0i16;
        let mut l_scan = l_gain_code; // Q16
        while l_sub(l_scan, 0x0800_0000) < 0 && sub(q_new, tmp) < 0 {
            l_scan = l_shl(l_scan, 1);
            q_new = add(q_new, 1);
        }
        let mut gain_code = round_word(l_scan); // scaled gain_code with Qnew

        // Scale exc[i_subfr - HIST .. + L_SUBFR] by (Q_new - Q_old).
        let scan_start = HIST + i_subfr - HIST; // = i_subfr
        scale_sig(
            &mut old_exc[scan_start..scan_start + HIST + L_SUBFR],
            sub(q_new, state.q_old),
        );
        state.q_old = q_new;

        // ---- LTP lag history + tilt update ----
        for i in (1..=4).rev() {
            state.lag_hist[i] = state.lag_hist[i - 1];
        }
        state.lag_hist[0] = t0;
        state.old_t0 = t0;
        state.old_t0_frac = 0;

        // voice factor from the scaled pitch excitation.
        let mut exc2 = [0i16; L_SUBFR];
        exc2.copy_from_slice(&old_exc[HIST + i_subfr..HIST + i_subfr + L_SUBFR]);
        scale_sig(&mut exc2, -3);

        // 7k path runs the pit_sharp post-processing setup (excp only used if pit_sharp > 16384).
        let pit_sharp = shl(gain_pit, 1);
        let mut excp = [0i16; L_SUBFR];
        if sub(pit_sharp, 16384) > 0 {
            for i in 0..L_SUBFR {
                let t = mult(exc2[i], pit_sharp);
                let mut lp = l_mult(t, gain_pit);
                lp = l_shr(lp, 1);
                excp[i] = round_word(lp);
            }
        }

        let voice_fac = voice_factor(&exc2, -3, gain_pit, &code, gain_code, L_SUBFR);
        state.tilt_code = add(shr(voice_fac, 2), 8192);

        // ---- Total excitation (pre-enhancement), update exc[] history ----
        exc2.copy_from_slice(&old_exc[HIST + i_subfr..HIST + i_subfr + L_SUBFR]);
        for i in 0..L_SUBFR {
            let mut lp = l_mult(code[i], gain_code);
            lp = l_shl(lp, 5);
            lp = l_mac(lp, old_exc[HIST + i_subfr + i], gain_pit);
            lp = l_shl(lp, 1);
            old_exc[HIST + i_subfr + i] = round_word(lp);
        }

        // Max of excitation for next scaling.
        let mut max = 1i16;
        for i in 0..L_SUBFR {
            let a = abs_s(old_exc[HIST + i_subfr + i]);
            if sub(a, max) > 0 {
                max = a;
            }
        }
        let scale_tmp = sub(add(norm_s(max), q_new), 1);
        state.qsubfr[3] = state.qsubfr[2];
        state.qsubfr[2] = state.qsubfr[1];
        state.qsubfr[1] = state.qsubfr[0];
        state.qsubfr[0] = scale_tmp;

        // ---- Phase dispersion (j=0 for 7k) ----
        let (gc_hi, gc_lo) = l_extract(l_gain_code);
        phase_dispersion(gc_hi, gain_pit, &mut code, 0, &mut state.disp_mem);
        // Note: phase_dispersion's gain_code arg is the high word of L_gain_code (Q0 ≈ gain_code).
        let _ = gc_lo;

        // ---- Noise enhancer ----
        let mut tmp = sub(16384, shr(voice_fac, 1)); // 1=unvoiced, 0=voiced
        let fac = mult(stab_fac, tmp);

        let mut l_thr = l_gain_code;
        if l_sub(l_thr, state.l_gc_thres) < 0 {
            let (h, l) = l_extract(l_gain_code);
            l_thr = l_add(l_thr, mpy_32_16(h, l, 6226));
            if l_sub(l_thr, state.l_gc_thres) > 0 {
                l_thr = state.l_gc_thres;
            }
        } else {
            let (h, l) = l_extract(l_gain_code);
            l_thr = mpy_32_16(h, l, 27536);
            if l_sub(l_thr, state.l_gc_thres) < 0 {
                l_thr = state.l_gc_thres;
            }
        }
        state.l_gc_thres = l_thr;

        let (h, l) = l_extract(l_gain_code);
        l_gain_code = mpy_32_16(h, l, sub(32767, fac));
        let (h2, l2) = l_extract(l_thr);
        l_gain_code = l_add(l_gain_code, mpy_32_16(h2, l2, fac));

        // ---- Pitch enhancer (HP-filter the code → code2) ----
        tmp = add(shr(voice_fac, 3), 4096); // 0.25=voiced
        let mut code2 = [0i16; L_SUBFR];
        let mut lp = l_deposit_h(code[0]);
        lp = l_msu(lp, code[1], tmp);
        code2[0] = round_word(lp);
        for i in 1..(L_SUBFR - 1) {
            let mut lp = l_deposit_h(code[i]);
            lp = l_msu(lp, code[i + 1], tmp);
            lp = l_msu(lp, code[i - 1], tmp);
            code2[i] = round_word(lp);
        }
        let mut lp = l_deposit_h(code[L_SUBFR - 1]);
        lp = l_msu(lp, code[L_SUBFR - 2], tmp);
        code2[L_SUBFR - 1] = round_word(lp);

        // Build enhanced excitation exc2.
        gain_code = round_word(l_shl(l_gain_code, q_new));
        for i in 0..L_SUBFR {
            let mut lp = l_mult(code2[i], gain_code);
            lp = l_shl(lp, 5);
            lp = l_mac(lp, exc2[i], gain_pit);
            lp = l_shl(lp, 1);
            exc2[i] = round_word(lp);
        }

        // pit_sharp agc2 (only when pit_sharp > 16384).
        if sub(pit_sharp, 16384) > 0 {
            for i in 0..L_SUBFR {
                excp[i] = add(excp[i], exc2[i]);
            }
            agc2(&exc2, &mut excp, L_SUBFR);
            exc2.copy_from_slice(&excp);
        }

        // ---- HF ISF interpolation (7k path) ----
        let mut hf_isf = [0i16; M16K];
        let j = i_subfr >> 6;
        for i in 0..M {
            let mut lp = l_mult(isf_tmp[i], sub(32767, INTERPOL_FRAC[j]));
            lp = l_mac(lp, isf[i], INTERPOL_FRAC[j]);
            hf_isf[i] = round_word(lp);
        }

        // ---- Synthesis (12.8 kHz core + HF) ----
        let out_off = i_subfr * 5 / 4;
        synthesis(
            state,
            &aq[sf * (M + 1)..sf * (M + 1) + (M + 1)],
            &exc2,
            q_new,
            &mut synth16k[out_off..out_off + L_SUBFR16K],
            0,
            &mut hf_isf,
            nb_bits,
        );
    }

    // Save excitation history for the next frame.
    state
        .old_exc
        .copy_from_slice(&old_exc[L_FRAME..L_FRAME + HIST]);
    // The reference also rescales exc back and runs dtx activity update; with no DTX in mode 0
    // those buffers are never read by the speech path, so they are intentionally skipped.

    state.prev_bfi = bfi;

    L_FRAME16K
}

/// 16 kHz synthesis of one subframe with HF extension (`synthesis()` in `dec_main.c`).
#[allow(clippy::too_many_arguments)]
fn synthesis(
    state: &mut DecoderState,
    aq: &[i16],
    exc: &[i16],
    q_new: i16,
    synth16k: &mut [i16],
    prms: i16,
    hf_isf: &mut [i16],
    nb_bits: usize,
) {
    let mut synth_hi = [0i16; M + L_SUBFR];
    let mut synth_lo = [0i16; M + L_SUBFR];
    let mut synth = [0i16; L_SUBFR];
    let mut hf = [0i16; L_SUBFR16K];
    let mut ap = [0i16; M16K + 1];
    let mut hf_a = [0i16; M16K + 1];

    synth_hi[..M].copy_from_slice(&state.mem_syn_hi);
    synth_lo[..M].copy_from_slice(&state.mem_syn_lo);

    syn_filt_32(aq, M, exc, q_new, &mut synth_hi, &mut synth_lo, L_SUBFR);

    state.mem_syn_hi.copy_from_slice(&synth_hi[L_SUBFR..L_SUBFR + M]);
    state.mem_syn_lo.copy_from_slice(&synth_lo[L_SUBFR..L_SUBFR + M]);

    deemph_32(
        &synth_hi[M..],
        &synth_lo[M..],
        &mut synth,
        PREEMPH_FAC,
        &mut state.mem_deemph,
    );

    hp50_12k8(&mut synth, &mut state.mem_sig_out);

    oversamp_16k(&synth, L_SUBFR, synth16k, &mut state.mem_oversamp);

    // ---- HF noise synthesis ----
    for sample in hf.iter_mut().take(L_SUBFR16K) {
        *sample = shr(random(&mut state.seed2), 3);
    }

    // Energy of excitation (exc scaled by -3, Q_new -= 3).
    let mut exc_scaled = [0i16; L_SUBFR];
    exc_scaled.copy_from_slice(&exc[..L_SUBFR]);
    scale_sig(&mut exc_scaled, -3);
    let q_new_hf = sub(q_new, 3);

    let (l_ee, exp_ener0) = dot_product12(&exc_scaled, &exc_scaled, L_SUBFR);
    let ener = extract_h(l_ee);
    let exp_ener = sub(exp_ener0, add(q_new_hf, q_new_hf));

    let (l_hh, mut exp) = dot_product12(&hf, &hf, L_SUBFR16K);
    let mut tmp = extract_h(l_hh);
    if sub(tmp, ener) > 0 {
        tmp = shr(tmp, 1);
        exp = add(exp, 1);
    }
    let mut l_tmp = l_deposit_h(div_s(tmp, ener));
    exp = sub(exp, exp_ener);
    isqrt_n(&mut l_tmp, &mut exp);
    l_tmp = l_shl(l_tmp, add(exp, 1));
    tmp = extract_h(l_tmp); // 2 * sqrt(ener_exc / ener_hf)
    for sample in hf.iter_mut().take(L_SUBFR16K) {
        *sample = mult(*sample, tmp);
    }

    // Tilt of synthesis speech.
    hp400_12k8(&mut synth, L_SUBFR, &mut state.mem_hp400);

    let mut l_r0 = 1i32;
    for &v in &synth[..L_SUBFR] {
        l_r0 = l_mac(l_r0, v, v);
    }
    exp = norm_l(l_r0);
    let ener_r0 = extract_h(l_shl(l_r0, exp));

    let mut l_r1 = 1i32;
    for i in 1..L_SUBFR {
        l_r1 = l_mac(l_r1, synth[i], synth[i - 1]);
    }
    let r1 = extract_h(l_shl(l_r1, exp));
    let fac = if r1 > 0 { div_s(r1, ener_r0) } else { 0 };

    let gain1 = sub(32767, fac);
    let mut gain2 = mult(sub(32767, fac), 20480);
    gain2 = shl(gain2, 1);

    let (weight1, weight2) = if state.vad_hist > 0 {
        (0i16, 32767i16)
    } else {
        (32767i16, 0i16)
    };
    let mut tmp = mult(weight1, gain1);
    tmp = add(tmp, mult(weight2, gain2));
    if tmp != 0 {
        tmp = add(tmp, 1);
    }
    if sub(tmp, 3277) < 0 {
        tmp = 3277; // 0.1 in Q15
    }

    // nb_bits < 24k for mode 0 → scale HF by tmp; the ≥24k HF-correction-gain branch is parity-only.
    if nb_bits >= 477 {
        let hf_gain_ind = prms as usize;
        let hf_corr_gain = HP_GAIN[hf_gain_ind];
        for sample in hf.iter_mut().take(L_SUBFR16K) {
            *sample = shl(mult(*sample, hf_corr_gain), 1);
        }
    } else {
        for sample in hf.iter_mut().take(L_SUBFR16K) {
            *sample = mult(*sample, tmp);
        }
    }

    // nb_bits ≤ 7k && SPEECH → ISF-extrapolated HF synthesis.
    let hf_in = hf; // copy so syn_filt can read input while writing hf (the C aliases HF in place)
    if nb_bits <= NBBITS_7K {
        isf_extrapolation(hf_isf);
        // Isp_Az for the 16 kHz order (HfIsf now holds ISPs).
        super::lpc::isp_az(hf_isf, &mut hf_a, M16K, false);
        weight_a(&hf_a, &mut ap, 29491, M16K); // fac = 0.9
        syn_filt(&ap, M16K, &hf_in, &mut hf, L_SUBFR16K, &mut state.mem_syn_hf, true);
    } else {
        weight_a(aq, &mut ap, 19661, M); // fac = 0.6
        let mut mem_lo = [0i16; M];
        mem_lo.copy_from_slice(&state.mem_syn_hf[M16K - M..]);
        syn_filt(&ap[..M + 1], M, &hf_in, &mut hf, L_SUBFR16K, &mut mem_lo, true);
        state.mem_syn_hf[M16K - M..].copy_from_slice(&mem_lo);
    }

    filt_6k_7k(&mut hf, L_SUBFR16K, &mut state.mem_hf);

    // nb_bits ≥ 24k: extra 7 kHz low-pass (parity only for mode 0).
    if nb_bits >= 477 {
        super::enhance::filt_7k(&mut hf, L_SUBFR16K, &mut state.mem_hf3);
    }

    for i in 0..L_SUBFR16K {
        synth16k[i] = add(synth16k[i], hf[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Words of one mode-0 `.cod` frame: 3 header words + 132 bit words.
    const COD_FRAME_WORDS: usize = 3 + NBBITS_7K;

    fn vector_path(name: &str) -> PathBuf {
        // CARGO_MANIFEST_DIR = crates/siphon-rtp-codec; vectors live at the workspace root.
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../reference/amr-wb/testv");
        path.push(name);
        path
    }

    fn read_le_i16(bytes: &[u8]) -> Vec<i16> {
        bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect()
    }

    #[test]
    fn fresh_state_matches_reference_init() {
        let state = DecoderState::new();
        assert_eq!(state.ispold, ISP_INIT);
        assert_eq!(state.isfold, ISF_INIT);
        assert_eq!(state.q_old, Q_MAX);
        assert_eq!(state.qsubfr, [Q_MAX; 4]);
        assert_eq!(state.lag_hist, [64; 5]);
        assert_eq!(state.dec_gain[0], -14336);
        assert_eq!(state.dec_gain[22], 21845);
        assert!(state.first_frame);
        // isf_buf seeded with isf_init in each of the L_MEANBUF rows.
        for row in state.isf_buf.chunks_exact(M) {
            assert_eq!(row, ISF_INIT);
        }
    }

    #[test]
    fn decodes_first_mode0_frame_bit_exact() {
        let cod = std::fs::read(vector_path("tst_m0.cod")).expect("read tst_m0.cod");
        let out = std::fs::read(vector_path("tst_m0.out")).expect("read tst_m0.out");
        let cod_words = read_le_i16(&cod);
        let ref_pcm = read_le_i16(&out);

        // First frame: header [flag, frame_type, mode] then 132 bit words.
        assert_eq!(&cod_words[1..3], &[0, 0], "frame 0 is RX_SPEECH_GOOD, mode 0");
        let bits = &cod_words[3..COD_FRAME_WORDS];

        let mut state = DecoderState::new();
        let mut synth = [0i16; L_FRAME16K];
        let produced = decode_frame(&mut state, bits, &mut synth);
        assert_eq!(produced, L_FRAME16K);
        assert_eq!(
            &synth[..],
            &ref_pcm[..L_FRAME16K],
            "first frame must byte-equal tst_m0.out"
        );
    }

    #[test]
    fn decodes_full_mode0_vector_bit_exact() {
        let cod = std::fs::read(vector_path("tst_m0.cod")).expect("read tst_m0.cod");
        let out = std::fs::read(vector_path("tst_m0.out")).expect("read tst_m0.out");
        let cod_words = read_le_i16(&cod);
        let ref_pcm = read_le_i16(&out);

        let frames = cod_words.len() / COD_FRAME_WORDS;
        assert_eq!(frames, 200, "tst_m0.cod is 200 frames");
        assert_eq!(ref_pcm.len(), frames * L_FRAME16K);

        let mut state = DecoderState::new();
        let mut decoded = Vec::with_capacity(ref_pcm.len());
        let mut synth = [0i16; L_FRAME16K];
        for f in 0..frames {
            let base = f * COD_FRAME_WORDS;
            let bits = &cod_words[base + 3..base + COD_FRAME_WORDS];
            decode_frame(&mut state, bits, &mut synth);
            decoded.extend_from_slice(&synth);
        }

        if decoded != ref_pcm {
            // Report the first divergence to aid diagnosis.
            let first = decoded
                .iter()
                .zip(ref_pcm.iter())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            panic!(
                "mismatch at sample {first} (frame {}, offset {}): got {}, want {}",
                first / L_FRAME16K,
                first % L_FRAME16K,
                decoded[first],
                ref_pcm[first]
            );
        }
        assert_eq!(decoded, ref_pcm, "all 200 frames must byte-equal tst_m0.out");
    }
}
