//! AMR-WB main decoder orchestration (3GPP TS 26.173 `dec_main.c`), ported bit-exact for the
//! speech path across **all 9 speech modes** (6.60 .. 23.85 kbit/s) plus bad-frame concealment.
//!
//! [`decode_frame`] runs the per-frame decoder-homing protocol (`decoder.c`) and dispatches to
//! [`decode_speech`], the generalized `decoder()` core: `Bits2prm`-order parameter read → ISF
//! dequant (36-bit for mode 0, 46-bit above) → ISP interpolation → per-subframe adaptive +
//! algebraic excitation (2-pulse for mode 0, 4-track otherwise) → gain decode → enhancers →
//! 12.8 kHz synthesis → 16 kHz HF synthesis, producing 320 Q0 samples per 20 ms frame. [`conceal`]
//! drives the same core with the bad-frame indicator set (lag/gain/ISF extrapolation, energy fade).
//!
//! DTX/CNG (comfort noise) is out of scope here; the speech and erasure paths are wired.

use super::bitstream::{NB_BITS, SerialBits};
use super::codebook::{dec_acelp_2t64, dec_acelp_4t64};
use super::constants::{
    L_FRAME, L_FRAME16K, L_INTERPOL, L_SUBFR, L_SUBFR16K, M, M16K, PIT_MAX, PIT_SHARP, PREEMPH_FAC,
};
use super::enhance::{
    agc2, filt_6k_7k, hp400_12k8, isf_extrapolation, phase_dispersion, preemph, scale_sig, syn_filt,
    voice_factor, weight_a,
};
use super::filters::{deemph_32, hp50_12k8, oversamp_16k, syn_filt_32};
use super::gains::{d_gain2, init_d_gain2, DEC_GAIN_LEN};
use super::isf_dequant::{dpisf_2s_36b, dpisf_2s_46b};
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

/// Speech-bit thresholds per the `dec_main.c` `NBBITS_*` chain.
const NBBITS_7K: usize = 132;
const NBBITS_9K: usize = 177;
const NBBITS_12K: usize = 253;
const NBBITS_14K: usize = 285;
const NBBITS_16K: usize = 317;
const NBBITS_18K: usize = 365;
const NBBITS_20K: usize = 397;
const NBBITS_24K: usize = 477;

/// Scaling cap for the excitation (`Q_MAX`).
const Q_MAX: i16 = 8;

/// Pitch lag constants (`cnst.h`).
const PIT_FR1_8B: i16 = 92;
const PIT_FR1_9B: i16 = 160;
const PIT_FR2: i16 = 128;
const PIT_MIN: i16 = 34;

/// LPC interpolation fractions `{0.45, 0.8, 0.96, 1.0}` (Q15) — only `[0..3]` feed `Int_isp`.
const INTERPOL_FRAC: [i16; 4] = [14746, 26214, 31457, 32767];

/// HF correction-gain table (`HP_gain`); only nb_bits ≥ 23.85k reads it.
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

/// Frame-to-frame decoder state (`Decoder_State`). The DTX history is omitted; the laid-out fields
/// are bit-exact with the reference so the speech and erasure paths match byte-for-byte.
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

/// Decode one good speech frame of `mode` (0..=8) including the decoder-homing protocol
/// (`decoder.c` per-frame flow): emit the constant `EHF_MASK` while homed and receiving a homing
/// frame, reset the core after a homing frame, and mask the output to 14 bits. `bits` are the speech
/// bits in encoder order (the `.cod` order). Returns `L_FRAME16K`.
pub fn decode_frame(state: &mut DecoderState, mode: u8, bits: &[i16], synth16k: &mut [i16]) -> usize {
    use super::homing::{homing_frame_test, homing_frame_test_first, EHF_MASK};

    // While homed, test only the first subframe of the incoming frame.
    let mut reset_flag = if state.reset_flag_old {
        homing_frame_test_first(bits, mode)
    } else {
        false
    };

    if reset_flag && state.reset_flag_old {
        // Homed and receiving a homing frame: emit the homing mask, no synthesis.
        synth16k[..L_FRAME16K].fill(EHF_MASK);
    } else {
        decode_speech(state, mode, bits, synth16k, false, false);
    }

    // 14-bit output (drop the 2 LSBs).
    for sample in synth16k.iter_mut().take(L_FRAME16K) {
        *sample &= 0xfffcu16 as i16;
    }

    // If not previously homed, test the whole frame for homing.
    if !state.reset_flag_old {
        reset_flag = homing_frame_test(bits, mode);
    }
    if reset_flag {
        state.reset_core();
    }
    state.reset_flag_old = reset_flag;

    L_FRAME16K
}

/// Conceal one lost/erased frame of `mode` (the `dec_main.c` bad-frame branch). Drives the decode
/// core with `bfi = 1` and `unusable_frame = 1` (RX_SPEECH_LOST / RX_NO_DATA): the ISF/gain/lag are
/// extrapolated and the innovative code is random, producing a faded continuation rather than
/// guessed audio. Writes `L_FRAME16K` masked-14-bit samples; returns `L_FRAME16K`.
pub fn conceal(state: &mut DecoderState, mode: u8, synth16k: &mut [i16]) -> usize {
    // An erased frame carries no usable bits; the decode core only reads the lag/gain/codebook
    // indices when bfi == 0, so an all-zero parameter buffer is never consumed on this path.
    let bits = [0i16; 0];
    decode_speech(state, mode, &bits, synth16k, true, true);

    for sample in synth16k.iter_mut().take(L_FRAME16K) {
        *sample &= 0xfffcu16 as i16;
    }
    // A concealed frame is never a homing frame; keep the homing driver as-is (prev_bfi advances it).
    state.reset_flag_old = false;
    L_FRAME16K
}

/// Decode one speech frame of `mode` from its serial bits into `synth16k[0..L_FRAME16K]` (Q0).
///
/// `bits` are the speech bits in encoder/`Bits2prm` order. `bfi` marks a bad frame (LSF/gain/pitch
/// concealment); `unusable_frame` additionally marks the bits as unusable (full erasure → random
/// code). Returns the number of output samples (`L_FRAME16K`). This is the raw synthesis; most
/// callers want [`decode_frame`] / [`conceal`], which also run the homing protocol / 14-bit mask.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_range_loop)]
pub fn decode_speech(
    state: &mut DecoderState,
    mode: u8,
    bits: &[i16],
    synth16k: &mut [i16],
    bfi: bool,
    unusable_frame: bool,
) -> usize {
    let nb_bits = NB_BITS[mode as usize];
    let mut prms = SerialBits::new(bits);

    // BFH state machine.
    if bfi {
        state.state = add(state.state, 1);
        if sub(state.state, 6) > 0 {
            state.state = 6;
        }
    } else {
        state.state = shr(state.state, 1);
    }

    // vad_flag is the first speech bit; update vad_hist on a good frame.
    let vad_flag = if bfi { 0 } else { prms.read(1) };
    if !bfi {
        if vad_flag == 0 {
            state.vad_hist = add(state.vad_hist, 1);
        } else {
            state.vad_hist = 0;
        }
    }

    // Working excitation buffer: old_exc[(L_FRAME+1) + PIT_MAX + L_INTERPOL]; exc starts after the
    // PIT_MAX+L_INTERPOL history.
    const HIST: usize = PIT_MAX + L_INTERPOL;
    let mut old_exc = [0i16; (L_FRAME + 1) + PIT_MAX + L_INTERPOL];
    old_exc[..HIST].copy_from_slice(&state.old_exc);
    // `exc[i]` ≡ `old_exc[HIST + i]`; negative `i` reaches the history.

    // ---- Decode the ISFs (36-bit ≤ 7k, 46-bit above) ----
    let mut isf = [0i16; M];
    if nb_bits <= NBBITS_7K {
        let ind = [
            prms.read(8),
            prms.read(8),
            prms.read(7),
            prms.read(7),
            prms.read(6),
        ];
        dpisf_2s_36b(
            &ind,
            &mut isf,
            &mut state.past_isfq,
            &state.isfold,
            &mut state.isf_buf,
            bfi,
            true,
        );
    } else {
        let ind = [
            prms.read(8),
            prms.read(8),
            prms.read(6),
            prms.read(7),
            prms.read(7),
            prms.read(5),
            prms.read(5),
        ];
        dpisf_2s_46b(
            &ind,
            &mut isf,
            &mut state.past_isfq,
            &state.isfold,
            &mut state.isf_buf,
            bfi,
            true,
        );
    }

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

    // T0_min carries from subframe 0 (absolute lag) into 1..4 (relative lag).
    let mut t0_min = 0i16;

    for sf in 0..4 {
        let i_subfr = sf * L_SUBFR;
        // pit_flag = i_subfr, except subframe 2 is a fresh absolute lag for nb_bits > 7k.
        let mut pit_flag = i_subfr as i16;
        if i_subfr == 2 * L_SUBFR && nb_bits > NBBITS_7K {
            pit_flag = 0;
        }

        // ---- Pitch lag decode ----
        let mut t0;
        let mut t0_frac;
        if pit_flag == 0 {
            if nb_bits <= NBBITS_9K {
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
            } else {
                let index = prms.read(9);
                if sub(index, (PIT_FR2 - PIT_MIN) * 4) < 0 {
                    t0 = add(PIT_MIN, shr(index, 2));
                    t0_frac = sub(index, shl(sub(t0, PIT_MIN), 2));
                } else if sub(index, ((PIT_FR2 - PIT_MIN) * 4) + ((PIT_FR1_9B - PIT_FR2) * 2)) < 0 {
                    let index = sub(index, (PIT_FR2 - PIT_MIN) * 4);
                    t0 = add(PIT_FR2, shr(index, 1));
                    let mut tf = sub(index, shl(sub(t0, PIT_FR2), 1));
                    tf = shl(tf, 1);
                    t0_frac = tf;
                } else {
                    t0 = add(
                        index,
                        PIT_FR1_9B - ((PIT_FR2 - PIT_MIN) * 4) - ((PIT_FR1_9B - PIT_FR2) * 2),
                    );
                    t0_frac = 0;
                }
            }
            // find T0_min and T0_max for subframe 2 and 4.
            t0_min = sub(t0, 8);
            if sub(t0_min, PIT_MIN) < 0 {
                t0_min = PIT_MIN;
            }
            let mut t0_max = add(t0_min, 15);
            if sub(t0_max, PIT_MAX as i16) > 0 {
                t0_max = PIT_MAX as i16;
                t0_min = sub(t0_max, 15);
            }
        } else if nb_bits <= NBBITS_9K {
            let index = prms.read(5);
            t0 = add(t0_min, shr(index, 1));
            let mut tf = sub(index, shl(sub(t0, t0_min), 1));
            tf = shl(tf, 1);
            t0_frac = tf;
        } else {
            let index = prms.read(6);
            t0 = add(t0_min, shr(index, 2));
            t0_frac = sub(index, shl(sub(t0, t0_min), 2));
        }

        // check BFI after pitch lag decoding: conceal the lag.
        if bfi {
            lagconc(
                &state.dec_gain,
                &state.lag_hist,
                &mut t0,
                &mut state.old_t0,
                &mut state.seed3,
                unusable_frame,
            );
            t0_frac = 0;
        }

        // ---- Adaptive codebook (pitch) excitation ----
        pred_lt4(&mut old_exc, HIST + i_subfr, t0, t0_frac, L_SUBFR + 1);

        // select: 1 (unusable), else 0 (≤9k) or a read bit (>9k).
        let select = if unusable_frame {
            1
        } else if nb_bits <= NBBITS_9K {
            0
        } else {
            prms.read(1)
        };

        if select == 0 {
            // find pitch excitation with lp filter.
            let mut code = [0i16; L_SUBFR];
            for i in 0..L_SUBFR {
                let base = HIST + i_subfr + i;
                let mut acc = l_mult(5898, old_exc[base - 1]);
                acc = l_mac(acc, 20972, old_exc[base]);
                acc = l_mac(acc, 5898, old_exc[base + 1]);
                code[i] = round_word(acc);
            }
            old_exc[HIST + i_subfr..HIST + i_subfr + L_SUBFR].copy_from_slice(&code);
        }

        // ---- Algebraic codebook ----
        let mut code = [0i16; L_SUBFR];
        if unusable_frame {
            for value in code.iter_mut() {
                *value = shr(random(&mut state.seed), 3);
            }
        } else if nb_bits <= NBBITS_7K {
            let idx = prms.read(12);
            dec_acelp_2t64(idx, &mut code);
        } else if nb_bits <= NBBITS_9K {
            let ind = [prms.read(5), prms.read(5), prms.read(5), prms.read(5)];
            dec_acelp_4t64(&ind, 20, &mut code);
        } else if nb_bits <= NBBITS_12K {
            let ind = [prms.read(9), prms.read(9), prms.read(9), prms.read(9)];
            dec_acelp_4t64(&ind, 36, &mut code);
        } else if nb_bits <= NBBITS_14K {
            let ind = [prms.read(13), prms.read(13), prms.read(9), prms.read(9)];
            dec_acelp_4t64(&ind, 44, &mut code);
        } else if nb_bits <= NBBITS_16K {
            let ind = [prms.read(13), prms.read(13), prms.read(13), prms.read(13)];
            dec_acelp_4t64(&ind, 52, &mut code);
        } else if nb_bits <= NBBITS_18K {
            let ind = [
                prms.read(2),
                prms.read(2),
                prms.read(2),
                prms.read(2),
                prms.read(14),
                prms.read(14),
                prms.read(14),
                prms.read(14),
            ];
            dec_acelp_4t64(&ind, 64, &mut code);
        } else if nb_bits <= NBBITS_20K {
            let ind = [
                prms.read(10),
                prms.read(10),
                prms.read(2),
                prms.read(2),
                prms.read(10),
                prms.read(10),
                prms.read(14),
                prms.read(14),
            ];
            dec_acelp_4t64(&ind, 72, &mut code);
        } else {
            let ind = [
                prms.read(11),
                prms.read(11),
                prms.read(11),
                prms.read(11),
                prms.read(11),
                prms.read(11),
                prms.read(11),
                prms.read(11),
            ];
            dec_acelp_4t64(&ind, 88, &mut code);
        }

        // Preemph + pitch sharpening on the code.
        let mut tmp_mem = 0i16;
        preemph(&mut code, state.tilt_code, L_SUBFR, &mut tmp_mem);
        let mut sharp_lag = t0;
        if sub(t0_frac, 2) > 0 {
            sharp_lag = add(sharp_lag, 1);
        }
        pit_shrp(&mut code, sharp_lag as usize, PIT_SHARP, L_SUBFR);

        // ---- Gain decode (6-bit ≤ 9k, else 7-bit) ----
        let gnbits = if nb_bits <= NBBITS_9K { 6 } else { 7 };
        let gindex = prms.read(gnbits);
        let (gain_pit, mut l_gain_code) = d_gain2(
            gindex,
            gnbits,
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
        let scan_start = i_subfr; // == HIST + i_subfr - HIST
        scale_sig(
            &mut old_exc[scan_start..scan_start + HIST + L_SUBFR],
            sub(q_new, state.q_old),
        );
        state.q_old = q_new;

        // ---- LTP lag history + tilt update (good frame only) ----
        if !bfi {
            for i in (1..=4).rev() {
                state.lag_hist[i] = state.lag_hist[i - 1];
            }
            state.lag_hist[0] = t0;
            state.old_t0 = t0;
            state.old_t0_frac = 0;
        }

        // voice factor from the scaled pitch excitation.
        let mut exc2 = [0i16; L_SUBFR];
        exc2.copy_from_slice(&old_exc[HIST + i_subfr..HIST + i_subfr + L_SUBFR]);
        scale_sig(&mut exc2, -3);

        // pit_sharp post-processing setup (≤9k only; excp used if pit_sharp > 16384).
        let mut pit_sharp = 0i16;
        let mut excp = [0i16; L_SUBFR];
        if nb_bits <= NBBITS_9K {
            pit_sharp = shl(gain_pit, 1);
            if sub(pit_sharp, 16384) > 0 {
                for i in 0..L_SUBFR {
                    let t = mult(exc2[i], pit_sharp);
                    let mut lp = l_mult(t, gain_pit);
                    lp = l_shr(lp, 1);
                    excp[i] = round_word(lp);
                }
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

        // ---- Phase dispersion: j = 0 (≤7k), 1 (≤9k), 2 (>9k) ----
        let disp_j = if nb_bits <= NBBITS_7K {
            0
        } else if nb_bits <= NBBITS_9K {
            1
        } else {
            2
        };
        let (gc_hi, _gc_lo) = l_extract(l_gain_code);
        phase_dispersion(gc_hi, gain_pit, &mut code, disp_j, &mut state.disp_mem);

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

        // pit_sharp agc2 (≤9k, only when pit_sharp > 16384).
        if nb_bits <= NBBITS_9K && sub(pit_sharp, 16384) > 0 {
            for i in 0..L_SUBFR {
                excp[i] = add(excp[i], exc2[i]);
            }
            agc2(&exc2, &mut excp, L_SUBFR);
            exc2.copy_from_slice(&excp);
        }

        // ---- HF ISF interpolation (≤7k path) ----
        let mut hf_isf = [0i16; M16K];
        if nb_bits <= NBBITS_7K {
            let j = i_subfr >> 6;
            for i in 0..M {
                let mut lp = l_mult(isf_tmp[i], sub(32767, INTERPOL_FRAC[j]));
                lp = l_mac(lp, isf[i], INTERPOL_FRAC[j]);
                hf_isf[i] = round_word(lp);
            }
        } else {
            // The >7k HF path filters with Aq directly; clear the low part of the HF synth memory.
            state.mem_syn_hf[..M16K - M].fill(0);
        }

        // ---- Synthesis (12.8 kHz core + HF). corr_gain (4 bits) only for nb_bits ≥ 24k. ----
        let corr_gain = if nb_bits >= NBBITS_24K && !bfi {
            prms.read(4)
        } else {
            0
        };
        let out_off = i_subfr * 5 / 4;
        synthesis(
            state,
            &aq[sf * (M + 1)..sf * (M + 1) + (M + 1)],
            &exc2,
            q_new,
            &mut synth16k[out_off..out_off + L_SUBFR16K],
            corr_gain,
            &mut hf_isf,
            nb_bits,
            bfi,
        );
    }

    // Save excitation history for the next frame.
    state
        .old_exc
        .copy_from_slice(&old_exc[L_FRAME..L_FRAME + HIST]);
    // The reference also rescales exc back and runs dtx activity update; with no DTX wired those
    // buffers are never read by the speech path, so they are intentionally skipped.

    state.prev_bfi = bfi;

    L_FRAME16K
}

/// LTP-lag concealment for a bad frame (`lagconc.c` `lagconc`). Reads the gain history from
/// `dec_gain[17..22]` (`pbuf2`, the 5 most recent pitch gains in Q14) and the lag history, and
/// replaces `*t0` with a constrained extrapolated lag; `seed` advances the lag-concealment RNG.
fn lagconc(
    dec_gain: &[i16; DEC_GAIN_LEN],
    lag_hist: &[i16; 5],
    t0: &mut i16,
    old_t0: &mut i16,
    seed: &mut i16,
    unusable_frame: bool,
) {
    const ONE_PER_LTPHIST: i16 = 6554;
    let gain_hist = &dec_gain[17..22]; // &dec_gain[17] in the C call

    let last_gain = gain_hist[4];
    let sec_last_gain = gain_hist[3];
    let last_lag = lag_hist[0];

    let mut min_lag = lag_hist[0];
    for &v in &lag_hist[1..] {
        if sub(v, min_lag) < 0 {
            min_lag = v;
        }
    }
    let mut max_lag = lag_hist[0];
    for &v in &lag_hist[1..] {
        if sub(v, max_lag) > 0 {
            max_lag = v;
        }
    }
    let mut min_gain = gain_hist[0];
    for &v in &gain_hist[1..] {
        if sub(v, min_gain) < 0 {
            min_gain = v;
        }
    }
    let lag_dif = sub(max_lag, min_lag);

    if unusable_frame {
        // RX_SPEECH_LOST: a small lag spread with strong gain keeps the previous lag; otherwise the
        // shared extrapolation applies (the first `lag_extrapolate` case coincides with `lag_hist[0]`).
        if sub(min_gain, 8192) > 0 && sub(lag_dif, 10) < 0 {
            *t0 = *old_t0;
        } else {
            *t0 = lag_extrapolate(lag_hist, min_gain, lag_dif, last_gain, sec_last_gain, seed);
        }
        if sub(*t0, max_lag) > 0 {
            *t0 = max_lag;
        }
        if sub(*t0, min_lag) < 0 {
            *t0 = min_lag;
        }
    } else {
        let mut mean_lag = 0i16;
        for &v in lag_hist.iter() {
            mean_lag = add(mean_lag, v);
        }
        mean_lag = mult(mean_lag, ONE_PER_LTPHIST);

        let tmp = sub(*t0, max_lag);
        let tmp2 = sub(*t0, last_lag);

        // `dec_main.c`/`lagconc.c`: a cascade of five conditions that each *keep* `*t0` unchanged;
        // only when none holds does the lag get re-estimated. Folded into one predicate (the keep
        // branches are pure no-ops, so order is immaterial — semantics are byte-identical).
        let keep = (sub(lag_dif, 10) < 0 && sub(*t0, sub(min_lag, 5)) > 0 && sub(tmp, 5) < 0)
            || (sub(last_gain, 8192) > 0
                && sub(sec_last_gain, 8192) > 0
                && add(tmp2, 10) > 0
                && sub(tmp2, 10) < 0)
            || (sub(min_gain, 6554) < 0
                && sub(last_gain, min_gain) == 0
                && sub(*t0, min_lag) > 0
                && sub(*t0, max_lag) < 0)
            || (sub(lag_dif, 70) < 0 && sub(*t0, min_lag) > 0 && sub(*t0, max_lag) < 0)
            || (sub(*t0, mean_lag) > 0 && sub(*t0, max_lag) < 0);

        if !keep {
            *t0 = lag_extrapolate(lag_hist, min_gain, lag_dif, last_gain, sec_last_gain, seed);
            if sub(*t0, max_lag) > 0 {
                *t0 = max_lag;
            }
            if sub(*t0, min_lag) < 0 {
                *t0 = min_lag;
            }
        }
    }
}

/// The shared LTP-lag fallback used by both `lagconc` branches (`lagconc.c`): take the most recent
/// lag when the gain history is stable / the lag spread is small, otherwise weight the sorted lag
/// history toward the larger lags and add a bounded random perturbation.
fn lag_extrapolate(
    lag_hist: &[i16; 5],
    min_gain: i16,
    lag_dif: i16,
    last_gain: i16,
    sec_last_gain: i16,
    seed: &mut i16,
) -> i16 {
    const ONE_PER_3: i16 = 10923;
    if (sub(min_gain, 8192) > 0 && sub(lag_dif, 10) < 0)
        || (sub(last_gain, 8192) > 0 && sub(sec_last_gain, 8192) > 0)
    {
        return lag_hist[0];
    }
    let mut lag_hist2 = *lag_hist;
    insertion_sort(&mut lag_hist2);
    let mut lag_dif = sub(lag_hist2[4], lag_hist2[2]);
    if sub(lag_dif, 40) > 0 {
        lag_dif = 40;
    }
    let d = random(seed);
    let tmp = shr(lag_dif, 1);
    let d2 = mult(tmp, d);
    let tmp = add(add(lag_hist2[2], lag_hist2[3]), lag_hist2[4]);
    add(mult(tmp, ONE_PER_3), d2)
}

/// In-place ascending insertion sort of the 5-entry lag history (`lagconc.c` `insertion_sort`).
fn insertion_sort(array: &mut [i16; 5]) {
    for i in 0..5 {
        let x = array[i];
        let mut j = i as isize - 1;
        while j >= 0 && sub(x, array[j as usize]) < 0 {
            array[(j + 1) as usize] = array[j as usize];
            j -= 1;
        }
        array[(j + 1) as usize] = x;
    }
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
    bfi: bool,
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

    // nb_bits ≥ 24k && good frame → HF correction-gain branch; else scale HF by tmp.
    if nb_bits >= NBBITS_24K && !bfi {
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

    // nb_bits ≤ 7k && SPEECH → ISF-extrapolated HF synthesis; else weight Aq.
    let hf_in = hf; // copy so syn_filt can read input while writing hf (the C aliases HF in place)
    if nb_bits <= NBBITS_7K {
        isf_extrapolation(hf_isf);
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

    // nb_bits ≥ 24k: extra 7 kHz low-pass.
    if nb_bits >= NBBITS_24K {
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

    fn vector_path(name: &str) -> PathBuf {
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

    /// Decode every frame of `tst_mN.cod` and compare with `tst_mN.out`, returning `Ok(())` or the
    /// first divergence. The `.cod` format is 3 header words (`flag, frame_type, mode`) + nb_bits
    /// speech words per frame.
    fn decode_mode_vector(mode: u8) -> Result<(), String> {
        let nb_bits = NB_BITS[mode as usize];
        let cod_frame_words = 3 + nb_bits;
        let cod = std::fs::read(vector_path(&format!("tst_m{mode}.cod")))
            .map_err(|e| format!("read tst_m{mode}.cod: {e}"))?;
        let out = std::fs::read(vector_path(&format!("tst_m{mode}.out")))
            .map_err(|e| format!("read tst_m{mode}.out: {e}"))?;
        let cod_words = read_le_i16(&cod);
        let ref_pcm = read_le_i16(&out);

        let frames = cod_words.len() / cod_frame_words;
        if frames != 200 {
            return Err(format!("tst_m{mode}.cod has {frames} frames, want 200"));
        }
        if ref_pcm.len() != frames * L_FRAME16K {
            return Err(format!("tst_m{mode}.out length {}", ref_pcm.len()));
        }

        let mut state = DecoderState::new();
        let mut synth = [0i16; L_FRAME16K];
        for f in 0..frames {
            let base = f * cod_frame_words;
            // header word [2] is the mode; sanity-check it.
            if cod_words[base + 2] != mode as i16 {
                return Err(format!(
                    "frame {f}: header mode {} != {mode}",
                    cod_words[base + 2]
                ));
            }
            let bits = &cod_words[base + 3..base + cod_frame_words];
            decode_frame(&mut state, mode, bits, &mut synth);
            for (k, (&got, &want)) in synth.iter().zip(&ref_pcm[f * L_FRAME16K..]).enumerate() {
                if got != want {
                    return Err(format!(
                        "mode {mode}: mismatch frame {f} sample {k}: got {got}, want {want}"
                    ));
                }
            }
        }
        Ok(())
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
        for row in state.isf_buf.chunks_exact(M) {
            assert_eq!(row, ISF_INIT);
        }
    }

    #[test]
    fn decodes_full_mode0_vector_bit_exact() {
        decode_mode_vector(0).expect("mode 0 must byte-equal tst_m0.out");
    }

    #[test]
    fn decodes_full_mode1_vector_bit_exact() {
        decode_mode_vector(1).expect("mode 1 must byte-equal tst_m1.out");
    }

    #[test]
    fn decodes_full_mode2_vector_bit_exact() {
        decode_mode_vector(2).expect("mode 2 (12.65k VoLTE) must byte-equal tst_m2.out");
    }

    #[test]
    fn decodes_full_mode3_vector_bit_exact() {
        decode_mode_vector(3).expect("mode 3 must byte-equal tst_m3.out");
    }

    #[test]
    fn decodes_full_mode4_vector_bit_exact() {
        decode_mode_vector(4).expect("mode 4 must byte-equal tst_m4.out");
    }

    #[test]
    fn decodes_full_mode5_vector_bit_exact() {
        decode_mode_vector(5).expect("mode 5 must byte-equal tst_m5.out");
    }

    #[test]
    fn decodes_full_mode6_vector_bit_exact() {
        decode_mode_vector(6).expect("mode 6 must byte-equal tst_m6.out");
    }

    #[test]
    fn decodes_full_mode7_vector_bit_exact() {
        decode_mode_vector(7).expect("mode 7 must byte-equal tst_m7.out");
    }

    #[test]
    fn decodes_full_mode8_vector_bit_exact() {
        decode_mode_vector(8).expect("mode 8 (23.85k) must byte-equal tst_m8.out");
    }

    #[test]
    fn first_mode0_frame_is_byte_exact() {
        let cod = std::fs::read(vector_path("tst_m0.cod")).expect("read tst_m0.cod");
        let out = std::fs::read(vector_path("tst_m0.out")).expect("read tst_m0.out");
        let cod_words = read_le_i16(&cod);
        let ref_pcm = read_le_i16(&out);
        let bits = &cod_words[3..3 + NBBITS_7K];
        let mut state = DecoderState::new();
        let mut synth = [0i16; L_FRAME16K];
        decode_frame(&mut state, 0, bits, &mut synth);
        assert_eq!(&synth[..], &ref_pcm[..L_FRAME16K]);
    }

    #[test]
    fn conceal_after_speech_is_bounded_and_finite() {
        // Decode a few good mode-2 frames, then conceal: output must be 320 samples, masked to
        // 14 bits, and never panic. PLC produces a faded continuation, not silence.
        let cod = std::fs::read(vector_path("tst_m2.cod")).expect("read tst_m2.cod");
        let cod_words = read_le_i16(&cod);
        const NB: usize = 253;
        let mut state = DecoderState::new();
        let mut synth = [0i16; L_FRAME16K];
        // Skip the two homing frames, decode some speech to warm the histories.
        for f in 0..8 {
            let base = f * (3 + NB);
            let bits = &cod_words[base + 3..base + 3 + NB];
            decode_frame(&mut state, 2, bits, &mut synth);
        }
        // Now conceal three lost frames.
        for _ in 0..3 {
            let n = conceal(&mut state, 2, &mut synth);
            assert_eq!(n, L_FRAME16K);
            for &s in synth.iter() {
                assert_eq!(s & 0x0003, 0, "output masked to 14 bits");
            }
        }
    }

    #[test]
    fn conceal_from_fresh_state_never_panics() {
        // Conceal immediately after reset (no prior speech) must still be bounded.
        let mut state = DecoderState::new();
        // Take the decoder out of the homed state so conceal exercises the synthesis path.
        state.reset_flag_old = false;
        let mut synth = [0i16; L_FRAME16K];
        for _ in 0..5 {
            let n = conceal(&mut state, 2, &mut synth);
            assert_eq!(n, L_FRAME16K);
        }
    }
}
