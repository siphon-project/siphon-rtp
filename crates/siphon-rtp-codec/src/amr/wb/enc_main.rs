// AMR-WB encoder — WORK IN PROGRESS: not yet wired into the codec factory or validated
// bit-exact. Ported from the 3GPP fixed-point C reference (index loops / manual slice
// copies mirror the C, plus not-yet-used WIP code); these style + dead-code lints are
// quieted module-wide until the encoder is complete and validated, then revisited.
#![allow(
    clippy::needless_range_loop,
    clippy::manual_memcpy,
    clippy::explicit_counter_loop,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    dead_code,
    unused
)]

//! AMR-WB encoder orchestration (3GPP TS 26.190 / TS 26.173 `cod_main.c` `coder()`), ported
//! bit-exact. Drives the per-20 ms-frame analysis: pre-processing → LP analysis → ISF quantization →
//! open-loop pitch → per-subframe (closed-loop pitch, algebraic codebook search, gain VQ, excitation
//! and filter-memory updates) → `Prm2bits` parameter packing.
//!
//! Non-DTX (`allow_dtx == 0`) speech path only; the comfort-noise (`MRDTX`) and the mode-8 high-band
//! gain quantization (`synthesis()`) tiers are not yet wired (mode 8 omits the final 4-bit HF index).

use crate::amr::basic_ops::{
    abs_s, add, extract_h, l_abs, l_deposit_h, l_mac, l_msu, l_mult, l_negate, l_shl, mult, norm_s,
    round_word, shl, shr, sub,
};
use crate::amr::wb::bitstream::parm_serial;
use crate::amr::wb::codebook::{dec_acelp_2t64, dec_acelp_4t64};
use crate::amr::wb::constants::{GP_CLIP, L_INTERPOL, PIT_MAX, PIT_MIN, PIT_SHARP};
use crate::amr::wb::enc_acelp::{
    acelp_2t64_fx, convolve, cor_h_x, g_pitch, gp_clip, gp_clip_test_gain_pit, gp_clip_test_isf,
    init_gp_clip, init_q_gain2, preemph, preemph2, q_gain2, quant_2p_2n1, quant_3p_3n1,
    quant_4p_4n, quant_5p_5n, quant_6p_6n_2, quant_1p_n1, syn_filt, updt_tar, voice_factor,
};
use crate::amr::wb::enc_lpc::{
    autocorr, az_isp, decim_12k8, hp50_12k8, lag_window, levinson, lp_decim2, qpisf_2s_36b,
    qpisf_2s_46b, residu, weight_a, GAMMA1, L_FILT, L_FRAME, L_FRAME16K, L_NEXT, L_SUBFR, L_TOTAL,
    L_WINDOW, PREEMPH_FAC, Q_MAX, TILT_FAC,
};
use crate::amr::wb::enc_pitch::{med_olag, pitch_med_ol, scale_mem_hp_wsp};
use crate::amr::wb::enc_vad::{wb_vad, wb_vad_tone_detection, VadState};
use crate::amr::wb::lpc::{int_isp, isf_isp, isp_isf};

const M: usize = 16;
const NB_SUBFR: usize = 4;
const OPL_DECIM: usize = 2;
const PIT_FR2: i16 = 128;
const PIT_FR1_9B: i16 = 160;
const PIT_FR1_8B: i16 = 92;

const NBBITS_7K: i16 = 132;
const NBBITS_9K: i16 = 177;
const NBBITS_12K: i16 = 253;
const NBBITS_14K: i16 = 285;
const NBBITS_16K: i16 = 317;
const NBBITS_18K: i16 = 365;
const NBBITS_20K: i16 = 397;
const NBBITS_24K: i16 = 477;

/// `nb_of_bits[mode]` (`bits.h`), speech modes 0..=8.
const NB_OF_BITS: [i16; 9] = [132, 177, 253, 285, 317, 365, 397, 461, 477];

/// LPC interpolation fractions {0.45, 0.8, 0.96} Q15 (`cod_main.c` `interpol_frac`, last 1.0 implicit).
const INTERPOL_FRAC: [i16; 3] = [14746, 26214, 31457];

/// Initial ISP (`cod_main.c` `isp_init`).
#[rustfmt::skip]
const ISP_INIT: [i16; M] = [
    32138, 30274, 27246, 23170, 18205, 12540, 6393, 0,
    -6393, -12540, -18205, -23170, -27246, -30274, -32138, 1475,
];
/// Initial ISF (`cod_main.c` `isf_init`).
#[rustfmt::skip]
const ISF_INIT: [i16; M] = [
    1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192,
    9216, 10240, 11264, 12288, 13312, 14336, 15360, 3840,
];

/// L_MEANBUF for the ISF dequant history.
const L_MEANBUF: usize = 3;

/// AMR-WB encoder state (`Coder_State`), the analysis-side single-owner working set.
#[derive(Clone, Debug)]
pub struct EncoderState {
    old_speech: [i16; L_TOTAL - L_FRAME], // 128
    old_wsp: [i16; PIT_MAX / OPL_DECIM],
    old_exc: [i16; PIT_MAX + L_INTERPOL],
    mem_decim: [i16; 2 * 15],
    mem_sig_in: [i16; 6],
    mem_preemph: i16,
    mem_wsp: i16,
    mem_decim2: [i16; 3],
    mem_levinson: [i16; 18],
    ispold: [i16; M],
    ispold_q: [i16; M],
    isfold: [i16; M],
    past_isfq: [i16; M],
    isf_buf: [i16; L_MEANBUF * M],
    mem_syn: [i16; M],
    mem_w0: i16,
    tilt_code: i16,
    first_frame: i16,
    gp_clip: [i16; 2],
    qua_gain: [i16; 4],
    hp_wsp_mem: [i16; 9],
    // cod_main.h: `old_hp_wsp[L_FRAME / OPL_DECIM + PIT_MAX / OPL_DECIM]` — sized for the 7k
    // (NBBITS_7K) path where `Pitch_med_ol` runs once over the *whole* L_FRAME/OPL_DECIM-sample
    // decimated frame (the higher modes use the half-frame `(L_FRAME/2)/OPL_DECIM` window twice and
    // never reach past `(L_FRAME/2)/OPL_DECIM + PIT_MAX/OPL_DECIM`). Init only zeroes that smaller
    // prefix (cod_main.c `Set_zero(.., (L_FRAME/2)/OPL_DECIM + PIT_MAX/OPL_DECIM)`); the tail is
    // written by `hp_wsp` before it is read, so zeroing the whole array here is bit-equivalent.
    old_hp_wsp: [i16; L_FRAME / OPL_DECIM + (PIT_MAX / OPL_DECIM)],
    old_t0_med: i16,
    ol_gain: i16,
    ada_w: i16,
    ol_wght_flg: i16,
    old_ol_lag: [i16; 5],
    old_wsp_max: i16,
    old_wsp_shift: i16,
    q_old: i16,
    q_max: [i16; 2],
    vad_hist: i16,
    vad: VadState,
}

impl Default for EncoderState {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderState {
    /// Reset to the reference's `Reset_encoder(st, 1)` initial state.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self {
            old_speech: [0; L_TOTAL - L_FRAME],
            old_wsp: [0; PIT_MAX / OPL_DECIM],
            old_exc: [0; PIT_MAX + L_INTERPOL],
            mem_decim: [0; 2 * 15],
            mem_sig_in: [0; 6],
            mem_preemph: 0,
            mem_wsp: 0,
            mem_decim2: [0; 3],
            mem_levinson: [0; 18],
            ispold: ISP_INIT,
            ispold_q: ISP_INIT,
            isfold: ISF_INIT,
            past_isfq: [0; M],
            isf_buf: [0; L_MEANBUF * M],
            mem_syn: [0; M],
            mem_w0: 0,
            tilt_code: 0,
            first_frame: 1,
            gp_clip: [0; 2],
            qua_gain: [0; 4],
            hp_wsp_mem: [0; 9],
            old_hp_wsp: [0; L_FRAME / OPL_DECIM + (PIT_MAX / OPL_DECIM)],
            old_t0_med: 40,
            ol_gain: 0,
            ada_w: 0,
            ol_wght_flg: 0,
            old_ol_lag: [40; 5],
            old_wsp_max: 0,
            old_wsp_shift: 0,
            q_old: 15,
            q_max: [15, 15],
            vad_hist: 0,
            vad: VadState::new(),
        };
        init_gp_clip(&mut s.gp_clip);
        init_q_gain2(&mut s.qua_gain);
        s
    }
}

/// Homing-frame pattern (`cnst.h` `EHF_MASK`).
const EHF_MASK: i16 = 0x0008;

/// `encoder_homing_frame_test` (`homing.c`): true iff every input sample equals `EHF_MASK`. Run on
/// the *raw* 16 kHz input before the 2-LSB delete, exactly as `cod_main.c` does.
#[must_use]
pub fn encoder_homing_frame_test(input_frame: &[i16]) -> bool {
    input_frame.iter().take(L_FRAME16K).all(|&s| s == EHF_MASK)
}

/// `Scale_sig` (`scale.c`): `x[i] = round(x[i] << exp)` via a 32-bit deposit/shift/round, so a
/// negative `exp` rounds (not truncates) — bit-exact with the reference.
fn scale_sig(x: &mut [i16], lg: usize, exp: i16) {
    for v in x.iter_mut().take(lg) {
        let l_tmp = l_shl(l_deposit_h(*v), exp);
        *v = round_word(l_tmp);
    }
}

/// Encode one 20 ms speech frame (`coder()`), modes 0..=8, non-DTX. The 16 kHz input `speech16k`
/// (320 samples) is encoded into `prms` (`nb_of_bits[mode]` `BIT_0`/`BIT_1` words, encoder order).
/// Returns the number of parameter bits written.
pub fn coder(state: &mut EncoderState, mode: u8, speech16k: &[i16], prms: &mut [i16]) -> usize {
    let ser_size = NB_OF_BITS[mode as usize];
    let mut pos = 0usize; // parameter write cursor into prms

    // Working speech / wsp / exc buffers with their layout pointers (offsets).
    let mut old_speech = [0i16; L_TOTAL];
    let mut old_wsp = [0i16; L_FRAME + PIT_MAX / OPL_DECIM];
    let mut old_exc = [0i16; (L_FRAME + 1) + PIT_MAX + L_INTERPOL];

    // pointers (offsets within the working buffers)
    let new_speech_off = L_TOTAL - L_FRAME - L_FILT; // new_speech
    let speech_off = L_TOTAL - L_FRAME - L_NEXT; // present frame
    let p_window_off = L_TOTAL - L_WINDOW;
    let exc_off = PIT_MAX + L_INTERPOL;
    let wsp_off = PIT_MAX / OPL_DECIM;

    // copy coder memory into working space
    old_speech[..L_TOTAL - L_FRAME].copy_from_slice(&state.old_speech);
    old_wsp[..PIT_MAX / OPL_DECIM].copy_from_slice(&state.old_wsp);
    old_exc[..PIT_MAX + L_INTERPOL].copy_from_slice(&state.old_exc);

    // -------- Decimation 16k -> 12.8k --------
    {
        let mut new_speech_buf = [0i16; L_FRAME + L_FILT];
        let mut mem = state.mem_decim;
        decim_12k8(speech16k, L_FRAME16K, &mut new_speech_buf, &mut mem);
        old_speech[new_speech_off..new_speech_off + L_FRAME].copy_from_slice(&new_speech_buf[..L_FRAME]);
        state.mem_decim = mem;

        // last L_FILT samples for autocorr window: code = mem_decim(2*L_FILT16k); error[0..L_FILT16k]=0
        let mut code = [0i16; 30 + 16]; // holds 2*L_FILT16k (=30) decim memory then output
        code[..30].copy_from_slice(&state.mem_decim[..30]);
        let error = [0i16; 15];
        let mut tail = [0i16; L_FILT + 4];
        decim_12k8(&error, 15, &mut tail, &mut code[..30].try_into().unwrap());
        // new_speech[L_FRAME..L_FRAME+L_FILT]
        for i in 0..L_FILT {
            old_speech[new_speech_off + L_FRAME + i] = tail[i];
        }
    }

    // -------- 50 Hz HP filtering --------
    {
        let mut block = [0i16; L_FRAME];
        block.copy_from_slice(&old_speech[new_speech_off..new_speech_off + L_FRAME]);
        let mut mem = state.mem_sig_in;
        hp50_12k8(&mut block, L_FRAME, &mut mem);
        old_speech[new_speech_off..new_speech_off + L_FRAME].copy_from_slice(&block);
        state.mem_sig_in = mem;

        // last L_FILT samples: code = mem_sig_in(6); HP50(new_speech+L_FRAME, L_FILT, code)
        let mut code = state.mem_sig_in; // copy of updated mem_sig_in (the C copies the *updated* mem)
        let mut tail = [0i16; L_FILT];
        tail.copy_from_slice(&old_speech[new_speech_off + L_FRAME..new_speech_off + L_FRAME + L_FILT]);
        hp50_12k8(&mut tail, L_FILT, &mut code);
        old_speech[new_speech_off + L_FRAME..new_speech_off + L_FRAME + L_FILT].copy_from_slice(&tail);
    }

    // -------- Pre-emphasis with scaling --------
    let mu = shr(PREEMPH_FAC, 1); // Q15 -> Q14
    // get max of new preemphased samples (L_FRAME + L_FILT)
    let mut l_max;
    {
        let ns = new_speech_off;
        let mut l_tmp = l_mult(old_speech[ns], 16384);
        l_tmp = l_msu(l_tmp, state.mem_preemph, mu);
        l_max = l_abs(l_tmp);
        for i in 1..(L_FRAME + L_FILT) {
            let mut l_tmp = l_mult(old_speech[ns + i], 16384);
            l_tmp = l_msu(l_tmp, old_speech[ns + i - 1], mu);
            l_tmp = l_abs(l_tmp);
            if l_tmp > l_max {
                l_max = l_tmp;
            }
        }
    }
    let tmp = extract_h(l_max);
    let mut shift = if tmp == 0 {
        Q_MAX
    } else {
        let mut s = sub(norm_s(tmp), 1);
        if s < 0 {
            s = 0;
        }
        if sub(s, Q_MAX) > 0 {
            s = Q_MAX;
        }
        s
    };
    let mut q_new = shift;
    if sub(q_new, state.q_max[0]) > 0 {
        q_new = state.q_max[0];
    }
    if sub(q_new, state.q_max[1]) > 0 {
        q_new = state.q_max[1];
    }
    let mut exp = sub(q_new, state.q_old);
    state.q_old = q_new;
    state.q_max[1] = state.q_max[0];
    state.q_max[0] = shift;

    // preemphasis with scaling (L_FRAME+L_FILT), in place on new_speech
    {
        let ns = new_speech_off;
        let tmp_last = old_speech[ns + L_FRAME - 1];
        for i in (1..(L_FRAME + L_FILT)).rev() {
            let mut l_tmp = l_mult(old_speech[ns + i], 16384);
            l_tmp = l_msu(l_tmp, old_speech[ns + i - 1], mu);
            l_tmp = l_shl(l_tmp, q_new);
            old_speech[ns + i] = round_word(l_tmp);
        }
        let mut l_tmp = l_mult(old_speech[ns], 16384);
        l_tmp = l_msu(l_tmp, state.mem_preemph, mu);
        l_tmp = l_shl(l_tmp, q_new);
        old_speech[ns] = round_word(l_tmp);
        state.mem_preemph = tmp_last;
    }

    // scale previous samples and memory
    scale_sig(&mut old_speech[..L_TOTAL - L_FRAME - L_FILT], L_TOTAL - L_FRAME - L_FILT, exp);
    scale_sig(&mut old_exc[..PIT_MAX + L_INTERPOL], PIT_MAX + L_INTERPOL, exp);
    scale_sig(&mut state.mem_syn, M, exp);
    scale_sig(&mut state.mem_decim2, 3, exp);
    {
        let mut t = [state.mem_wsp];
        scale_sig(&mut t, 1, exp);
        state.mem_wsp = t[0];
        let mut t = [state.mem_w0];
        scale_sig(&mut t, 1, exp);
        state.mem_w0 = t[0];
    }

    // -------- VAD --------
    let vad_flag;
    {
        let mut buf = [0i16; L_FRAME];
        buf.copy_from_slice(&old_speech[new_speech_off..new_speech_off + L_FRAME]);
        scale_sig(&mut buf, L_FRAME, sub(1, q_new));
        vad_flag = wb_vad(&mut state.vad, &buf);
        if vad_flag == 0 {
            state.vad_hist = add(state.vad_hist, 1);
        } else {
            state.vad_hist = 0;
        }
    }

    // (non-DTX) write VAD flag as the 1st parameter
    parm_serial(vad_flag, 1, prms, &mut pos);

    // -------- LP analysis --------
    let mut r_h = [0i16; M + 1];
    let mut r_l = [0i16; M + 1];
    let mut a = [0i16; NB_SUBFR * (M + 1)];
    let mut rc = [0i16; M];
    autocorr(&old_speech[p_window_off..p_window_off + L_WINDOW], M, &mut r_h, &mut r_l);
    lag_window(&mut r_h, &mut r_l);
    {
        let mut a0 = [0i16; M + 1];
        levinson(&r_h, &r_l, &mut a0, &mut rc, &mut state.mem_levinson);
        a[..M + 1].copy_from_slice(&a0);
    }
    let mut ispnew = [0i16; M];
    az_isp(&a[..M + 1], &mut ispnew, &state.ispold);
    int_isp(&state.ispold, &ispnew, &INTERPOL_FRAC, &mut a);
    state.ispold = ispnew;

    let mut isf = [0i16; M];
    isp_isf(&ispnew, &mut isf, M);

    gp_clip_test_isf(ser_size, &isf, &mut state.gp_clip);

    // -------- Open-loop pitch --------
    let mut wsp = old_wsp; // working copy; we operate via wsp_off
    // build weighted speech wsp[i_subfr..] = Residu(weight_a(A_subfr)) over present frame
    {
        let mut p_a = 0usize; // index into a (per-subframe M+1)
        let mut i_subfr = 0usize;
        while i_subfr < L_FRAME {
            let mut ap = [0i16; M + 1];
            weight_a(&a[p_a..p_a + M + 1], &mut ap, GAMMA1, M);
            // Residu(Ap, M, &speech[i_subfr], &wsp[i_subfr], L_SUBFR)
            // speech buffer = old_speech with speech_off; wsp buffer = wsp with wsp_off
            let mut out = [0i16; L_SUBFR];
            residu(&ap, M, &old_speech, speech_off + i_subfr, &mut out, L_SUBFR);
            wsp[wsp_off + i_subfr..wsp_off + i_subfr + L_SUBFR].copy_from_slice(&out);
            p_a += M + 1;
            i_subfr += L_SUBFR;
        }
    }
    // Deemph2(wsp, TILT_FAC, L_FRAME, &mem_wsp)
    {
        let mut mem = state.mem_wsp;
        deemph2(&mut wsp[wsp_off..wsp_off + L_FRAME], TILT_FAC, &mut mem);
        state.mem_wsp = mem;
    }
    // max value on wsp[] for 12-bit scaling
    let mut max = 0i16;
    for i in 0..L_FRAME {
        let t = abs_s(wsp[wsp_off + i]);
        if sub(t, max) > 0 {
            max = t;
        }
    }
    let mut tmp_m = state.old_wsp_max;
    if sub(max, tmp_m) > 0 {
        tmp_m = max;
    }
    state.old_wsp_max = max;
    let mut shift_ol = sub(norm_s(tmp_m), 3);
    if shift_ol > 0 {
        shift_ol = 0;
    }
    // LP_Decim2(wsp, L_FRAME, mem_decim2)
    {
        let mut mem = state.mem_decim2;
        lp_decim2(&mut wsp[wsp_off..wsp_off + L_FRAME], L_FRAME, &mut mem);
        state.mem_decim2 = mem;
    }
    scale_sig(&mut wsp[wsp_off..wsp_off + L_FRAME / OPL_DECIM], L_FRAME / OPL_DECIM, shift_ol);
    // scale old_wsp (exp must be Q_new-Q_old): exp = add(exp, sub(shift, old_wsp_shift))
    exp = add(exp, sub(shift_ol, state.old_wsp_shift));
    state.old_wsp_shift = shift_ol;
    scale_sig(&mut wsp[..PIT_MAX / OPL_DECIM], PIT_MAX / OPL_DECIM, exp);
    scale_sig(&mut state.old_hp_wsp, PIT_MAX / OPL_DECIM, exp);
    scale_mem_hp_wsp(&mut state.hp_wsp_mem, exp);

    // Pitch_med_ol over first half (or whole frame for 7k)
    let t_op;
    let t_op2;
    {
        let lframe = if sub(ser_size, NBBITS_7K) == 0 {
            (L_FRAME / OPL_DECIM) as i16
        } else {
            ((L_FRAME / 2) / OPL_DECIM) as i16
        };
        let mut gain = state.ol_gain;
        let t = pitch_med_ol(
            &wsp,
            wsp_off,
            (PIT_MIN / OPL_DECIM) as i16,
            (PIT_MAX / OPL_DECIM) as i16,
            lframe,
            state.old_t0_med,
            &mut gain,
            &mut state.hp_wsp_mem,
            &mut state.old_hp_wsp,
            state.ol_wght_flg,
        );
        state.ol_gain = gain;

        if sub(state.ol_gain, 19661) > 0 {
            state.old_t0_med = med_olag(t, &mut state.old_ol_lag);
            state.ada_w = 32767;
        } else {
            state.ada_w = mult(state.ada_w, 29491);
        }
        state.ol_wght_flg = if sub(state.ada_w, 26214) < 0 { 0 } else { 1 };
        wb_vad_tone_detection(&mut state.vad, state.ol_gain);
        let mut t_first = t;
        t_first *= OPL_DECIM as i16;

        if sub(ser_size, NBBITS_7K) != 0 {
            let mut gain2 = state.ol_gain;
            let t2 = pitch_med_ol(
                &wsp,
                wsp_off + ((L_FRAME / 2) / OPL_DECIM),
                (PIT_MIN / OPL_DECIM) as i16,
                (PIT_MAX / OPL_DECIM) as i16,
                ((L_FRAME / 2) / OPL_DECIM) as i16,
                state.old_t0_med,
                &mut gain2,
                &mut state.hp_wsp_mem,
                &mut state.old_hp_wsp,
                state.ol_wght_flg,
            );
            state.ol_gain = gain2;
            if sub(state.ol_gain, 19661) > 0 {
                state.old_t0_med = med_olag(t2, &mut state.old_ol_lag);
                state.ada_w = 32767;
            } else {
                state.ada_w = mult(state.ada_w, 29491);
            }
            state.ol_wght_flg = if sub(state.ada_w, 26214) < 0 { 0 } else { 1 };
            wb_vad_tone_detection(&mut state.vad, state.ol_gain);
            let t2s = t2 * OPL_DECIM as i16;
            t_op = t_first;
            t_op2 = t2s;
        } else {
            t_op = t_first;
            t_op2 = t_first;
        }
    }

    // -------- ISF quantization --------
    let mut indice = [0i16; 8];
    if sub(ser_size, NBBITS_7K) <= 0 {
        qpisf_2s_36b(&isf.clone(), &mut isf, &mut state.past_isfq, &mut state.isf_buf, &mut indice, 4);
        parm_serial(indice[0], 8, prms, &mut pos);
        parm_serial(indice[1], 8, prms, &mut pos);
        parm_serial(indice[2], 7, prms, &mut pos);
        parm_serial(indice[3], 7, prms, &mut pos);
        parm_serial(indice[4], 6, prms, &mut pos);
    } else {
        qpisf_2s_46b(&isf.clone(), &mut isf, &mut state.past_isfq, &mut state.isf_buf, &mut indice, 4);
        parm_serial(indice[0], 8, prms, &mut pos);
        parm_serial(indice[1], 8, prms, &mut pos);
        parm_serial(indice[2], 6, prms, &mut pos);
        parm_serial(indice[3], 7, prms, &mut pos);
        parm_serial(indice[4], 7, prms, &mut pos);
        parm_serial(indice[5], 5, prms, &mut pos);
        parm_serial(indice[6], 5, prms, &mut pos);
    }

    // stability factor
    let stab_fac;
    {
        let mut l_tmp = 0i32;
        for i in 0..(M - 1) {
            let t = sub(isf[i], state.isfold[i]);
            l_tmp = l_mac(l_tmp, t, t);
        }
        let mut t = extract_h(l_shl(l_tmp, 8));
        t = mult(t, 26214);
        t = sub(20480, t);
        let mut sf = shl(t, 1);
        if sf < 0 {
            sf = 0;
        }
        stab_fac = sf;
    }
    state.isfold = isf;

    // ISF -> ISP (quantized)
    let mut ispnew_q = [0i16; M];
    isf_isp(&isf, &mut ispnew_q, M);
    if state.first_frame != 0 {
        state.first_frame = 0;
        state.ispold_q = ispnew_q;
    }
    let mut aq = [0i16; NB_SUBFR * (M + 1)];
    int_isp(&state.ispold_q, &ispnew_q, &INTERPOL_FRAC, &mut aq);
    state.ispold_q = ispnew_q;

    // residual exc[i_subfr] = Residu(Aq, speech)
    {
        let mut p_aq = 0usize;
        let mut i_subfr = 0usize;
        while i_subfr < L_FRAME {
            let mut out = [0i16; L_SUBFR];
            residu(&aq[p_aq..p_aq + M + 1], M, &old_speech, speech_off + i_subfr, &mut out, L_SUBFR);
            old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR].copy_from_slice(&out);
            p_aq += M + 1;
            i_subfr += L_SUBFR;
        }
    }

    // range for closed loop pitch in subframe 1
    let mut t0_min = sub(t_op, 8);
    if sub(t0_min, PIT_MIN as i16) < 0 {
        t0_min = PIT_MIN as i16;
    }
    let mut t0_max = add(t0_min, 15);
    if sub(t0_max, PIT_MAX as i16) > 0 {
        t0_max = PIT_MAX as i16;
        t0_min = sub(t0_max, 15);
    }

    // ---- subframe loop ----
    let mut p_a = 0usize;
    let mut p_aq = 0usize;
    let shift = shift_ol; // alias used by subframe scaling (matches C `shift`)
    let mut i_subfr = 0usize;
    while i_subfr < L_FRAME {
        let mut pit_flag = i_subfr as i16;
        if i_subfr == 2 * L_SUBFR && sub(ser_size, NBBITS_7K) > 0 {
            pit_flag = 0;
            t0_min = sub(t_op2, 8);
            if sub(t0_min, PIT_MIN as i16) < 0 {
                t0_min = PIT_MIN as i16;
            }
            t0_max = add(t0_min, 15);
            if sub(t0_max, PIT_MAX as i16) > 0 {
                t0_max = PIT_MAX as i16;
                t0_min = sub(t0_max, 15);
            }
        }

        // ---- target vector for pitch search ----
        let mut error = [0i16; M + L_SUBFR];
        for i in 0..M {
            error[i] = sub(old_speech[speech_off + i + i_subfr - M], state.mem_syn[i]);
        }
        // Residu(p_Aq, speech) -> exc[i_subfr]
        {
            let mut out = [0i16; L_SUBFR];
            residu(&aq[p_aq..p_aq + M + 1], M, &old_speech, speech_off + i_subfr, &mut out, L_SUBFR);
            old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR].copy_from_slice(&out);
        }
        // Syn_filt(p_Aq, M, &exc[i_subfr], error+M, L_SUBFR, error, 0)
        {
            let exc_slice: Vec<i16> = old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR].to_vec();
            let mut mem = [0i16; M];
            mem.copy_from_slice(&error[..M]);
            let mut out = [0i16; L_SUBFR];
            syn_filt(&aq[p_aq..p_aq + M + 1], M, &exc_slice, &mut out, L_SUBFR, &mut mem, false);
            error[M..M + L_SUBFR].copy_from_slice(&out);
        }
        let mut xn = [0i16; L_SUBFR];
        {
            let mut ap = [0i16; M + 1];
            weight_a(&a[p_a..p_a + M + 1], &mut ap, GAMMA1, M);
            residu(&ap, M, &error, M, &mut xn, L_SUBFR);
        }
        {
            let mut mem = state.mem_w0;
            deemph2(&mut xn, TILT_FAC, &mut mem);
            state.mem_w0 = mem;
        }

        // ---- cn[] (residual-domain target) ----
        let mut cn = [0i16; L_SUBFR];
        {
            let mut code = [0i16; M + L_SUBFR];
            // Set_zero(code, M); Copy(xn, code+M, L_SUBFR/2)
            code[M..M + L_SUBFR / 2].copy_from_slice(&xn[..L_SUBFR / 2]);
            let mut t = 0i16;
            preemph2(&mut code[M..M + L_SUBFR / 2], TILT_FAC, L_SUBFR / 2, &mut t);
            let mut ap = [0i16; M + 1];
            weight_a(&a[p_a..p_a + M + 1], &mut ap, GAMMA1, M);
            // Syn_filt(Ap, M, code+M, code+M, L_SUBFR/2, code, 0): mem=code[0..M]
            {
                let inp: Vec<i16> = code[M..M + L_SUBFR / 2].to_vec();
                let mut mem = [0i16; M];
                mem.copy_from_slice(&code[..M]);
                let mut out = [0i16; L_SUBFR / 2];
                syn_filt(&ap, M, &inp, &mut out, L_SUBFR / 2, &mut mem, false);
                code[M..M + L_SUBFR / 2].copy_from_slice(&out);
            }
            // Residu(p_Aq, code+M, cn, L_SUBFR/2)
            residu(&aq[p_aq..p_aq + M + 1], M, &code, M, &mut cn, L_SUBFR / 2);
            // second half: cn[L_SUBFR/2..] = exc[i_subfr + L_SUBFR/2 ..]
            cn[L_SUBFR / 2..].copy_from_slice(
                &old_exc[exc_off + i_subfr + L_SUBFR / 2..exc_off + i_subfr + L_SUBFR],
            );
        }

        // ---- impulse response h1[] ----
        let mut h1 = [0i16; L_SUBFR];
        let mut h2 = [0i16; L_SUBFR];
        {
            let mut error2 = [0i16; M + L_SUBFR];
            let mut ap = [0i16; M + 1];
            weight_a(&a[p_a..p_a + M + 1], &mut ap, GAMMA1, M);
            error2[M..M + M].copy_from_slice(&ap[..M]); // Weight_a writes ap[0..=M]; but C does Weight_a(p_A, error+M, ..) writing M+1 coeffs into error[M..]
            // Correct: Weight_a writes M+1 coefficients at error+M.
            error2[M..M + M + 1].copy_from_slice(&ap);
            for i in 0..L_SUBFR {
                let mut l_tmp = l_mult(error2[i + M], 16384);
                for j in 1..=M {
                    l_tmp = l_msu(l_tmp, aq[p_aq + j], error2[i + M - j]);
                }
                let v = round_word(l_shl(l_tmp, 3));
                h1[i] = v;
                error2[i + M] = v;
            }
            if std::env::var("AMRWB_DBG").is_ok() && i_subfr == 64 {
                eprintln!("RDBG H1RAW={h1:?}");
                eprintln!("RDBG AQ={:?}", &aq[p_aq..p_aq + M + 1]);
            }
            let mut t = 0i16;
            deemph2(&mut h1, TILT_FAC, &mut t);
            h2.copy_from_slice(&h1);
            scale_sig(&mut h2, L_SUBFR, -2);
            if std::env::var("AMRWB_DBG").is_ok() && i_subfr == 64 {
                eprintln!("RDBG H1DE={h1:?}");
                eprintln!("RDBG H2SC={h2:?}");
            }
        }

        // scale xn and h1
        scale_sig(&mut xn, L_SUBFR, shift);
        scale_sig(&mut h1, L_SUBFR, add(1, shift));

        // ---- closed-loop fractional pitch ----
        let mut t0_frac = 0i16;
        let mut t0;
        if sub(ser_size, NBBITS_9K) <= 0 {
            t0 = crate::amr::wb::enc_acelp::pitch_fr4(
                &old_exc, exc_off + i_subfr, &xn, &h1, t0_min, t0_max, &mut t0_frac, pit_flag,
                PIT_MIN as i16, PIT_FR1_8B, L_SUBFR,
            );
            if pit_flag == 0 {
                let index = if sub(t0, PIT_FR1_8B) < 0 {
                    sub(add(shl(t0, 1), shr(t0_frac, 1)), PIT_MIN as i16 * 2)
                } else {
                    add(sub(t0, PIT_FR1_8B), (PIT_FR1_8B - PIT_MIN as i16) * 2)
                };
                parm_serial(index, 8, prms, &mut pos);
                t0_min = sub(t0, 8);
                if sub(t0_min, PIT_MIN as i16) < 0 {
                    t0_min = PIT_MIN as i16;
                }
                t0_max = add(t0_min, 15);
                if sub(t0_max, PIT_MAX as i16) > 0 {
                    t0_max = PIT_MAX as i16;
                    t0_min = sub(t0_max, 15);
                }
            } else {
                let i = sub(t0, t0_min);
                let index = add(shl(i, 1), shr(t0_frac, 1));
                parm_serial(index, 5, prms, &mut pos);
            }
        } else {
            t0 = crate::amr::wb::enc_acelp::pitch_fr4(
                &old_exc, exc_off + i_subfr, &xn, &h1, t0_min, t0_max, &mut t0_frac, pit_flag,
                PIT_FR2, PIT_FR1_9B, L_SUBFR,
            );
            if pit_flag == 0 {
                let index = if sub(t0, PIT_FR2) < 0 {
                    sub(add(shl(t0, 2), t0_frac), PIT_MIN as i16 * 4)
                } else if sub(t0, PIT_FR1_9B) < 0 {
                    add(sub(add(shl(t0, 1), shr(t0_frac, 1)), PIT_FR2 * 2), (PIT_FR2 - PIT_MIN as i16) * 4)
                } else {
                    add(add(sub(t0, PIT_FR1_9B), (PIT_FR2 - PIT_MIN as i16) * 4), (PIT_FR1_9B - PIT_FR2) * 2)
                };
                parm_serial(index, 9, prms, &mut pos);
                t0_min = sub(t0, 8);
                if sub(t0_min, PIT_MIN as i16) < 0 {
                    t0_min = PIT_MIN as i16;
                }
                t0_max = add(t0_min, 15);
                if sub(t0_max, PIT_MAX as i16) > 0 {
                    t0_max = PIT_MAX as i16;
                    t0_min = sub(t0_max, 15);
                }
            } else {
                let i = sub(t0, t0_min);
                let index = add(shl(i, 2), t0_frac);
                parm_serial(index, 6, prms, &mut pos);
            }
        }

        let clip_gain = gp_clip(ser_size, &state.gp_clip);

        // ---- adaptive codebook ----
        // Pred_lt4(&exc[i_subfr], T0, T0_frac, L_SUBFR+1)
        crate::amr::wb::pitch::pred_lt4(&mut old_exc, exc_off + i_subfr, t0, t0_frac, L_SUBFR + 1);

        let mut y1 = [0i16; L_SUBFR];
        let mut y2 = [0i16; L_SUBFR];
        let mut g_coeff = [0i16; 4];
        let mut g_coeff2 = [0i16; 4];
        let mut dn = [0i16; L_SUBFR];
        let mut xn2 = [0i16; L_SUBFR];
        let gain1;
        if sub(ser_size, NBBITS_9K) > 0 {
            convolve(&old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR], &h1, &mut y1, L_SUBFR);
            let mut g = g_pitch(&xn, &y1, &mut g_coeff, L_SUBFR);
            if clip_gain != 0 && sub(g, GP_CLIP) > 0 {
                g = GP_CLIP;
            }
            gain1 = g;
            updt_tar(&xn, &mut dn, &y1, gain1, L_SUBFR);
        } else {
            gain1 = 0;
        }

        // lp-filtered pitch excitation -> code[]
        let mut code = [0i16; L_SUBFR];
        for i in 0..L_SUBFR {
            let mut l_tmp = l_mult(5898, old_exc[exc_off + i_subfr + i - 1]);
            l_tmp = l_mac(l_tmp, 20972, old_exc[exc_off + i_subfr + i]);
            l_tmp = l_mac(l_tmp, 5898, old_exc[exc_off + i_subfr + i + 1]);
            code[i] = round_word(l_tmp);
        }
        convolve(&code, &h1, &mut y2, L_SUBFR);
        let mut gain2 = g_pitch(&xn, &y2, &mut g_coeff2, L_SUBFR);
        if clip_gain != 0 && sub(gain2, GP_CLIP) > 0 {
            gain2 = GP_CLIP;
        }
        updt_tar(&xn, &mut xn2, &y2, gain2, L_SUBFR);

        // choose best prediction
        let mut select = 0i16;
        if sub(ser_size, NBBITS_9K) > 0 {
            let mut l_tmp = 0i32;
            for i in 0..L_SUBFR {
                l_tmp = l_mac(l_tmp, dn[i], dn[i]);
            }
            for i in 0..L_SUBFR {
                l_tmp = l_msu(l_tmp, xn2[i], xn2[i]);
            }
            if l_tmp <= 0 {
                select = 1;
            }
            parm_serial(select, 1, prms, &mut pos);
        }
        let gain_pit_pre;
        if select == 0 {
            gain_pit_pre = gain2;
            old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR].copy_from_slice(&code);
            y1.copy_from_slice(&y2);
            g_coeff.copy_from_slice(&g_coeff2);
        } else {
            gain_pit_pre = gain1;
            xn2.copy_from_slice(&dn);
        }
        let mut gain_pit = gain_pit_pre;

        // update cn for codebook search
        {
            let cn_copy = cn;
            updt_tar(&cn_copy, &mut cn, &old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR], gain_pit, L_SUBFR);
        }
        scale_sig(&mut cn, L_SUBFR, shift);

        // include fixed-gain pitch contribution into h2[]
        if std::env::var("AMRWB_DBG").is_ok() {
            eprintln!("RDBG PRE sf={i_subfr} tilt={} T0={t0} T0f={t0_frac} xn2={xn2:?}", state.tilt_code);
        }
        {
            let mut t = 0i16;
            preemph(&mut h2, state.tilt_code, L_SUBFR, &mut t);
        }
        let mut t0_sh = t0;
        if t0_frac > 2 {
            t0_sh = add(t0, 1);
        }
        crate::amr::wb::pitch::pit_shrp(&mut h2, t0_sh as usize, PIT_SHARP, L_SUBFR);

        // correlation + codebook search
        cor_h_x(&h2, &xn2, &mut dn);

        let mut indice_cb = [0i16; 8];
        if sub(ser_size, NBBITS_7K) <= 0 {
            acelp_2t64_fx(&mut dn, &cn, &h2, &mut code, &mut y2, &mut indice_cb);
            parm_serial(indice_cb[0], 12, prms, &mut pos);
        } else {
            let nbbits = acelp_nbbits(ser_size);
            if std::env::var("AMRWB_DBG").is_ok() {
                eprintln!(
                    "RDBG ACELPIN sf={i_subfr} dn={:?}",
                    &dn[..]
                );
                eprintln!("RDBG ACELPIN sf={i_subfr} h2={:?}", &h2[..]);
                eprintln!("RDBG ACELPIN sf={i_subfr} cn={:?}", &cn[..]);
            }
            acelp_4t64_search(&mut dn, &cn, &h2, &mut code, &mut y2, nbbits, ser_size, &mut indice_cb);
            if std::env::var("AMRWB_DBG").is_ok() {
                eprintln!(
                    "RDBG ACELPIDX sf={i_subfr}: {} {} {} {}",
                    indice_cb[0], indice_cb[1], indice_cb[2], indice_cb[3]
                );
            }
            emit_acelp_indices(nbbits, ser_size, &indice_cb, prms, &mut pos);
        }

        // add fixed-gain pitch contribution to code[]
        {
            let mut t = 0i16;
            preemph(&mut code, state.tilt_code, L_SUBFR, &mut t);
        }
        crate::amr::wb::pitch::pit_shrp(&mut code, t0_sh as usize, PIT_SHARP, L_SUBFR);

        // gain quantization
        let mut l_gain_code: i32;
        {
            let mut gc = 0i32;
            let nbits = if sub(ser_size, NBBITS_9K) <= 0 { 6 } else { 7 };
            let index = q_gain2(
                &xn, &y1, add(q_new, shift), &y2, &code, &g_coeff, L_SUBFR, nbits, &mut gain_pit,
                &mut gc, clip_gain, &mut state.qua_gain,
            );
            l_gain_code = gc;
            parm_serial(index, nbits, prms, &mut pos);
        }
        gp_clip_test_gain_pit(ser_size, gain_pit, &mut state.gp_clip);

        let l_tmp = l_shl(l_gain_code, q_new);
        let gain_code = round_word(l_tmp);

        // voice factor + tilt_code
        let mut exc2 = [0i16; L_SUBFR];
        exc2.copy_from_slice(&old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR]);
        scale_sig(&mut exc2, L_SUBFR, shift);
        let voice_fac = voice_factor(&exc2, shift, gain_pit, &code, gain_code, L_SUBFR);
        state.tilt_code = add(shr(voice_fac, 2), 8192);

        // mem_w0 update
        {
            let mut l_tmp = l_mult(gain_code, y2[L_SUBFR - 1]);
            l_tmp = l_shl(l_tmp, add(5, shift));
            l_tmp = l_negate(l_tmp);
            l_tmp = l_mac(l_tmp, xn[L_SUBFR - 1], 16384);
            l_tmp = l_msu(l_tmp, y1[L_SUBFR - 1], gain_pit);
            l_tmp = l_shl(l_tmp, sub(1, shift));
            state.mem_w0 = round_word(l_tmp);
        }

        // build total excitation
        if sub(ser_size, NBBITS_24K) >= 0 {
            exc2.copy_from_slice(&old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR]);
        }
        for i in 0..L_SUBFR {
            let mut l_tmp = l_mult(gain_code, code[i]);
            l_tmp = l_shl(l_tmp, 5);
            l_tmp = l_mac(l_tmp, old_exc[exc_off + i_subfr + i], gain_pit);
            l_tmp = l_shl(l_tmp, 1);
            old_exc[exc_off + i_subfr + i] = round_word(l_tmp);
        }

        // Syn_filt to update mem_syn
        {
            let exc_slice: Vec<i16> = old_exc[exc_off + i_subfr..exc_off + i_subfr + L_SUBFR].to_vec();
            let mut synth = [0i16; L_SUBFR];
            syn_filt(&aq[p_aq..p_aq + M + 1], M, &exc_slice, &mut synth, L_SUBFR, &mut state.mem_syn, true);
        }
        // (mode 8 high-band synthesis + 4-bit index omitted; see module docs.)
        let _ = (stab_fac, &l_gain_code);
        l_gain_code = 0;
        let _ = l_gain_code;

        p_a += M + 1;
        p_aq += M + 1;
        i_subfr += L_SUBFR;
    }

    // update memory for next frame
    state.old_speech.copy_from_slice(&old_speech[L_FRAME..L_TOTAL]);
    state.old_wsp.copy_from_slice(&wsp[L_FRAME / OPL_DECIM..L_FRAME / OPL_DECIM + PIT_MAX / OPL_DECIM]);
    state.old_exc.copy_from_slice(&old_exc[L_FRAME..L_FRAME + PIT_MAX + L_INTERPOL]);

    pos
}

/// Map `ser_size` to the ACELP pulse budget (`coder.c` mode dispatch).
fn acelp_nbbits(ser_size: i16) -> i16 {
    if sub(ser_size, NBBITS_9K) <= 0 {
        20
    } else if sub(ser_size, NBBITS_12K) <= 0 {
        36
    } else if sub(ser_size, NBBITS_14K) <= 0 {
        44
    } else if sub(ser_size, NBBITS_16K) <= 0 {
        52
    } else if sub(ser_size, NBBITS_18K) <= 0 {
        64
    } else if sub(ser_size, NBBITS_20K) <= 0 {
        72
    } else {
        88
    }
}

/// Pack the per-track ACELP indices for the given budget (`coder.c` `Parm_serial` block).
fn emit_acelp_indices(nbbits: i16, _ser_size: i16, indice: &[i16], prms: &mut [i16], pos: &mut usize) {
    match nbbits {
        20 => {
            for &v in indice.iter().take(4) {
                parm_serial(v, 5, prms, pos);
            }
        }
        36 => {
            for &v in indice.iter().take(4) {
                parm_serial(v, 9, prms, pos);
            }
        }
        44 => {
            parm_serial(indice[0], 13, prms, pos);
            parm_serial(indice[1], 13, prms, pos);
            parm_serial(indice[2], 9, prms, pos);
            parm_serial(indice[3], 9, prms, pos);
        }
        52 => {
            for &v in indice.iter().take(4) {
                parm_serial(v, 13, prms, pos);
            }
        }
        64 => {
            parm_serial(indice[0], 2, prms, pos);
            parm_serial(indice[1], 2, prms, pos);
            parm_serial(indice[2], 2, prms, pos);
            parm_serial(indice[3], 2, prms, pos);
            parm_serial(indice[4], 14, prms, pos);
            parm_serial(indice[5], 14, prms, pos);
            parm_serial(indice[6], 14, prms, pos);
            parm_serial(indice[7], 14, prms, pos);
        }
        72 => {
            parm_serial(indice[0], 10, prms, pos);
            parm_serial(indice[1], 10, prms, pos);
            parm_serial(indice[2], 2, prms, pos);
            parm_serial(indice[3], 2, prms, pos);
            parm_serial(indice[4], 10, prms, pos);
            parm_serial(indice[5], 10, prms, pos);
            parm_serial(indice[6], 14, prms, pos);
            parm_serial(indice[7], 14, prms, pos);
        }
        _ => {
            for &v in indice.iter().take(8) {
                parm_serial(v, 11, prms, pos);
            }
        }
    }
}

/// `deemph2` shim (the encoder uses the filters-module variant but with its own mem handling).
fn deemph2(x: &mut [i16], mu: i16, mem: &mut i16) {
    crate::amr::wb::filters::deemph2(x, mu, mem);
}

// `acelp_4t64_search` lives in enc_acelp via a thin wrapper; declared here to keep enc_main focused.
use crate::amr::wb::enc_acelp::acelp_4t64_search;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_state_reset_matches_reference_init() {
        let s = EncoderState::new();
        assert_eq!(s.ispold, ISP_INIT);
        assert_eq!(s.isfold, ISF_INIT);
        assert_eq!(s.old_t0_med, 40);
        assert_eq!(s.q_old, 15);
        assert_eq!(s.q_max, [15, 15]);
        assert_eq!(s.gp_clip[1], 9830);
        assert!(s.qua_gain.iter().all(|&v| v == -14336));
    }

    #[test]
    fn silence_encodes_without_panicking() {
        let mut s = EncoderState::new();
        let mut prms = [0i16; 477];
        let n = coder(&mut s, 2, &[0i16; 320], &mut prms);
        assert_eq!(n, 253);
    }
}
