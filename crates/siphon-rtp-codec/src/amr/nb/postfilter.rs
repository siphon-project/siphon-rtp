//! AMR-NB adaptive post-filter + phase dispersion — 3GPP TS 26.073 `pstfilt.c`, `ph_disp.c`.
//! Ported bit-exact.
//!
//! [`PostFilter`] runs the decoder's adaptive post-filter on the synthesis speech: inverse-filter
//! through `A(z/g1)`, tilt-compensate, synthesis through `1/A(z/g2)`, then adaptive gain control.
//! [`PhDisp`] performs adaptive phase dispersion and forms the total excitation fed to synthesis.

use crate::amr::basic_ops::{add, div_s, extract_h, l_mac, l_mult, l_shl, mult, round_word, sub};
use crate::amr::nb::constants::{AGC_FAC, L_FRAME, L_SUBFR, M, MP1, MU};
use crate::amr::nb::filters::{agc, preemphasis, residu, syn_filt, weight_ai, AgcState};
use crate::amr::AmrNbMode;

/// Size of the truncated impulse response of `A(z/g1)/A(z/g2)` (`pstfilt.c` `L_H`).
const L_H: usize = 22;

/// Spectral expansion factor `gamma3` for MR122/MR102 (`pstfilt.c` `gamma3_MR122`).
const GAMMA3_MR122: [i16; M] = [22938, 16057, 11240, 7868, 5508, 3856, 2699, 1889, 1322, 925];
/// Spectral expansion factor `gamma3` for the other modes (`pstfilt.c` `gamma3`).
const GAMMA3: [i16; M] = [18022, 9912, 5451, 2998, 1649, 907, 499, 274, 151, 83];
/// Spectral expansion factor `gamma4` for MR122/MR102 (`pstfilt.c` `gamma4_MR122`).
const GAMMA4_MR122: [i16; M] = [24576, 18432, 13824, 10368, 7776, 5832, 4374, 3281, 2461, 1846];
/// Spectral expansion factor `gamma4` for the other modes (`pstfilt.c` `gamma4`).
const GAMMA4: [i16; M] = [22938, 16057, 11240, 7868, 5508, 3856, 2699, 1889, 1322, 925];

/// Adaptive post-filter state (`pstfilt.h` `Post_FilterState`).
#[derive(Debug, Clone)]
pub struct PostFilter {
    /// `1/A(z/g2)` synthesis memory (`mem_syn_pst[M]`).
    mem_syn_pst: [i16; M],
    /// `A(z/g1)` residual buffer (`res2[L_SUBFR]`).
    res2: [i16; L_SUBFR],
    /// Working synthesis buffer, `M` history words + one frame (`synth_buf[L_FRAME + M]`).
    synth_buf: [i16; L_FRAME + M],
    /// Tilt-compensation pre-emphasis memory.
    preemph_mem: i16,
    /// Adaptive gain control state.
    agc_state: AgcState,
}

impl Default for PostFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PostFilter {
    /// Reset all post-filter state to zero (`Post_Filter_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            mem_syn_pst: [0; M],
            res2: [0; L_SUBFR],
            synth_buf: [0; L_FRAME + M],
            preemph_mem: 0,
            agc_state: AgcState::new(),
        }
    }

    /// Post-filter one frame of synthesis speech in place (`pstfilt.c` `Post_Filter`).
    /// `syn` is the L_FRAME synthesis (post-filtered on return); `az_4` the 4×MP1 interpolated LPC.
    pub fn run(&mut self, mode: usize, syn: &mut [i16], az_4: &[i16]) {
        // syn_work occupies synth_buf[M..]; the M words before it (synth_buf[0..M]) carry the
        // previous frame's tail and are left intact here (updated at end of frame).
        self.synth_buf[M..M + L_FRAME].copy_from_slice(&syn[..L_FRAME]);

        let use_mr122_gamma =
            mode == AmrNbMode::Mr1220 as usize || mode == AmrNbMode::Mr1020 as usize;

        let mut h = [0i16; L_H];
        let mut ap3 = [0i16; MP1];
        let mut ap4 = [0i16; MP1];

        let mut subfr = 0usize;
        while subfr < L_FRAME {
            let az = &az_4[(subfr / L_SUBFR) * MP1..];

            if use_mr122_gamma {
                weight_ai(az, &GAMMA3_MR122, &mut ap3);
                weight_ai(az, &GAMMA4_MR122, &mut ap4);
            } else {
                weight_ai(az, &GAMMA3, &mut ap3);
                weight_ai(az, &GAMMA4, &mut ap4);
            }

            // res2 = A(z/g1) * syn_work[subfr..]. Residu reads `M` history before the subframe,
            // i.e. synth_buf[M + subfr - j]; pass synth_buf with base = M + subfr.
            residu(&ap3, &self.synth_buf, M + subfr, &mut self.res2, L_SUBFR);

            // impulse response of A(z/g1)/A(z/g2): h[0..M+1] = Ap3, h[M+1..] = 0, then filter h
            // through 1/A(z/g2). The reference passes &h[M+1] (the zeroed tail) as Syn_filt's
            // M-word memory; with update=0 that memory is read-only, so a zeroed scratch matches.
            h[..M + 1].copy_from_slice(&ap3[..M + 1]);
            for hv in h.iter_mut().take(L_H).skip(M + 1) {
                *hv = 0;
            }
            let h_in = h;
            let mut h_mem = [0i16; M];
            syn_filt(&ap4, &h_in, &mut h, L_H, &mut h_mem, false);

            // 1st correlations of h[]
            let mut l_tmp = l_mult(h[0], h[0]);
            for &hv in &h[1..L_H] {
                l_tmp = l_mac(l_tmp, hv, hv);
            }
            let temp1 = extract_h(l_tmp);

            let mut l_tmp = l_mult(h[0], h[1]);
            for i in 1..L_H - 1 {
                l_tmp = l_mac(l_tmp, h[i], h[i + 1]);
            }
            let temp2 = extract_h(l_tmp);

            let temp2 = if temp2 <= 0 {
                0
            } else {
                let t = mult(temp2, MU);
                div_s(t, temp1)
            };

            preemphasis(&mut self.preemph_mem, &mut self.res2, temp2, L_SUBFR);

            // 1/A(z/g2)
            syn_filt(
                &ap4,
                &self.res2,
                &mut syn[subfr..],
                L_SUBFR,
                &mut self.mem_syn_pst,
                true,
            );

            // scale output to input energy
            let mut sig_in = [0i16; L_SUBFR];
            sig_in.copy_from_slice(&self.synth_buf[M + subfr..M + subfr + L_SUBFR]);
            agc(
                &mut self.agc_state,
                &sig_in,
                &mut syn[subfr..subfr + L_SUBFR],
                AGC_FAC,
                L_SUBFR,
            );

            subfr += L_SUBFR;
        }

        // update syn_work[] history: synth_buf[0..M] = syn_work[L_FRAME-M..L_FRAME]
        let tail_start = M + L_FRAME - M;
        let tail: [i16; M] = self.synth_buf[tail_start..tail_start + M]
            .try_into()
            .expect("M-word tail");
        self.synth_buf[..M].copy_from_slice(&tail);
    }
}

/// Phase-dispersion memory size (`ph_disp.h` `PHDGAINMEMSIZE`).
const PHDGAINMEMSIZE: usize = 5;
/// LTP-gain threshold 0.6 (Q14) (`ph_disp.h` `PHDTHR1LTP`).
const PHDTHR1LTP: i16 = 9830;
/// LTP-gain threshold 0.9 (Q14) (`ph_disp.h` `PHDTHR2LTP`).
const PHDTHR2LTP: i16 = 14746;
/// Onset detection factor 2.0 (Q13) (`ph_disp.h` `ONFACTPLUS1`).
const ONFACTPLUS1: i16 = 16384;
/// Onset hold length (`ph_disp.h` `ONLENGTH`).
const ONLENGTH: i16 = 2;

/// Phase-dispersion impulse response, low/max dispersion, MR795 (`ph_disp.tab` `ph_imp_low_MR795`).
#[rustfmt::skip]
const PH_IMP_LOW_MR795: [i16; L_SUBFR] = [
    26777, 801, 2505, -683, -1382, 582, 604, -1274, 3511, -5894,
    4534, -499, -1940, 3011, -5058, 5614, -1990, -1061, -1459, 4442,
    -700, -5335, 4609, 452, -589, -3352, 2953, 1267, -1212, -2590,
    1731, 3670, -4475, -975, 4391, -2537, 949, -1363, -979, 5734,
];
/// Phase-dispersion impulse response, medium dispersion, MR795 (`ph_disp.tab` `ph_imp_mid_MR795`).
#[rustfmt::skip]
const PH_IMP_MID_MR795: [i16; L_SUBFR] = [
    30274, 3831, -4036, 2972, -1048, -1002, 2477, -3043, 2815, -2231,
    1753, -1611, 1714, -1775, 1543, -1008, 429, -169, 472, -1264,
    2176, -2706, 2523, -1621, 344, 826, -1529, 1724, -1657, 1701,
    -2063, 2644, -3060, 2897, -1978, 557, 780, -1369, 842, 655,
];
/// Phase-dispersion impulse response, low/max dispersion, other modes (`ph_disp.tab` `ph_imp_low`).
#[rustfmt::skip]
const PH_IMP_LOW: [i16; L_SUBFR] = [
    14690, 11518, 1268, -2761, -5671, 7514, -35, -2807, -3040, 4823,
    2952, -8424, 3785, 1455, 2179, -8637, 8051, -2103, -1454, 777,
    1108, -2385, 2254, -363, -674, -2103, 6046, -5681, 1072, 3123,
    -5058, 5312, -2329, -3728, 6924, -3889, 675, -1775, 29, 10145,
];
/// Phase-dispersion impulse response, medium dispersion, other modes (`ph_disp.tab` `ph_imp_mid`).
#[rustfmt::skip]
const PH_IMP_MID: [i16; L_SUBFR] = [
    30274, 3831, -4036, 2972, -1048, -1002, 2477, -3043, 2815, -2231,
    1753, -1611, 1714, -1775, 1543, -1008, 429, -169, 472, -1264,
    2176, -2706, 2523, -1621, 344, 826, -1529, 1724, -1657, 1701,
    -2063, 2644, -3060, 2897, -1978, 557, 780, -1369, 842, 655,
];

/// Adaptive phase-dispersion state (`ph_disp.h` `ph_dispState`).
#[derive(Debug, Clone, Default)]
pub struct PhDisp {
    gain_mem: [i16; PHDGAINMEMSIZE],
    prev_state: i16,
    prev_cb_gain: i16,
    lock_full: i16,
    onset: i16,
}

impl PhDisp {
    /// Reset all phase-dispersion state to zero (`ph_disp_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock full phase dispersion (`ph_disp_lock`).
    pub fn lock(&mut self) {
        self.lock_full = 1;
    }

    /// Release the dispersion lock (`ph_disp_release`).
    pub fn release(&mut self) {
        self.lock_full = 0;
    }

    /// Adaptive phase dispersion + total-excitation formation (`ph_disp.c` `ph_disp`).
    ///
    /// `x` is the LTP excitation in, total excitation out (Q0). `inno` is the innovation (Q13, Q12
    /// for MR122) and may be dispersed in place. `cb_gain` Q1, `ltp_gain` Q14, `pitch_fac` Q14 (Q13
    /// for MR122), `tmp_shift` the pre-round left shift.
    pub fn run(
        &mut self,
        mode: usize,
        x: &mut [i16],
        cb_gain: i16,
        ltp_gain: i16,
        inno: &mut [i16],
        pitch_fac: i16,
        tmp_shift: i16,
    ) {
        // update LTP gain memory
        for i in (1..PHDGAINMEMSIZE).rev() {
            self.gain_mem[i] = self.gain_mem[i - 1];
        }
        self.gain_mem[0] = ltp_gain;

        // basic adaption
        let mut imp_nr = if sub(ltp_gain, PHDTHR2LTP) < 0 {
            if sub(ltp_gain, PHDTHR1LTP) > 0 {
                1
            } else {
                0
            }
        } else {
            2
        };

        // onset indicator
        let tmp1 = round_word(l_shl(l_mult(self.prev_cb_gain, ONFACTPLUS1), 2));
        if sub(cb_gain, tmp1) > 0 {
            self.onset = ONLENGTH;
        } else if self.onset > 0 {
            self.onset = sub(self.onset, 1);
        }

        // if not onset, use max dispersion when half-or-more gainMem < 0.6
        if self.onset == 0 {
            let mut i1 = 0i16;
            for &g in &self.gain_mem {
                if sub(g, PHDTHR1LTP) < 0 {
                    i1 = add(i1, 1);
                }
            }
            if sub(i1, 2) > 0 {
                imp_nr = 0;
            }
        }
        // restrict decrease to one step if not onset
        if sub(imp_nr, add(self.prev_state, 1)) > 0 && self.onset == 0 {
            imp_nr = sub(imp_nr, 1);
        }
        // one step less if onset
        if sub(imp_nr, 2) < 0 && self.onset > 0 {
            imp_nr = add(imp_nr, 1);
        }
        // disable for very low cbGain
        if sub(cb_gain, 10) < 0 {
            imp_nr = 2;
        }
        if self.lock_full == 1 {
            imp_nr = 0;
        }

        self.prev_state = imp_nr;
        self.prev_cb_gain = cb_gain;

        // disperse innovation for all modes but MR122, MR102, MR74, and only if imp_nr < 2
        let disperse = mode != AmrNbMode::Mr1220 as usize
            && mode != AmrNbMode::Mr1020 as usize
            && mode != AmrNbMode::Mr740 as usize
            && imp_nr < 2;
        if disperse {
            let mut inno_sav = [0i16; L_SUBFR];
            let mut ps_poss = [0i16; L_SUBFR];
            let mut nze = 0usize;
            for i in 0..L_SUBFR {
                if inno[i] != 0 {
                    ps_poss[nze] = i as i16;
                    nze += 1;
                }
                inno_sav[i] = inno[i];
                inno[i] = 0;
            }
            let ph_imp: &[i16; L_SUBFR] = if mode == AmrNbMode::Mr795 as usize {
                if imp_nr == 0 {
                    &PH_IMP_LOW_MR795
                } else {
                    &PH_IMP_MID_MR795
                }
            } else if imp_nr == 0 {
                &PH_IMP_LOW
            } else {
                &PH_IMP_MID
            };

            // circular convolution: `i` indexes the (circularly shifted) output while `j` advances
            // the impulse response independently, so an index loop mirrors the reference directly.
            for &ppos_i in ps_poss.iter().take(nze) {
                let ppos = ppos_i as usize;
                let mut j = 0usize;
                #[allow(clippy::needless_range_loop)]
                for i in ppos..L_SUBFR {
                    let t = mult(inno_sav[ppos], ph_imp[j]);
                    inno[i] = add(inno[i], t);
                    j += 1;
                }
                #[allow(clippy::needless_range_loop)]
                for i in 0..ppos {
                    let t = mult(inno_sav[ppos], ph_imp[j]);
                    inno[i] = add(inno[i], t);
                    j += 1;
                }
            }
        }

        // total excitation
        for i in 0..L_SUBFR {
            let mut l_temp = l_mult(x[i], pitch_fac);
            l_temp = l_mac(l_temp, inno[i], cb_gain);
            l_temp = l_shl(l_temp, tmp_shift);
            x[i] = round_word(l_temp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_filter_runs_and_changes_silence_to_silence() {
        let mut pf = PostFilter::new();
        let mut syn = [0i16; L_FRAME];
        let mut az = [0i16; 4 * MP1];
        for sf in 0..4 {
            az[sf * MP1] = 4096; // identity LPC per subframe
        }
        pf.run(AmrNbMode::Mr1220 as usize, &mut syn, &az);
        // Silence in -> silence out (no energy to scale), state stays zero.
        assert!(syn.iter().all(|&v| v == 0));
    }

    #[test]
    fn post_filter_history_persists_across_frames() {
        let mut pf = PostFilter::new();
        let mut az = [0i16; 4 * MP1];
        for sf in 0..4 {
            az[sf * MP1] = 4096;
        }
        let mut syn = [1000i16; L_FRAME];
        pf.run(AmrNbMode::Mr475 as usize, &mut syn, &az);
        // After a non-silent frame the synth_buf history (the M words before syn_work) is updated.
        assert!(pf.synth_buf[..M].iter().any(|&v| v != 0));
    }

    #[test]
    fn ph_disp_total_excitation_no_dispersion_path() {
        // MR122 never disperses; it just forms gain_pit*x + gain_code*inno.
        let mut pd = PhDisp::new();
        let mut x = [10i16; L_SUBFR];
        let mut inno = [5i16; L_SUBFR];
        pd.run(AmrNbMode::Mr1220 as usize, &mut x, 100, 8000, &mut inno, 8192, 2);
        // Deterministic, finite, and inno unchanged (no dispersion for MR122).
        assert!(inno.iter().all(|&v| v == 5));
        assert!(x.iter().any(|&v| v != 0));
    }

    #[test]
    fn ph_disp_disperses_for_low_modes() {
        // MR475 with low ltp gain (max dispersion) modifies the innovation.
        let mut pd = PhDisp::new();
        let mut x = [0i16; L_SUBFR];
        let mut inno = [0i16; L_SUBFR];
        inno[5] = 4096; // one pulse
        let inno_before = inno;
        pd.run(AmrNbMode::Mr475 as usize, &mut x, 5000, 1000, &mut inno, 8192, 1);
        // ltpGain 1000 < 0.6 -> max dispersion; the single pulse is spread (circular convolution).
        assert_ne!(inno, inno_before);
    }
}
