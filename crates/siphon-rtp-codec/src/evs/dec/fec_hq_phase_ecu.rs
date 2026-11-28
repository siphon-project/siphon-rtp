//! HQ phase ECU (TS 26.442 `lib_dec/FEC_HQ_phase_ecu_fx.c`; TS 26.447 §5.4.3.3).

mod analysis;
mod subst;
mod synthesis;

pub use analysis::*;
pub use subst::*;
pub use synthesis::*;

use crate::evs::cnst::{
    ACELP_LOOK_NS, LGW_MAX, LPROT32K, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K,
    PH_ECU_LOOKAHEAD_NS,
};
use crate::evs::com::tools::copy;
use crate::evs::dec::state::DecoderState;
use crate::evs::macros::ns2sa;
use crate::itu::basic_ops::{add, shl, shr, sub};

/// `hq_phase_ecu_fx`: the frequency-domain phase ECU. A new prototype spectrum is analysed from
/// the previous synthesis when the previous frame was good (or on the first lost frame after a
/// pitch-based one), otherwise the stored one is advanced in time; the substitution spectrum is
/// transformed into `ecu_rec` (the TDA domain frame).
///
/// The reference's arguments `time_offs`, `X_sav`, `Q_spec`, `num_p`, `plocs`, `plocsi`,
/// `env_stab`, `last_fec`, `ph_ecu_active`, `prev_bfi`, `old_is_transient`, `mag_chg_1st`,
/// `Xavg`, `beta_mute` and `bwidth_fx` are, at its only caller, the like-named decoder state
/// fields, and `prevsynth` is `st.synth_history[st.prev_good_synth..]`.
pub fn hq_phase_ecu(st: &mut DecoderState, ecu_rec: &mut [i32], output_frame: i16) {
    let mut mag_chg = [0i16; LGW_MAX as usize];
    let mut ph_dith: i16 = 0;
    let mut x = [0i16; LPROT48K];
    let mut alpha = [0i16; LGW_MAX as usize];
    let mut beta = [0i16; LGW_MAX as usize];
    // `prevsynth + offset` may point before `prev_good_synth` (into the history it sits in)
    let good_synth = st.prev_good_synth as isize;

    let lprot: i16 = if sub(output_frame, L_FRAME48K) == 0 {
        LPROT48K as i16 // 1536 = (2*output_frame)*1024/1280
    } else if sub(output_frame, L_FRAME32K) == 0 {
        LPROT32K // 1024
    } else if output_frame == L_FRAME16K {
        512
    } else {
        256
    };

    if st.prev_bfi == 0
        || (st.prev_bfi != 0 && st.last_fec != 0 && sub(st.time_offs, output_frame) == 0)
    {
        if !(st.prev_bfi != 0 && st.last_fec != 0) {
            st.time_offs = 0;
        }

        let offset = isize::from(sub(sub(shl(output_frame, 1), lprot), st.time_offs));
        let start = (good_synth + offset).max(0) as usize;

        trans_ana(
            &st.synth_history[start..],
            &TransAnaParams {
                output_frame,
                time_offs: st.time_offs,
                est_mus_content: st.env_stab,
                last_fec: st.last_fec,
            },
            &mut TransAnaOut {
                mag_chg: &mut mag_chg,
                ph_dith: &mut ph_dith,
                mag_chg_1st: &mut st.mag_chg_1st,
                alpha: &mut alpha,
                beta: &mut beta,
                beta_mute: &mut st.beta_mute,
                xavg: &mut st.xavg,
            },
        );

        spec_ana(
            &st.synth_history[start..],
            output_frame,
            st.bwidth,
            &mut SpecAnaOut {
                plocs: &mut st.plocs,
                plocsi: &mut st.plocsi,
                num_plocs: &mut st.num_p,
                x_sav: &mut st.x_sav,
                q: &mut st.q_x_sav,
            },
        );

        if st.prev_bfi != 0 && st.last_fec != 0 {
            st.time_offs = add(st.time_offs, output_frame);
        }
    } else {
        st.time_offs = add(st.time_offs, output_frame);

        let offset = isize::from(sub(shl(output_frame, 1), lprot));
        let start = (good_synth + offset).max(0) as usize;
        trans_ana(
            &st.synth_history[start..],
            &TransAnaParams {
                output_frame,
                time_offs: st.time_offs,
                est_mus_content: st.env_stab,
                last_fec: 0,
            },
            &mut TransAnaOut {
                mag_chg: &mut mag_chg,
                ph_dith: &mut ph_dith,
                mag_chg_1st: &mut st.mag_chg_1st,
                alpha: &mut alpha,
                beta: &mut beta,
                beta_mute: &mut st.beta_mute,
                xavg: &mut st.xavg,
            },
        );
    }

    copy(&st.x_sav, &mut x, lprot);

    // seed for own_rand2
    let mut seed = st.time_offs;
    if st.num_p > 0 {
        seed = add(seed, st.plocs[(st.num_p - 1) as usize]);
    }

    subst_spec(
        &SubstSpecInput {
            plocs: &st.plocs,
            plocsi: &st.plocsi,
            time_offs: st.time_offs,
            mag_chg: &mag_chg,
            ph_dith,
            is_trans: &st.old_is_transient,
            output_frame,
            alpha: &alpha,
            beta: &beta,
            beta_mute: st.beta_mute,
            xavg: &st.xavg,
        },
        &mut st.num_p,
        &mut x,
        &mut seed,
    );

    // reconstructed frame in tda domain
    rec_frame(&mut x, ecu_rec, output_frame, st.q_x_sav);

    st.last_fec = 0;
    st.ph_ecu_active = 1;
}

/// `hq_ecu_fx`: the HQ concealment of a lost WB, SWB or FB frame into `ecu_rec` (TDA domain):
/// the pitch-dependent algorithm ([`fec_alg`], which also fills `gapsynth`) for a stable voiced
/// signal after a good frame, the frequency-domain phase ECU ([`hq_phase_ecu`]) otherwise.
///
/// The reference's `prevsynth`, `time_offs`, `X_sav`, `Q_spec`, `num_p`, `plocs`, `plocsi`,
/// `env_stab`, `last_fec`, `ph_ecu_HqVoicing`, `ph_ecu_active`, `prev_bfi`, `old_is_transient`,
/// `mag_chg_1st`, `Xavg` and `beta_mute` arguments are, at its only caller (`hq_core_dec_fx`),
/// the like-named fields of the decoder state it also gets, so they are read from there.
pub fn hq_ecu(st: &mut DecoderState, ecu_rec: &mut [i32], gapsynth: &mut [i16], output_frame: i16) {
    let mut prevsynth_lp = [0i16; 2 * L_FRAME8K as usize];
    let mut corr: i16 = 0; // Q15
                           // init (values are changed after)
    let mut decimatefactor: i16 = 4;
    let mut n = shr(output_frame, 2);
    // prevsynth + NS2SA(output_frame*50, ACELP_LOOK_NS/2 - PH_ECU_LOOKAHEAD_NS), a few samples
    // before the good-synthesis pointer
    let look = i32::from(ns2sa(
        i32::from(output_frame) * 50,
        ACELP_LOOK_NS / 2 - PH_ECU_LOOKAHEAD_NS,
    ));
    let pitch_start = (st.prev_good_synth as i32 + look).max(0) as usize;

    // find pitch and R value
    if !(sub(output_frame, L_FRAME16K) < 0) {
        fec_ecu_pitch(
            &st.synth_history[pitch_start..],
            &mut prevsynth_lp,
            output_frame,
            &mut n,
            &mut corr,
            &mut decimatefactor,
            st.ph_ecu_hq_voicing,
        );
    }

    let prev_bfi = st.prev_bfi != 0;
    let not_transient = st.old_is_transient[0] == 0 || st.old_is_transient[1] != 0;
    let high_rate = st.total_brate >= 48000
        && (sub(output_frame, L_FRAME16K) >= 0
            && !prev_bfi
            && not_transient
            && (st.ph_ecu_hq_voicing != 0
                || ((st.env_stab_plc != 0 && sub(corr, 19661) < 0)
                    || (st.env_stab_plc == 0 && sub(corr, 27853) > 0))));
    let low_rate = st.total_brate < 48000
        && ((st.ph_ecu_hq_voicing != 0 || sub(corr, 27853) > 0) && !prev_bfi && not_transient);
    if high_rate || low_rate {
        fec_alg(
            &st.synth_history[pitch_start..],
            &prevsynth_lp,
            &mut st.ni_seed_forfec,
            ecu_rec,
            output_frame,
            n,
            decimatefactor,
            st.ph_ecu_hq_voicing,
            gapsynth,
        );

        st.last_fec = 1;
        st.ph_ecu_active = 0;
        st.time_offs = output_frame;
    } else {
        hq_phase_ecu(st, ecu_rec, output_frame);
    }
}
