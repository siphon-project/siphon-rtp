//! `lib_dec/FEC_scale_syn_fx.c` against `fn_FEC_scale_syn`: three consecutive frames per case,
//! carrying the scaling flag, the long-term energies, the LP energy and the synthesis memory.
//! `get_gain` (the LP tilt, over the aliased `E_UTIL_synthesis` call) and `Sqrt_Ratio32` are
//! also proven on their own (`get_gain.rs`, `tools.rs`).

use siphon_rtp_codec::evs::dec::fec_scale_syn::{
    fec_scale_syn, FecScaleSynParams, FecScaleSynState,
};
use siphon_rtp_codec::itu::stl2009::StlFlags;

use crate::common::{corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn fec_scale_syn_matches_the_reference() {
    let Some(cases) = corpus_sized("FEC_scale_syn", "fec_scale_syn", 2000) else {
        return;
    };
    for case in &cases {
        let mut scaling_flag = case.i16("scaling_flag");
        let mut old_enr_lp = case.i16("old_enr_LP");
        let mut lp_av = case.i32("lp_av");
        let mut lp_max = case.i32("lp_max");
        let mut mem_syn = case.i16s("mem_syn");
        for k in 0..3 {
            let field = |name: &str| format!("{name}{k}");
            let p = FecScaleSynParams {
                l_frame: case.i16(&field("L_frame")),
                clas: case.i16(&field("clas")),
                last_good: case.i16(&field("last_good")),
                l_enr_old: case.i32(&field("enr_old")),
                l_enr_q: case.i32(&field("enr_q")),
                coder_type: case.i16(&field("coder_type")),
                lsf_q_prediction: case.i16(&field("LSF_Q_prediction")),
                bfi: case.i16(&field("bfi")),
                total_brate: case.i32(&field("total_brate")),
                prev_bfi: case.i16(&field("prev_bfi")),
                last_core_brate: case.i32(&field("last_core_brate")),
                q_exc: case.i16(&field("Q_exc")),
                q_syn: case.i16(&field("Q_syn")),
                avoid_lpc_burst_on_recovery: case.i16(&field("avoid")),
                force_scaling: case.i16(&field("force")),
            };
            let mut synth = case.i16s(&field("synth"));
            let mut exc = case.i16s(&field("exc"));
            let mut exc2 = case.i16s(&field("exc2"));
            let mut update_flg = 0x55;
            let mut flags = StlFlags::default();
            let mut state = FecScaleSynState {
                update_flg: &mut update_flg,
                scaling_flag: &mut scaling_flag,
                lp_ener_fec_av: &mut lp_av,
                lp_ener_fec_max: &mut lp_max,
                old_enr_lp: &mut old_enr_lp,
            };
            fec_scale_syn(
                &p,
                &mut state,
                &mut synth,
                &case.i16s(&field("pitch")),
                &mut exc,
                &mut exc2,
                &case.i16s(&field("Aq")),
                &case.i16s(&field("mem_tmp")),
                &mut mem_syn,
                &mut flags,
            );
            check(
                case,
                &field("scalars"),
                &(
                    update_flg,
                    scaling_flag,
                    old_enr_lp,
                    lp_av,
                    lp_max,
                    i16::from(flags.carry),
                ),
                &(
                    case.out_i16(&field("update")),
                    case.out_i16(&field("scaling_flag")),
                    case.out_i16(&field("old_enr_LP")),
                    case.out_i32(&field("lp_av")),
                    case.out_i32(&field("lp_max")),
                    case.out_i16(&field("carry")),
                ),
            );
            check(
                case,
                &field("mem_syn"),
                &mem_syn,
                &case.out_i16s(&field("mem_syn")),
            );
            check(
                case,
                &field("synth"),
                &synth,
                &case.out_i16s(&field("synth")),
            );
            check(case, &field("exc"), &exc, &case.out_i16s(&field("exc")));
            check(case, &field("exc2"), &exc2, &case.out_i16s(&field("exc2")));
        }
    }
}
