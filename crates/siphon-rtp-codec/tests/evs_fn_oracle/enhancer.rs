//! `lib_com/enhancer_fx.c` against `fn_enhancer`: four consecutive subframes per case through one
//! dispersion memory and gain threshold (covers `phase_dispersion_fx` and `agc2_fx`).

use siphon_rtp_codec::evs::com::enhancer::enhancer;
use siphon_rtp_codec::evs::dec::state::DispMem;

use crate::common::{corpus, mismatch};

#[test]
fn enhancer_matches_the_reference() {
    let Some(cases) = corpus("enhancer", "enhancer") else {
        return;
    };
    for case in &cases {
        let mut dm = DispMem::zeroed();
        dm.prev_state = case.i16("prev_state");
        dm.prev_gain_code = case.i32("prev_gain_code");
        dm.prev_gain_pit
            .copy_from_slice(&case.i16s("prev_gain_pit"));
        let mut gc_threshold = case.i32("gc_threshold");
        let mut exc2 = case.i16s("exc2");
        for c in 0..4 {
            let mut code = case.i16s(&format!("code{c}"));
            enhancer(
                case.i32("core_brate"),
                case.i16("opt_amr_wb"),
                case.i16(&format!("coder_type{c}")),
                (c * 64) as i16,
                case.i16("L_frame"),
                case.i16(&format!("voice_fac{c}")),
                case.i16(&format!("stab_fac{c}")),
                case.i32(&format!("norm_gain_code{c}")),
                case.i16(&format!("gain_inov{c}")),
                &mut gc_threshold,
                &mut code,
                &mut exc2,
                case.i16(&format!("gain_pit{c}")),
                &mut dm,
                case.i16("Q_exc"),
            );
            let name = format!("code{c}");
            if let Some(message) = mismatch(case, &name, &code, &case.out_i16s(&name)) {
                panic!("{message}");
            }
        }
        for (name, rust, reference) in [
            ("exc2", exc2.clone(), case.out_i16s("exc2")),
            (
                "prev_gain_pit",
                dm.prev_gain_pit.to_vec(),
                case.out_i16s("prev_gain_pit"),
            ),
            (
                "prev_state",
                vec![dm.prev_state],
                case.out_i16s("prev_state"),
            ),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &reference) {
                panic!("{message}");
            }
        }
        for (name, rust, reference) in [
            ("gc_threshold", gc_threshold, case.out_i32("gc_threshold")),
            (
                "prev_gain_code",
                dm.prev_gain_code,
                case.out_i32("prev_gain_code"),
            ),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &reference) {
                panic!("{message}");
            }
        }
    }
}
