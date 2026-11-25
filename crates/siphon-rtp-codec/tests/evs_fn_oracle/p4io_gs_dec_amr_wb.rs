//! `improv_amr_wb_gs_fx` (`lib_dec/gs_dec_amr_wb_fx.c`, with its statics `gs_dec_amr_wb_fx`,
//! `Ener_per_band_fx`, `Apply_gain_fx`, `normalize_spec_fx`, `NoiseFill_fx`) against
//! `fn_p4io_gs_dec_amr_wb`.

use siphon_rtp_codec::evs::dec::gs_dec_amr_wb::improv_amr_wb_gs;

use crate::common::{corpus, mismatch};

#[test]
fn improv_amr_wb_gs_matches_the_reference() {
    let Some(cases) = corpus("p4io_gs_dec_amr_wb", "improv_amr_wb_gs") else {
        return;
    };
    let mut modified = 0;
    for case in &cases {
        let mut seed_tcx = case.i16("seed_tcx");
        let mut old_aq = case.i16s("old_aq");
        let mut mem_syn2 = case.i16s("mem_syn2");
        let mut aq = case.i16s("aq");
        let mut exc2 = case.i16s("exc2");
        let mut syn = case.i16s("syn");
        improv_amr_wb_gs(
            case.i16("clas"),
            case.i16("coder_type"),
            case.i32("core_brate"),
            &mut seed_tcx,
            &mut old_aq,
            &mut mem_syn2,
            case.i16("lt_voice_fac"),
            case.i16("locattack"),
            &mut aq,
            &mut exc2,
            case.i16("q_exc2"),
            &case.i16s("mem_tmp"),
            &mut syn,
            case.i16("q_syn"),
            &case.i16s("pitch_buf"),
            case.i16("last_ener"),
            case.i16("rate_switching_reset"),
            case.i16("last_coder_type"),
        );
        let message = mismatch(case, "seed_tcx", &seed_tcx, &case.out_i16("seed_tcx"))
            .or_else(|| mismatch(case, "old_aq", &old_aq, &case.out_i16s("old_aq")))
            .or_else(|| mismatch(case, "mem_syn2", &mem_syn2, &case.out_i16s("mem_syn2")))
            .or_else(|| mismatch(case, "aq", &aq, &case.out_i16s("aq")))
            .or_else(|| mismatch(case, "exc2", &exc2, &case.out_i16s("exc2")))
            .or_else(|| mismatch(case, "syn", &syn, &case.out_i16s("syn")));
        if let Some(message) = message {
            panic!("{message}");
        }
        modified += usize::from(exc2 != case.i16s("exc2"));
    }
    // the modification is entered by a good part of the corpus (and left alone by the rest)
    assert!(
        modified > cases.len() / 10 && modified < cases.len(),
        "{modified}"
    );
}
