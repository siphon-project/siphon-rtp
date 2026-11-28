//! `lib_dec/updt_dec_fx.c` against `fn_updt_dec`: each update on a state whose read fields are
//! random, comparing every field written.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::updt_dec::{updt_bw_switching, updt_dec, updt_dec_common};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn check16(case: &Case, name: &str, rust: &[i16]) {
    check(case, name, &rust.to_vec(), &case.out_i16s(name));
}

#[test]
fn updt_dec_matches_the_reference() {
    let Some(cases) = corpus("updt_dec", "updt_dec") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.opt_amr_wb = case.i16("opt_amr_wb");
        st.l_frame = case.i16("st_l_frame");
        st.bpf_off = case.i16("bpf_off");
        st.last_gsc_noisy_speech_flag = case.i16("last_gsc_noisy");
        st.last_gsc_pit_band_idx = case.i16("last_gsc_pit");
        st.total_brate = case.i32("total_brate");
        st.core_brate = case.i32("core_brate");
        st.seed_tcx = case.i16("seed_tcx");
        st.gsc_noisy_speech = case.i16("gsc_noisy");
        st.upd_cnt = case.i16("upd_cnt");
        st.old_pitch_buf
            .copy_from_slice(&case.i32s("old_pitch_buf"));
        st.mem_pitch_gain
            .copy_from_slice(&case.i16s("mem_pitch_gain"));
        st.lsfoldbfi0.copy_from_slice(&case.i16s("lsfoldbfi0"));
        st.lsfoldbfi1.copy_from_slice(&case.i16s("lsfoldbfi1"));
        st.last_core = case.i16("last_core");
        st.hq_voicing = case.i16("hq_voicing");
        st.last_ppp_mode_dec = case.i16("last_ppp");
        st.ppp_mode_dec = case.i16("ppp");
        st.nelp_mode_dec = case.i16("nelp");
        st.vbr_hw_bwe_disable_dec = case.i16("vbr_hw");
        st.last_voice_factor = case.i16("last_voice_factor");
        st.noise_lev = case.i16("noise_lev");
        st.old_y_gain.copy_from_slice(&case.i16s("old_y_gain"));
        st.last_gsc_spectrum
            .copy_from_slice(&case.i16s("last_gsc_spectrum"));
        st.last_coder_type = case.i16("last_coder_type");

        updt_dec(
            &mut st,
            case.i16("L_frame"),
            case.i16("coder_type"),
            &case.i16s("old_exc"),
            &case.i16s("pitch_buf"),
            case.i16("Es_pred"),
            &case.i16s("Aq"),
            &case.i16s("lsf_new"),
            &case.i16s("lsp_new"),
            &case.i16s("voice_factors"),
            &case.i16s("old_bwe_exc"),
            &case.i16s("gain_buf"),
        );

        check16(case, "old_exc", &st.old_exc);
        check16(case, "old_bwe_exc", &st.old_bwe_exc);
        check16(case, "lsf_old", &st.lsf_old);
        check16(case, "lsp_old", &st.lsp_old);
        check16(case, "last_coder_type", &[st.last_coder_type]);
        check16(case, "last_gsc_pit", &[st.last_gsc_pit_band_idx]);
        check16(case, "last_voice_factor", &[st.last_voice_factor]);
        check16(case, "noise_lev", &[st.noise_lev]);
        check16(case, "old_y_gain", &st.old_y_gain);
        check16(case, "last_gsc_spectrum", &st.last_gsc_spectrum);
        check16(case, "last_gsc_noisy", &[st.last_gsc_noisy_speech_flag]);
        check16(case, "upd_cnt", &[st.upd_cnt]);
        check(
            case,
            "old_pitch_buf",
            &st.old_pitch_buf.to_vec(),
            &case.out_i32s("old_pitch_buf"),
        );
        check16(case, "mem_pitch_gain", &st.mem_pitch_gain);
        check16(case, "lsfoldbfi0", &st.lsfoldbfi0);
        check16(case, "lsfoldbfi1", &st.lsfoldbfi1);
        check16(case, "hq_voicing", &[st.hq_voicing]);
        check16(case, "old_ppp", &[st.old_ppp_mode]);
        check16(case, "last_ppp", &[st.last_ppp_mode_dec]);
        check16(case, "last_nelp", &[st.last_nelp_mode_dec]);
        check16(case, "last_vbr_hw", &[st.last_vbr_hw_bwe_disable_dec]);
        check16(case, "old_aq", &st.old_aq_12_8);
        check16(case, "old_es_pred", &[st.old_es_pred]);
    }
}

#[test]
fn updt_bw_switching_matches_the_reference() {
    let Some(cases) = corpus("updt_dec", "updt_bw_switching") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.output_fs = case.i32("output_fs");
        st.bwidth = case.i16("bwidth");
        st.ener_lh = case.i32("ener_lh");
        st.ener_ll = case.i32("ener_ll");
        st.core = case.i16("core");
        st.bws_cnt = case.i16("bws_cnt");
        st.prev_mode = case.i16("prev_mode");
        st.last_inner_frame = case.i16("last_inner_frame");
        st.core_brate = case.i32("core_brate");
        st.prev_hqswb_clas = case.i16("prev_hqswb_clas");
        st.prev_weight1 = case.i16("prev_weight1");
        st.tilt_swb = case.i16("tilt_swb");
        updt_bw_switching(&mut st, &case.i16s("synth"), case.i16("qpost"));
        check16(case, "tilt_swb", &[st.tilt_swb]);
        check(
            case,
            "prev_ener_lh",
            &st.prev_ener_lh,
            &case.out_i32("prev_ener_lh"),
        );
        check(
            case,
            "prev_ener_ll",
            &st.prev_ener_ll,
            &case.out_i32("prev_ener_ll"),
        );
        check16(case, "last_bwidth", &[st.last_bwidth]);
        check16(case, "last_inner_frame", &[st.last_inner_frame]);
        check16(case, "prev_weight1", &[st.prev_weight1]);
    }
}

#[test]
fn updt_dec_common_matches_the_reference() {
    let Some(cases) = corpus("updt_dec", "updt_dec_common") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        st.codec_mode = case.i16("codec_mode");
        st.extl = case.i16("extl");
        st.l_frame = case.i16("l_frame");
        st.prev_bfi = case.i16("prev_bfi");
        st.bfi = case.i16("bfi");
        st.nb_lost_cmpt = case.i16("nb_lost_cmpt");
        st.con_tcx = case.i16("con_tcx");
        st.last_core = case.i16("last_core");
        st.rf_frame_type = case.i16("rf_frame_type");
        st.use_partial_copy = case.i16("use_partial_copy");
        st.last_good = case.i16("last_good");
        st.clas_dec = case.i16("clas_dec");
        st.m_frame_type = case.i16("m_frame_type");
        st.rf_flag = case.i16("rf_flag");
        st.rf_flag_last = case.i16("rf_flag_last");
        st.core_brate = case.i32("core_brate");
        st.total_brate = case.i32("total_brate");
        st.last_is_cng = case.i16("last_is_cng") as i8;
        st.core = case.i16("core");
        st.output_fs = case.i32("output_fs");
        st.q_old_postdec = case.i16("q_old_postdec");
        st.cng_type = case.i16("cng_type");
        st.tcxonly = case.i16("tcxonly") as i8;
        st.sr_core = case.i32("sr_core");
        st.last_active_brate = case.i32("last_active_brate");
        st.last_core_bfi = case.i16("last_core_bfi");
        st.mem_ma.copy_from_slice(&case.i16s("mem_ma"));
        st.mem_ar.copy_from_slice(&case.i16s("mem_ar"));
        updt_dec_common(&mut st, case.i16("hq_core_type"), &case.i16s("synth"));
        check16(case, "last_codec_mode", &[st.last_codec_mode]);
        check16(case, "last_extl", &[st.last_extl]);
        check16(case, "last_l_frame", &[st.last_l_frame]);
        check16(case, "prev_old_bfi", &[st.prev_old_bfi]);
        check16(case, "prev_bfi", &[st.prev_bfi]);
        check16(case, "old_bfi_cnt", &[st.old_bfi_cnt]);
        check16(case, "last_con_tcx", &[st.last_con_tcx]);
        check16(case, "con_tcx", &[st.con_tcx]);
        check16(case, "prev_last_core", &[st.prev_last_core]);
        check16(case, "tcx_conceal_recalc_exc", &[st.tcx_conceal_recalc_exc]);
        check16(case, "last_good", &[st.last_good]);
        check16(case, "prev_rf_frame_type", &[st.prev_rf_frame_type]);
        check16(case, "rf_flag_last", &[st.rf_flag_last]);
        check(
            case,
            "last_active_brate",
            &st.last_active_brate,
            &case.out_i32("last_active_brate"),
        );
        check16(case, "last_core", &[st.last_core]);
        check16(case, "last_hq_core_type", &[st.last_hq_core_type]);
        check16(case, "last_is_cng", &[i16::from(st.last_is_cng)]);
        check16(case, "last_core_bfi", &[st.last_core_bfi]);
        check(
            case,
            "last_core_brate",
            &st.last_core_brate,
            &case.out_i32("last_core_brate"),
        );
        check16(case, "old_synth_sw", &st.old_synth_sw);
        check16(case, "mem_ma", &st.mem_ma);
        check16(case, "mem_ar", &st.mem_ar);
    }
}
