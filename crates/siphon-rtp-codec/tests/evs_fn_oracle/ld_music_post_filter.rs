//! `lib_dec/LD_music_post_filter_fx.c` against `fn_LD_music_post_filter`. The static
//! `spectrum_mod_dct_fx`, `analy_sp_dct_fx`, `find_enr_dct_fx` and `norm_lfe` are proven through
//! `LD_music_post_filter_fx`, run over four consecutive frames carrying every memory.

use siphon_rtp_codec::evs::dec::ld_music_post_filter::{
    ld_music_post_filter, post_music_post_p, prep_music_post_p, LdMusicState, PostMusicMemories,
};
use siphon_rtp_codec::evs::dec::state::Pfstat;

use crate::common::{corpus_sized, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn ld_music_post_filter_matches_the_reference_over_consecutive_frames() {
    // each case is four frames of 640-bin state; 500 keep the corpus to a few hundred megabytes
    let Some(cases) = corpus_sized("LD_music_post_filter", "ld_music_post_filter", 500) else {
        return;
    };
    for case in &cases {
        let mut last_music_flag = case.i16("last_music_flag");
        let mut thresh = case.i16s("thresh");
        let mut nb_thr_1 = case.i16("nb_thr_1");
        let mut nb_thr_3 = case.i16("nb_thr_3");
        let mut lt_diff_etot = case.i16s("lt_diff_etot");
        let mut mem_etot = case.i16("mem_etot");
        let mut bckr = case.i32s("bckr");
        let mut lf_eo = case.i32s("lf_eo");
        let mut lp_gbin = case.i16s("lp_gbin");
        let mut filt_lfe = case.i16s("filt_lfe");
        let mut last_nonfull_music = case.i16("last_nonfull_music");
        let mut old_ener_q = case.i16("old_ener_q");
        for k in 0..4 {
            let field = |name: &str| format!("{name}{k}");
            let mut dtc = case.i16s(&field("dtc"));
            let mut st = LdMusicState {
                last_music_flag: &mut last_music_flag,
                thresh: &mut thresh,
                nb_thr_1: &mut nb_thr_1,
                nb_thr_3: &mut nb_thr_3,
                lt_diff_etot: &mut lt_diff_etot,
                mem_etot: &mut mem_etot,
                bckr: &mut bckr,
                lf_eo: &mut lf_eo,
                lp_gbin: &mut lp_gbin,
                filt_lfe: &mut filt_lfe,
                last_nonfull_music: &mut last_nonfull_music,
                old_ener_q: &mut old_ener_q,
            };
            ld_music_post_filter(
                &mut dtc,
                case.i32("core_brate"),
                &mut st,
                case.i16("min_ns_gain"),
                case.i16("coder_type"),
                case.i16(&field("last_coder_type")),
                case.i16(&field("qdct")),
            );
            check(case, &field("dtc"), &dtc, &case.out_i16s(&field("dtc")));
            let scalars = vec![
                last_music_flag,
                nb_thr_1,
                nb_thr_3,
                mem_etot,
                last_nonfull_music,
                old_ener_q,
            ];
            check(
                case,
                &field("scalars"),
                &scalars,
                &case.out_i16s(&field("scalars")),
            );
            check(
                case,
                &field("thresh"),
                &thresh,
                &case.out_i16s(&field("thresh")),
            );
            check(
                case,
                &field("lt_diff_etot"),
                &lt_diff_etot,
                &case.out_i16s(&field("lt_diff_etot")),
            );
            check(case, &field("bckr"), &bckr, &case.out_i32s(&field("bckr")));
            check(
                case,
                &field("lf_eo"),
                &lf_eo,
                &case.out_i32s(&field("lf_eo")),
            );
            check(
                case,
                &field("lp_gbin"),
                &lp_gbin,
                &case.out_i16s(&field("lp_gbin")),
            );
            check(
                case,
                &field("filt_lfe"),
                &filt_lfe,
                &case.out_i16s(&field("filt_lfe")),
            );
        }
    }
}

#[test]
fn prep_music_post_p_matches_the_reference() {
    let Some(cases) = corpus_sized("LD_music_post_filter", "prep", 2000) else {
        return;
    };
    for case in &cases {
        let mut exc = case.i16s("exc");
        let mut filt = case.i16s("filt");
        let mut gbin = case.i16s("gbin");
        let mut dct = vec![0x5555_i16; 640];
        let mut qdct = 99;
        prep_music_post_p(
            &mut exc,
            &mut dct,
            &mut filt,
            case.i16("last_core"),
            &case.i16s("pitch"),
            &mut gbin,
            case.i16("q_exc"),
            &mut qdct,
        );
        check(case, "exc", &exc, &case.out_i16s("exc"));
        check(case, "dct", &dct, &case.out_i16s("dct"));
        check(case, "filt", &filt, &case.out_i16s("filt"));
        check(case, "gbin", &gbin, &case.out_i16s("gbin"));
        check(case, "qdct", &qdct, &case.out_i16("qdct"));
    }
}

#[test]
fn post_music_post_p_matches_the_reference() {
    let Some(cases) = corpus_sized("LD_music_post_filter", "post", 2000) else {
        return;
    };
    for case in &cases {
        let mem_tmp = case.i16s("mem_tmp");
        let mut mem_syn2 = case.i16s("mem_syn2");
        let mut clas = case.i16s("clas");
        let mut pst = case.i16s("pst");
        let mut pf = Pfstat::zeroed();
        pf.mem_pf_in.copy_from_slice(&case.i16s("pf_in"));
        pf.mem_res2.copy_from_slice(&case.i16s("pf_res2"));
        pf.mem_stp.copy_from_slice(&case.i16s("pf_stp"));
        let (mut deemph, mut err, mut agc) = (case.i16("deemph"), case.i16("err"), case.i16("agc"));
        let mut q_exc = case.i16("q_exc");
        let mut prev_q_syn = case.i16("prev_q_syn");
        let mut q_syn = case.i16("q_syn");
        let mut mem_tmp2 = vec![0x1234_i16; 16];
        let mut exc2 = vec![0i16; 256];
        let mut syn = vec![0i16; 256];
        let tmpbuf = case.i16s("tmpbuf");
        let mut mem = PostMusicMemories {
            mem_tmp: (case.i16("alias") == 0).then_some(&mem_tmp[..]),
            st_mem_syn2: &mut mem_syn2,
            mem_syn_clas_estim: &mut clas,
            mem_deemph: &mut deemph,
            pst_old_syn: &mut pst,
            pst_mem_deemp_err: &mut err,
            mem_agc: &mut agc,
            pf_stat: &mut pf,
            mem_tmp2: Some(&mut mem_tmp2),
        };
        post_music_post_p(
            &case.i16s("dct"),
            &mut exc2,
            &mut mem,
            &case.i16s("aq"),
            &mut syn,
            &mut q_exc,
            &mut prev_q_syn,
            &mut q_syn,
            case.i16("is_io"),
            (case.i16("has_tmp") != 0).then_some(&tmpbuf[..]),
        );
        check(case, "exc2", &exc2, &case.out_i16s("exc2"));
        check(case, "syn", &syn, &case.out_i16s("syn"));
        check(case, "mem_syn2", &mem_syn2, &case.out_i16s("mem_syn2"));
        check(case, "mem_tmp2", &mem_tmp2, &case.out_i16s("mem_tmp2"));
        check(case, "clas", &clas, &case.out_i16s("clas"));
        check(case, "pst", &pst, &case.out_i16s("pst"));
        check(
            case,
            "pf_in",
            &pf.mem_pf_in.to_vec(),
            &case.out_i16s("pf_in"),
        );
        check(
            case,
            "pf_res2",
            &pf.mem_res2.to_vec(),
            &case.out_i16s("pf_res2"),
        );
        check(
            case,
            "pf_stp",
            &pf.mem_stp.to_vec(),
            &case.out_i16s("pf_stp"),
        );
        let scalars = (deemph, err, agc, q_exc, prev_q_syn, q_syn);
        let reference = (
            case.out_i16("deemph"),
            case.out_i16("err"),
            case.out_i16("agc"),
            case.out_i16("q_exc"),
            case.out_i16("prev_q_syn"),
            case.out_i16("q_syn"),
        );
        check(case, "scalars", &scalars, &reference);
    }
}
