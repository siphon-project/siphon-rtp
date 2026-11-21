//! `lib_com/lsf_tools_fx.c` (the functions the 7.2 / 8 kbit/s decoder runs) against
//! `fn_lsf_tools`. `xsf_to_xsp` is proven through `E_LPC_lsf_lsp_conversion`, `xsp_to_xsf` through
//! `E_LPC_lsp_lsf_conversion`.

use siphon_rtp_codec::evs::com::lsf_tools::{
    e_lpc_a_lsp_conversion, e_lpc_f_isp_a_conversion, e_lpc_f_lsp_a_conversion,
    e_lpc_f_lsp_pol_get, e_lpc_isf_isp_conversion, e_lpc_lsf_lsp_conversion,
    e_lpc_lsp_lsf_conversion, find_pred_mode, lsf2lsp, lsf_allocate, lsf_stab, lsp2lsf,
    qlsf_arsn_tcvq_dec_16k, reorder_isf, reorder_lsf, sub_lsp2lsf, vq_dec_lvq,
};
use siphon_rtp_codec::evs::com::mslvq_com::init_lvq;

use crate::common::{corpus, mismatch, Case};

fn check16(case: &Case, name: &str, rust: &[i16]) {
    if let Some(message) = mismatch(case, name, &rust.to_vec(), &case.out_i16s(name)) {
        panic!("{message}");
    }
}

#[test]
fn e_lpc_f_lsp_pol_get_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsp_pol_get") else {
        return;
    };
    for case in &cases {
        let lsp = case.i16s("lsp");
        let n = case.i16("n");
        let mut f = vec![0i32; n as usize + 1];
        let ovf = e_lpc_f_lsp_pol_get(
            &lsp[case.i16("first") as usize..],
            &mut f,
            n,
            case.i16("past_ovf"),
            case.i16("is_mode1"),
        );
        let rust = [vec![i32::from(ovf)], f].concat();
        let reference = [vec![case.out_i32("ovf")], case.out_i32s("f")].concat();
        if let Some(message) = mismatch(case, "ovf/f", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn e_lpc_f_lsp_a_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsp_a_conversion") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut a = vec![0i16; m as usize + 1];
        e_lpc_f_lsp_a_conversion(&case.i16s("lsp"), &mut a, m);
        check16(case, "a", &a);
    }
}

#[test]
fn reorder_lsf_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "reorder_lsf") else {
        return;
    };
    for case in &cases {
        let mut lsf = case.i16s("lsf");
        reorder_lsf(
            &mut lsf,
            case.i16("min_dist"),
            case.i16("n"),
            case.i32("fs"),
        );
        check16(case, "lsf", &lsf);
    }
}

#[test]
fn lsf_stab_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsf_stab") else {
        return;
    };
    for case in &cases {
        let stab = lsf_stab(
            &case.i16s("lsf"),
            &case.i16s("lsfold"),
            case.i16("opt_amr_wb"),
            case.i16("l_frame"),
        );
        check16(case, "stab", &[stab]);
    }
}

#[test]
fn lsf2lsp_and_lsp2lsf_match_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsp_lsf") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut lsp = vec![0i16; m as usize];
        let mut lsf = vec![0i16; m as usize];
        lsf2lsp(&case.i16s("lsf"), &mut lsp, m, case.i32("int_fs"));
        lsp2lsf(&case.i16s("lsp"), &mut lsf, m, case.i32("int_fs"));
        check16(case, "lsf2lsp", &lsp);
        check16(case, "lsp2lsf", &lsf);
    }
}

#[test]
fn sub_lsp2lsf_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "sub_lsp2lsf") else {
        return;
    };
    for case in &cases {
        let lsf = sub_lsp2lsf(case.i16("lsp"));
        if let Some(message) = mismatch(case, "lsf", &lsf, &case.out_i32("lsf")) {
            panic!("{message}");
        }
    }
}

#[test]
fn e_lpc_lsf_lsp_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsf_lsp_conversion") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut lsp = vec![0i16; m as usize];
        e_lpc_lsf_lsp_conversion(&case.i16s("lsf"), &mut lsp, m);
        check16(case, "lsp", &lsp);
    }
}

#[test]
fn find_pred_mode_and_lsf_allocate_match_the_reference() {
    let Some(cases) = corpus("lsf_tools", "pred_mode_and_allocate") else {
        return;
    };
    for case in &cases {
        let (mut mode_lvq, mut mode_lvq_p) = (-99i16, -99i16);
        let predmode = find_pred_mode(
            case.i16("coder_type"),
            case.i16("bwidth"),
            case.i32("int_fs"),
            &mut mode_lvq,
            &mut mode_lvq_p,
            case.i32("core_brate"),
        );
        let (mut stages0, mut stages1) = (-7i16, -7i16);
        let (mut levels0, mut levels1, mut bits0, mut bits1) = (
            vec![-7i16; 6],
            vec![-7i16; 6],
            vec![-7i16; 6],
            vec![-7i16; 6],
        );
        lsf_allocate(
            case.i16("n_bits") - (predmode >> 1),
            mode_lvq,
            mode_lvq_p,
            &mut stages0,
            &mut stages1,
            &mut levels0,
            &mut levels1,
            &mut bits0,
            &mut bits1,
        );
        let rust = [
            vec![predmode, mode_lvq, mode_lvq_p, stages0, stages1],
            levels0,
            levels1,
            bits0,
            bits1,
        ]
        .concat();
        let reference = [
            vec![
                case.out_i16("predmode"),
                case.out_i16("mode_lvq"),
                case.out_i16("mode_lvq_p"),
                case.out_i16("stages0"),
                case.out_i16("stages1"),
            ],
            case.out_i16s("levels0"),
            case.out_i16s("levels1"),
            case.out_i16s("bits0"),
            case.out_i16s("bits1"),
        ]
        .concat();
        if let Some(message) = mismatch(case, "allocation", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn vq_dec_lvq_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "vq_dec_lvq") else {
        return;
    };
    let mut offset_scale1 = vec![[0i32; 4]; 129];
    let mut offset_scale2 = vec![[0i32; 4]; 129];
    let mut offset_scale1_p = vec![[0i32; 4]; 146];
    let mut offset_scale2_p = vec![[0i32; 4]; 146];
    let mut no_scales = vec![[0i16; 2]; 128];
    let mut no_scales_p = vec![[0i16; 2]; 145];
    init_lvq(
        &mut offset_scale1,
        &mut offset_scale2,
        &mut offset_scale1_p,
        &mut offset_scale2_p,
        &mut no_scales,
        &mut no_scales_p,
    );
    for case in &cases {
        let mut x = vec![0x5555i16; 16];
        let mut indices = case.i16s("indices");
        let ber = vq_dec_lvq(
            case.i16("sf_flag"),
            &mut x,
            &mut indices,
            case.i16("stages"),
            16,
            case.i16("mode"),
            case.i16("no_bits"),
            offset_scale1.as_flattened(),
            offset_scale2.as_flattened(),
            offset_scale1_p.as_flattened(),
            offset_scale2_p.as_flattened(),
            no_scales.as_flattened(),
            no_scales_p.as_flattened(),
        );
        let rust = [vec![ber], x, indices].concat();
        let reference = [
            vec![case.out_i16("ber")],
            case.out_i16s("x"),
            case.out_i16s("indices"),
        ]
        .concat();
        if let Some(message) = mismatch(case, "ber/x/indices", &rust, &reference) {
            panic!("{message}");
        }
    }
}

#[test]
fn e_lpc_lsp_lsf_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "lsp_lsf_conversion") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut lsf = vec![0i16; m as usize];
        e_lpc_lsp_lsf_conversion(&case.i16s("lsp"), &mut lsf, m);
        check16(case, "lsf", &lsf);
    }
}

/// `E_LPC_a_lsp_conversion`; proves the static `chebyshev` through it.
#[test]
fn e_lpc_a_lsp_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "a_lsp_conversion") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut lsp = vec![0i16; m as usize];
        e_lpc_a_lsp_conversion(&case.i16s("a"), &mut lsp, &case.i16s("old_lsp"), m);
        check16(case, "lsp", &lsp);
    }
}

#[test]
fn e_lpc_f_isp_a_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "isp_a_conversion") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut a = vec![0i16; m as usize + 1];
        e_lpc_f_isp_a_conversion(&case.i16s("isp"), &mut a, m);
        check16(case, "a", &a);
    }
}

#[test]
fn reorder_isf_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "reorder_isf") else {
        return;
    };
    for case in &cases {
        let mut isf = case.i16s("isf");
        reorder_isf(
            &mut isf,
            case.i16("min_dist"),
            case.i16("n"),
            case.i16("fs"),
        );
        check16(case, "isf", &isf);
    }
}

#[test]
fn e_lpc_isf_isp_conversion_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "isf_isp_conversion") else {
        return;
    };
    for case in &cases {
        let isf = case.i16s("isf");
        let mut isp = vec![0i16; isf.len()];
        e_lpc_isf_isp_conversion(&isf, &mut isp, case.i16("m"));
        check16(case, "isp", &isp);
    }
}

#[test]
fn qlsf_arsn_tcvq_dec_16k_matches_the_reference() {
    let Some(cases) = corpus("lsf_tools", "tcvq_dec") else {
        return;
    };
    for case in &cases {
        let mut y = [0i16; 16];
        let sn = qlsf_arsn_tcvq_dec_16k(&mut y, &case.i16s("indice"), case.i16("nbits"));
        assert_eq!(sn, case.out_i16("sn"), "{}", case.line);
        if let Some(message) = mismatch(case, "y", &y.to_vec(), &case.out_i16s("y")) {
            panic!("{message}");
        }
    }
}
