//! `lib_com/lpc_tools_fx.c` (`E_LPC_lev_dur_stab`) against `fn_lpc_tools`, with and without the
//! stability memory and the error vector.

use siphon_rtp_codec::evs::com::lpc_tools::e_lpc_lev_dur_stab;

use crate::common::{corpus, mismatch};

#[test]
fn e_lpc_lev_dur_stab_matches_the_reference() {
    let Some(cases) = corpus("lpc_tools", "lev_dur") else {
        return;
    };
    for case in &cases {
        let order = case.i16("order");
        let n = order as usize + 1;
        let mut a = vec![0i16; n];
        let mut mem = case.i16s("mem");
        let mut eps = vec![0i32; n];
        let with_eps = case.i16("with_eps") != 0;
        let flag = e_lpc_lev_dur_stab(
            &case.i16s("rh"),
            &case.i16s("rl"),
            &mut a,
            with_eps.then_some(&mut eps[..]),
            order,
            (case.i16("with_mem") != 0).then_some(&mut mem[..]),
            case.i16("k_max"),
        );
        let message = mismatch(case, "A", &a, &case.out_i16s("A"))
            .or_else(|| mismatch(case, "flag", &flag, &case.out_i16("flag")))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16s("mem")))
            .or_else(|| {
                with_eps
                    .then(|| mismatch(case, "eps", &eps, &case.out_i32s("eps")))
                    .flatten()
            });
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn autocorr_matches_the_reference() {
    use siphon_rtp_codec::evs::com::lpc_tools::autocorr;

    let Some(cases) = corpus("lpc_tools", "autocorr") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut r_h = vec![0i16; m as usize + 1];
        let mut r_l = vec![0i16; m as usize + 1];
        let mut q_r = -99;
        autocorr(
            &case.i16s("x"),
            m,
            &mut r_h,
            &mut r_l,
            &mut q_r,
            case.i16("len"),
            &case.i16s("wind"),
            case.i16("rev_flag"),
            case.i16("sym_flag"),
        );
        let message = mismatch(case, "r_h", &r_h, &case.out_i16s("r_h"))
            .or_else(|| mismatch(case, "r_l", &r_l, &case.out_i16s("r_l")))
            .or_else(|| mismatch(case, "q_r", &q_r, &case.out_i16("q_r")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
