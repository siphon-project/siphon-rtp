//! `lib_com/tcx_mdct_window.c` against `fn_tcx_mdct_window`: `mdct_window_aldo` at every frame
//! length the TCX configures, with the outputs prefilled by a sentinel so a missed or extra write
//! shows (the oracle prints one element past each part). `mdct_window_sine` is the
//! `getSineWindowTable` lookup, proven by the `rom_basop_util` oracle.

use siphon_rtp_codec::evs::com::tcx_mdct_window::mdct_window_aldo;
use siphon_rtp_codec::evs::dec::state::PWord16;

use crate::common::{corpus, mismatch};

const SENTINEL: i16 = -12345;

#[test]
fn mdct_window_aldo_matches_the_reference() {
    let Some(cases) = corpus("tcx_mdct_window", "mdct_window_aldo") else {
        return;
    };
    for case in &cases {
        let n = case.i16("n");
        let (n0, n7) = (n as usize * 9 / 32, n as usize * 7 / 32);
        let mut window1 = vec![SENTINEL; 271];
        let mut sentinel = PWord16::zeroed();
        sentinel.v.re = SENTINEL;
        sentinel.v.im = SENTINEL;
        let mut trunc = vec![sentinel; 211];
        let mut window2 = vec![sentinel; 211];
        mdct_window_aldo(&mut window1, &mut trunc, &mut window2, n);
        let part = |p: &[PWord16], re: bool| -> Vec<i16> {
            p[..=n7]
                .iter()
                .map(|w| if re { w.v.re } else { w.v.im })
                .collect()
        };
        let outputs = [
            ("window1", window1[..=n0].to_vec()),
            ("trunc_re", part(&trunc, true)),
            ("trunc_im", part(&trunc, false)),
            ("window2_re", part(&window2, true)),
            ("window2_im", part(&window2, false)),
        ];
        for (name, rust) in outputs {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}
