//! `lib_dec/dec_acelp.c` against `fn_dec_acelp`.

use siphon_rtp_codec::evs::cnst::NB_TRACK_FCB_4T;
use siphon_rtp_codec::evs::dec::dec_acelp::{
    d_acelp_decode_arithtrack, d_acelp_indexing, fcb_pulse_track_joint_decode,
};
use siphon_rtp_codec::evs::rom::PULSECONFTABLE;

use crate::common::{corpus, mismatch};

#[test]
fn d_acelp_decode_arithtrack_matches_the_reference() {
    let Some(cases) = corpus("dec_acelp", "decode_arithtrack") else {
        return;
    };
    for case in &cases {
        let mut v = case.i16s("v");
        let track = case.i16("track") as usize;
        d_acelp_decode_arithtrack(&mut v[track..], case.i32("s"), case.i16("p"), 4, 16);
        if let Some(message) = mismatch(case, "v", &v, &case.out_i16s("v")) {
            panic!("{message}");
        }
    }
}

#[test]
fn d_acelp_indexing_matches_the_reference() {
    let Some(cases) = corpus("dec_acelp", "indexing") else {
        return;
    };
    for case in &cases {
        let mut code = vec![0x1234; 64];
        let mut ber = 0;
        let config = PULSECONFTABLE[case.i16("config") as usize];
        d_acelp_indexing(
            &mut code,
            config,
            NB_TRACK_FCB_4T,
            &case.i16s("index"),
            &mut ber,
        );
        if let Some(message) = mismatch(case, "code", &code, &case.out_i16s("code"))
            .or_else(|| mismatch(case, "ber", &ber, &case.out_i16("ber")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn fcb_pulse_track_joint_decode_matches_the_reference() {
    let Some(cases) = corpus("dec_acelp", "joint_decode") else {
        return;
    };
    for case in &cases {
        let idxs: Vec<u16> = case.i32s("idxs").iter().map(|&v| v as u16).collect();
        let mut index_n: Vec<u32> = case.i32s("index_n").iter().map(|&v| v as u32).collect();
        fcb_pulse_track_joint_decode(
            &idxs,
            case.i16("wordcnt"),
            &mut index_n,
            &case.i16s("pulse_num"),
            4,
        );
        let reference: Vec<u32> = case.out_i32s("index_n").iter().map(|&v| v as u32).collect();
        if let Some(message) = mismatch(case, "index_n", &index_n, &reference) {
            panic!("{message}");
        }
    }
}
