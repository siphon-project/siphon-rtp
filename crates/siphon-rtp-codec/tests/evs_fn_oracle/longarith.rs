//! `lib_com/longarith.c` against `fn_longarith`.

use siphon_rtp_codec::evs::com::longarith::longshr;

use crate::common::{corpus, mismatch};

#[test]
fn longshr_matches_the_reference() {
    let Some(cases) = corpus("longarith", "longshr") else {
        return;
    };
    for case in &cases {
        let mut a: Vec<u32> = case.i32s("a").iter().map(|&v| v as u32).collect();
        let len = a.len() as i16;
        longshr(&mut a, case.i16("bits"), len);
        let reference: Vec<u32> = case.out_i32s("a").iter().map(|&v| v as u32).collect();
        if let Some(message) = mismatch(case, "a", &a, &reference) {
            panic!("{message}");
        }
    }
}
