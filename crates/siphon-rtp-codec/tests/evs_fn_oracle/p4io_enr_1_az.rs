//! `lib_com/enr_1_az_fx.c` with the STL `Overflow` flag it leaves behind (which `improv_amr_wb_gs_fx`
//! reads) against `fn_p4io_enr_1_az`.

use siphon_rtp_codec::evs::com::enr_1_az::{enr_1_az, enr_1_az_flagged};

use crate::common::{corpus, mismatch};

#[test]
fn enr_1_az_and_its_overflow_flag_match_the_reference() {
    let Some(cases) = corpus("p4io_enr_1_az", "enr_1_az") else {
        return;
    };
    let mut overflows = 0;
    for case in &cases {
        let aq = case.i16s("aq");
        let len = case.i16("len");
        let (enr, overflow) = enr_1_az_flagged(&aq, len);
        let message = mismatch(case, "enr", &enr, &case.out_i16("enr")).or_else(|| {
            mismatch(
                case,
                "overflow",
                &i32::from(overflow),
                &case.out_i32("overflow"),
            )
        });
        if let Some(message) = message {
            panic!("{message}");
        }
        assert_eq!(enr_1_az(&aq, len), enr);
        overflows += usize::from(overflow);
    }
    // both outcomes are exercised
    assert!(
        overflows > 100 && overflows < cases.len() - 100,
        "{overflows}"
    );
}
