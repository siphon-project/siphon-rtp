//! `lib_com/lerp.c` against `fn_lerp`: two buffers ([`lerp`]), in place, and two offsets of one
//! memory ([`lerp_within`]), at the decoder's buffer lengths and random ones, ratios up to 8 so the
//! staged path runs too. `lerp_proc` is proven through `lerp`.

use siphon_rtp_codec::evs::com::lerp::{lerp, lerp_in_place, lerp_within};

use crate::common::{corpus, mismatch};

#[test]
fn lerp_matches_the_reference() {
    let Some(cases) = corpus("lerp", "lerp") else {
        return;
    };
    for case in &cases {
        let (new, old) = (case.i16("new"), case.i16("old"));
        let (name, rust) = match case.i16("mode") {
            0 => {
                // A reduction by more than 3.96 halves in stages through `f_out`, so it needs room
                // for the first stage (`old / 2`), not just the result.
                let mut out = case.i16s("out");
                out.resize(out.len().max(old as usize), 0);
                lerp(&case.i16s("f"), &mut out, new, old);
                out.truncate(new as usize);
                ("out", out)
            }
            1 => {
                let mut x = case.i16s("x");
                lerp_in_place(&mut x, new, old);
                ("x", x)
            }
            _ => {
                let mut x = case.i16s("x");
                let (f_at, out_at) = (case.i32("f_at") as usize, case.i32("out_at") as usize);
                lerp_within(&mut x, f_at, out_at, new, old);
                ("x", x)
            }
        };
        if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
            panic!("{message}");
        }
    }
}
