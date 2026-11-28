//! `lib_com/hq2_noise_inject_fx.c` against `fn_hq2_noise_inject`: two consecutive frames through one
//! noise-filling memory, on band layouts from `hq2_core_configure` and spectra from
//! `mdct_spectrum_denorm`.

use siphon_rtp_codec::evs::com::hq2_noise_inject::hq2_noise_inject;

use crate::common::{corpus, mismatch, Case};
use crate::hq2_core_com::configure;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn hq2_noise_inject_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("hq2_noise_inject", "hq2_noise_inject") else {
        return;
    };
    for case in &cases {
        let c = configure(case);
        let mut last_ni_gain = case.i32s("last_ni_gain");
        let mut last_env = case.i16s("last_env");
        let mut last_max_pos_pulse = case.i16("last_max_pos_pulse");
        for frame in 0..2 {
            let name = |base: &str| format!("{base}{frame}");
            let mut y2 = case.i32s(&format!("y2_{frame}"));
            let mut ep = case.i32s(&name("ep"));
            hq2_noise_inject(
                &mut y2,
                &c.band_start,
                &c.band_end,
                &c.band_width,
                &mut ep,
                &case.i32s(&name("rk")),
                &case.i16s(&name("npulses")),
                case.i16(&name("seed")),
                c.bands,
                0,
                case.i16(&name("bw_low")),
                case.i16(&name("bw_high")),
                case.i32(&name("ener_l")),
                case.i32(&name("ener_h")),
                &mut last_ni_gain,
                &mut last_env,
                &mut last_max_pos_pulse,
                &case.i16s(&name("p2a_flags")),
                c.p2a_bands,
                case.i16("hqswb_clas"),
                case.i16("bwidth"),
                case.i32("bwe_br"),
            );
            check(
                case,
                &format!("y2_{frame}"),
                &y2,
                &case.out_i32s(&format!("y2_{frame}")),
            );
            check(case, &name("ep"), &ep, &case.out_i32s(&name("ep")));
            check(
                case,
                &name("last_ni_gain"),
                &last_ni_gain,
                &case.out_i32s(&name("last_ni_gain")),
            );
            check(
                case,
                &name("last_env"),
                &last_env,
                &case.out_i16s(&name("last_env")),
            );
            check(
                case,
                &name("last_max_pos_pulse"),
                &last_max_pos_pulse,
                &case.out_i16(&name("last_max_pos_pulse")),
            );
        }
    }
}
