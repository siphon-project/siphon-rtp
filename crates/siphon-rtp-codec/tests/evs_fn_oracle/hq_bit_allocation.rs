//! `lib_com/hq_bit_allocation_fx.c` against `fn_hq_bit_allocation`: every HQ class and frame
//! length the high-rate decoder runs (24.4 .. 128 kbit/s, 320 / 640 / 960 coefficients), with the
//! callees `bitalloc`, `bitallocsum`, `bit_alloc_f`, `bit_alloc_wb`, `map_quant_weight`,
//! `limit_band_noise_level_calc` and `find_last_band` reached through it.

use siphon_rtp_codec::evs::com::hq_bit_allocation::hq_bit_allocation;

use crate::common::{corpus, mismatch};

#[test]
fn hq_bit_allocation_matches_the_reference() {
    let Some(cases) = corpus("hq_bit_allocation", "hq_bit_allocation") else {
        return;
    };
    let mut seen = std::collections::BTreeSet::new();
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let nb_sfm = case.i16("nb_sfm");
        let mut num_bits = case.i16("num_bits");
        let mut noise_level = [-7i16; 2];
        let mut r = [-7i16; 44];
        let mut rsubband = [-7i16; 44];
        let mut sum = -7;
        let mut core_sfm = -7;
        hq_bit_allocation(
            case.i32("core_brate"),
            case.i16("length"),
            case.i16("hqswb_clas"),
            &mut num_bits,
            &case.i16s("normqlg2"),
            nb_sfm,
            &case.i16s("sfmsize"),
            &mut noise_level,
            &mut r,
            &mut rsubband,
            &mut sum,
            &mut core_sfm,
            case.i16("num_env_bands"),
        );
        if let Some(message) = [
            mismatch(case, "num_bits", &num_bits, &case.out_i16("num_bits")),
            mismatch(
                case,
                "noise_level",
                &noise_level[0],
                &case.out_i16("noise_level"),
            ),
            mismatch(case, "r", &r.to_vec(), &case.out_i16s("r")),
            mismatch(
                case,
                "rsubband",
                &rsubband[..nb_sfm as usize].to_vec(),
                &case.out_i16s("rsubband"),
            ),
            mismatch(case, "sum", &sum, &case.out_i16("sum")),
            mismatch(case, "core_sfm", &core_sfm, &case.out_i16("core_sfm")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
        seen.insert((
            case.i16("length"),
            case.i16("hqswb_clas"),
            case.i32("core_brate") <= 32000,
        ));
    }
    assert!(
        seen.len() >= 12,
        "only {} class/length/rate combinations: {seen:?}",
        seen.len()
    );
}
