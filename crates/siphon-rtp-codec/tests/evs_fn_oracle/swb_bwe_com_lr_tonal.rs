//! `Gettonl_scalfact_fx` (`lib_com/swb_bwe_com_lr_fx.c`) against `fn_swb_bwe_com_lr_noise`: run on
//! what `ton_ene_est_fx` hands it in the decoder's harmonic chain (`DecodeSWBSubbands_fx`), two
//! frames through `har_est_fx` / `noise_extr_corcod_fx` state; a quarter synthetic.

use siphon_rtp_codec::evs::com::swb_bwe_com_lr::{gettonl_scalfact, GainItemFx};

use crate::common::{corpus, mismatch};

#[test]
fn gettonl_scalfact_matches_the_reference() {
    let Some(cases) = corpus("swb_bwe_com_lr_noise", "gettonl_scalfact") else {
        return;
    };
    for case in &cases {
        let mut xsynth = case.i32s("xsynth");
        let pk_sf: Vec<GainItemFx> = case
            .i16s("nmr")
            .iter()
            .zip(case.i16s("gidx"))
            .map(|(&nmr_value, gain_index)| GainItemFx {
                nmr_value,
                gain_index,
            })
            .collect();
        gettonl_scalfact(
            &mut xsynth,
            12,
            &case.i32s("codbuf"),
            case.i16("low"),
            case.i16("high"),
            case.i16("har_bands"),
            case.i16("bands"),
            &case.i32s("band_energy"),
            14,
            &case.i16s("band_start"),
            &case.i16s("band_end"),
            &case.i16s("flags"),
            &case.i32s("be_tonal"),
            case.i16("qbel"),
            &pk_sf,
            case.i16("qss"),
            &case.i16s("pul_res"),
        );
        if let Some(message) = mismatch(case, "xsynth", &xsynth, &case.out_i32s("xsynth")) {
            panic!("{message}");
        }
    }
}
