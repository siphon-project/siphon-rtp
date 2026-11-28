//! `lib_dec/tonalMDCTconcealment.c` (`TonalMDCTConceal_Init`) against `fn_tonalMDCTconcealment`.

use siphon_rtp_codec::evs::dec::state::Tonalmdctconceal;
use siphon_rtp_codec::evs::dec::tonal_mdct_concealment::tonal_mdct_conceal_init;

use crate::common::{corpus, mismatch};

#[test]
fn tonal_mdct_conceal_init_matches_the_reference() {
    let Some(cases) = corpus("tonalMDCTconcealment", "init") else {
        return;
    };
    for case in &cases {
        let mut conceal = Box::new(Tonalmdctconceal::zeroed());
        if case.i16("dirty") != 0 {
            conceal.last_block_data.block_is_valid = 1;
            conceal.second_last_block_data.block_is_valid = 1;
            conceal.last_block_data.block_is_concealed = 1;
            conceal.second_last_block_data.block_is_concealed = 1;
        }
        conceal.last_pitch_lag = case.i32("last_pitch_lag");
        conceal.n_samples = case.i16("old_n_samples");
        conceal.n_scale_factors = case.i16("old_n_scale_factors");
        let result = tonal_mdct_conceal_init(
            &mut conceal,
            case.i16("n_samples"),
            case.i16("n_samples_core"),
            case.i16("n_scale_factors"),
        );
        assert_eq!(result, Ok(()));
        let offset = |slot: Option<usize>| slot.map_or(-1, |value| value as i64);
        let rust: Vec<(&str, i64)> = vec![
            ("error", 0),
            ("n_samples", conceal.n_samples.into()),
            ("n_samples_core", conceal.n_samples_core.into()),
            ("n_scale_factors", conceal.n_scale_factors.into()),
            ("last_pitch_lag", conceal.last_pitch_lag.into()),
            (
                "last_spectral",
                offset(conceal.last_block_data.spectral_data),
            ),
            (
                "second_spectral",
                offset(conceal.second_last_block_data.spectral_data),
            ),
            ("second_power", offset(conceal.second_last_power_spectrum)),
            ("last_sf", offset(conceal.last_block_data.scale_factors)),
            (
                "second_sf",
                offset(conceal.second_last_block_data.scale_factors),
            ),
            (
                "last_sf_exp",
                offset(conceal.last_block_data.scale_factors_exp),
            ),
            (
                "second_sf_exp",
                offset(conceal.second_last_block_data.scale_factors_exp),
            ),
            ("valid", conceal.last_block_data.block_is_valid.into()),
            (
                "second_valid",
                conceal.second_last_block_data.block_is_valid.into(),
            ),
            (
                "concealed",
                conceal.last_block_data.block_is_concealed.into(),
            ),
            (
                "second_concealed",
                conceal.second_last_block_data.block_is_concealed.into(),
            ),
            ("last_pcm_out", offset(conceal.last_pcm_out)),
            ("second_last_pcm_out", offset(conceal.second_last_pcm_out)),
        ];
        for (name, value) in rust {
            if let Some(message) = mismatch(case, name, &value, &case.outputs[name][0]) {
                panic!("{message}");
            }
        }
        // The two aliases without a field of their own (see the port's doc comment).
        assert_eq!(case.outputs["tci_at_time_data"][0], 1);
        assert_eq!(case.outputs["tcx_cfg_is_argument"][0], 1);
    }
}
