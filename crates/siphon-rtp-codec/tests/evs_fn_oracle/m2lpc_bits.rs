//! `lib_com/bits_alloc.c` against `fn_m2lpc_bits`.

use siphon_rtp_codec::evs::com::bits_alloc::{
    bits_alloc_adjust_acelp_fixed_cdk, bits_alloc_config_acelp, bits_alloc_init_config_acelp,
};
use siphon_rtp_codec::evs::dec::state::AcelpConfig;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The reference's `memset(&config, 0x5a, ...)` pattern.
fn patterned_config() -> AcelpConfig {
    let mut config = AcelpConfig::zeroed();
    config.mode_index = 0x5a5a;
    config.mid_lpc = 0x5a;
    config.mid_lpc_enable = 0x5a;
    config.pre_emphasis = 0x5a;
    config.pitch_sharpening = 0x5a;
    config.phase_scrambling = 0x5a;
    config.formant_enh = 0x5a5a;
    config.formant_tilt = 0x5a;
    config.voice_tilt = 0x5a;
    config.formant_enh_num = 0x5a5a;
    config.formant_enh_den = 0x5a5a;
    config.bpf_mode = 0x5a5a;
    config.nrg_mode = 0x5a5a;
    config.nrg_bits = 0x5a5a;
    config.ltp_mode = 0x5a5a;
    config.ltp_bits = 0x5a5a;
    config.ltf_mode = 0x5a5a;
    config.ltf_bits = 0x5a5a;
    config.gains_mode = [0x5a5a; 5];
    config.fixed_cdk_index = [0x5a5a; 5];
    config
}

fn check_config(case: &Case, config: &AcelpConfig) {
    let fields = vec![
        config.mode_index,
        i16::from(config.mid_lpc),
        i16::from(config.mid_lpc_enable),
        i16::from(config.pre_emphasis),
        i16::from(config.pitch_sharpening),
        i16::from(config.phase_scrambling),
        config.formant_enh,
        i16::from(config.formant_tilt),
        i16::from(config.voice_tilt),
        config.formant_enh_num,
        config.formant_enh_den,
        config.bpf_mode,
        config.nrg_mode,
        config.nrg_bits,
        config.ltp_mode,
        config.ltp_bits,
        config.ltf_mode,
        config.ltf_bits,
    ];
    check(case, "config", &fields, &case.out_i16s("config"));
    check(
        case,
        "gains_mode",
        &config.gains_mode.to_vec(),
        &case.out_i16s("gains_mode"),
    );
    check(
        case,
        "fixed_cdk_index",
        &config.fixed_cdk_index.to_vec(),
        &case.out_i16s("fixed_cdk_index"),
    );
}

#[test]
fn bits_alloc_init_config_acelp_matches_the_reference() {
    let Some(cases) = corpus("m2lpc_bits", "init_config") else {
        return;
    };
    for case in &cases {
        let mut config = patterned_config();
        bits_alloc_init_config_acelp(
            case.i32("rate"),
            case.i16("narrow") as i8,
            case.i16("nb_subfr"),
            &mut config,
        );
        check_config(case, &config);
    }
}

#[test]
fn bits_alloc_config_acelp_matches_the_reference() {
    let Some(cases) = corpus("m2lpc_bits", "config_acelp") else {
        return;
    };
    for case in &cases {
        let mut config = AcelpConfig::zeroed();
        bits_alloc_init_config_acelp(
            case.i32("rate"),
            case.i16("narrow") as i8,
            case.i16("nb_subfr"),
            &mut config,
        );
        config.gains_mode = [55; 5];
        config.fixed_cdk_index = [66; 5];
        let r = bits_alloc_config_acelp(
            case.i16("bits_frame"),
            case.i16("coder_type"),
            &mut config,
            case.i16("narrow"),
            case.i16("nb_subfr"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        // The reference's config also holds what the zeroed struct leaves; compare its printed fields.
        check_config(case, &config);
    }
}

#[test]
fn bits_alloc_adjust_acelp_fixed_cdk_matches_the_reference() {
    let Some(cases) = corpus("m2lpc_bits", "adjust") else {
        return;
    };
    for case in &cases {
        let mut index = [66i16; 5];
        let r = bits_alloc_adjust_acelp_fixed_cdk(
            case.i16("bits_frame"),
            &mut index,
            case.i16("nb_subfr"),
        );
        check(case, "r", &r, &case.out_i16("r"));
        check(case, "index", &index.to_vec(), &case.out_i16s("index"));
    }
}
