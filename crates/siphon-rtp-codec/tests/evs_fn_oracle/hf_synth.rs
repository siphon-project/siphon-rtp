//! `lib_dec/hf_synth_fx.c` against `fn_hf_synth` (`hf_synthesis_fx` through `hf_synth_fx`).

use siphon_rtp_codec::evs::dec::hf_synth::{filt_6k_7k_scale, hf_synth, hf_synth_reset};

use crate::common::{corpus, mismatch};

#[test]
fn filt_6k_7k_scale_matches_the_reference() {
    let Some(cases) = corpus("hf_synth", "filt_6k_7k_scale") else {
        return;
    };
    for case in &cases {
        let mut signal = case.i16s("signal");
        let mut mem = case.i16s("mem");
        let lg = signal.len() as i16;
        filt_6k_7k_scale(&mut signal, lg, &mut mem, case.i16("fact"), case.i16("exp"));
        if let Some(message) = mismatch(case, "signal", &signal, &case.out_i16s("signal"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16s("mem")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn hf_synth_reset_matches_the_reference() {
    let Some(cases) = corpus("hf_synth", "hf_synth_reset") else {
        return;
    };
    for case in &cases {
        let mut seed = case.i16("seed");
        let mut mem_hf = case.i16s("mem_hf");
        let mut syn = case.i16s("syn");
        let mut hp400 = case.i16s("hp400");
        let mut interp = case.i16s("interp");
        let mut delay = case.i16s("delay");
        hf_synth_reset(
            &mut seed,
            &mut mem_hf,
            &mut syn,
            &mut hp400,
            &mut interp,
            &mut delay,
        );
        let message = mismatch(case, "seed", &seed, &case.out_i16("seed"))
            .or_else(|| mismatch(case, "mem_hf", &mem_hf, &case.out_i16s("mem_hf")))
            .or_else(|| mismatch(case, "syn", &syn, &case.out_i16s("syn")))
            .or_else(|| mismatch(case, "hp400", &hp400, &case.out_i16s("hp400")))
            .or_else(|| mismatch(case, "interp", &interp, &case.out_i16s("interp")))
            .or_else(|| mismatch(case, "delay", &delay, &case.out_i16s("delay")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}

#[test]
fn hf_synth_matches_the_reference() {
    let Some(cases) = corpus("hf_synth", "hf_synth") else {
        return;
    };
    for case in &cases {
        let mut synth = case.i16s("synth");
        let mut synth16k = case.i16s("synth16k");
        let mut seed = case.i16("seed");
        let mut hp400 = case.i16s("hp400");
        let mut syn_hf = case.i16s("syn_hf");
        let mut mem_hf = case.i16s("mem_hf");
        let mut delay = case.i16s("delay");
        let mut mem_exp1 = case.i16("mem_exp1");
        let mut interp = case.i16s("interp");
        hf_synth(
            case.i32("brate"),
            case.i16("out_frame"),
            &case.i16s("aq"),
            &case.i16s("exc"),
            &mut synth,
            &mut synth16k,
            &mut seed,
            &mut hp400,
            &mut syn_hf,
            &mut mem_hf,
            case.i16("q_exc"),
            case.i16("q_syn2"),
            &mut delay,
            &mut mem_exp1,
            &mut interp,
            case.i16("extl"),
            case.i16("cng_mode"),
        );
        let message = mismatch(case, "synth", &synth, &case.out_i16s("synth"))
            .or_else(|| mismatch(case, "synth16k", &synth16k, &case.out_i16s("synth16k")))
            .or_else(|| mismatch(case, "seed", &seed, &case.out_i16("seed")))
            .or_else(|| mismatch(case, "hp400", &hp400, &case.out_i16s("hp400")))
            .or_else(|| mismatch(case, "syn_hf", &syn_hf, &case.out_i16s("syn_hf")))
            .or_else(|| mismatch(case, "mem_hf", &mem_hf, &case.out_i16s("mem_hf")))
            .or_else(|| mismatch(case, "delay", &delay, &case.out_i16s("delay")))
            .or_else(|| mismatch(case, "mem_exp1", &mem_exp1, &case.out_i16("mem_exp1")))
            .or_else(|| mismatch(case, "interp", &interp, &case.out_i16s("interp")));
        if let Some(message) = message {
            panic!("{message}");
        }
    }
}
