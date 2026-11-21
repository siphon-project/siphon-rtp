//! `lib_com/modif_fs_fx.c` against `fn_modif_fs` (the 2:1 and 3:1 interpolators, the cubic
//! interpolator).

use siphon_rtp_codec::evs::com::modif_fs::{
    interpolate_3_over_1_allpass, interpolate_allpass_steep, modify_fs, modify_fs_in_place,
    modify_fs_intcub3m_sup, retro_interp4_5, retro_interp5_4,
};
use siphon_rtp_codec::evs::rom::ALLPASS_POLES_3_OV_2;

use crate::common::{corpus, mismatch};

#[test]
fn interpolate_allpass_steep_matches_the_reference() {
    let Some(cases) = corpus("modif_fs", "interpolate_allpass_steep") else {
        return;
    };
    for case in &cases {
        let input = case.i16s("in");
        let mut state = case.i16s("state");
        let mut out = vec![0; 2 * input.len()];
        interpolate_allpass_steep(&input, &mut state, input.len() as i16, &mut out);
        if let Some(message) = mismatch(case, "out", &out, &case.out_i16s("out"))
            .or_else(|| mismatch(case, "state", &state, &case.out_i16s("state")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn interpolate_3_over_1_allpass_matches_the_reference() {
    let Some(cases) = corpus("modif_fs", "interpolate_3_over_1") else {
        return;
    };
    for case in &cases {
        let input = case.i16s("in");
        let mut mem = case.i16s("mem");
        let mut out = vec![0; 3 * input.len()];
        interpolate_3_over_1_allpass(
            &input,
            input.len() as i16,
            &mut out,
            &mut mem,
            &ALLPASS_POLES_3_OV_2,
        );
        if let Some(message) = mismatch(case, "out", &out, &case.out_i16s("out"))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16s("mem")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn modify_fs_intcub3m_sup_matches_the_reference() {
    let Some(cases) = corpus("modif_fs", "intcub3m_sup") else {
        return;
    };
    for case in &cases {
        let input = case.i16s("in");
        let lg = input.len() as i16 - 2;
        let mut out = vec![-12345i16; 4 * 200 + 16];
        let mut delay = -99;
        let lg_out = modify_fs_intcub3m_sup(
            &input,
            2,
            lg,
            case.i32("fin"),
            &mut out,
            case.i32("fout"),
            &mut delay,
        );
        out.truncate(4 * lg as usize + 16);
        if let Some(message) = mismatch(case, "lg_out", &lg_out, &case.out_i16("lg_out"))
            .or_else(|| mismatch(case, "delay", &delay, &case.out_i16("delay")))
            .or_else(|| mismatch(case, "out", &out, &case.out_i16s("out")))
        {
            panic!("{message}");
        }
    }
}

#[test]
fn retro_interp_matches_the_reference() {
    for (function, forward) in [("retro_interp4_5", true), ("retro_interp5_4", false)] {
        let Some(cases) = corpus("modif_fs", function) else {
            return;
        };
        for case in &cases {
            let mut memory = case.i16s("memory");
            if forward {
                retro_interp4_5(&case.i16s("syn"), &mut memory);
            } else {
                retro_interp5_4(&mut memory);
            }
            if let Some(message) = mismatch(case, function, &memory, &case.out_i16s("memory")) {
                panic!("{message}");
            }
        }
    }
}

/// `modify_Fs_fx` over every rate pair of the resampling table (the same buffer in and out too).
#[test]
fn modify_fs_matches_the_reference() {
    let Some(cases) = corpus("modif_fs", "modify_fs") else {
        return;
    };
    for case in &cases {
        let lg = case.i16("lg");
        let (fin, fout) = (case.i32("fin"), case.i32("fout"));
        let mut mem = case.i16s("mem");
        let mut out = vec![-12345i16; 1920];
        let lg_out = modify_fs(
            &case.i16s("in"),
            lg,
            fin,
            &mut out,
            fout,
            &mut mem,
            case.i16("nblp"),
        );
        let expected = case.out_i16s("out");
        let shown = expected.len();
        if let Some(index) = (0..shown).find(|&i| out[i] != expected[i]) {
            panic!(
                "fin {fin} fout {fout} lg {lg} nblp {}: lg_out {lg_out} (ref {}): first difference at {index} of {shown}: rust {} ref {}",
                case.i16("nblp"),
                case.out_i16("lg_out"),
                out[index],
                expected[index]
            );
        }
        if let Some(message) = mismatch(case, "lg_out", &lg_out, &case.out_i16("lg_out"))
            .or_else(|| mismatch(case, "out", &out[..shown].to_vec(), &expected))
            .or_else(|| mismatch(case, "mem", &mem, &case.out_i16s("mem")))
        {
            panic!("{message}");
        }
        // the same buffer as input and output, as CNG_exc_fx calls it (the output starts at 0)
        let mut sig = vec![0i16; 1920];
        sig[..lg as usize].copy_from_slice(&case.i16s("in"));
        let mut mem = case.i16s("mem");
        let lg_out = modify_fs_in_place(&mut sig, lg, fin, fout, &mut mem, case.i16("nblp"));
        if let Some(message) = mismatch(case, "in-place lg_out", &lg_out, &case.out_i16("lg_out"))
            .or_else(|| {
                mismatch(
                    case,
                    "in-place out",
                    &sig[..lg_out as usize].to_vec(),
                    &expected[..lg_out as usize].to_vec(),
                )
            })
            .or_else(|| mismatch(case, "in-place mem", &mem, &case.out_i16s("mem")))
        {
            panic!("{message}");
        }
    }
}
