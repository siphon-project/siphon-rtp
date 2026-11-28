//! `lib_dec/bass_psfilter_fx.c` against `fn_bass_psfilter`. `Pit_track_fx` is static and proven
//! through `bass_psfilter_fx` with `Opt_AMR_WB` set.

use siphon_rtp_codec::evs::cnst::CLDFB_ANALYSIS;
use siphon_rtp_codec::evs::com::cldfb::{configure_cldfb, open_cldfb, CLDFB_ROW};
use siphon_rtp_codec::evs::dec::bass_psfilter::{
    add_bass_post_filter, bass_psfilter, bass_psfilter_init, BassPsfilterState,
};
use siphon_rtp_codec::evs::dec::state::CldfbScaleFactor;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn bass_psfilter_matches_the_reference_over_consecutive_frames() {
    let Some(cases) = corpus("bass_psfilter", "bass_psfilter") else {
        return;
    };
    for case in &cases {
        let opt_amr_wb = case.i16("opt_amr_wb");
        let l_frame = case.i16("l_frame");
        let mut old_syn = case.i16s("old_syn");
        let mut mem_deemph_err = case.i16("mem_deemph_err");
        let mut lp_ener = case.i16("lp_ener");
        let mut v_stab_smooth = case.i16("v_stab_smooth");
        let mut mem_mean_pit = case.i16s("mem_mean_pit");
        let mut track_on_hist = case.i16s("track_on_hist");
        let mut vibrato_hist = case.i16s("vibrato_hist");
        let mut psf_att = case.i16("psf_att");
        for k in 0..3 {
            let field = |name: &str| format!("{name}{k}");
            let pitch = case.i16s(&field("pitch"));
            let mut noise = vec![0x5555_i16; l_frame as usize];
            let mut st = BassPsfilterState {
                old_syn: &mut old_syn,
                mem_deemph_err: &mut mem_deemph_err,
                lp_ener: &mut lp_ener,
                v_stab_smooth: &mut v_stab_smooth,
                mem_mean_pit: &mut mem_mean_pit,
                track_on_hist: &mut track_on_hist,
                vibrato_hist: &mut vibrato_hist,
                psf_att: &mut psf_att,
            };
            bass_psfilter(
                opt_amr_wb,
                &case.i16s(&field("synth")),
                l_frame,
                (case.i16(&field("null_pitch")) == 0).then_some(&pitch[..]),
                &mut st,
                case.i16(&field("bpf_off")),
                case.i16(&field("v_stab")),
                case.i16(&field("coder_type")),
                case.i16(&field("q_syn")),
                &mut noise,
            );
            check(
                case,
                &field("noise"),
                &noise,
                &case.out_i16s(&field("noise")),
            );
            check(
                case,
                &field("old_syn"),
                &old_syn,
                &case.out_i16s(&field("old_syn")),
            );
            check(
                case,
                &field("state"),
                &vec![mem_deemph_err, lp_ener, v_stab_smooth, psf_att],
                &case.out_i16s(&field("state")),
            );
            check(
                case,
                &field("mem_mean_pit"),
                &mem_mean_pit,
                &case.out_i16s(&field("mem_mean_pit")),
            );
            check(
                case,
                &field("track_on_hist"),
                &track_on_hist,
                &case.out_i16s(&field("track_on_hist")),
            );
            check(
                case,
                &field("vibrato_hist"),
                &vibrato_hist,
                &case.out_i16s(&field("vibrato_hist")),
            );
        }
    }
}

#[test]
fn bass_psfilter_init_matches_the_reference() {
    let Some(cases) = corpus("bass_psfilter", "init") else {
        return;
    };
    for case in &cases {
        let mut old_syn = vec![0x1234_i16; 290];
        let (mut mem, mut lp) = (7, 7);
        bass_psfilter_init(&mut old_syn, &mut mem, &mut lp);
        check(case, "old_syn", &old_syn, &case.out_i16s("old_syn"));
        check(
            case,
            "mem/lp",
            &(mem, lp),
            &(case.out_i16("mem"), case.out_i16("lp")),
        );
    }
}

fn rows(flat: &[i32]) -> Vec<[i32; CLDFB_ROW]> {
    flat.chunks(CLDFB_ROW)
        .map(|chunk| {
            let mut row = [0i32; CLDFB_ROW];
            row.copy_from_slice(chunk);
            row
        })
        .collect()
}

#[test]
fn add_bass_post_filter_matches_the_reference() {
    let Some(cases) = corpus("bass_psfilter", "add_bass_post_filter") else {
        return;
    };
    for case in &cases {
        let m = case.i16("m");
        let mut handle = None;
        open_cldfb(&mut handle, CLDFB_ANALYSIS, 60, 960);
        let mut bank = handle.expect("opened");
        configure_cldfb(&mut bank, m, 16 * m);
        let states = case.i16s("states");
        bank.filter_states[..states.len()].copy_from_slice(&states);
        bank.filter_states_e.copy_from_slice(&case.i16s("states_e"));
        bank.filter_states_eg = case.i16("eg");
        let mut scale = CldfbScaleFactor::zeroed();
        scale.lb_scale = case.i16("lb_scale");
        let mut r = rows(&case.i32s("r"));
        let mut i = rows(&case.i32s("i"));
        add_bass_post_filter(
            &case.i16s("time"),
            &mut r,
            &mut i,
            &mut bank,
            case.i16("time_e"),
            case.i16("slots"),
            case.i16("total"),
            case.i16("nbands"),
            &mut scale,
        );
        check(case, "r", &r.concat(), &case.out_i32s("r"));
        check(case, "i", &i.concat(), &case.out_i32s("i"));
        check(case, "lb_scale", &scale.lb_scale, &case.out_i16("lb_scale"));
        check(
            case,
            "states",
            &bank.filter_states[..states.len()].to_vec(),
            &case.out_i16s("states"),
        );
        check(
            case,
            "states_e",
            &bank.filter_states_e.to_vec(),
            &case.out_i16s("states_e"),
        );
    }
}
