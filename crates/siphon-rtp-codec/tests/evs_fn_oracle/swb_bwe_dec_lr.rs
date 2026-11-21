//! `lib_dec/swb_bwe_dec_lr_fx.c` against `fn_swb_bwe_dec_lr`: `swb_bwe_dec_lr_fx` (and the
//! file-local `DecodeSWBGenericParameters_fx` / `DecodeSWBSubbands_fx` through it) over three
//! consecutive SWB frames on one decoder, `HQ_NORMAL` and `HQ_HARMONIC`. The whole state is
//! compared after every frame (`state_dump.rs`).

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::swb_bwe_dec_lr::swb_bwe_dec_lr;

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn swb_bwe_dec_lr_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("swb_bwe_dec_lr", "swb_bwe_dec_lr", 150) else {
        return;
    };
    for (index, case) in cases.iter().enumerate() {
        let mut st = Box::new(DecoderState::zeroed());
        st.output_fs = case.i32("output_fs");
        st.output_frame = case.i16("output_frame");
        init_decoder(&mut st);
        state_dump::load(&mut st, &case.inputs, "in.");
        for f in 0..3 {
            let mode = case.i32s(&format!("f{f}_mode"));
            let bits = case.i16s(&format!("f{f}_bits"));
            for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
                *slot = bit as u16;
            }
            st.total_num_bits = mode[7] as i16;
            st.next_bit_pos = 0;
            let clas = mode[1] as i16;
            let mut m = vec![-7i32; 640];
            let mut ni_seed = mode[6] as i16;
            swb_bwe_dec_lr(
                &mut st,
                &case.i32s(&format!("f{f}_y2")),
                12,
                &mut m,
                mode[0],
                mode[2] as i16,
                &case.i16s(&format!("f{f}_start")),
                &case.i16s(&format!("f{f}_end")),
                &case.i32s(&format!("f{f}_energy")),
                14,
                &case.i16s(&format!("f{f}_flags")),
                clas,
                mode[3] as i16,
                mode[4] as i16,
                mode[5] as i16,
                &case.i16s(&format!("f{f}_width")),
                &case.i32s(&format!("f{f}_y2_ni")),
                &mut ni_seed,
            );
            let context = format!("case {index} frame {f}: brate {}, class {clas}", mode[0]);
            check(
                case,
                &format!("{context} m"),
                &m,
                &case.i32s(&format!("f{f}_m")),
            );
            check(
                case,
                &format!("{context} ni_seed"),
                &ni_seed,
                &case.i16(&format!("f{f}_ni_seed")),
            );
            let prefix = format!("f{f}.");
            let mut after: BTreeMap<String, Vec<i64>> = case
                .inputs
                .iter()
                .filter_map(|(key, values)| {
                    key.strip_prefix("in.")
                        .map(|rest| (format!("st.{rest}"), values.clone()))
                })
                .collect();
            for (key, values) in &case.inputs {
                if let Some(rest) = key.strip_prefix(&prefix) {
                    after.insert(format!("st.{rest}"), values.clone());
                }
            }
            state_dump::check(&mut st, &after, "st.", &context);
            st.prev_hqswb_clas = clas;
        }
    }
}
