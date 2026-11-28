//! `lib_dec/range_dec_fx.c` against `fn_range_dec`: a range-coded segment read through a random
//! mix of `rc_dec_uniform`, `rc_dec_bits` and `rc_decode` + `rc_dec_update`, the coder state
//! compared after every step (`rc_dec_read` is proven through all of them).

use siphon_rtp_codec::evs::dec::range_dec::{
    rc_dec_bits, rc_dec_finish, rc_dec_init, rc_dec_uniform, rc_dec_update, rc_decode,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

fn trace(st: &DecoderState, t: &mut Vec<i32>) {
    t.extend_from_slice(&[
        st.rc_low as i32,
        st.rc_range as i32,
        st.rc_help as i32,
        i32::from(st.rc_num_bits),
        i32::from(st.rc_offset),
        i32::from(st.rc_end),
        i32::from(st.next_bit_pos),
        i32::from(st.ber_detect),
    ]);
}

#[test]
fn range_decoder_matches_the_reference() {
    let Some(cases) = corpus("range_dec", "range") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = 1;
        let (op, param, width) = (case.i32s("op"), case.i32s("param"), case.i32s("width"));

        let mut values = Vec::new();
        let mut t = Vec::new();
        rc_dec_init(&mut st, case.i16("tot_bits"));
        trace(&st, &mut t);
        for i in 0..op.len() {
            let value = match op[i] {
                0 => rc_dec_uniform(&mut st, param[i] as u32) as i32,
                1 => rc_dec_bits(&mut st, param[i] as i16),
                _ => {
                    let tot = param[i] as u32;
                    let w = width[i] as u32;
                    let val = rc_decode(&mut st, tot);
                    let cum = val.wrapping_sub(val % w);
                    let mut sym = if tot.wrapping_sub(cum) < w {
                        tot.wrapping_sub(cum)
                    } else {
                        w
                    };
                    if sym == 0 {
                        sym = 1;
                    }
                    rc_dec_update(&mut st, cum, sym);
                    val as i32
                }
            };
            values.push(value);
            trace(&st, &mut t);
        }
        rc_dec_finish(&mut st);
        trace(&st, &mut t);

        for (name, rust) in [("value", &values), ("trace", &t)] {
            if let Some(message) = mismatch(case, name, rust, &case.out_i32s(name)) {
                panic!("{message}");
            }
        }
    }
}
