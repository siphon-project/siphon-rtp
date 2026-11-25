//! `lib_dec/ari_dec.c` and `lib_com/ari.c` against `fn_m2arith_ari_dec`.

use siphon_rtp_codec::evs::cnst::MODE2;
use siphon_rtp_codec::evs::com::ari::{l_multi31x16_x2, mul_sbc_14bits};
use siphon_rtp_codec::evs::dec::ari_dec::{
    ari_decode_14bits_bit_ext, ari_decode_14bits_pow, ari_decode_14bits_s17_ext,
    ari_decode_14bits_s27_ext, ari_decode_14bits_sign, ari_decode_overflow,
    ari_start_decoding_14bits, ari_start_decoding_14bits_prm,
};
use siphon_rtp_codec::evs::dec::state::{DecoderState, TastatDec};
use siphon_rtp_codec::evs::rom::ARI_PK_S17_LC_EXT;

use crate::common::{corpus, corpus_sized, mismatch};

/// A table-driven decode run: random 17- and 27-symbol models and the real `ari_pk_s17_LC_ext`
/// rows, on random bitstreams.
#[test]
fn ari_table_decodes_match_the_reference() {
    let Some(cases) = corpus_sized("m2arith_ari_dec", "ari_session", 3000) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        let bits = case.i32s("bits");
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = case.i16("total_num_bits");
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = MODE2;
        st.ber_detect = 0;
        let steps = case.i16("steps") as usize;
        let kinds = case.i16s("kinds");
        let pkis = case.i16s("pkis");
        let mut s = TastatDec::zeroed();
        ari_start_decoding_14bits(&mut st, &mut s);
        let mut symbols = Vec::new();
        let mut overflow = Vec::new();
        for step in 0..steps {
            let table: Vec<u16> = case
                .i32s(&format!("table{step}"))
                .into_iter()
                .map(|v| v as u16)
                .collect();
            let symbol = match kinds[step] {
                0 => ari_decode_14bits_s17_ext(&mut st, &mut s, &table),
                1 => ari_decode_14bits_s27_ext(&mut st, &mut s, &table),
                2 => ari_decode_14bits_bit_ext(&mut st, &mut s),
                _ => ari_decode_14bits_s17_ext(
                    &mut st,
                    &mut s,
                    &ARI_PK_S17_LC_EXT[pkis[step] as usize],
                ),
            };
            symbols.push(symbol);
            overflow.push(i16::from(ari_decode_overflow(&s)));
        }
        for (name, rust) in [
            ("symbols", symbols),
            ("overflow", overflow),
            ("next_bit_pos", vec![st.next_bit_pos]),
            ("ber_detect", vec![st.ber_detect]),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
        for (name, rust) in [("low", s.low), ("high", s.high), ("vobf", s.vobf)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
    }
}

fn replay_notbl(
    prm: &[i16],
    bits: i16,
    bp: i16,
    base: i16,
    sign: bool,
    s: &mut TastatDec,
) -> (i16, i16) {
    let mut res = 7;
    let position = if sign {
        ari_decode_14bits_sign(prm, bp, bits, &mut res, s)
    } else {
        ari_decode_14bits_pow(prm, bp, bits, &mut res, s, base)
    };
    (res, position)
}

/// Pow and sign decodes over a parameter array, started with `ari_start_decoding_14bits_prm`.
#[test]
fn ari_prm_session_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_ari_dec", "ari_prm_session", 5000) else {
        return;
    };
    let mut nonzero = 0;
    for case in &cases {
        let prm = case.i16s("prm");
        let bits = case.i16("bits");
        let steps = case.i16("steps") as usize;
        let kinds = case.i16s("kinds");
        let bases = case.i16s("bases");
        let mut s = TastatDec::zeroed();
        let mut position = ari_start_decoding_14bits_prm(&prm, case.i16("bp"), &mut s);
        let mut results = vec![0_i16; steps];
        let mut positions = vec![0_i16; steps];
        for step in 0..steps {
            if position < 0 {
                break;
            }
            let (res, next) =
                replay_notbl(&prm, bits, position, bases[step], kinds[step] == 1, &mut s);
            position = next;
            results[step] = res;
            positions[step] = position;
        }
        nonzero += results.iter().filter(|&&r| r != 0).count();
        for (name, rust) in [("results", results), ("positions", positions)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
        for (name, rust) in [("low", s.low), ("high", s.high), ("vobf", s.vobf)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
    }
    assert!(nonzero > 0, "no case decoded a non-zero symbol");
}

/// One pow / sign decode from a directly set state at the end of the budget, which reaches the
/// bit-error return (-1).
#[test]
fn ari_notbl_direct_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_ari_dec", "ari_notbl_direct", 10000) else {
        return;
    };
    let mut errors = 0;
    for case in &cases {
        let prm = case.i16s("prm");
        let mut s = TastatDec {
            low: case.i32("low"),
            high: case.i32("high"),
            vobf: case.i32("vobf"),
        };
        let (res, position) = replay_notbl(
            &prm,
            case.i16("bits"),
            case.i16("bp"),
            case.i16("base"),
            case.i16("sign") == 1,
            &mut s,
        );
        errors += usize::from(position < 0);
        for (name, rust) in [("res", res), ("position", position)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16(name)) {
                panic!("{message}");
            }
        }
        for (name, rust) in [("low", s.low), ("high", s.high), ("vobf", s.vobf)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
    }
    assert!(errors > 0, "no case reached the bit-error return");
}

#[test]
fn ari_multiplies_match_the_reference() {
    let Some(cases) = corpus("m2arith_ari_dec", "mul") else {
        return;
    };
    for case in &cases {
        let mul = mul_sbc_14bits(case.i32("range"), case.i16("c"));
        let multi = l_multi31x16_x2(case.i16("xh"), case.i16("xl"), case.i16("y"));
        for (name, rust) in [("mul", mul), ("multi", multi)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
    }
}

/// One table-driven decode from a directly set state, including a value below `low` (a bit-error
/// state: the reference saturates `cum`).
#[test]
fn ari_ext_direct_matches_the_reference() {
    let Some(cases) = corpus_sized("m2arith_ari_dec", "ari_ext_direct", 5000) else {
        return;
    };
    let mut st = Box::new(DecoderState::zeroed());
    for case in &cases {
        st.bit_stream.fill(0);
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&case.i32s("bits")) {
            *slot = bit as u16;
        }
        st.total_num_bits = 80;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = MODE2;
        st.ber_detect = 0;
        let table: Vec<u16> = case.i32s("table").into_iter().map(|v| v as u16).collect();
        let mut s = TastatDec {
            low: case.i32("low"),
            high: case.i32("high"),
            vobf: case.i32("vobf"),
        };
        let symbol = if case.i16("symbols") == 17 {
            ari_decode_14bits_s17_ext(&mut st, &mut s, &table)
        } else {
            ari_decode_14bits_s27_ext(&mut st, &mut s, &table)
        };
        for (name, rust) in [
            ("symbol", symbol),
            ("next_bit_pos", st.next_bit_pos),
            ("ber_detect", st.ber_detect),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16(name)) {
                panic!("{message}");
            }
        }
        for (name, rust) in [("low", s.low), ("high", s.high), ("vobf", s.vobf)] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i32(name)) {
                panic!("{message}");
            }
        }
    }
}
