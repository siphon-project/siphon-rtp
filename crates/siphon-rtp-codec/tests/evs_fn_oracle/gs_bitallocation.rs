//! `lib_com/gs_bitallocation_fx.c` against `fn_gs_bitallocation` (decoder side, no concatenation).

use siphon_rtp_codec::evs::com::gs_bitallocation::bands_and_bit_alloc;

use crate::common::{corpus, mismatch};

#[test]
fn bands_and_bit_alloc_matches_the_reference() {
    let Some(cases) = corpus("gs_bitallocation", "bands_and_bit_alloc") else {
        return;
    };
    for case in &cases {
        let mut bit = 0x1234;
        let mut max_ener_band = vec![-999i16; 16];
        let mut out_bits = vec![-999i16; 16];
        let out = bands_and_bit_alloc(
            case.i16("cor_strong_limit"),
            case.i16("noise_lev"),
            case.i32("core_brate"),
            case.i16("diff_len"),
            case.i16("bits_used"),
            &mut bit,
            &case.i16s("ener_per_bd_i_q"),
            &mut max_ener_band,
            &mut out_bits,
            None,
            case.i16("coder_type"),
            case.i16("bwidth"),
            case.i16("gsc_noisy_speech"),
        );
        let rust = [
            vec![bit],
            max_ener_band,
            out_bits,
            vec![out.nb_subbands, out.pvq_len],
        ]
        .concat();
        let reference = [
            vec![case.out_i16("bit")],
            case.out_i16s("max_ener_band"),
            case.out_i16s("out_bits_per_bands"),
            vec![case.out_i16("nb_subbands"), case.out_i16("pvq_len")],
        ]
        .concat();
        if let Some(message) = mismatch(
            case,
            "bit/max_ener_band/out_bits_per_bands/nb_subbands/pvq_len",
            &rust,
            &reference,
        ) {
            panic!("{message}");
        }
    }
}
