//! HQ mode selector (TS 26.442 `lib_dec/hq_classifier_dec_fx.c`; TS 26.445 §6.2.2.3).

use crate::evs::cnst::{
    HQ_32K, HQ_GEN_FB, HQ_GEN_SWB, HQ_NORMAL, HQ_TRANSIENT, L_FRAME32K, L_FRAME48K,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::dec::state::DecoderState;
use crate::itu::basic_ops::sub;

/// `hq_classifier_dec_fx`: read the HQ class of the frame. Sets the transient flag and the class
/// (`HQ_GEN_SWB` / `HQ_GEN_FB` for the generic modes of 32 / 48 kHz frames) and returns the
/// number of bits consumed.
pub fn hq_classifier_dec(
    st: &mut DecoderState,
    core_brate: i32,
    length: i16,
    is_transient: &mut i16,
    hqswb_clas: &mut i16,
) -> i16 {
    if sub(length, L_FRAME32K) >= 0 && core_brate <= i32::from(HQ_32K) {
        *hqswb_clas = get_next_indice(st, 2) as i16;
        if sub(length, L_FRAME48K) == 0 && sub(*hqswb_clas, HQ_NORMAL) == 0 {
            *hqswb_clas = HQ_GEN_FB;
        }
    } else {
        *hqswb_clas = get_next_indice(st, 1) as i16;
    }

    *is_transient = 0;
    if sub(*hqswb_clas, HQ_TRANSIENT) == 0 {
        *is_transient = 1;
    }

    if *hqswb_clas == HQ_NORMAL && sub(length, L_FRAME32K) == 0 && core_brate <= i32::from(HQ_32K) {
        *hqswb_clas = HQ_GEN_SWB;
    }

    let mut bits: i16 = 1;
    if sub(length, L_FRAME32K) >= 0 && core_brate <= i32::from(HQ_32K) {
        bits = 2;
    }
    bits
}
