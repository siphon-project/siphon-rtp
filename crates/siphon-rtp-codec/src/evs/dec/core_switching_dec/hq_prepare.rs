//! `core_switching_hq_prepare_dec_fx` (TS 26.442 `lib_dec/core_switching_dec_fx.c`; TS 26.445
//! §6.3.4): the HQ core's bit budget in the first HQ frame after an ACELP frame.

use crate::evs::cnst::{
    ACELP_11K60, ACELP_14K80, ACELP_22K60, ACELP_24K40, ACELP_8K00, AUDIODELAYBITS, GENERIC,
    HQ_CORE, L_FRAME, L_FRAME16K, L_FRAME8K, NOOFGAINBITS1, TRANSITION,
};
use crate::evs::com::bitstream::{bit_alloc_idx, bit_alloc_idx_16khz};
use crate::evs::com::tools::{copy_scale_sig, set16};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    ACB_BITS_16KHZ_TBL, ACB_BITS_TBL, FCB_BITS_16KHZ_TBL, FCB_BITS_TBL, GAIN_BITS_16KHZ_TBL,
    GAIN_BITS_TBL, INNER_FRAME_TBL_FX,
};
use crate::itu::basic_ops::{l_add, l_sub, negate, sub};

/// A bit-allocation table entry. The index comes from `BIT_ALLOC_IDX*` of a rate the switching
/// frame's own core rate clamps into the ACELP range, so it is inside the table; a corrupt rate
/// reads 0 instead of past the end.
fn entry(table: &[i16], index: i32) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|i| table.get(i))
        .copied()
        .unwrap_or(0)
}

/// `core_switching_hq_prepare_dec_fx`: save the concealed previous output into `fer_samples`
/// after a lost HQ frame, subtract the ACELP switching frame's bits (LP flag, pitch, gain, FCB)
/// and, unless the band is narrow, the BWE gain and delay bits from `num_bits`, and clear
/// `old_out`.
pub fn core_switching_hq_prepare_dec(
    st_fx: &mut DecoderState,
    num_bits: &mut i16,
    output_frame: i16,
) {
    if sub(st_fx.last_core, HQ_CORE) == 0 && st_fx.prev_bfi != 0 {
        copy_scale_sig(
            &st_fx.old_out,
            &mut st_fx.fer_samples,
            output_frame,
            negate(st_fx.q_old_wtda),
        ); // Q0
    }

    // set switching frame bit-rate
    if sub(st_fx.last_l_frame, L_FRAME) == 0 {
        let mut cbrate = l_add(st_fx.core_brate, 0);
        if l_sub(st_fx.core_brate, i32::from(ACELP_24K40)) > 0 {
            cbrate = l_add(i32::from(ACELP_24K40), 0);
        }

        // subtract ACELP switching frame bits
        if l_sub(st_fx.core_brate, i32::from(ACELP_11K60)) >= 0 {
            *num_bits = sub(*num_bits, 1); // LP_FLAG bit
        }
        *num_bits = sub(
            *num_bits,
            entry(&ACB_BITS_TBL, bit_alloc_idx(cbrate, GENERIC, 0, 0)),
        ); // pitch bits
        *num_bits = sub(
            *num_bits,
            entry(&GAIN_BITS_TBL, bit_alloc_idx(cbrate, TRANSITION, 0, 0)),
        ); // gain bits
        *num_bits = sub(
            *num_bits,
            entry(&FCB_BITS_TBL, bit_alloc_idx(cbrate, GENERIC, 0, 0)),
        ); // FCB bits
    } else {
        // L_frame_fx == L_FRAME16k
        let cbrate = if l_sub(st_fx.core_brate, i32::from(ACELP_8K00)) <= 0 {
            l_add(i32::from(ACELP_8K00), 0)
        } else if l_sub(st_fx.core_brate, i32::from(ACELP_14K80)) <= 0 {
            l_add(i32::from(ACELP_14K80), 0)
        } else {
            st_fx.core_brate.min(i32::from(ACELP_22K60))
        };

        // subtract ACELP switching frame bits
        if l_sub(st_fx.core_brate, i32::from(ACELP_11K60)) >= 0 {
            *num_bits = sub(*num_bits, 1); // LP_FLAG bit
        }
        *num_bits = sub(
            *num_bits,
            entry(
                &ACB_BITS_16KHZ_TBL,
                bit_alloc_idx_16khz(cbrate, GENERIC, 0, 0),
            ),
        ); // pitch bits
        *num_bits = sub(
            *num_bits,
            entry(
                &GAIN_BITS_16KHZ_TBL,
                bit_alloc_idx_16khz(cbrate, GENERIC, 0, 0),
            ),
        ); // gain bits
        *num_bits = sub(
            *num_bits,
            entry(
                &FCB_BITS_16KHZ_TBL,
                bit_alloc_idx_16khz(cbrate, GENERIC, 0, 0),
            ),
        ); // FCB bits
    }

    // subtract BWE bits
    // `bwidth` indexes the four-entry table (NB..FB); a corrupt value reads as NB.
    let inner = INNER_FRAME_TBL_FX
        .get(usize::try_from(st_fx.bwidth).unwrap_or(0))
        .copied()
        .unwrap_or(L_FRAME8K);
    if !((sub(inner, L_FRAME16K) == 0 && sub(st_fx.last_l_frame, L_FRAME16K) == 0)
        || sub(inner, L_FRAME8K) == 0)
    {
        *num_bits = sub(*num_bits, NOOFGAINBITS1 + AUDIODELAYBITS);
    }

    // reset state of old_out if switching
    set16(&mut st_fx.old_out, 0, output_frame);
}
