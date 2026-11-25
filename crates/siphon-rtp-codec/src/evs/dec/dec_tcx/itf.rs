//! The IGF temporal flattening step of `decoder_tcx` (TS 26.442 `lib_dec/dec_tcx.c`; TS 26.445
//! §6.2.2.3.10 "IGF temporal flattening"): the lines the core coded and the IGF replaced by the
//! virtual spectrum are filtered with the inter-tone filter (ITF) derived from the flattened
//! spectrum.

use crate::evs::cnst::{IGF_START_MN, ITF_MAX_FILTER_ORDER, N_MAX_TCX};
use crate::evs::com::basop_util::get_scale_factor32;
use crate::evs::com::tns_base::{itf_apply, itf_detect};
use crate::evs::dec::state::{DecoderState, IgfdecInstance};
use crate::itu::basic_ops::{l_shl, l_shr, shl, sub};

/// `flag_sparse[index]` of the IGF instance, `index = line - IGF_START_MN`.
///
/// The TCX-10 grids start below `IGF_START_MN`, so the reference reads before the array: in
/// `IGFDEC_INSTANCE` that is the end of `infoTCXNoise`, which sits directly before `flag_sparse`
/// (see `store_flag_sparse` in `igf_dec/appl.rs`, which mirrors the matching writes).
/// `IGFDecApplyMono` clears `infoTCXNoise` after those writes, so such a read sees 0.
fn flag_sparse_at(h: &IgfdecInstance, index: i32) -> i16 {
    match usize::try_from(index) {
        Ok(at) => h.flag_sparse[at],
        Err(_) => h.info_tcx_noise[(h.info_tcx_noise.len() as i32 + index) as usize],
    }
}

/// `virtualSpec[index]` of the IGF instance, `index = line - IGF_START_MN`; a negative index
/// reads the end of `flag_sparse`, which sits directly before `virtualSpec`, as the
/// little-endian pair `flag_sparse[len + 2 * index]` (low half), `flag_sparse[len + 2 * index +
/// 1]` (high half) (see `store_virtual_spec` in `igf_dec/appl.rs`).
fn virtual_spec_at(h: &IgfdecInstance, index: i32) -> i32 {
    match usize::try_from(index) {
        Ok(at) => h.virtual_spec[at],
        Err(_) => {
            let at = (h.flag_sparse.len() as i32 + 2 * index) as usize;
            i32::from(h.flag_sparse[at] as u16) | (i32::from(h.flag_sparse[at + 1]) << 16)
        }
    }
}

/// The flattening of `x` between the IGF start and stop line (`st.h_igf_dec`), for a frame whose
/// IGF flattening trigger is set and that carries no TNS.
pub(super) fn igf_flattening(st: &DecoderState, x_e: i16, x: &mut [i32]) {
    let h = &st.h_igf_dec;
    let start_line = h.info_igf_start_line;
    let end_line = h.info_igf_stop_line;
    let mut x_itf = [0i32; (N_MAX_TCX - IGF_START_MN) as usize];

    const MAX_ORDER: i16 = 8;
    let mut curr_order: i16 = 0;
    let mut a_itf = [0i16; ITF_MAX_FILTER_ORDER as usize + 1];
    let mut q_a_itf: i16 = 0;
    let mut prediction_gain: i16 = 0;

    for j in start_line..end_line {
        let index = i32::from(j) - i32::from(IGF_START_MN);
        if sub(flag_sparse_at(h, index), 2) == 0 {
            // a 2 is only ever stored at a line >= IGF_START_MN, and the negative-index reads
            // above see the cleared infoTCXNoise, so the index is not negative here
            if let Ok(slot) = usize::try_from(index) {
                x_itf[slot] = x[j as usize];
            }
            x[j as usize] = virtual_spec_at(h, index);
        }
    }
    itf_detect(
        &x[IGF_START_MN as usize..],
        start_line,
        end_line,
        MAX_ORDER,
        &mut a_itf,
        &mut q_a_itf,
        &mut prediction_gain,
        &mut curr_order,
        shl(x_e, 1),
    );
    let (from, to) = (start_line as usize, end_line as usize);
    let mut s = get_scale_factor32(&x[from..], sub(end_line, start_line));
    s = sub(s, 2);
    for line in &mut x[from..to] {
        *line = l_shl(*line, s);
    }

    itf_apply(x, start_line, end_line, &a_itf, q_a_itf, curr_order);

    for line in &mut x[from..to] {
        *line = l_shr(*line, s);
    }

    for j in start_line..end_line {
        let index = i32::from(j) - i32::from(IGF_START_MN);
        if sub(flag_sparse_at(h, index), 2) == 0 {
            if let Ok(slot) = usize::try_from(index) {
                x[j as usize] = x_itf[slot];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_flag_sparse_index_reads_the_end_of_info_tcx_noise() {
        let mut h = IgfdecInstance::zeroed();
        let len = h.info_tcx_noise.len();
        h.info_tcx_noise[len - 1] = 7;
        h.info_tcx_noise[len - 3] = 9;
        assert_eq!(flag_sparse_at(&h, -1), 7);
        assert_eq!(flag_sparse_at(&h, -3), 9);
        h.flag_sparse[3] = 5;
        assert_eq!(flag_sparse_at(&h, 3), 5);
    }

    #[test]
    fn negative_virtual_spec_index_reads_a_little_endian_pair_of_flag_sparse() {
        let mut h = IgfdecInstance::zeroed();
        let len = h.flag_sparse.len();
        h.flag_sparse[len - 2] = -2; // low half 0xfffe
        h.flag_sparse[len - 1] = 3; // high half
        assert_eq!(virtual_spec_at(&h, -1), (3 << 16) | 0xfffe);
        h.virtual_spec[4] = -9;
        assert_eq!(virtual_spec_at(&h, 4), -9);
    }
}
