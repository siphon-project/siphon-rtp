//! Radix-2 complex and real FFT on 16-bit data (TS 26.442 `lib_com/fft_rel_fx.c`), used by the
//! pitch enhancer's codebook smoothing (`enhancer_fx.c`), the LPC/LSP conversions (`fft_fx.c`) and
//! the HQ phase ECU.
//!
//! Every butterfly halves through `L_mult(x, 16384)` + `mac_r`, so the output carries the reference's
//! per-stage scaling; operators are kept in the C order.

use crate::evs::rom::{
    FFT_REORDER_1024, FFT_REORDER_128, FFT_REORDER_256, FFT_REORDER_512, FFT_REORDER_64,
};
use crate::itu::basic_ops::{add, l_mac, l_msu, l_mult, l_negate, shl, shr, sub};
use crate::itu::stl2009::{mac_r, msu_r};

/// The largest transform the reference supports (`Word16 temp[1024]` in `r_fft_fx_lc`).
const MAX_SIZE: usize = 1024;

fn reorder_table(size: i16) -> Option<&'static [i16]> {
    match size {
        1024 => Some(&FFT_REORDER_1024),
        512 => Some(&FFT_REORDER_512),
        256 => Some(&FFT_REORDER_256),
        128 => Some(&FFT_REORDER_128),
        64 => Some(&FFT_REORDER_64),
        _ => None,
    }
}

/// `c_fft_fx`: complex FFT of `size / 2` interleaved points, forward (`isign != 0`) or inverse.
///
/// `phs_tbl` holds the forward twiddles in its first `size` entries and the inverse ones in the next
/// `size`. A size without a reorder table (the C dereferences `NULL`) leaves `out_ptr` untouched;
/// every reference call site passes a constant size from the table.
fn c_fft(
    phs_tbl: &[i16],
    size: i16,
    num_stage: i16,
    in_ptr: &[i16],
    out_ptr: &mut [i16],
    isign: i16,
) {
    let Some(table) = reorder_table(size) else {
        return;
    };
    let n = size as usize;
    let mut entry = table.iter().map(|&offset| offset as usize);
    let mut next = || entry.next().unwrap_or(0);
    if isign != 0 {
        for k in (0..n).step_by(8) {
            let p1 = next();
            let mut l_tmp1 = l_mult(in_ptr[p1], 16384);
            let mut l_tmp2 = l_mult(in_ptr[p1 + 1], 16384);
            let p1 = next();
            let mut tmp1 = msu_r(l_tmp1, in_ptr[p1], 16384);
            let mut tmp3 = mac_r(l_tmp1, in_ptr[p1], 16384);
            let p2 = next();
            let p3 = next();
            l_tmp1 = l_mult(in_ptr[p2], 16384);
            let mut tmp2 = mac_r(l_tmp1, in_ptr[p3], 16384);
            let tmp4 = msu_r(l_tmp1, in_ptr[p3], 16384);
            l_tmp1 = l_mult(tmp3, 16384);
            out_ptr[k] = mac_r(l_tmp1, tmp2, 16384);
            out_ptr[k + 4] = msu_r(l_tmp1, tmp2, 16384);
            tmp2 = mac_r(l_tmp2, in_ptr[p1 + 1], 16384);
            tmp3 = msu_r(l_tmp2, in_ptr[p1 + 1], 16384);
            l_tmp2 = l_mult(in_ptr[p2 + 1], 16384);
            l_tmp1 = l_mult(tmp1, 16384);
            tmp1 = msu_r(l_tmp2, in_ptr[p3 + 1], 16384);
            out_ptr[k + 2] = mac_r(l_tmp1, tmp1, 16384);
            out_ptr[k + 6] = msu_r(l_tmp1, tmp1, 16384);
            l_tmp1 = l_mult(tmp2, 16384);
            tmp2 = mac_r(l_tmp2, in_ptr[p3 + 1], 16384);
            out_ptr[k + 1] = mac_r(l_tmp1, tmp2, 16384);
            out_ptr[k + 5] = msu_r(l_tmp1, tmp2, 16384);
            l_tmp1 = l_mult(tmp3, 16384);
            out_ptr[k + 3] = msu_r(l_tmp1, tmp4, 16384);
            out_ptr[k + 7] = mac_r(l_tmp1, tmp4, 16384);
        }
        for i in 2..num_stage {
            let jj = shl(2, i);
            let kk = shl(jj, 1);
            let ii = shr(size, i);
            let mut ji: i16 = 0;
            for j in (0..jj).step_by(2) {
                for k in (j..size).step_by(kk as usize) {
                    let kj = add(k, jj) as usize;
                    let (k, w) = (k as usize, ji as usize);
                    let l_tmp1 = l_msu(
                        l_mult(out_ptr[kj], phs_tbl[w]),
                        out_ptr[kj + 1],
                        phs_tbl[w + 1],
                    );
                    let l_tmp2 = l_mac(
                        l_mult(out_ptr[kj + 1], phs_tbl[w]),
                        out_ptr[kj],
                        phs_tbl[w + 1],
                    );
                    out_ptr[kj] = mac_r(l_negate(l_tmp1), out_ptr[k], 16384);
                    out_ptr[kj + 1] = mac_r(l_negate(l_tmp2), out_ptr[k + 1], 16384);
                    out_ptr[k] = mac_r(l_tmp1, out_ptr[k], 16384);
                    out_ptr[k + 1] = mac_r(l_tmp2, out_ptr[k + 1], 16384);
                }
                ji = add(ji, ii);
            }
        }
    } else {
        for k in (0..n).step_by(8) {
            let p1 = next();
            let p2 = next();
            let p3 = next();
            let p4 = next();
            let mut tmp3 = sub(in_ptr[p1], in_ptr[p2]);
            let mut tmp4 = add(in_ptr[p1], in_ptr[p2]);
            let tmp2 = sub(in_ptr[p3], in_ptr[p4]);
            let mut tmp1 = sub(in_ptr[p3 + 1], in_ptr[p4 + 1]);
            out_ptr[k + 2] = sub(tmp3, tmp1);
            out_ptr[k + 6] = add(tmp3, tmp1);
            tmp1 = sub(in_ptr[p1 + 1], in_ptr[p2 + 1]);
            out_ptr[k + 3] = add(tmp1, tmp2);
            out_ptr[k + 7] = sub(tmp1, tmp2);
            tmp1 = add(in_ptr[p3], in_ptr[p4]);
            tmp3 = add(in_ptr[p3 + 1], in_ptr[p4 + 1]);
            out_ptr[k] = add(tmp4, tmp1);
            out_ptr[k + 4] = sub(tmp4, tmp1);
            tmp4 = add(in_ptr[p1 + 1], in_ptr[p2 + 1]);
            out_ptr[k + 1] = add(tmp4, tmp3);
            out_ptr[k + 5] = sub(tmp4, tmp3);
        }
        let table_ptr = &phs_tbl[n..];
        for i in 2..num_stage {
            let jj = shl(2, i);
            let kk = shl(jj, 1);
            let ii = shr(size, i);
            let mut ji: i16 = 0;
            for j in (0..jj).step_by(2) {
                for k in (j..size).step_by(kk as usize) {
                    let kj = add(k, jj) as usize;
                    let (k, w) = (k as usize, ji as usize);
                    let tmp1 = mac_r(
                        l_mult(out_ptr[kj], table_ptr[w]),
                        out_ptr[kj + 1],
                        table_ptr[w + 1],
                    );
                    let tmp2 = msu_r(
                        l_mult(out_ptr[kj + 1], table_ptr[w]),
                        out_ptr[kj],
                        table_ptr[w + 1],
                    );
                    out_ptr[kj] = sub(out_ptr[k], tmp1);
                    out_ptr[kj + 1] = sub(out_ptr[k + 1], tmp2);
                    out_ptr[k] = add(out_ptr[k], tmp1);
                    out_ptr[k + 1] = add(out_ptr[k + 1], tmp2);
                }
                ji = add(ji, ii);
            }
        }
    }
}

/// The forward real-FFT post-processing of `r_fft_fx_lc`: split the complex FFT in `temp` into the
/// real spectrum `out_ptr` (real parts `0..=size2`, imaginary parts above, mirrored).
fn r_fft_forward_split(
    phs_tbl: &[i16],
    size: usize,
    size2: usize,
    num_stage: i16,
    temp: &[i16],
    out_ptr: &mut [i16],
) {
    out_ptr[size2] = sub(temp[0], temp[1]);
    out_ptr[0] = sub(add(temp[0], temp[1]), shr(num_stage, 1));
    let mut ptr_dn = size - 1;
    let mut pt_ima_dn = size - 1;
    let mut pt_real_dn = size2 - 1;
    let mut phstbl_ptr_dn = size - 1;
    for i in (2..=size2).step_by(2) {
        let mut ltmp1_imag = l_mult(temp[i + 1], 16384);
        ltmp1_imag = l_msu(ltmp1_imag, temp[ptr_dn], 16384);
        let tmp2_real = add(temp[i + 1], temp[ptr_dn]);
        ptr_dn -= 1;
        let mut ltmp1_real = l_mult(temp[i], 16384);
        ltmp1_real = l_mac(ltmp1_real, temp[ptr_dn], 16384);
        let tmp2_imag = sub(temp[ptr_dn], temp[i]);
        ptr_dn = ptr_dn.wrapping_sub(1);
        // ptRealUp / ptImaUp step up once per iteration from 1 and size2 + 1.
        let (pt_real_up, pt_ima_up) = (i / 2, size2 + i / 2);
        out_ptr[pt_real_up] = msu_r(
            l_mac(ltmp1_real, tmp2_real, phs_tbl[i]),
            tmp2_imag,
            phs_tbl[i + 1],
        );
        out_ptr[pt_ima_dn] = mac_r(
            l_mac(ltmp1_imag, tmp2_imag, phs_tbl[i]),
            tmp2_real,
            phs_tbl[i + 1],
        );
        pt_ima_dn -= 1;
        let ltmp1 = l_mac(l_negate(ltmp1_imag), tmp2_real, phs_tbl[phstbl_ptr_dn]);
        ltmp1_real = l_mac(ltmp1_real, tmp2_imag, phs_tbl[phstbl_ptr_dn]);
        phstbl_ptr_dn -= 1;
        out_ptr[pt_ima_up] = msu_r(ltmp1, tmp2_imag, phs_tbl[phstbl_ptr_dn]);
        out_ptr[pt_real_dn] = mac_r(ltmp1_real, tmp2_real, phs_tbl[phstbl_ptr_dn]);
        pt_real_dn = pt_real_dn.wrapping_sub(1);
        phstbl_ptr_dn -= 1;
    }
}

/// The inverse real-FFT pre-processing of `r_fft_fx_lc`: fold the real spectrum `in_ptr` into the
/// complex FFT input `temp`.
fn r_fft_inverse_fold(
    phs_tbl: &[i16],
    size: usize,
    size2: usize,
    in_ptr: &[i16],
    temp: &mut [i16],
) {
    let ltmp1 = l_mult(in_ptr[0], 16384);
    temp[0] = mac_r(ltmp1, in_ptr[size2], 16384);
    temp[1] = msu_r(ltmp1, in_ptr[size2], 16384);
    let mut ptr_dn = size - 1;
    let mut pt_ima_dn = size - 1;
    let mut pt_real_dn = size2 - 1;
    let mut phstbl_ptr_dn = size - 1;
    for i in (2..=size2).step_by(2) {
        // ptRealUp / ptImaUp step up once per iteration from 1 and size2 + 1.
        let (pt_real_up, pt_ima_up) = (i / 2, size2 + i / 2);
        let mut ltmp1_imag = l_mult(in_ptr[pt_ima_dn], 16384);
        ltmp1_imag = l_msu(ltmp1_imag, in_ptr[pt_ima_up], 16384);
        let tmp2_real = add(in_ptr[pt_ima_dn], in_ptr[pt_ima_up]);
        pt_ima_dn -= 1;
        let mut ltmp1_real = l_mult(in_ptr[pt_real_up], 16384);
        ltmp1_real = l_mac(ltmp1_real, in_ptr[pt_real_dn], 16384);
        let tmp2_imag = sub(in_ptr[pt_real_up], in_ptr[pt_real_dn]);
        pt_real_dn = pt_real_dn.wrapping_sub(1);
        temp[i] = mac_r(
            l_msu(ltmp1_real, tmp2_real, phs_tbl[i]),
            tmp2_imag,
            phs_tbl[i + 1],
        );
        temp[i + 1] = mac_r(
            l_mac(ltmp1_imag, tmp2_imag, phs_tbl[i]),
            tmp2_real,
            phs_tbl[i + 1],
        );
        let ltmp1 = l_mac(l_negate(ltmp1_imag), tmp2_real, phs_tbl[phstbl_ptr_dn]);
        ltmp1_real = l_msu(ltmp1_real, tmp2_imag, phs_tbl[phstbl_ptr_dn]);
        phstbl_ptr_dn -= 1;
        temp[ptr_dn] = msu_r(ltmp1, tmp2_imag, phs_tbl[phstbl_ptr_dn]);
        ptr_dn -= 1;
        temp[ptr_dn] = msu_r(ltmp1_real, tmp2_real, phs_tbl[phstbl_ptr_dn]);
        ptr_dn = ptr_dn.wrapping_sub(1);
        phstbl_ptr_dn -= 1;
    }
}

/// Whether the reference supports this transform: a reorder table exists, `size2 = size / 2`, and
/// the buffers hold what the C would touch. The C has no checks; an unsupported call would read a
/// `NULL` table or past its buffers, so the port returns without touching the output instead.
fn supported(
    phs_tbl: &[i16],
    size: i16,
    size2: i16,
    num_stage: i16,
    len_in: usize,
    len_out: usize,
) -> bool {
    let n = size as usize;
    reorder_table(size).is_some()
        && size2 == size / 2
        // the last butterfly stage spans 2^num_stage, which must stay inside the transform
        && (0..15).contains(&num_stage)
        && (1usize << num_stage) <= n / 2
        && n <= MAX_SIZE
        && phs_tbl.len() >= 2 * n
        && len_in >= n
        && len_out >= n
}

/// `r_fft_fx_lc`: real FFT of `size` 16-bit samples, forward (`isign != 0`) or inverse, from
/// `in_ptr` into `out_ptr`. `phs_tbl` holds `2 * size` twiddles (e.g. `PHS_TBL_DEC` for 64,
/// `FFT_W64` for 128); `num_stage` is `log2(size) - 1` (`NUM_STAGES` = 5 for 64). The forward result has the real parts in
/// `out[0..=size2]` and the imaginary parts in `out[size2+1..]`.
///
/// The reference calls it in place as often as not; use [`r_fft_fx_lc_in_place`] for that.
pub fn r_fft_fx_lc(
    phs_tbl: &[i16],
    size: i16,
    size2: i16,
    num_stage: i16,
    in_ptr: &[i16],
    out_ptr: &mut [i16],
    isign: i16,
) {
    if !supported(phs_tbl, size, size2, num_stage, in_ptr.len(), out_ptr.len()) {
        return;
    }
    let (n, n2) = (size as usize, size2 as usize);
    let mut temp = [0i16; MAX_SIZE];
    if isign != 0 {
        c_fft(phs_tbl, size, num_stage, in_ptr, &mut temp, isign);
        r_fft_forward_split(phs_tbl, n, n2, num_stage, &temp, out_ptr);
    } else {
        r_fft_inverse_fold(phs_tbl, n, n2, in_ptr, &mut temp);
        c_fft(phs_tbl, size, num_stage, &temp, out_ptr, isign);
    }
}

/// [`r_fft_fx_lc`] with `in_ptr == out_ptr`, as `fft_fx.c` and the HQ phase ECU call it. Both
/// directions route through the reference's own `temp[1024]`, so input and output never overlap
/// in a single pass and the in-place result equals the out-of-place one.
pub fn r_fft_fx_lc_in_place(
    phs_tbl: &[i16],
    size: i16,
    size2: i16,
    num_stage: i16,
    x: &mut [i16],
    isign: i16,
) {
    if !supported(phs_tbl, size, size2, num_stage, x.len(), x.len()) {
        return;
    }
    let (n, n2) = (size as usize, size2 as usize);
    let mut temp = [0i16; MAX_SIZE];
    if isign != 0 {
        c_fft(phs_tbl, size, num_stage, x, &mut temp, isign);
        r_fft_forward_split(phs_tbl, n, n2, num_stage, &temp, x);
    } else {
        r_fft_inverse_fold(phs_tbl, n, n2, x, &mut temp);
        c_fft(phs_tbl, size, num_stage, &temp, x, isign);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::rom::PHS_TBL_DEC;

    #[test]
    fn in_place_matches_out_of_place() {
        let input: Vec<i16> = (0..64).map(|i| ((i * 977) % 2001 - 1000) as i16).collect();
        for isign in [0, 1] {
            let mut separate = [0i16; 64];
            r_fft_fx_lc(&PHS_TBL_DEC, 64, 32, 5, &input, &mut separate, isign);
            let mut in_place = input.clone();
            r_fft_fx_lc_in_place(&PHS_TBL_DEC, 64, 32, 5, &mut in_place, isign);
            assert_eq!(&separate[..], &in_place[..]);
        }
    }

    #[test]
    fn unsupported_sizes_leave_the_output_untouched() {
        let mut out = [7i16; 64];
        r_fft_fx_lc(&PHS_TBL_DEC, 48, 24, 5, &[0; 64], &mut out, 1);
        assert_eq!(out, [7; 64]);
        r_fft_fx_lc(&PHS_TBL_DEC, 128, 64, 6, &[0; 128], &mut out, 1);
        assert_eq!(out, [7; 64]);
    }
}
