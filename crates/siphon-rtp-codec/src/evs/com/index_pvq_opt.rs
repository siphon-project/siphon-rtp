//! MPVQ (modular pyramid vector quantiser) indexing: codebook sizes, offset tables and index
//! decoding (TS 26.442 `lib_com/index_pvq_opt_fx.c`; TS 26.445 §5.3.4.2.7.3, §6.2.3.2). The
//! encoder half (`vec2mind_*`, `mpvq_encode_vec_fx`) is not ported here.
//!
//! The offsets follow the reference's `A(n,k)` / `U(n,k)` recursions: `A(n,k)` is the number of
//! vectors of dimension `n` with at most `k-1` pulses in the first position's complement, `U` is
//! `(A - 1) / 2`, and `N_MPVQ(n,k) = 1 + U(n,k+1) + U(n,k)`. Dimensions up to five use direct
//! closed forms; larger ones a row recursion kept in the caller's `h_mem`.

use crate::evs::rom::EXACTDIVODD_FX;
use crate::itu::basic_ops::{add, norm_s, shl, shr, sub};
use crate::itu::stl2009::{
    lshr, mpy_32_32_uu, ul_add_ns_d, ul_lshl, ul_lshr, ul_mpy_32_32, ul_sub_ns, ul_sub_ns_d,
};

/// Complexity setting: direct functional calculation limit & low-dimension recursion limit
/// (`N_OPT_FX`).
const N_OPT_FX: i16 = 5;
/// Odd-divisor table / N-row recursion limit (`TABLE_LIM_OPT_FX`).
const TABLE_LIM_OPT_FX: i16 = 96;
/// 1/3 modulo 2^32 (`UDIVBY3_FX`).
const UDIVBY3_FX: u32 = 2_863_311_531;

/// The reference's `PvqEntry_fx`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PvqEntry {
    pub lead_sign_ind: i16,
    pub index: u32,
    pub size: u32,
    pub dim: i16,
    pub k_val: i16,
}

/// `u_extract_l`: the low 16 bits, as the reference's signed casts leave them.
const fn u_extract_l(x: u32) -> i16 {
    x as u16 as i16
}

/// `exactdivodd_fx[index]`, the modular inverse of `2·index + 1`; 0 past the table (only an
/// out-of-range pulse count gets there).
fn exactdivodd(index: i16) -> u32 {
    usize::try_from(index)
        .ok()
        .and_then(|index| EXACTDIVODD_FX.get(index))
        .copied()
        .unwrap_or(0)
}

/// `f_odd_exact_div_opt_fx`: `(num1p·num2p - num3) / (2·den1 + 1)`, known a priori to be exact.
#[must_use]
pub fn f_odd_exact_div_opt(num1p: u32, num2p: u32, num3: u32, den1: i16) -> u32 {
    ul_mpy_32_32(
        exactdivodd(den1),
        ul_sub_ns_d(ul_mpy_32_32(num1p, num2p), num3),
    )
}

/// `f_even_exact_div_opt_fx`: `(num1p·num2p - num3) / den1` for an even `den1` (at most 127),
/// known a priori to be exact.
#[must_use]
pub fn f_even_exact_div_opt(ul_num1p: u32, ul_num2p: u32, ul_num3: u32, den1: i16) -> u32 {
    let den1_m1 = sub(den1, 1); // remove top bit
    let mut even_sh = sub(15, norm_s(den1_m1 ^ den1)); // STL signed ops ok as den1 <= 127
    let ul_oddfactor = exactdivodd(lshr(den1_m1, even_sh));
    even_sh = sub(even_sh, 1);

    let (mut ul_tmp_h, ul_tmp) = mpy_32_32_uu(ul_num1p, ul_num2p);
    let (ul_tmp, sgn) = ul_sub_ns(ul_tmp, ul_num3); // may wrap for underflow
    if sgn {
        ul_tmp_h = ul_sub_ns_d(ul_tmp_h, 1);
    }
    let ul_tmp = ul_lshl(ul_tmp_h, sub(32, even_sh)) | ul_lshr(ul_tmp, even_sh);
    // now use tabled modular multiplicative inverse for the odd part division
    ul_mpy_32_32(ul_tmp, ul_oddfactor)
}

/// `a_three_fx`: offset `A(3, k)`.
fn a_three(k_val: u32) -> u32 {
    if k_val != 0 {
        ul_add_ns_d(1, ul_mpy_32_32(k_val, ul_lshl(ul_sub_ns_d(k_val, 1), 1)))
    } else {
        0
    }
}

/// `a_four_fx`: offset `A(4, k)`.
fn a_four(k_val: u32) -> u32 {
    if k_val != 0 {
        let ul_2k = ul_lshl(k_val, 1);
        ul_mpy_32_32(
            UDIVBY3_FX,
            ul_sub_ns_d(
                ul_mpy_32_32(
                    ul_2k,
                    ul_add_ns_d(4, ul_mpy_32_32(ul_sub_ns_d(ul_2k, 3), k_val)),
                ),
                3,
            ),
        )
    } else {
        0
    }
}

/// `a_five_fx`: offset `A(5, k)`.
fn a_five(k_val: u32) -> u32 {
    if k_val == 0 {
        0
    } else if ul_sub_ns_d(k_val, 1) == 0 {
        1
    } else {
        ul_add_ns_d(
            1,
            ul_lshl(
                ul_mpy_32_32(
                    ul_mpy_32_32(
                        ul_sub_ns_d(
                            ul_mpy_32_32(
                                ul_add_ns_d(ul_mpy_32_32(ul_sub_ns_d(k_val, 2), k_val), 5),
                                k_val,
                            ),
                            4,
                        ),
                        k_val,
                    ),
                    UDIVBY3_FX,
                ),
                1,
            ),
        )
    }
}

/// `direct_msize_fx`: `N_MPVQ(n, k)` by closed form for `n` = 1..5.
fn direct_msize(dim_in: i16, k_in: i16) -> u32 {
    let mut ul_msize: u32 = 1; // k==0 or dim==1, and base for other dims
    if k_in != 0 {
        let k = u32::from(k_in as u16); // UL_deposit_l
        let ksq = ul_mpy_32_32(k, k);
        match dim_in {
            5 => {
                ul_msize = ul_add_ns_d(
                    ul_msize,
                    ul_lshl(
                        ul_mpy_32_32(ul_mpy_32_32(ksq, ul_add_ns_d(5, ksq)), UDIVBY3_FX),
                        1,
                    ),
                );
            }
            4 => {
                ul_msize = ul_lshl(
                    ul_mpy_32_32(ul_mpy_32_32(k, ul_add_ns_d(ksq, 2)), UDIVBY3_FX),
                    2,
                );
            }
            3 => ul_msize = ul_add_ns_d(ul_msize, ul_lshl(ksq, 1)),
            2 => ul_msize = ul_lshl(k, 1),
            _ => {}
        }
    }
    ul_msize
}

/// `initOffsets_fx`: `h_mem[0..=k]` with the starting offsets `A(dim_in, 0..=k)` and
/// `h_mem[k + 1] = U(dim_in, k + 1)`, for `dim_in` 2 or 3. `h_mem` holds `k + 2` entries.
fn init_offsets(dim_in: i16, h_mem: &mut [u32], k_val_in: i16) {
    h_mem[0] = 0; // A(=>0,k=0)
    h_mem[1] = 1; // A(*,k=1)
    let ul_k_val_in = u32::from(k_val_in as u16);
    if dim_in == 2 {
        let mut k_val: u32 = 2;
        while k_val <= ul_k_val_in {
            h_mem[k_val as usize] = ul_sub_ns_d(ul_lshl(k_val, 1), 1); // A(2, 2 .. k)
            k_val += 1;
        }
        h_mem[k_val as usize] = ul_k_val_in; // U(2,k+1)
    } else {
        let mut k_val_prev: u32 = 1;
        let mut k_val_curr: u32 = 2;
        while k_val_curr <= ul_k_val_in {
            h_mem[k_val_curr as usize] =
                ul_add_ns_d(1, ul_mpy_32_32(k_val_curr, ul_lshl(k_val_prev, 1)));
            k_val_prev = k_val_curr;
            k_val_curr += 1;
        }
        h_mem[k_val_curr as usize] = ul_mpy_32_32(k_val_curr, k_val_prev); // U(3,k_val_in+1)
    }
}

/// `a_fwd_fx`: offsets `A(n, k)` from the lower row `A(n-1, k)`, in place over
/// `h[at - 1..=at + n_items]` (the reference passes `&h[at]` and reads one before it).
fn a_fwd(h: &mut [u32], at: usize, n_items: i16) {
    let mut a_in0: u32 = 1;
    let items = usize::try_from(n_items).unwrap_or(0);
    for i in 1..=items {
        let a_1 = ul_add_ns_d(a_in0, ul_add_ns_d(h[at + i - 1], h[at + i]));
        h[at + i - 1] = a_in0;
        a_in0 = a_1;
    }
    h[at + items] = a_in0;
}

/// `a_bwd_fx`: offsets `A(n, k)` from the higher row `A(n+1, k)`, in place over
/// `a_in[0..=n_items]`.
pub fn a_bwd(a_in: &mut [u32], n_items: i16) {
    let mut a_in0: u32 = 0;
    let items = usize::try_from(n_items)
        .unwrap_or(0)
        .min(a_in.len().saturating_sub(1));
    for i in 1..=items {
        let a_1 = ul_sub_ns_d(ul_sub_ns_d(a_in[i], a_in0), a_in[i - 1]);
        a_in[i - 1] = a_in0;
        a_in0 = a_1;
    }
    a_in[items] = a_in0;
}

/// `direct_row_A2U_rec_calc_fx`: `U(n, k)` from `A(n, k-2)` and `A(n, k-1)`.
#[must_use]
pub fn direct_row_a2u_rec_calc(dim_in: i16, k_val_in: i16, a_km2: u32, a_km1: u32) -> u32 {
    let divisor = sub(k_val_in, 1);
    let ul_um2 = ul_lshr(a_km2, 1);
    let ul_dim = u32::from(dim_in as u16);
    let km2_size = ul_add_ns_d(ul_add_ns_d(ul_lshr(a_km1, 1), ul_um2), 1);
    if divisor & 1 != 0 {
        // odd
        ul_add_ns_d(
            ul_um2,
            f_odd_exact_div_opt(ul_dim, a_km1, km2_size, shr(divisor, 1)),
        )
    } else {
        // even divisor
        ul_add_ns_d(
            ul_um2,
            f_even_exact_div_opt(ul_dim, a_km1, km2_size, divisor),
        )
    }
}

/// `a_u_fwd_fx`: one dimension up for both the `A` row and the trailing `U(n, k+1)`.
fn a_u_fwd(a_u_in: &mut [u32], k_val_in: i16, mem_size_m1: i16) {
    let k = k_val_in as usize;
    let m = mem_size_m1 as usize;
    let u_kp1_prev = a_u_in[m]; // previous n U(n,k+1) value
    let u_k_prev = ul_lshr(a_u_in[k], 1); // previous n A(n,k) value
    a_fwd(a_u_in, 1, k_val_in); // a_u_in[k==ZERO] = zero if n>0
                                // U(n,k+1) = 1 + U(n-1,k+1) + (A(n-1,k)-1)/2 + (A(n,k)-1)/2
    let u_kp1 = ul_lshr(a_u_in[k], 1);
    a_u_in[m] = ul_add_ns_d(1, ul_add_ns_d(u_kp1_prev, ul_add_ns_d(u_k_prev, u_kp1)));
}

/// `nm_h_prep_opt_fx`: `N_MPVQ(n, k)` for `n > 5`, leaving the offsets `A(n, 0..=k)` and
/// `U(n, k+1)` in `h[0..=k+1]`. A pulse count whose table would not fit `h` returns 0 with `h`
/// untouched (the decoder sizes `h` for `KMAX_NON_DIRECT_FX` pulses).
#[must_use]
pub fn nm_h_prep_opt(dim_in: i16, k_val_in: i16, h: &mut [u32]) -> u32 {
    let Ok(k) = usize::try_from(k_val_in) else {
        return 0;
    };
    if h.len() < k + 2 || h.len() < 3 {
        return 0;
    }
    h[0] = 0; // A(=>0,k=0)
    h[1] = 1; // A(*,k=1)
    let mem_size_m1 = add(k_val_in, 1);

    let (a_k, u_kp1);
    if k_val_in > TABLE_LIM_OPT_FX {
        // start from A(3), U(3) (dim_in > N_OPT_FX here, so always 3)
        let d_start: i16 = if dim_in >= 3 { 3 } else { 2 };
        init_offsets(d_start, h, k_val_in);
        for _ in d_start..dim_in {
            a_u_fwd(h, k_val_in, mem_size_m1);
        }
        a_k = h[k];
        u_kp1 = h[mem_size_m1 as usize];
    } else {
        let num_d_sub1 = u32::from(sub(shl(dim_in, 1), 1) as u16);
        h[2] = num_d_sub1;
        // interleaved "odd, even [odd]" divisor calls
        let mut h_save_a = num_d_sub1;
        let mut h_save_b: u32 = 1;
        let tmp = sub(k_val_in, 3);
        let mut add_last_odd: i16 = 0; // k_val_in = 0 1 2
        if tmp == 0 {
            add_last_odd = 1; // k_val_in = 3
        }
        let mut k_val: i16 = 3;
        if tmp > 0 {
            // k_val_in = 3,4, 5,6, 7 ...
            let mut end_loop = mem_size_m1;
            add_last_odd = k_val_in & 1;
            if add_last_odd != 0 {
                end_loop = sub(end_loop, 1); // an even number of (odd-even) pairs
            }
            while k_val < end_loop {
                // A(n,k) = A(n,k-2) + ((2*n-1)*A(n,k-1)-A(n,k-2)) /(k-1)
                // first odd k, even divisor
                h_save_b = ul_add_ns_d(
                    h_save_b,
                    f_even_exact_div_opt(num_d_sub1, h_save_a, h_save_b, sub(k_val, 1)),
                );
                h[k_val as usize] = h_save_b;
                // next even k, odd divisor
                h_save_a = ul_add_ns_d(
                    h_save_a,
                    f_odd_exact_div_opt(num_d_sub1, h_save_b, h_save_a, shr(k_val, 1)),
                );
                k_val += 1;
                h[k_val as usize] = h_save_a;
                k_val += 1;
            }
        }
        if add_last_odd != 0 {
            // a last odd call as needed, not for k_val_in in [0,1,2]
            h_save_b = ul_add_ns_d(
                h_save_b,
                f_even_exact_div_opt(num_d_sub1, h_save_a, h_save_b, sub(k_val, 1)),
            );
            h[k] = h_save_b;
        }
        // always do the last (k+1) recursion based on U(n,k+1) = func(A(n-2,k+1), A(n-1,k+1))
        a_k = h[k];
        let km1 = usize::try_from(sub(mem_size_m1, 2)).unwrap_or(0);
        u_kp1 = direct_row_a2u_rec_calc(dim_in, mem_size_m1, h[km1], a_k);
        h[mem_size_m1 as usize] = u_kp1;
    }
    // N_MPVQ(n,k) = 1 + U(n,k+1) + U(n,k) = 1 + U(n,k+1) + floor(A(n,k)/2)
    ul_add_ns_d(1, ul_add_ns_d(u_kp1, ul_lshr(a_k, 1)))
}

/// `find_amp_split_offset_func_mem_fx`: the first `k` in `0..=high` whose offset `h_func(k)` is not
/// below `ind_in`, by a binary search; returns `(k, h_func(k))`.
fn find_amp_split_offset_func_mem(
    ind_in: u32,
    mut high: i16,
    h_func: fn(u32) -> u32,
) -> (i16, u32) {
    let mut low: i16 = 0;
    loop {
        let k_test = shr(add(low, high), 1); // split range in half
        let offset = h_func(u32::from(k_test as u16));
        let (ul_tmp, sgn) = ul_sub_ns(offset, ind_in);
        if sgn {
            // offset < ind_in
            low = add(1, k_test);
            if k_test >= high {
                return (k_test, offset);
            }
        } else {
            // ind_in <= offset
            high = sub(k_test, 1);
            if ul_tmp == 0 {
                return (k_test, offset);
            }
        }
        if low > high + 1 {
            // unreachable for a monotonic offset function; ends the search on a corrupt index
            return (k_test, offset);
        }
    }
}

/// `get_lead_sign_fx`: the leading sign stored in the index's LSB (-1 if set), removing it.
pub fn get_lead_sign(ind: &mut u32) -> i16 {
    let leading_sign = if *ind & 1 != 0 { -1 } else { 1 };
    *ind = ul_lshr(*ind, 1);
    leading_sign
}

/// `mind2vec_one_fx`: one dimension: all `k_val_in` pulses at `vec_out[0]`, signed.
fn mind2vec_one(mut k_val_in: i16, leading_sign: i16, _ind: u32, vec_out: &mut [i16]) {
    if leading_sign < 0 {
        k_val_in = crate::itu::basic_ops::negate(k_val_in);
    }
    if let Some(first) = vec_out.first_mut() {
        *first = k_val_in;
    }
}

/// `mind2vec_two_fx`: two dimensions.
fn mind2vec_two(k_val_in: i16, leading_sign: i16, ind_in: u32, vec_out: &mut [i16]) {
    if ind_in == 0 {
        mind2vec_one(k_val_in, leading_sign, ind_in, vec_out);
    } else if sub(u_extract_l(ind_in), sub(shl(k_val_in, 1), 1)) == 0 {
        mind2vec_one(k_val_in, leading_sign, ind_in, &mut vec_out[1..]);
    } else {
        let ul_ind_tmp = ul_sub_ns_d(ind_in, 1);
        let mut val1 = u_extract_l(ul_add_ns_d(1, ul_lshr(ul_ind_tmp, 1)));
        mind2vec_one(sub(k_val_in, val1), leading_sign, ind_in, vec_out);
        if ul_ind_tmp & 1 != 0 {
            val1 = crate::itu::basic_ops::negate(val1);
        }
        vec_out[1] = val1;
    }
}

/// `setval_update_sign_fx`: place `k_delta` pulses at `vec_out[0]`, read the next leading sign
/// from the index, and return the pulses left.
pub fn setval_update_sign(
    k_delta: i16,
    mut k_max_local: i16,
    leading_sign: &mut i16,
    ind_in: &mut u32,
    vec_out: &mut [i16],
) -> i16 {
    if k_delta != 0 {
        mind2vec_one(k_delta, *leading_sign, *ind_in, vec_out);
        *leading_sign = get_lead_sign(ind_in);
        k_max_local = sub(k_max_local, k_delta);
    }
    k_max_local
}

/// `mind2vec_three_fx`: three dimensions, the first amplitude by a direct square root.
fn mind2vec_three(
    mut k_max_local: i16,
    mut leading_sign: i16,
    mut ind_in: u32,
    vec_out: &mut [i16],
) {
    if ind_in != 0 {
        // acc_val = (isqrt(2·ind - 1) + 1) / 2
        let acc_val = lshr(
            add(
                1,
                crate::evs::com::basop_util::get_sqrt_word32(
                    ul_sub_ns_d(ul_lshl(ind_in, 1), 1) as i32
                ),
            ),
            1,
        );
        let k_delta = sub(k_max_local, acc_val);
        ind_in = ul_sub_ns_d(ind_in, a_three(u32::from(acc_val as u16))); // remove amplitude offset
        k_max_local = setval_update_sign(
            k_delta,
            k_max_local,
            &mut leading_sign,
            &mut ind_in,
            vec_out,
        );
        mind2vec_two(k_max_local, leading_sign, ind_in, &mut vec_out[1..]);
    } else {
        mind2vec_one(k_max_local, leading_sign, ind_in, vec_out);
    }
}

/// `mind2vec_direct_fx`: one dimension of the direct decoders (4, 5): split off the first
/// amplitude with the dimension's offset function, then the next lower dimension.
fn mind2vec_direct(
    mut k_max_local: i16,
    mut leading_sign: i16,
    mut ind: u32,
    h_func: fn(u32) -> u32,
    nd_func: fn(i16, i16, u32, &mut [i16]),
    vec_out: &mut [i16],
) {
    if ind != 0 {
        let (k_test, ul_tmp_offset) = find_amp_split_offset_func_mem(ind, k_max_local, h_func);
        let k_delta = sub(k_max_local, k_test);
        ind = ul_sub_ns_d(ind, ul_tmp_offset); // remove amplitude offset A(n,k_acc)
        k_max_local =
            setval_update_sign(k_delta, k_max_local, &mut leading_sign, &mut ind, vec_out);
        nd_func(k_max_local, leading_sign, ind, &mut vec_out[1..]); // next lower dimension
    } else {
        mind2vec_one(k_max_local, leading_sign, ind, vec_out);
    }
}

/// `mind2vec_four_fx`.
fn mind2vec_four(k_val_in: i16, leading_sign: i16, ind_in: u32, vec_out: &mut [i16]) {
    mind2vec_direct(
        k_val_in,
        leading_sign,
        ind_in,
        a_four,
        mind2vec_three,
        vec_out,
    );
}

/// `mind2vec_five_fx`.
fn mind2vec_five(k_val_in: i16, leading_sign: i16, ind_in: u32, vec_out: &mut [i16]) {
    mind2vec_direct(
        k_val_in,
        leading_sign,
        ind_in,
        a_five,
        mind2vec_four,
        vec_out,
    );
}

/// `mind2vec_fx`: the generic decoder for dimensions above five, walking the offset rows in
/// `h_in` down one dimension per position.
pub fn mind2vec(
    dim_in: i16,
    mut k_max_local: i16,
    mut leading_sign: i16,
    mut ind: u32,
    vec_out: &mut [i16],
    h_in: &mut [u32],
) {
    for pos in 0..usize::try_from(dim_in).unwrap_or(0).min(vec_out.len()) {
        // first to last position decoding
        if ind == 0 {
            mind2vec_one(k_max_local, leading_sign, ind, &mut vec_out[pos..]);
            break; // "fast" recursion exit
        }
        // regular linear magnitude search
        let mut k_acc = usize::try_from(k_max_local).unwrap_or(0);
        let Some(&offset) = h_in.get(k_acc) else {
            return;
        };
        let (mut ul_diff, mut sgn) = ul_sub_ns(ind, offset);
        while sgn {
            // h_in[0] is always 0, so this ends at k_acc == 0 at the latest
            if k_acc == 0 {
                break;
            }
            k_acc -= 1;
            (ul_diff, sgn) = ul_sub_ns(ind, h_in[k_acc]);
        }
        ind = ul_diff; // save amplitude index offset A(n, k_acc)
        let k_delta = sub(k_max_local, k_acc as i16); // amplitude decoding
        k_max_local = setval_update_sign(
            k_delta,
            k_max_local,
            &mut leading_sign,
            &mut ind,
            &mut vec_out[pos..],
        );
        // move from A(n,kmax) to A(n-1, k_max_local); no need to update U(n,k_max_local+1)
        a_bwd(h_in, add(k_max_local, 1));
    }
}

/// `get_size_mpvq_calc_offset_fx`: the codebook size `N_MPVQ(dim_in, k_val_in)` (and, for
/// `dim_in > 5`, the offset table in `h_mem`, which holds at least `k_val_in + 2` entries).
#[must_use]
pub fn get_size_mpvq_calc_offset(dim_in: i16, k_val_in: i16, h_mem: &mut [u32]) -> PvqEntry {
    let size = if dim_in > N_OPT_FX {
        // non-direct solutions, use A+U relation
        nm_h_prep_opt(dim_in, k_val_in, h_mem)
    } else {
        direct_msize(dim_in, k_val_in)
    };
    PvqEntry {
        lead_sign_ind: 0,
        index: 0,
        size,
        dim: dim_in,
        k_val: k_val_in,
    }
}

/// `mpvq_decode_vec_fx`: decode `entry` (sign, index, dimension, pulses) into the pulse vector
/// `vec_out[0..dim]`; `h_mem` is the offset table [`get_size_mpvq_calc_offset`] prepared (it is
/// consumed row by row for `dim > 5`).
pub fn mpvq_decode_vec(entry: &PvqEntry, h_mem: &mut [u32], vec_out: &mut [i16]) {
    let dim = usize::try_from(entry.dim).unwrap_or(0).min(vec_out.len());
    // set all of short vector to zero, required for fast/early exit logic
    for value in vec_out.iter_mut().take(dim) {
        *value = 0;
    }
    let leading_sign = if entry.lead_sign_ind != 0 { -1 } else { 1 };
    if entry.k_val != 0 {
        let out = &mut vec_out[..dim];
        match entry.dim {
            // generic
            dim if dim > N_OPT_FX => {
                mind2vec(
                    entry.dim,
                    entry.k_val,
                    leading_sign,
                    entry.index,
                    out,
                    h_mem,
                );
            }
            // specialized functions, with direct offset calculations
            1 => mind2vec_one(entry.k_val, leading_sign, entry.index, out),
            2 => mind2vec_two(entry.k_val, leading_sign, entry.index, out),
            3 => mind2vec_three(entry.k_val, leading_sign, entry.index, out),
            4 => mind2vec_four(entry.k_val, leading_sign, entry.index, out),
            5 => mind2vec_five(entry.k_val, leading_sign, entry.index, out),
            // dimension 0: the reference calls a NULL function pointer
            _ => {}
        }
    }
}
