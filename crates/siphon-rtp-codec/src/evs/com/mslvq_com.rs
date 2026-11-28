//! Multiple-scale lattice VQ (MSLVQ) of the LSF residual: table initialisation and index decoding
//! (TS 26.442 `lib_com/mslvq_com_fx.c`; TS 26.445 §5.2.2.1.4).
//!
//! The encoder's `multiply32_32_64_fx` is not ported here.

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    LATTICE_DIM, LEN_INDICE, LVQ_COD_MODES, MAX_NO_MODES, MAX_NO_MODES_P, MAX_NO_SCALES, START_CNG,
};
use crate::evs::rom::{
    CNG_SORT_FX, C_VQ_FX, MIN_LAT_BITS_PRED_FX, MIN_LAT_BITS_SN_FX, NO_LEAD_FX, NO_LEAD_P_FX,
    NO_VALS_FX, NO_VALS_IND_FX, OFFSET_IN_LVQ_MODE_PRED_FX, OFFSET_IN_LVQ_MODE_SN_FX,
    OFFSET_LVQ_MODES_PRED_FX, OFFSET_LVQ_MODES_SN_FX, PERM_MSLVQ_FX, PI0_FX, PL_PAR_FX, SCALES_FX,
    SCALES_P_FX, SIGMA_MSLVQ_FX, SIGMA_P_FX, TABLE_NO_CV_FX, VALS_FX,
};
use crate::itu::basic_ops::{
    add, extract_l, l_add, l_mult, l_shl, l_shr, l_sub, negate, norm_l, norm_s, round_word, shl,
    shr, sub,
};
use crate::itu::stl2009::{div_l, l_mult0};

/// Columns of an offset-scale row (`MAX_NO_SCALES + 1`).
const NO_MODES: usize = MAX_NO_SCALES as usize + 1;
/// `LATTICE_DIM` as an index.
const DIM: usize = LATTICE_DIM as usize;

/// `table[index]` for a signed index, or `None` outside the table.
fn at<T: Copy>(table: &[T], index: i32) -> Option<T> {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
}

/// `init_lvq_fx`: the number of truncations (scales) of each MSLVQ structure, for each of the two
/// LSF subvectors, and the index offset of each truncation; for the safety-net and the predictive
/// structures. Called once at decoder initialisation.
pub fn init_lvq(
    offset_scale1: &mut [[i32; NO_MODES]],
    offset_scale2: &mut [[i32; NO_MODES]],
    offset_scale1_p: &mut [[i32; NO_MODES]],
    offset_scale2_p: &mut [[i32; NO_MODES]],
    no_scales: &mut [[i16; 2]],
    no_scales_p: &mut [[i16; 2]],
) {
    let scales = MAX_NO_SCALES as usize;
    let count = |row: &[i16], from: usize| {
        row[from..from + scales]
            .iter()
            .take_while(|&&leaders| leaders > 0)
            .count() as i16
    };
    // safety-net mode
    for (row, out) in NO_LEAD_FX
        .iter()
        .zip(no_scales.iter_mut())
        .take(MAX_NO_MODES as usize)
    {
        out[0] = count(row, 0);
        out[1] = count(row, scales);
    }
    // predictive mode
    for (row, out) in NO_LEAD_P_FX
        .iter()
        .zip(no_scales_p.iter_mut())
        .take(MAX_NO_MODES_P as usize)
    {
        out[0] = count(row, 0);
        out[1] = count(row, scales);
    }
    // index offsets for each truncation
    init_offset(
        offset_scale1,
        offset_scale2,
        offset_scale1_p,
        offset_scale2_p,
        no_scales,
        no_scales_p,
    );
}

/// `make_offset_scale_fx`: the cumulated index offsets of the `no_scl` truncations of MSLVQ
/// structure `j`, whose truncations hold `no_ld[i]` leaders.
pub fn make_offset_scale(
    j: usize,
    tab_no_cv: &[i32],
    no_ld: &[i16],
    no_scl: i16,
    offset_scale: &mut [[i32; NO_MODES]],
) {
    let Some(row) = offset_scale.get_mut(j) else {
        return;
    };
    row[0] = 1;
    for i in 1..=usize::try_from(no_scl).unwrap_or(0).min(NO_MODES - 1) {
        let leaders = no_ld.get(i - 1).copied().unwrap_or(0);
        row[i] = l_add(row[i - 1], at(tab_no_cv, leaders.into()).unwrap_or(0));
    }
}

/// `init_offset_fx`: [`make_offset_scale`] for every structure and subvector, plus the sentinel
/// row past the last structure.
pub fn init_offset(
    offset_scale1: &mut [[i32; NO_MODES]],
    offset_scale2: &mut [[i32; NO_MODES]],
    offset_scale1_p: &mut [[i32; NO_MODES]],
    offset_scale2_p: &mut [[i32; NO_MODES]],
    no_scales: &[[i16; 2]],
    no_scales_p: &[[i16; 2]],
) {
    let scales = MAX_NO_SCALES as usize;
    // safety-net
    for (j, (row, count)) in NO_LEAD_FX
        .iter()
        .zip(no_scales)
        .enumerate()
        .take(MAX_NO_MODES as usize)
    {
        make_offset_scale(j, &TABLE_NO_CV_FX, row, count[0], offset_scale1);
        make_offset_scale(j, &TABLE_NO_CV_FX, &row[scales..], count[1], offset_scale2);
    }
    // predictive modes AR and MA
    for (j, (row, count)) in NO_LEAD_P_FX
        .iter()
        .zip(no_scales_p)
        .enumerate()
        .take(MAX_NO_MODES_P as usize)
    {
        make_offset_scale(j, &TABLE_NO_CV_FX, row, count[0], offset_scale1_p);
        make_offset_scale(
            j,
            &TABLE_NO_CV_FX,
            &row[scales..],
            count[1],
            offset_scale2_p,
        );
    }
    for (table, sentinel) in [
        (offset_scale1, MAX_NO_MODES),
        (offset_scale2, MAX_NO_MODES),
        (offset_scale1_p, MAX_NO_MODES_P),
        (offset_scale2_p, MAX_NO_MODES_P),
    ] {
        if let Some(row) = table.get_mut(sentinel as usize) {
            row[0] = 1;
        }
    }
}

/// Zero the decoded vector and both scales: the reference's reaction to an index that cannot have
/// come from the encoder (a bit error). Returns the bit-error flag.
fn decode_indexes_corrupt(x_lvq: &mut [i16], scales: &mut [i16; 2]) -> i16 {
    for value in x_lvq.iter_mut().take(2 * DIM) {
        *value = 0;
    }
    *scales = [0, 0];
    1
}

/// One subvector's leader search and combinatorial decoding: `index` (already relative to the
/// truncation offset) into `cv`; `None` when it lies past `table_no_cv` (corrupt).
fn decode_indexes_subvector(index: i32, cv: &mut [i16]) -> Option<()> {
    // find idx_leader
    let mut i: i32 = 1;
    while index >= at(&TABLE_NO_CV_FX, i)? {
        i += 1;
    }
    let im1 = i - 1;
    // The reference subtracts with a plain C `-` for the second subvector and L_sub for the first;
    // both operands are small non-negative counts, so they agree.
    decode_comb(l_sub(index, at(&TABLE_NO_CV_FX, im1)?), cv, im1 as i16);
    Some(())
}

/// `decode_indexes_fx`: split the LSF lattice index (three 15-bit words) into the two subvectors'
/// indices, find each one's truncation and leader class, and decode the lattice codevectors (Q1)
/// and their scales. Returns 1 on a bit error (corrupt index), else 0.
pub fn decode_indexes(
    index: &mut [i16],
    no_bits: i16,
    p_scales: &[i16],
    p_no_scales: &[i16],
    p_offset_scale1: &[i32],
    p_offset_scale2: &[i32],
    x_lvq: &mut [i16],
    mode_glb: i16,
    scales: &mut [i16; 2],
) -> i16 {
    let len_scales = i32::from(MAX_NO_SCALES * 2);
    let no_modes = i32::from(MAX_NO_SCALES + 1);

    if no_bits <= shl(LEN_INDICE, 1) {
        // the third short is not used
        index[2] = 0;
        if no_bits <= LEN_INDICE {
            index[1] = 0;
        }
    }
    // safety check in case of bit errors
    for word in index.iter_mut().take(3) {
        if *word < 0 {
            *word = 0;
            return decode_indexes_corrupt(x_lvq, scales);
        }
    }

    let mode = i32::from(mode_glb);
    let tmp = mode * no_modes;
    let (Some(no_scales_1), Some(no_scales_2)) =
        (at(p_no_scales, 2 * mode), at(p_no_scales, 2 * mode + 1))
    else {
        return decode_indexes_corrupt(x_lvq, scales);
    };
    let Some(limit2) = at(p_offset_scale2, tmp + i32::from(no_scales_2)) else {
        return decode_indexes_corrupt(x_lvq, scales);
    };

    // first subvector
    let (mut index1, mut index2) = if limit2 > 0 {
        divide_64_32(index, limit2)
    } else {
        // this is for very low bitrates, so there is no loss in truncation
        (i32::from(index[0]), 0)
    };

    if index1 == 0 {
        for value in x_lvq.iter_mut().take(DIM) {
            *value = 0;
        }
        scales[0] = 0;
    } else {
        let Some(limit1) = at(p_offset_scale1, tmp + i32::from(no_scales_1)) else {
            return decode_indexes_corrupt(x_lvq, scales);
        };
        if index1 >= limit1 {
            // safety check in case of bit errors
            return decode_indexes_corrupt(x_lvq, scales);
        }
        // find idx_scale
        let mut i: i16 = 1;
        while i <= no_scales_1
            && at(p_offset_scale1, tmp + i32::from(i)).is_some_and(|o| index1 >= o)
        {
            i = add(i, 1);
        }
        let idx_scale = i32::from(sub(i, 1));
        index1 = l_sub(index1, at(p_offset_scale1, tmp + idx_scale).unwrap_or(0));
        if decode_indexes_subvector(index1, &mut x_lvq[..DIM]).is_none() {
            return decode_indexes_corrupt(x_lvq, scales);
        }
        scales[0] = at(p_scales, mode * len_scales + idx_scale).unwrap_or(0);
    }

    // second subvector
    if index2 == 0 {
        for value in x_lvq.iter_mut().skip(DIM).take(DIM) {
            *value = 0;
        }
        scales[1] = 0;
    } else {
        // find the index for the scale/truncation (index2 is a remainder of the division by the
        // last offset, so the search ends inside the row)
        let mut i: i32 = 1;
        while at(p_offset_scale2, tmp + i).is_some_and(|o| index2 >= o) {
            i += 1;
        }
        let idx_scale = i - 1;
        index2 = l_sub(index2, at(p_offset_scale2, tmp + idx_scale).unwrap_or(0));
        if decode_indexes_subvector(index2, &mut x_lvq[DIM..2 * DIM]).is_none() {
            return decode_indexes_corrupt(x_lvq, scales);
        }
        scales[1] = at(
            p_scales,
            mode * len_scales + i32::from(MAX_NO_SCALES) + idx_scale,
        )
        .unwrap_or(0);
    }
    0
}

/// `deindex_lvq_fx`: decode the MSLVQ index of an LSF residual into `x_lvq` (16 values, Q(x2.56)),
/// for coding mode `mode`, safety-net (`sf_flag == 1`) or predictive, at `no_bits` lattice bits.
/// The offset and scale-count tables are the decoder state's, flattened row by row
/// (`st.offset_scale1.as_flattened()`, ...). Returns 1 on a bit error, else 0.
pub fn deindex_lvq(
    index: &mut [i16],
    x_lvq: &mut [i16],
    mode: i16,
    sf_flag: i16,
    no_bits: i16,
    p_offset_scale1: &[i32],
    p_offset_scale2: &[i32],
    p_no_scales: &[i16],
) -> i16 {
    let mode_index = usize::try_from(mode).unwrap_or(usize::MAX);
    let safety_net = sf_flag == 1;
    let (mode_glb, p_scales, sigma): (Option<i16>, &[i16], Option<&[i16; 16]>) = if safety_net {
        // `offset_in_lvq_mode_SN_fx[mode][no_bits - min_lat_bits]` indexes the 2-D table as the
        // flat array it is: MODE2's 16 kHz TRANSITION frame (mode 16, 23 lattice bits against a
        // minimum of 32) reaches row 15 through a negative column, so the row is not bounds-checked.
        let offset_in = MIN_LAT_BITS_SN_FX.get(mode_index).and_then(|min| {
            at(
                OFFSET_IN_LVQ_MODE_SN_FX.as_flattened(),
                mode_index as i32 * OFFSET_IN_LVQ_MODE_SN_FX[0].len() as i32
                    + i32::from(sub(no_bits, *min)),
            )
        });
        (
            OFFSET_LVQ_MODES_SN_FX
                .get(mode_index)
                .zip(offset_in)
                .map(|(&base, offset)| add(base, offset)),
            SCALES_FX.as_flattened(),
            SIGMA_MSLVQ_FX.get(mode_index),
        )
    } else {
        // indexed flat, as for the safety-net table above
        let offset_in = MIN_LAT_BITS_PRED_FX.get(mode_index).and_then(|min| {
            at(
                OFFSET_IN_LVQ_MODE_PRED_FX.as_flattened(),
                mode_index as i32 * OFFSET_IN_LVQ_MODE_PRED_FX[0].len() as i32
                    + i32::from(sub(no_bits, *min)),
            )
        });
        (
            OFFSET_LVQ_MODES_PRED_FX
                .get(mode_index)
                .zip(offset_in)
                .map(|(&base, offset)| add(base, offset)),
            SCALES_P_FX.as_flattened(),
            SIGMA_P_FX.get(mode_index),
        )
    };
    // A mode / bit count outside the reference's tables never comes from the decoder's own LSF
    // configuration; treat it like a corrupt index rather than read past the tables.
    let (Some(mode_glb), Some(sigma)) = (mode_glb, sigma) else {
        let mut scales = [0; 2];
        return decode_indexes_corrupt(x_lvq, &mut scales);
    };

    // decode the lattice index into the lattice codevectors for the two subvectors (Q1)
    let mut scales = [0i16; 2];
    let ber_flag = decode_indexes(
        index,
        no_bits,
        p_scales,
        p_no_scales,
        p_offset_scale1,
        p_offset_scale2,
        x_lvq,
        mode_glb,
        &mut scales,
    );

    // safety net (sigma_MSLVQ) or predictive AR / MA (sigma_p): the same scaling
    for (half, &scale) in scales.iter().enumerate() {
        if scale == 0 {
            continue;
        }
        for i in half * DIM..(half + 1) * DIM {
            let l_tmp = l_mult(x_lvq[i], scale); // Q1+Q11+Q1 = Q13
                                                 // Increase calculation accuracy by shifting more to the left and rounding
            let l_tmp = l_shl(mult_32_16(l_tmp, shl(sigma[i], 3)), 15);
            x_lvq[i] = round_word(l_tmp);
        }
    }
    ber_flag
}

/// `permute_fx`: swap `p_tmp1[perm[0]]` and `p_tmp1[perm[1]]`, then, when `perm[2]` is not -1,
/// `p_tmp1[perm[2]]` and `p_tmp1[perm[3]]`.
pub fn permute(p_tmp1: &mut [i16], perm: &[i16; 4]) {
    let p1 = perm[0] as usize;
    let p2 = perm[1] as usize;
    p_tmp1.swap(p1, p2);
    if add(perm[2], 1) > 0 {
        p_tmp1.swap(perm[2] as usize, perm[3] as usize);
    }
}

/// `deindex_lvq_cng_fx`: decode the MSLVQ index of an LP-CNG (SID) LSF residual into `x_lvq`
/// (16 values, Q(x2.56)) for the first-stage codevector `idx_cv` (0..=15), at `no_bits` lattice
/// bits. Returns 1 on a bit error, else 0.
pub fn deindex_lvq_cng(
    index: &mut [i16],
    x_lvq: &mut [i16],
    idx_cv: i16,
    no_bits: i16,
    p_offset_scale1: &[i32],
    p_offset_scale2: &[i32],
    p_no_scales: &[i16],
) -> i16 {
    // idx_cv is a 4-bit index; the masks only keep a corrupt caller inside the tables.
    let idx_cv = idx_cv & 15;
    let mode_glb = add(START_CNG, idx_cv);
    let mode = add(LVQ_COD_MODES, idx_cv);

    let mut scales = [0i16; 2];
    let ber_flag = decode_indexes(
        index,
        no_bits,
        SCALES_FX.as_flattened(),
        p_no_scales,
        p_offset_scale1,
        p_offset_scale2,
        x_lvq,
        mode_glb,
        &mut scales,
    );

    let sigma = &SIGMA_MSLVQ_FX[mode as usize];
    for (half, &scale) in scales.iter().enumerate() {
        for i in half * DIM..(half + 1) * DIM {
            let l_tmp = l_mult(x_lvq[i], scale); // Q1+Q11+Q1 = Q13
            let l_tmp = l_shl(mult_32_16(l_tmp, shl(sigma[i], 3)), 15);
            x_lvq[i] = round_word(l_tmp);
        }
    }

    // check if permutation is needed
    if CNG_SORT_FX[idx_cv as usize] != 0 {
        permute(x_lvq, &PERM_MSLVQ_FX[idx_cv as usize]);
    }

    ber_flag
}

/// `idx2c_fx`: combinatorial deindexing: the positions `p[0..k]` of `k` components among `n`
/// from index `val`.
pub fn idx2c(mut n: i16, p: &mut [i16], k: i16, mut val: i16) {
    let mut skip: i16 = 0;
    let mut pos: i16 = 0;
    let k1 = sub(k, 1);
    let c_vq = |row: i16| -> i16 {
        // C_VQ_fx[n - pos - 1][k1]; valid indices keep both inside the 9x9 table.
        C_VQ_FX
            .get(usize::try_from(row).unwrap_or(usize::MAX))
            .and_then(|row| at(row, k1.into()))
            .unwrap_or(i16::MAX)
    };
    while sub(add(skip, sub(c_vq(n - pos - 1), 1)), val) < 0 {
        skip = add(skip, c_vq(n - pos - 1));
        pos += 1;
        if pos >= n {
            // only a corrupt index walks off the table; the reference would read out of bounds
            break;
        }
    }
    let Some(first) = p.first_mut() else {
        return;
    };
    *first = pos;
    n = sub(n, add(pos, 1));
    val = sub(val, skip);
    if k <= 1 {
        return;
    }
    idx2c(n, &mut p[1..], k1, val);
    // pos+1
    for slot in p.iter_mut().take(k as usize).skip(1) {
        *slot = add(*slot, add(pos, 1));
    }
}

/// `decode_comb_fx`: decode a codevector of leader class `idx_lead` from its combinatorial index:
/// the sign index and the position index of the leader's values.
pub fn decode_comb(index: i32, cv: &mut [i16], idx_lead: i16) {
    let Some(pi0) = at(&PI0_FX, idx_lead.into()) else {
        return;
    };
    let idx_sign = extract_l(i32::from(div_l(l_shl(index, 1), pi0))); // index / pi0
    let index = l_sub(index, l_mult0(idx_sign, pi0));
    decode_leaders(extract_l(index), idx_lead, cv);
    decode_sign_pc1(cv, idx_sign, at(&PL_PAR_FX, idx_lead.into()).unwrap_or(0));
}

/// `decode_sign_pc1_fx`: apply the signs of `idx_sign` to the non-zero components of `c`; with a
/// parity constraint the last component's sign follows from the others.
pub fn decode_sign_pc1(c: &mut [i16], mut idx_sign: i16, parity: i16) {
    let mut len = LATTICE_DIM;
    let mut cnt_neg: i16 = 1;
    if parity != 0 {
        len = sub(len, 1);
    }
    for value in c.iter_mut().take(len as usize) {
        if *value > 0 {
            if idx_sign & 1 != 0 {
                *value = negate(*value);
                cnt_neg = negate(cnt_neg);
            }
            idx_sign = shr(idx_sign, 1);
        }
    }
    if len < LATTICE_DIM && cnt_neg != parity {
        c[len as usize] = negate(c[len as usize]);
    }
}

/// `decode_leaders_fx`: place the values of leader class `idx_lead` (Q1) into `cv` according to the
/// position index `index`.
pub fn decode_leaders(mut index: i16, idx_lead: i16, cv: &mut [i16]) {
    let lead = usize::try_from(idx_lead).unwrap_or(usize::MAX);
    let (Some(&no_vals_loc), Some(vals), Some(ind)) = (
        NO_VALS_FX.get(lead),
        VALS_FX.get(lead),
        NO_VALS_IND_FX.get(lead),
    ) else {
        return;
    };
    let Some(last) = usize::try_from(no_vals_loc - 1)
        .ok()
        .filter(|&last| last < 4)
    else {
        return;
    };
    let mut p = [0i16; DIM];
    let val_crt = vals[last];
    let no_vals_last = ind[last];
    for value in cv.iter_mut().take(no_vals_last.max(0) as usize) {
        *value = val_crt;
    }
    let mut dim_loc = no_vals_last;
    let c_vq = |dim: i16, n: i16| -> i16 {
        C_VQ_FX
            .get(usize::try_from(dim).unwrap_or(usize::MAX))
            .and_then(|row| at(row, n.into()))
            .unwrap_or(1)
    };
    match no_vals_loc {
        2 => {
            idx2c(LATTICE_DIM, &mut p, ind[0], index);
            put_value(cv, &p, vals[0], no_vals_last, ind[0]);
        }
        3 | 4 => {
            if no_vals_loc == 4 {
                dim_loc = add(dim_loc, ind[2]);
                let n_crt = ind[2];
                let (index1, rem) = divide_16_16(index, c_vq(dim_loc, n_crt));
                index = rem;
                idx2c(dim_loc, &mut p, n_crt, index);
                put_value(cv, &p, vals[2], no_vals_last, ind[2]);
                index = index1;
                // no break: falls through into the three-value case
            }
            dim_loc = add(dim_loc, ind[1]);
            let n_crt = ind[1];
            let (index1, rem) = divide_16_16(index, c_vq(dim_loc, n_crt));
            index = rem;
            idx2c(dim_loc, &mut p, n_crt, index);
            put_value(cv, &p, vals[1], sub(dim_loc, n_crt), n_crt);
            idx2c(LATTICE_DIM, &mut p, ind[0], index1);
            put_value(cv, &p, vals[0], dim_loc, ind[0]);
        }
        _ => {}
    }
}

/// `divide_32_32_fx`: integer division by shift-and-subtract; returns `(y / x, y % x)` for the
/// non-negative operands the decoder passes.
pub fn divide_32_32(y: i32, x: i32) -> (i32, i32) {
    if y < x {
        return (0, y);
    }
    let mut result: i32 = 0;
    let ny = if y == 0 { 0 } else { sub(31, norm_l(y)) };
    let nx = if x == 0 { 0 } else { sub(31, norm_l(x)) };
    let nyx = sub(ny, nx);
    let mut t = l_shr(y, add(nyx, 1));
    for i in 0..=nyx {
        t = l_add(l_shl(t, 1), l_shr(y, sub(nyx, i)) & 1);
        result = l_shl(result, 1);
        let l_tmp = l_sub(t, x);
        if l_tmp >= 0 {
            result = l_add(result, 1);
            t = l_tmp;
        }
    }
    (result, t)
}

/// `divide_16_16_fx`: [`divide_32_32`] for 16-bit operands; returns `(y / x, y % x)`.
pub fn divide_16_16(y: i16, x: i16) -> (i16, i16) {
    if y < x {
        return (0, y);
    }
    let mut result: i16 = 0;
    let ny = if y == 0 { 0 } else { sub(15, norm_s(y)) };
    let nx = if x == 0 { 0 } else { sub(15, norm_s(x)) };
    let nyx = sub(ny, nx);
    let mut t = shr(y, add(nyx, 1)) & sub(shl(1, sub(nx, 1)), 1);
    for i in 0..=nyx {
        t = add(shl(t, 1), shr(y, sub(nyx, i)) & 1);
        result = shl(result, 1);
        let tmp = sub(t, x);
        if tmp >= 0 {
            result = add(result, 1);
            t = tmp;
        }
    }
    (result, t)
}

/// `divide_64_32_fx`: divide the up-to-46-bit index held in three 15-bit words `xs` by `y`;
/// returns `(quotient, remainder)`.
pub fn divide_64_32(xs: &[i16], y: i32) -> (i32, i32) {
    let x0 = l_add(
        l_add(
            l_shl(i32::from(xs[2] & 1), 2 * LEN_INDICE),
            l_shl(i32::from(xs[1]), LEN_INDICE),
        ),
        i32::from(xs[0]),
    );
    let x1 = l_shr(i32::from(xs[2]), 1);
    let nb_x1 = if x1 == 0 { 0 } else { sub(31, norm_l(x1)) };
    // take the first 31 bits
    if nb_x1 > 0 {
        let x_tmp = l_add(l_shl(x1, sub(31, nb_x1)), l_shr(x0, nb_x1));
        let (q, r) = divide_32_32(x_tmp, y);
        // this is the first remainder
        let r = l_add(l_shl(r, nb_x1), x0 & i32::from(sub(shl(1, nb_x1), 1)));
        let (q1, rem) = divide_32_32(r, y);
        (l_add(l_shl(q, nb_x1), q1), rem)
    } else {
        divide_32_32(x0, y)
    }
}

/// `put_value_fx`: insert `no_new_val` copies of `val` at positions `p` into the first
/// `dim + no_new_val` components of `cv`, shifting the existing ones into the free positions.
pub fn put_value(cv: &mut [i16], p: &[i16], val: i16, dim: i16, no_new_val: i16) {
    let mut cv_out = [0i16; DIM];
    let mut occ = [false; DIM];
    let limit = usize::try_from(add(dim, no_new_val)).unwrap_or(0).min(DIM);
    for &position in p.iter().take(no_new_val.max(0) as usize) {
        // positions come from idx2c over at most LATTICE_DIM components
        if let Some(position) = usize::try_from(position).ok().filter(|&p| p < DIM) {
            cv_out[position] = val;
            occ[position] = true;
        }
    }
    let mut cnt = 0;
    for i in 0..limit {
        if !occ[i] {
            cv_out[i] = cv.get(cnt).copied().unwrap_or(0);
            cnt += 1;
        }
    }
    cv[..limit].copy_from_slice(&cv_out[..limit]);
}
