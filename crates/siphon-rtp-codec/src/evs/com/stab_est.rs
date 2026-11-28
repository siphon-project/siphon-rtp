//! Spectral stability estimate for the music/speech decision (TS 26.442 `lib_com/stab_est_fx.c`).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::com::math_op::isqrt_lc;
use crate::itu::basic_ops::{add, extract_h, l_mac, l_shl, norm_l, round_word, sub};
use crate::itu::stl2009::{l_mac0, l_mult0};

/// History length of `lt_diff_etot` (`MAX_LT` in the reference).
const MAX_LT: usize = 40;
/// The deviation is measured over the newest 15 entries, `lt_diff_etot[MAX_LT - 15..MAX_LT]`.
const DEV_WINDOW: usize = 15;

/// `stab_est_fx`: update the 40-frame history of total-energy differences and the music
/// thresholds, and return the stability-based music flag (0..=4; 0 when `vad_flag == 0`).
///
/// `lt_diff_etot` holds 40 entries; `thresh` four.
pub fn stab_est(
    etot: i16,
    lt_diff_etot: &mut [i16],
    mem_etot: &mut i16,
    nb_thr_3: &mut i16,
    nb_thr_1: &mut i16,
    thresh: &mut [i16],
    last_music_flag: &mut i16,
    vad_flag: i16,
) -> i16 {
    // (Word16)((1.0f / 40) * 32768) = 819.
    const INV_MAX_LT: i16 = 819;
    let mut l_tmp: i32 = 0;
    for i in 1..MAX_LT {
        l_tmp = l_mac(l_tmp, lt_diff_etot[i - 1], INV_MAX_LT);
        lt_diff_etot[i - 1] = lt_diff_etot[i];
    }
    l_tmp = l_mac(l_tmp, lt_diff_etot[MAX_LT - 1], INV_MAX_LT);
    let mean_diff = round_word(l_tmp);

    let mut tmp16 = sub(lt_diff_etot[MAX_LT - DEV_WINDOW], mean_diff);
    l_tmp = l_mult0(tmp16, tmp16);
    for &value in &lt_diff_etot[MAX_LT - DEV_WINDOW + 1..MAX_LT] {
        tmp16 = sub(value, mean_diff);
        l_tmp = l_mac0(l_tmp, tmp16, tmp16);
    }
    lt_diff_etot[MAX_LT - 1] = sub(etot, *mem_etot);
    *mem_etot = etot;

    // dev = sqrt(sum / 25) through x · isqrt(x).
    l_tmp = mpy_32_16_1(l_tmp, 1311);
    let exp1 = norm_l(l_tmp);
    l_tmp = l_shl(l_tmp, exp1);
    tmp16 = round_word(l_tmp);
    let mut exp2 = sub(31, exp1);
    l_tmp = isqrt_lc(l_tmp, &mut exp2);
    l_tmp = mpy_32_16_1(l_tmp, tmp16);
    exp2 = sub(31 - 15, sub(exp1, exp2));
    l_tmp = l_shl(l_tmp, exp2);
    let dev = extract_h(l_shl(l_tmp, 3));

    // `*nb_thr_3 += 1` is plain C arithmetic in the reference (wrapping, not `add`).
    let mut music_flag2 = 0;
    if dev < thresh[3] && *last_music_flag >= 3 {
        music_flag2 = 4;
        *nb_thr_3 = nb_thr_3.wrapping_add(1);
        *nb_thr_1 = 0;
    } else if dev < thresh[2] && *last_music_flag >= 2 {
        music_flag2 = 3;
        *nb_thr_3 = nb_thr_3.wrapping_add(1);
        *nb_thr_1 = 0;
    } else if dev < thresh[1] && *last_music_flag >= 1 {
        music_flag2 = 2;
    } else if dev < thresh[0] {
        music_flag2 = 1;
    } else {
        *nb_thr_1 = add(*nb_thr_1, 1);
        *nb_thr_3 = 0;
    }

    if *nb_thr_3 > 30 {
        for value in thresh.iter_mut().take(4) {
            *value = add(*value, 320);
        }
    } else if *nb_thr_1 > 30 {
        for value in thresh.iter_mut().take(4) {
            *value = sub(*value, 320);
        }
    }
    thresh[0] = thresh[0].max(3840);
    thresh[1] = thresh[1].max(2560);
    thresh[2] = thresh[2].max(1920);
    thresh[0] = thresh[0].min(9600);
    thresh[1] = thresh[1].min(8640);
    thresh[2] = thresh[2].min(6720);
    thresh[3] = thresh[3].max(1280);
    thresh[3] = thresh[3].min(5760);

    *last_music_flag = music_flag2;
    if vad_flag == 0 {
        music_flag2 = 0;
    }
    music_flag2
}
