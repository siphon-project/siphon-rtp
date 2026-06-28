//! AMR-WB LPC / ISP domain conversions (3GPP TS 26.173 `isp_isf.c`), ported bit-exact.
//!
//! The codec quantizes the spectral envelope as ISF (immittance spectral frequencies); the decoder
//! converts the dequantized ISF to ISP (`isf_isp`), interpolates per subframe, and then to LPC
//! coefficients. Both directions are a cos / acos approximated by a 129-point table + linear
//! interpolation. `isp_isf` is the inverse (used for the stability factor and concealment).

use crate::amr::basic_ops::{add, extract_l, l_mult, l_shl, l_shr, round_word, shl, shr, sub};

/// `cos(x)` in Q15 over 128 segments (TS 26.173 `isp_isf.tab`). 129 real entries; one extra
/// duplicate of the last so the `table[ind+1]` read at `ind = 128` (where the offset is always 0)
/// stays in bounds — bit-exact with the reference's one-past read, which is also multiplied by 0.
#[rustfmt::skip]
static TABLE: [i16; 130] = [
    32767,
    32758,  32729,  32679,  32610,  32522,  32413,  32286,  32138,
    31972,  31786,  31581,  31357,  31114,  30853,  30572,  30274,
    29957,  29622,  29269,  28899,  28511,  28106,  27684,  27246,
    26791,  26320,  25833,  25330,  24812,  24279,  23732,  23170,
    22595,  22006,  21403,  20788,  20160,  19520,  18868,  18205,
    17531,  16846,  16151,  15447,  14733,  14010,  13279,  12540,
    11793,  11039,  10279,   9512,   8740,   7962,   7180,   6393,
     5602,   4808,   4011,   3212,   2411,   1608,    804,      0,
     -804,  -1608,  -2411,  -3212,  -4011,  -4808,  -5602,  -6393,
    -7180,  -7962,  -8740,  -9512, -10279, -11039, -11793, -12540,
   -13279, -14010, -14733, -15447, -16151, -16846, -17531, -18205,
   -18868, -19520, -20160, -20788, -21403, -22006, -22595, -23170,
   -23732, -24279, -24812, -25330, -25833, -26320, -26791, -27246,
   -27684, -28106, -28511, -28899, -29269, -29622, -29957, -30274,
   -30572, -30853, -31114, -31357, -31581, -31786, -31972, -32138,
   -32286, -32413, -32522, -32610, -32679, -32729, -32758, -32768,
   -32768,
];

/// `d(acos)/dx` slope per segment, Q15 (TS 26.173 `isp_isf.tab`).
#[rustfmt::skip]
static SLOPE: [i16; 128] = [
    -26214, -9039, -5243, -3799, -2979, -2405, -2064, -1771,
    -1579, -1409, -1279, -1170, -1079, -1004, -933, -880,
    -827, -783, -743, -708, -676, -647, -621, -599,
    -576, -557, -538, -521, -506, -492, -479, -466,
    -456, -445, -435, -426, -417, -410, -402, -395,
    -389, -383, -377, -372, -367, -363, -359, -355,
    -351, -348, -345, -342, -340, -337, -335, -333,
    -331, -330, -329, -328, -327, -326, -326, -326,
    -326, -326, -326, -327, -328, -329, -330, -331,
    -333, -335, -337, -340, -342, -345, -348, -351,
    -355, -359, -363, -367, -372, -377, -383, -389,
    -395, -402, -410, -417, -426, -435, -445, -456,
    -466, -479, -492, -506, -521, -538, -557, -576,
    -599, -621, -647, -676, -708, -743, -783, -827,
    -880, -933, -1004, -1079, -1170, -1279, -1409, -1579,
    -1771, -2064, -2405, -2979, -3799, -5243, -9039, -26214,
];

/// ISF → ISP (`Isf_isp`): `isp[i] = cos(isf[i])` via table interpolation. `isf`/`isp` are Q15,
/// length `m`; the last ISF is doubled before conversion.
pub fn isf_isp(isf: &[i16], isp: &mut [i16], m: usize) {
    isp[..m - 1].copy_from_slice(&isf[..m - 1]);
    isp[m - 1] = shl(isf[m - 1], 1);

    for value in isp.iter_mut().take(m) {
        let ind = shr(*value, 7) as usize; // b7-b15
        let offset = *value & 0x007f; // b0-b6
        // isp = table[ind] + (table[ind+1] - table[ind]) * offset / 128
        let l_tmp = l_mult(sub(TABLE[ind + 1], TABLE[ind]), offset);
        *value = add(TABLE[ind], extract_l(l_shr(l_tmp, 8)));
    }
}

/// ISP → ISF (`Isp_isf`): `isf[i] = acos(isp[i])` via table search + slope interpolation. `isp`/`isf`
/// are Q15, length `m`; the last ISF is halved on output.
pub fn isp_isf(isp: &[i16], isf: &mut [i16], m: usize) {
    let mut ind: i16 = 127;
    for i in (0..m).rev() {
        if (i as i16) >= (m as i16 - 2) {
            ind = 127; // restart the search near the table end for the top two ISPs
        }
        // Find the table entry just greater than isp[i] (table is monotonically decreasing).
        while sub(TABLE[ind as usize], isp[i]) < 0 {
            ind -= 1;
        }
        let l_tmp = l_mult(sub(isp[i], TABLE[ind as usize]), SLOPE[ind as usize]);
        isf[i] = round_word(l_shl(l_tmp, 4));
        isf[i] = add(isf[i], shl(ind, 7));
    }
    isf[m - 1] = shr(isf[m - 1], 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::wb::constants::M;

    #[test]
    fn isf_zero_maps_to_isp_unity() {
        // ISF all 0 → cos(0) = 1.0 → ISP all 0x7FFF (table[0]).
        let mut isp = [0i16; M];
        isf_isp(&[0; M], &mut isp, M);
        assert!(isp.iter().all(|&v| v == 32767));
    }

    #[test]
    fn isp_unity_maps_back_to_isf_zero() {
        // ISP all 1.0 (0x7FFF) → acos(1) = 0 → ISF all 0.
        let mut isf = [0i16; M];
        isp_isf(&[32767; M], &mut isf, M);
        assert!(isf.iter().all(|&v| v == 0));
    }

    #[test]
    fn isf_isp_round_trips_a_realistic_vector() {
        // A monotonically increasing ISF set (Q15), like a dequantized envelope.
        let isf: [i16; M] = [
            500, 1100, 1900, 2800, 3900, 5100, 6400, 7800, 9200, 10500, 11700, 12700, 13500, 14100,
            14600, 7000,
        ];
        let mut isp = [0i16; M];
        isf_isp(&isf, &mut isp, M);
        let mut back = [0i16; M];
        isp_isf(&isp, &mut back, M);
        for (orig, recovered) in isf.iter().zip(back.iter()) {
            assert!(
                (orig - recovered).abs() <= 2,
                "isf {orig} -> isp -> isf {recovered}"
            );
        }
    }
}
