//! Accessors over the BASOP sine and twiddle tables (TS 26.442 `lib_com/rom_basop_util.c`). The
//! tables themselves are generated into [`crate::evs::rom`]; only the two lookup functions live here.

use crate::evs::rom::types::PWord16;
use crate::evs::rom::{
    SINETABLE320, SINETABLE512, SINEWINDOW10, SINEWINDOW112, SINEWINDOW120, SINEWINDOW140,
    SINEWINDOW16, SINEWINDOW180, SINEWINDOW20, SINEWINDOW224, SINEWINDOW280, SINEWINDOW30,
    SINEWINDOW32, SINEWINDOW40, SINEWINDOW420, SINEWINDOW48, SINEWINDOW60, SINEWINDOW70,
    SINEWINDOW96, WINDOWSLOPES,
};
use crate::itu::basic_ops::{norm_s, shl, sub};
use crate::itu::stl2009::lshl;

/// `DCTIV_SINETABLE_SIZE_LD`: ld of the radix-2 sine table's quarter period (512).
const DCTIV_SINETABLE_SIZE_LD: i16 = 9;
/// `DCTIV_SINETABLE320_SIZE_LD`: the same for the 640-raster table (320).
const DCTIV_SINETABLE320_SIZE_LD: i16 = 8;

/// The tables [`basop_get_tables`] selects for one transform length.
#[derive(Debug, Clone, Copy)]
pub struct BasopTables {
    /// `*ptwiddle`: the sine window slope for the length (empty where the C has `NULL`).
    pub twiddle: &'static [PWord16],
    /// `*sin_twiddle`: the quarter-period sine table (empty where the C has `NULL`).
    pub sin_twiddle: &'static [PWord16],
    /// `*psin_step`: the stride into `sin_twiddle` for this length (0 where unsupported).
    pub sin_step: i16,
}

/// `BASOP_getTables`: the window slope, sine table and sine stride for a transform of `length`
/// (a power of two, or a power of two times five on the 640 raster).
///
/// The C returns each through an optional out-pointer; here all three come back together and a
/// caller takes the ones it asked for. A length off both rasters gets the C's `default` branch
/// (empty tables, step 0). Where the reference would index `windowSlopes` out of bounds (a length
/// below 4 or above the tables) an empty slice is returned instead; no decoder call site does this.
#[must_use]
pub fn basop_get_tables(length: i16) -> BasopTables {
    // ld2 of length - 2 + 1: -2 because the first table entry is the window of size 4, +1 because
    // ceil(log2(length)) is already included.
    let ld2_length = sub(16 - 1 - 1, norm_s(length));
    // The "eigenvalue" (the five leftmost bits) of the length.
    let eigen = lshl(length, sub(15, ld2_length)) as u16;
    let slope = |raster: usize, index: i16| -> &'static [PWord16] {
        usize::try_from(index)
            .ok()
            .and_then(|index| WINDOWSLOPES[0][raster].get(index))
            .copied()
            .unwrap_or(&[])
    };
    match eigen {
        // 640
        0xa000 => BasopTables {
            twiddle: slope(1, sub(ld2_length, 1)),
            sin_twiddle: &SINETABLE320,
            sin_step: shl(1, sub(DCTIV_SINETABLE320_SIZE_LD + 1, ld2_length)),
        },
        // radix 2
        0x8000 => BasopTables {
            twiddle: slope(0, sub(ld2_length, 2)),
            sin_twiddle: &SINETABLE512,
            sin_step: shl(1, sub(DCTIV_SINETABLE_SIZE_LD + 1, ld2_length)),
        },
        // "not instrumented, probably obsolete"
        _ => BasopTables {
            twiddle: &[],
            sin_twiddle: &[],
            sin_step: 0,
        },
    }
}

/// `getSineWindowTable`: the sine window slope of `length`, or `None` for a length the reference
/// has no table for (the C returns `NULL` and asserts).
#[must_use]
pub fn get_sine_window_table(length: i16) -> Option<&'static [PWord16]> {
    let table: &'static [PWord16] = match length {
        10 => &SINEWINDOW10,
        16 => &SINEWINDOW16,
        20 => &SINEWINDOW20,
        30 => &SINEWINDOW30,
        32 => &SINEWINDOW32,
        40 => &SINEWINDOW40,
        48 => &SINEWINDOW48,
        60 => &SINEWINDOW60,
        70 => &SINEWINDOW70,
        96 => &SINEWINDOW96,
        112 => &SINEWINDOW112,
        120 => &SINEWINDOW120,
        140 => &SINEWINDOW140,
        180 => &SINEWINDOW180,
        224 => &SINEWINDOW224,
        280 => &SINEWINDOW280,
        420 => &SINEWINDOW420,
        _ => return None,
    };
    Some(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::rom::{SINEWINDOW160, SINEWINDOW256, SINEWINDOW320};

    #[test]
    fn radix_two_lengths_select_the_512_sine_table() {
        let tables = basop_get_tables(256);
        assert!(std::ptr::eq(tables.twiddle, &SINEWINDOW256[..]));
        assert!(std::ptr::eq(tables.sin_twiddle, &SINETABLE512[..]));
        assert_eq!(tables.sin_step, 4);
        assert_eq!(basop_get_tables(512).sin_step, 2);
    }

    #[test]
    fn the_640_raster_selects_the_320_sine_table() {
        let tables = basop_get_tables(320);
        assert!(std::ptr::eq(tables.twiddle, &SINEWINDOW320[..]));
        assert!(std::ptr::eq(tables.sin_twiddle, &SINETABLE320[..]));
        assert_eq!(tables.sin_step, 2);
        assert!(std::ptr::eq(
            basop_get_tables(160).twiddle,
            &SINEWINDOW160[..]
        ));
        // 640 would index windowSlopes[0][1][8], one past the table, in the C; only its sine table
        // and step are ever asked for at that length (BASOP_rfft passes ptwiddle = NULL).
        let tables = basop_get_tables(640);
        assert!(tables.twiddle.is_empty());
        assert_eq!(tables.sin_step, 1);
    }

    #[test]
    fn lengths_off_both_rasters_get_no_tables() {
        for length in [0, 3, 96, 600] {
            let tables = basop_get_tables(length);
            assert!(tables.twiddle.is_empty() && tables.sin_twiddle.is_empty());
            assert_eq!(tables.sin_step, 0);
        }
        // Below the smallest slope the reference would index before the table; we return empty.
        assert!(basop_get_tables(2).twiddle.is_empty());
    }

    #[test]
    fn sine_window_lookup_covers_exactly_the_reference_lengths() {
        assert_eq!(get_sine_window_table(10).map(<[_]>::len), Some(5));
        assert_eq!(get_sine_window_table(420).map(<[_]>::len), Some(210));
        assert!(get_sine_window_table(64).is_none());
    }
}
