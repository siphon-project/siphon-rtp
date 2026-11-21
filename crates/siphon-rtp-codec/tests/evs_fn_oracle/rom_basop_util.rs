//! `lib_com/rom_basop_util.c` against `fn_rom_basop_util`: the table each accessor selects, compared
//! by content (and, for the sine tables, by identity).

use siphon_rtp_codec::evs::com::rom_basop_util::{basop_get_tables, get_sine_window_table};
use siphon_rtp_codec::evs::rom::types::PWord16;
use siphon_rtp_codec::evs::rom::{SINETABLE320, SINETABLE512};

use crate::common::{corpus, mismatch};

fn flatten(table: &[PWord16]) -> Vec<i16> {
    table.iter().flat_map(|w| [w.v.re, w.v.im]).collect()
}

fn sine_id(table: &[PWord16]) -> i16 {
    if std::ptr::eq(table, &SINETABLE512[..]) {
        512
    } else if std::ptr::eq(table, &SINETABLE320[..]) {
        320
    } else if table.is_empty() {
        0
    } else {
        -1
    }
}

#[test]
fn basop_get_tables_matches_the_reference() {
    let Some(cases) = corpus("rom_basop_util", "basop_get_tables") else {
        return;
    };
    for case in &cases {
        let tables = basop_get_tables(case.i16("length"));
        let sine = sine_id(tables.sin_twiddle);
        if let Some(message) = mismatch(case, "sine", &sine, &case.out_i16("sine")) {
            panic!("{message}");
        }
        let mode = case.i16("mode");
        if mode <= 1 {
            let step = tables.sin_step;
            if let Some(message) = mismatch(case, "step", &step, &case.out_i16("step")) {
                panic!("{message}");
            }
        }
        if mode == 0 {
            let twiddle = flatten(tables.twiddle);
            if let Some(message) = mismatch(case, "twiddle", &twiddle, &case.out_i16s("twiddle")) {
                panic!("{message}");
            }
        }
    }
}

#[test]
fn get_sine_window_table_matches_the_reference() {
    let Some(cases) = corpus("rom_basop_util", "get_sine_window_table") else {
        return;
    };
    for case in &cases {
        let table = get_sine_window_table(case.i16("length")).map_or_else(Vec::new, flatten);
        if let Some(message) = mismatch(case, "table", &table, &case.out_i16s("table")) {
            panic!("{message}");
        }
    }
}
