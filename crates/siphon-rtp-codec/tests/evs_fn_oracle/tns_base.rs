//! `lib_com/tns_base.c` against `fn_tns_base` (`InitTnsConfiguration`).

use siphon_rtp_codec::evs::com::tns_base::init_tns_configuration;
use siphon_rtp_codec::evs::dec::state::{STnsConfig, TnsParameters};
use siphon_rtp_codec::evs::rom::{
    TNSPARAMETERS16KHZ, TNSPARAMETERS16KHZ_GROUPED, TNSPARAMETERS32KHZ, TNSPARAMETERS32KHZ_GROUPED,
    TNSPARAMETERS48KHZ_GROUPED, TNSPARAMETERSIGF32KHZ_LOWBR,
};

use crate::common::{corpus, mismatch};

/// The TNS parameter tables in the oracle's numbering.
fn tables() -> [&'static [TnsParameters]; 6] {
    [
        &TNSPARAMETERSIGF32KHZ_LOWBR,
        &TNSPARAMETERS32KHZ,
        &TNSPARAMETERS32KHZ_GROUPED,
        &TNSPARAMETERS16KHZ,
        &TNSPARAMETERS16KHZ_GROUPED,
        &TNSPARAMETERS48KHZ_GROUPED,
    ]
}

/// The oracle's number of a TNS parameter table (`-1` = none of them, NULL included).
pub fn table_id(table: &'static [TnsParameters]) -> i16 {
    tables()
        .iter()
        .position(|t| !table.is_empty() && std::ptr::eq(t.as_ptr(), table.as_ptr()))
        .map_or(-1, |i| i as i16)
}

/// The table the oracle numbers `id` (empty, NULL, for -1).
pub fn table_from_id(id: i16) -> &'static [TnsParameters] {
    usize::try_from(id).ok().map_or(&[], |id| tables()[id])
}

#[test]
fn init_tns_configuration_matches_the_reference() {
    let Some(cases) = corpus("tns_base", "init_tns_configuration") else {
        return;
    };
    for case in &cases {
        let mut config = STnsConfig::zeroed();
        config
            .i_filter_borders
            .copy_from_slice(&case.i16s("borders"));
        let result = init_tns_configuration(
            case.i32("sr"),
            case.i16("frame_length"),
            &mut config,
            case.i16("igf_stop_freq"),
            case.i32("bitrate"),
        );
        let rust = vec![
            i16::from(result.is_err()),
            config.max_order,
            config.n_max_filters,
            table_id(config.p_tns_parameters),
            config.i_filter_borders[0],
            config.i_filter_borders[1],
            config.i_filter_borders[2],
        ];
        let mut reference = vec![
            case.out_i16("err"),
            case.out_i16("c_max_order"),
            case.out_i16("c_n_max_filters"),
            case.out_i16("c_table"),
        ];
        reference.extend(case.out_i16s("c_borders"));
        if let Some(message) = mismatch(case, "config", &rust, &reference) {
            panic!("{message}");
        }
    }
}
