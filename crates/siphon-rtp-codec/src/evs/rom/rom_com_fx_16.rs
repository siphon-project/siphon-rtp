//! Generated from the TS 26.442 `rom_com_fx.c` by `reference/evs/oracle/gen_rom.sh`; do not edit.

#[allow(unused_imports)]
use super::*;

/// `resampling_cfg_tbl_fx` (rom_com_fx.c).
pub static RESAMPLING_CFG_TBL_FX: [ResamplingCfgFx; 21] = [
    ResamplingCfgFx {
        fin_fx: 8000,
        fout_fx: 12800,
        fac_num_fx: 8,
        fac_den_fx: 5,
        lg_out: 256,
        filter_fx: tail(&FILTER5_39S320_120_FX, 0),
        filt_len_fx: 15,
        flags_fx: 32768,
    },
    ResamplingCfgFx {
        fin_fx: 12800,
        fout_fx: 8000,
        fac_num_fx: 5,
        fac_den_fx: 8,
        lg_out: 160,
        filter_fx: tail(&FILTER5_39S320_120_FX, 0),
        filt_len_fx: 24,
        flags_fx: 32768,
    },
    ResamplingCfgFx {
        fin_fx: 16000,
        fout_fx: 8000,
        fac_num_fx: 6,
        fac_den_fx: 12,
        lg_out: 160,
        filter_fx: tail(&FILTER_LP12_180H_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 12800,
        fout_fx: 16000,
        fac_num_fx: 15,
        fac_den_fx: 12,
        lg_out: 320,
        filter_fx: tail(&FILTER_LP15_180H_FX, 0),
        filt_len_fx: 12,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 12800,
        fout_fx: 32000,
        fac_num_fx: 15,
        fac_den_fx: 6,
        lg_out: 640,
        filter_fx: tail(&FILTER_LP15_180H_FX, 0),
        filt_len_fx: 12,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 12800,
        fout_fx: 48000,
        fac_num_fx: 15,
        fac_den_fx: 4,
        lg_out: 960,
        filter_fx: tail(&FILTER_LP15_180H_FX, 0),
        filt_len_fx: 12,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 16000,
        fout_fx: 12800,
        fac_num_fx: 12,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP15_180H_FX, 0),
        filt_len_fx: 15,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 16000,
        fout_fx: 32000,
        fac_num_fx: 12,
        fac_den_fx: 6,
        lg_out: 640,
        filter_fx: tail(&FILTER_LP12_180H_FX, 0),
        filt_len_fx: 15,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 16000,
        fout_fx: 48000,
        fac_num_fx: 12,
        fac_den_fx: 4,
        lg_out: 960,
        filter_fx: tail(&FILTER_LP12_180H_FX, 0),
        filt_len_fx: 15,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 32000,
        fout_fx: 12800,
        fac_num_fx: 6,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP15_180H_13B_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 32000,
        fout_fx: 16000,
        fac_num_fx: 6,
        fac_den_fx: 12,
        lg_out: 320,
        filter_fx: tail(&FILTER_LP12_180H_13B_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 32000,
        fout_fx: 25600,
        fac_num_fx: 12,
        fac_den_fx: 15,
        lg_out: 512,
        filter_fx: tail(&FILTER_LP15_360H_13B_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 32000,
        fout_fx: 48000,
        fac_num_fx: 3,
        fac_den_fx: 2,
        lg_out: 960,
        filter_fx: tail(&FILTER_LP3_90H_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 48000,
        fout_fx: 12800,
        fac_num_fx: 4,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP15_180H_13B_FX, 0),
        filt_len_fx: 45,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 48000,
        fout_fx: 16000,
        fac_num_fx: 4,
        fac_den_fx: 12,
        lg_out: 320,
        filter_fx: tail(&FILTER_LP12_180H_13B_FX, 0),
        filt_len_fx: 45,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 48000,
        fout_fx: 25600,
        fac_num_fx: 8,
        fac_den_fx: 15,
        lg_out: 512,
        filter_fx: tail(&FILTER_LP15_360H_13B_FX, 0),
        filt_len_fx: 45,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 48000,
        fout_fx: 32000,
        fac_num_fx: 2,
        fac_den_fx: 3,
        lg_out: 640,
        filter_fx: tail(&FILTER_LP3_90H_FX, 0),
        filt_len_fx: 45,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 16000,
        fout_fx: 12800,
        fac_num_fx: 12,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP24_90H_FX, 0),
        filt_len_fx: 15,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 32000,
        fout_fx: 12800,
        fac_num_fx: 6,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP24_90H_13B_FX, 0),
        filt_len_fx: 30,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 48000,
        fout_fx: 12800,
        fac_num_fx: 4,
        fac_den_fx: 15,
        lg_out: 256,
        filter_fx: tail(&FILTER_LP24_90H_13B_FX, 0),
        filt_len_fx: 45,
        flags_fx: 0,
    },
    ResamplingCfgFx {
        fin_fx: 0,
        fout_fx: 0,
        fac_num_fx: 0,
        fac_den_fx: 0,
        lg_out: 0,
        filter_fx: &[],
        filt_len_fx: 0,
        flags_fx: 0,
    },
];

/// `lsf_q_cb_fx` (rom_com_fx.c).
pub static LSF_Q_CB_FX: [&[i16]; 5] = [
    tail(&LSF_Q_CB_4B_FX, 0),
    tail(&LSF_Q_CB_4B_FX, 0),
    tail(&LSF_Q_CB_3B_FX, 0),
    tail(&LSF_Q_CB_3B_FX, 0),
    tail(&LSF_Q_CB_3B_FX, 0),
];

/// `xcore_config_8kHz_007200bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_007200BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 13,
    bw: 160,
    band_width: tail(&BAND_WIDTH_160_13_6_2_0_0, 0),
    l_qint: 536870912,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 2,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_008000bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_008000BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 14,
    bw: 160,
    band_width: tail(&BAND_WIDTH_160_14_6_3_0_0, 0),
    l_qint: 536870912,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 2,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_013200bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_013200BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 17,
    bw: 160,
    band_width: tail(&BAND_WIDTH_160_17_6_3_0_0, 0),
    l_qint: 429496730,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 2,
    p2a_th: 24576,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_016400bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_016400BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 18,
    bw: 160,
    band_width: tail(&BAND_WIDTH_160_18_6_4_0_0, 0),
    l_qint: 322122547,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 2,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_007200bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_007200BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 4,
    bw: 40,
    band_width: tail(&BAND_WIDTH_40_4_6_0_0_0, 0),
    l_qint: 966367642,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 2,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 9830,
    ld_slope: 2949,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_008000bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_008000BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 4,
    bw: 40,
    band_width: tail(&BAND_WIDTH_40_4_6_0_0_0, 0),
    l_qint: 1181116006,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 9830,
    ld_slope: 2949,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_013200bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_013200BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 5,
    bw: 40,
    band_width: tail(&BAND_WIDTH_40_5_6_0_0_0, 0),
    l_qint: 751619276,
    eref: 24576,
    bit_alloc_weight: 11469,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 22938,
    ld_slope: 3604,
    ni_coef: 19661,
};

/// `xcore_config_8kHz_016400bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_8KHZ_016400BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 5,
    bw: 40,
    band_width: tail(&BAND_WIDTH_40_5_6_0_0_0, 0),
    l_qint: 536870912,
    eref: 24576,
    bit_alloc_weight: 11469,
    gqlevs: 2,
    ngq: 6,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 22491,
    ld_slope: 3604,
    ni_coef: 19661,
};

/// `xcore_config_16kHz_013200bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_16KHZ_013200BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 18,
    bw: 320,
    band_width: tail(&BAND_WIDTH_320_18_6_3_0_0, 0),
    l_qint: 429496730,
    eref: 24576,
    bit_alloc_weight: 13106,
    gqlevs: 2,
    ngq: 6,
    p2a_bands: 3,
    p2a_th: 24576,
    pd_thresh: 13107,
    ld_slope: 3932,
    ni_coef: 18022,
};

/// `xcore_config_16kHz_016400bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_16KHZ_016400BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 20,
    bw: 320,
    band_width: tail(&BAND_WIDTH_320_20_6_3_0_0, 0),
    l_qint: 429496730,
    eref: 24576,
    bit_alloc_weight: 13106,
    gqlevs: 2,
    ngq: 6,
    p2a_bands: 3,
    p2a_th: 24576,
    pd_thresh: 13107,
    ld_slope: 3932,
    ni_coef: 19660,
};

/// `xcore_config_16kHz_013200bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_16KHZ_013200BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 7,
    bw: 80,
    band_width: tail(&BAND_WIDTH_80_7_6_0_0_0, 0),
    l_qint: 966367642,
    eref: 24576,
    bit_alloc_weight: 9830,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 9830,
    ld_slope: 4258,
    ni_coef: 18022,
};

/// `xcore_config_16kHz_016400bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_16KHZ_016400BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 7,
    bw: 80,
    band_width: tail(&BAND_WIDTH_80_7_6_0_0_0, 0),
    l_qint: 966367642,
    eref: 24576,
    bit_alloc_weight: 11468,
    gqlevs: 2,
    ngq: 8,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 9830,
    ld_slope: 4258,
    ni_coef: 19660,
};

/// `xcore_config_32kHz_013200bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_32KHZ_013200BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 22,
    bw: 568,
    band_width: tail(&BAND_WIDTH_568_22_6_2_0_0, 0),
    l_qint: 322122547,
    eref: 24576,
    bit_alloc_weight: 6554,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 5,
    p2a_th: 28672,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_32kHz_016400bps_long_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_32KHZ_016400BPS_LONG_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 24,
    bw: 640,
    band_width: tail(&BAND_WIDTH_640_24_6_4_0_0, 0),
    l_qint: 322122547,
    eref: 24576,
    bit_alloc_weight: 8192,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 5,
    p2a_th: 28672,
    pd_thresh: 13107,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `xcore_config_32kHz_013200bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_32KHZ_013200BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 8,
    bw: 142,
    band_width: tail(&BAND_WIDTH_142_8_8_0_0_0, 0),
    l_qint: 1610612736,
    eref: 24576,
    bit_alloc_weight: 13107,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 16384,
    ld_slope: 3604,
    ni_coef: 19661,
};

/// `xcore_config_32kHz_016400bps_short_fx` (rom_com_fx.c).
pub static XCORE_CONFIG_32KHZ_016400BPS_SHORT_FX: XcoreConfigFx = XcoreConfigFx {
    bands: 8,
    bw: 160,
    band_width: tail(&BAND_WIDTH_160_8_8_0_0_0, 0),
    l_qint: 644245094,
    eref: 24576,
    bit_alloc_weight: 8192,
    gqlevs: 2,
    ngq: 4,
    p2a_bands: 0,
    p2a_th: 0,
    pd_thresh: 9830,
    ld_slope: 4260,
    ni_coef: 19661,
};

/// `hBitsN` (rom_com_fx.c).
pub static HBITSN: [&[u8]; 65] = [
    tail(&F_LOG2_N, 0),
    tail(&HBITSMINUS1_N01, 0),
    tail(&HBITSMINUS1_N02, 0),
    tail(&HBITSMINUS1_N03, 0),
    tail(&HBITSMINUS1_N04, 0),
    tail(&HBITSMINUS1_N05, 0),
    tail(&HBITSMINUS1_N06, 0),
    tail(&HBITSMINUS1_N07, 0),
    tail(&HBITSMINUS1_N08, 0),
    tail(&HBITSMINUS1_N09, 0),
    tail(&HBITSMINUS1_N10, 0),
    tail(&HBITSMINUS1_N11, 0),
    tail(&HBITSMINUS1_N12, 0),
    tail(&HBITSMINUS1_N13, 0),
    tail(&HBITSMINUS1_N14, 0),
    tail(&HBITSMINUS1_N15, 0),
    tail(&HBITSMINUS1_N16, 0),
    tail(&HBITSMINUS1_N17, 0),
    tail(&HBITSMINUS1_N18, 0),
    tail(&HBITSMINUS1_N19, 0),
    tail(&HBITSMINUS1_N20, 0),
    tail(&HBITSMINUS1_N21, 0),
    tail(&HBITSMINUS1_N22, 0),
    tail(&HBITSMINUS1_N23, 0),
    tail(&HBITSMINUS1_N24, 0),
    tail(&HBITSMINUS1_N25, 0),
    tail(&HBITSMINUS1_N26, 0),
    tail(&HBITSMINUS1_N27, 0),
    tail(&HBITSMINUS1_N28, 0),
    tail(&HBITSMINUS1_N29, 0),
    tail(&HBITSMINUS1_N30, 0),
    tail(&HBITSMINUS1_N31, 0),
    tail(&HBITSMINUS1_N32, 0),
    tail(&HBITSMINUS1_N33, 0),
    tail(&HBITSMINUS1_N34, 0),
    tail(&HBITSMINUS1_N35, 0),
    tail(&HBITSMINUS1_N36, 0),
    tail(&HBITSMINUS1_N37, 0),
    tail(&HBITSMINUS1_N38, 0),
    tail(&HBITSMINUS1_N39, 0),
    tail(&HBITSMINUS1_N40, 0),
    tail(&HBITSMINUS1_N41, 0),
    tail(&HBITSMINUS1_N42, 0),
    tail(&HBITSMINUS1_N43, 0),
    tail(&HBITSMINUS1_N44, 0),
    tail(&HBITSMINUS1_N45, 0),
    tail(&HBITSMINUS1_N46, 0),
    tail(&HBITSMINUS1_N47, 0),
    tail(&HBITSMINUS1_N48, 0),
    tail(&HBITSMINUS1_N49, 0),
    tail(&HBITSMINUS1_N50, 0),
    tail(&HBITSMINUS1_N51, 0),
    tail(&HBITSMINUS1_N52, 0),
    tail(&HBITSMINUS1_N53, 0),
    tail(&HBITSMINUS1_N54, 0),
    tail(&HBITSMINUS1_N55, 0),
    tail(&HBITSMINUS1_N56, 0),
    tail(&HBITSMINUS1_N57, 0),
    tail(&HBITSMINUS1_N58, 0),
    tail(&HBITSMINUS1_N59, 0),
    tail(&HBITSMINUS1_N60, 0),
    tail(&HBITSMINUS1_N61, 0),
    tail(&HBITSMINUS1_N62, 0),
    tail(&HBITSMINUS1_N63, 0),
    tail(&HBITSMINUS1_N64, 0),
];

/// `tcxLtpFilters` (rom_com_fx.c).
pub static TCXLTPFILTERS: [TcxLtpFilter; 12] = [
    TcxLtpFilter {
        filt: tail(&INTER_CORE_12_8KHZ_OUTPUT_8KHZ, 0),
        length: 2,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_12_8KHZ_OUTPUT_16KHZ, 0),
        length: 3,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_12_8KHZ_OUTPUT_32KHZ, 0),
        length: 5,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_12_8KHZ_OUTPUT_48KHZ, 0),
        length: 8,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_16KHZ_OUTPUT_8KHZ, 0),
        length: 2,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_16KHZ_OUTPUT_16KHZ, 0),
        length: 2,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_16KHZ_OUTPUT_32KHZ, 0),
        length: 4,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_16KHZ_OUTPUT_48KHZ, 0),
        length: 6,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_25_6KHZ_OUTPUT_8KHZ, 0),
        length: 2,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_25_6KHZ_OUTPUT_16KHZ, 0),
        length: 2,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_25_6KHZ_OUTPUT_32KHZ, 0),
        length: 3,
    },
    TcxLtpFilter {
        filt: tail(&INTER_CORE_25_6KHZ_OUTPUT_48KHZ, 0),
        length: 4,
    },
];

/// `FdCngSetup_nb` (rom_com_fx.c).
pub static FDCNGSETUP_NB: FdCngSetup = FdCngSetup {
    fftlen: 512,
    stop_fftbin: 160,
    num_partitions: 17,
    sid_partitions: tail(&SIDPARTITIONS_NB, 0),
    num_shaping_partitions: 34,
    shaping_partitions: tail(&SHAPINGPARTITIONS_NB, 0),
};

/// `FdCngSetup_wb1` (rom_com_fx.c).
pub static FDCNGSETUP_WB1: FdCngSetup = FdCngSetup {
    fftlen: 512,
    stop_fftbin: 256,
    num_partitions: 20,
    sid_partitions: tail(&SIDPARTITIONS_WB1, 0),
    num_shaping_partitions: 40,
    shaping_partitions: tail(&SHAPINGPARTITIONS_WB1, 0),
};

/// `FdCngSetup_wb2` (rom_com_fx.c).
pub static FDCNGSETUP_WB2: FdCngSetup = FdCngSetup {
    fftlen: 512,
    stop_fftbin: 256,
    num_partitions: 21,
    sid_partitions: tail(&SIDPARTITIONS_WB2, 0),
    num_shaping_partitions: 40,
    shaping_partitions: tail(&SHAPINGPARTITIONS_WB2, 0),
};

/// `FdCngSetup_wb3` (rom_com_fx.c).
pub static FDCNGSETUP_WB3: FdCngSetup = FdCngSetup {
    fftlen: 640,
    stop_fftbin: 320,
    num_partitions: 21,
    sid_partitions: tail(&SIDPARTITIONS_WB3, 0),
    num_shaping_partitions: 39,
    shaping_partitions: tail(&SHAPINGPARTITIONS_WB3, 0),
};

/// `FdCngSetup_swb1` (rom_com_fx.c).
pub static FDCNGSETUP_SWB1: FdCngSetup = FdCngSetup {
    fftlen: 512,
    stop_fftbin: 256,
    num_partitions: 24,
    sid_partitions: tail(&SIDPARTITIONS_SWB1, 0),
    num_shaping_partitions: 40,
    shaping_partitions: tail(&SHAPINGPARTITIONS_SWB1, 0),
};

/// `FdCngSetup_swb2` (rom_com_fx.c).
pub static FDCNGSETUP_SWB2: FdCngSetup = FdCngSetup {
    fftlen: 640,
    stop_fftbin: 320,
    num_partitions: 24,
    sid_partitions: tail(&SIDPARTITIONS_SWB2, 0),
    num_shaping_partitions: 39,
    shaping_partitions: tail(&SHAPINGPARTITIONS_SWB2, 0),
};

/// `cdk_37bits` (rom_com_fx.c).
pub static CDK_37BITS: [&[i16]; 6] = [
    tail(&CDK_37BITS_1_FX, 0),
    tail(&CDK_37BITS_2_FX, 0),
    tail(&CDK_37BITS_3_FX, 0),
    tail(&CDK_37BITS_4_FX, 0),
    tail(&CDK_37BITS_5_FX, 0),
    tail(&CDK_37BITS_6_FX, 0),
];

/// `Ratios` (rom_com_fx.c).
pub static RATIOS: [[&[i16]; 17]; 2] = [
    [
        tail(&RATIOS_NB_2, 0),
        tail(&RATIOS_NB_3, 0),
        tail(&RATIOS_NB_4, 0),
        tail(&RATIOS_NB_5, 0),
        tail(&RATIOS_NB_6, 0),
        tail(&RATIOS_NB_7, 0),
        tail(&RATIOS_NB_8, 0),
        tail(&RATIOS_NB_9, 0),
        tail(&RATIOS_NB_10, 0),
        tail(&RATIOS_NB_11, 0),
        tail(&RATIOS_NB_12, 0),
        tail(&RATIOS_NB_13, 0),
        tail(&RATIOS_NB_14, 0),
        tail(&RATIOS_NB_15, 0),
        tail(&RATIOS_NB_16, 0),
        tail(&RATIOS_NB_17, 0),
        tail(&RATIOS_NB_18, 0),
    ],
    [
        tail(&RATIOS_WB_2, 0),
        tail(&RATIOS_WB_3, 0),
        tail(&RATIOS_WB_4, 0),
        tail(&RATIOS_WB_5, 0),
        tail(&RATIOS_WB_6, 0),
        tail(&RATIOS_WB_7, 0),
        tail(&RATIOS_WB_8, 0),
        tail(&RATIOS_WB_9, 0),
        tail(&RATIOS_WB_10, 0),
        tail(&RATIOS_WB_11, 0),
        tail(&RATIOS_WB_12, 0),
        tail(&RATIOS_WB_13, 0),
        tail(&RATIOS_WB_14, 0),
        tail(&RATIOS_WB_15, 0),
        tail(&RATIOS_WB_16, 0),
        tail(&RATIOS_WB_17, 0),
        tail(&RATIOS_WB_18, 0),
    ],
];

/// `lsf_codebook` (rom_com_fx.c).
pub static LSF_CODEBOOK: [[[&[i16]; 3]; 2]; 2] = [
    [
        [
            tail(&LSF_CDK_WB_GC_STG1, 0),
            tail(&LSF_CDK_WB_GC_STG2, 0),
            tail(&LSF_CDK_WB_GC_STG3, 0),
        ],
        [
            tail(&LSF_CDK_WB_VC_STG1, 0),
            tail(&LSF_CDK_WB_VC_STG2, 0),
            tail(&LSF_CDK_WB_VC_STG3, 0),
        ],
    ],
    [
        [
            tail(&LSF_CDK_NB_GC_STG1, 0),
            tail(&LSF_CDK_NB_GC_STG2, 0),
            tail(&LSF_CDK_NB_GC_STG3, 0),
        ],
        [
            tail(&LSF_CDK_NB_VC_STG1, 0),
            tail(&LSF_CDK_NB_VC_STG2, 0),
            tail(&LSF_CDK_NB_VC_STG3, 0),
        ],
    ],
];

/// `lsf_ind_codebook` (rom_com_fx.c).
pub static LSF_IND_CODEBOOK: [[[&[i16]; 1]; 2]; 2] = [
    [
        [tail(&LSF_IND_CDK_WB_GC_STG4, 0)],
        [tail(&LSF_IND_CDK_WB_VC_STG4, 0)],
    ],
    [
        [tail(&LSF_IND_CDK_NB_GC_STG4, 0)],
        [tail(&LSF_IND_CDK_NB_VC_STG4, 0)],
    ],
];

/// `f_log2_n` (rom_com_fx.c).
pub static F_LOG2_N: [u8; 65] = [
    255, 255, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1,
];

/// `finegain_fx` (rom_com_fx.c).
pub static FINEGAIN_FX: [&[i16]; 5] = [
    tail(&FINEGAIN_1_FX, 0),
    tail(&FINEGAIN_2_FX, 0),
    tail(&FINEGAIN_3_FX, 0),
    tail(&FINEGAIN_4_FX, 0),
    tail(&FINEGAIN_5_FX, 0),
];

/// `lsf_means` (rom_com_fx.c).
pub static LSF_MEANS: [&[i16]; 2] = [
    tail(&MEANS_WB_31BITS_MA_LSF, 0),
    tail(&MEANS_NB_31BITS_MA_LSF, 0),
];

/// `codesTnsCoeffSWBTCX20` (rom_com_fx.c).
pub static CODESTNSCOEFFSWBTCX20: [&[Coding]; 8] = [
    tail(&CODESTNSCOEFF0TCX20, 0),
    tail(&CODESTNSCOEFF1TCX20, 0),
    tail(&CODESTNSCOEFF2TCX20, 0),
    tail(&CODESTNSCOEFF3TCX20, 0),
    tail(&CODESTNSCOEFF4TCX20, 0),
    tail(&CODESTNSCOEFF5, 0),
    tail(&CODESTNSCOEFF6, 0),
    tail(&CODESTNSCOEFF7, 0),
];

/// `codesTnsCoeffSWBTCX10` (rom_com_fx.c).
pub static CODESTNSCOEFFSWBTCX10: [&[Coding]; 8] = [
    tail(&CODESTNSCOEFF0TCX10, 0),
    tail(&CODESTNSCOEFF1TCX10, 0),
    tail(&CODESTNSCOEFF2TCX10, 0),
    tail(&CODESTNSCOEFF3TCX10, 0),
    tail(&CODESTNSCOEFF4TCX10, 0),
    tail(&CODESTNSCOEFF5, 0),
    tail(&CODESTNSCOEFF6, 0),
    tail(&CODESTNSCOEFF7, 0),
];

/// `codesTnsCoeffWBTCX20` (rom_com_fx.c).
pub static CODESTNSCOEFFWBTCX20: [&[Coding]; 8] = [
    tail(&CODESTNSCOEFF0WBTCX20, 0),
    tail(&CODESTNSCOEFF1WBTCX20, 0),
    tail(&CODESTNSCOEFF2WB, 0),
    tail(&CODESTNSCOEFF3WB, 0),
    tail(&CODESTNSCOEFF456, 0),
    tail(&CODESTNSCOEFF456, 0),
    tail(&CODESTNSCOEFF456, 0),
    tail(&CODESTNSCOEFF7, 0),
];

/// `cldfb_protoFilter_2_5ms` (rom_com_fx.c).
pub static CLDFB_PROTOFILTER_2_5MS: [&[i16]; 6] = [
    tail(&CLDFB80_10, 0),
    tail(&CLDFB80_16, 0),
    tail(&CLDFB80_20, 0),
    tail(&CLDFB80_32, 0),
    tail(&CLDFB80_40, 0),
    tail(&CLDFB80_60, 0),
];

/// `w_a` (rom_com_fx.c).
pub static W_A: [&[PWord16]; 7] = [
    tail(&W1N8, 0),
    tail(&W2N8, 0),
    tail(&W3N8, 0),
    tail(&W4N8, 0),
    tail(&W5N8, 0),
    tail(&W6N8, 0),
    tail(&W7N8, 0),
];
