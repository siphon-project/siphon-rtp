//! Generated from the TS 26.442 `rom_com_fx.c` by `reference/evs/oracle/gen_rom.sh`; do not edit.

#[allow(unused_imports)]
use super::*;

/// `igfMode` (rom_com_fx.c).
pub static IGFMODE: [IgfMode; 15] = [
    IgfMode {
        sample_rate: 16000,
        frame_length: 320,
        bit_rate: 9600,
        igf_min_fq: 774,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 16000,
        frame_length: 320,
        bit_rate: 13200,
        igf_min_fq: 774,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 9600,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 2,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 13200,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 13200,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 2,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 16400,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 24400,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 32000,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 32000,
        frame_length: 640,
        bit_rate: 48000,
        igf_min_fq: 1600,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 16400,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 4,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 24400,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 2,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 32000,
        igf_min_fq: 800,
        trans_fac: 20480,
        max_hopsize: 2,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 48000,
        igf_min_fq: 1600,
        trans_fac: 20480,
        max_hopsize: 2,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 96000,
        igf_min_fq: 1600,
        trans_fac: 8192,
        max_hopsize: 1,
    },
    IgfMode {
        sample_rate: 48000,
        frame_length: 960,
        bit_rate: 128000,
        igf_min_fq: 1600,
        trans_fac: 8192,
        max_hopsize: 1,
    },
];

/// `bwMode2fs` (rom_com_fx.c).
pub static BWMODE2FS: [i32; 4] = [8000, 16000, 32000, 48000];

/// `w1N8` (rom_com_fx.c).
pub static W1N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 32729,
            im: -1608,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32610,
            im: -3212,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32413,
            im: -4808,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32138,
            im: -6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31786,
            im: -7962,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31357,
            im: -9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30853,
            im: -11039,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30274,
            im: -12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29622,
            im: -14010,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28899,
            im: -15447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28106,
            im: -16846,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26320,
            im: -19520,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25330,
            im: -20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24279,
            im: -22006,
        },
    },
];

/// `w2N8` (rom_com_fx.c).
pub static W2N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 32610,
            im: -3212,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32138,
            im: -6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31357,
            im: -9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30274,
            im: -12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28899,
            im: -15447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25330,
            im: -20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23170,
            im: -23170,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 20788,
            im: -25330,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 18205,
            im: -27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 15447,
            im: -28899,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 9512,
            im: -31357,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 3212,
            im: -32610,
        },
    },
];

/// `w3N8` (rom_com_fx.c).
pub static W3N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 32413,
            im: -4808,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31357,
            im: -9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29622,
            im: -14010,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24279,
            im: -22006,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 20788,
            im: -25330,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 16846,
            im: -28106,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 7962,
            im: -31786,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 3212,
            im: -32610,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -1608,
            im: -32729,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -11039,
            im: -30853,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -15447,
            im: -28899,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -19520,
            im: -26320,
        },
    },
];

/// `w4N8` (rom_com_fx.c).
pub static W4N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 32138,
            im: -6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30274,
            im: -12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23170,
            im: -23170,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 18205,
            im: -27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V { re: 0, im: -32768 },
    },
    PWord16 {
        v: PWord16V {
            re: -6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -18205,
            im: -27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -23170,
            im: -23170,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -30274,
            im: -12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32138,
            im: -6393,
        },
    },
];

/// `w5N8` (rom_com_fx.c).
pub static W5N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 31786,
            im: -7962,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28899,
            im: -15447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24279,
            im: -22006,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 18205,
            im: -27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 11039,
            im: -30853,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 3212,
            im: -32610,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -4808,
            im: -32413,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -19520,
            im: -26320,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -25330,
            im: -20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -29622,
            im: -14010,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32138,
            im: -6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32729,
            im: 1608,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -31357,
            im: 9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -28106,
            im: 16846,
        },
    },
];

/// `w6N8` (rom_com_fx.c).
pub static W6N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 31357,
            im: -9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: -18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 20788,
            im: -25330,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 12540,
            im: -30274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 3212,
            im: -32610,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -15447,
            im: -28899,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -23170,
            im: -23170,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -28899,
            im: -15447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32138,
            im: -6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32610,
            im: 3212,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -30274,
            im: 12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -25330,
            im: 20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -18205,
            im: 27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -9512,
            im: 31357,
        },
    },
];

/// `w7N8` (rom_com_fx.c).
pub static W7N8: [PWord16; 15] = [
    PWord16 {
        v: PWord16V {
            re: 30853,
            im: -11039,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25330,
            im: -20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 16846,
            im: -28106,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 6393,
            im: -32138,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -4808,
            im: -32413,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -15447,
            im: -28899,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -24279,
            im: -22006,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -30274,
            im: -12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -32729,
            im: -1608,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -31357,
            im: 9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -26320,
            im: 19520,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -18205,
            im: 27246,
        },
    },
    PWord16 {
        v: PWord16V {
            re: -7962,
            im: 31786,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 3212,
            im: 32610,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 14010,
            im: 29622,
        },
    },
];
