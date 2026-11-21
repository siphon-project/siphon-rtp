//! A walk over every field of the decoder state, for oracles that compare the whole state.
//!
//! The `visit_*` functions below are generated, together with the `rd_dump_*` / `rd_fill_*`
//! functions of `reference/evs/oracle/fn/init_dec.c`, by one gdb walk over the reference's debug
//! info for `Decoder_State_fx` (field names by the rules of `oracle/state_export.py`), so both
//! sides list the same fields in the same order under the same keys (the C field paths).
//! Regenerate both together whenever `gen_state.sh` changes the state.
//! A [`StateVisitor`] either dumps the state as the oracle prints it, fills every integer field
//! with the oracle's deterministic pattern, or loads a state the oracle printed.
//!
//! Pointers: a ROM table is compared on its first entries (it is not loaded: init sets it, and the
//! init oracle proves that); a pointer into the state's own arrays is an offset (or a row index),
//! -1 for NULL; an owned buffer (`Vec`) is compared and loaded in full.

// The generated walks index arrays by position because the index is part of each field key.
#![allow(clippy::too_many_lines, clippy::needless_range_loop, dead_code)]

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::state::*;
use siphon_rtp_codec::evs::rom::types::{PWord16, TnsParameters};

use crate::tns_base::{table_from_id, table_id};

/// The oracle's `rd_pattern_next`: an LCG in [-16384, 16383].
#[derive(Debug, Clone, Copy)]
pub struct Pattern(pub u32);

impl Pattern {
    fn next(&mut self) -> i32 {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12345);
        ((self.0 >> 16) & 0x7fff) as i32 - 16384
    }
}

/// An integer field (or nested array of them) as the oracle prints it.
pub trait Leaf {
    fn put(&self, out: &mut Vec<i64>);
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>);
    fn fill(&mut self, pattern: &mut Pattern);
}

macro_rules! leaf {
    ($($t:ty => $fill:expr),*) => {$(
        impl Leaf for $t {
            fn put(&self, out: &mut Vec<i64>) {
                out.push(i64::from(*self));
            }
            fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
                *self = *values.next().expect("enough values") as $t;
            }
            #[allow(clippy::redundant_closure_call)]
            fn fill(&mut self, pattern: &mut Pattern) {
                *self = ($fill)(pattern.next());
            }
        }
    )*};
}
leaf!(
    i8 => |v: i32| v as i8,
    u8 => |v: i32| v as u8,
    i16 => |v: i32| v as i16,
    u16 => |v: i32| v as u16,
    i32 => |v: i32| v.wrapping_mul(65537),
    u32 => |v: i32| v.wrapping_mul(65537) as u32
);

impl<T: Leaf, const N: usize> Leaf for [T; N] {
    fn put(&self, out: &mut Vec<i64>) {
        for x in self {
            x.put(out);
        }
    }
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
        for x in self {
            x.take(values);
        }
    }
    fn fill(&mut self, pattern: &mut Pattern) {
        for x in self {
            x.fill(pattern);
        }
    }
}

impl Leaf for PWord16 {
    fn put(&self, out: &mut Vec<i64>) {
        self.v.re.put(out);
        self.v.im.put(out);
    }
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
        self.v.re.take(values);
        self.v.im.take(values);
    }
    fn fill(&mut self, pattern: &mut Pattern) {
        self.v.re.fill(pattern);
        self.v.im.fill(pattern);
    }
}

/// What a walk does at each field.
pub enum Mode<'a> {
    /// Collect `(key, values)` in walk order.
    Dump(Vec<(String, Vec<i64>)>),
    /// Fill every integer field from the pattern.
    Fill(Pattern),
    /// Load every field from an oracle dump.
    Load(&'a BTreeMap<String, Vec<i64>>),
}

pub struct StateVisitor<'a> {
    pub mode: Mode<'a>,
    /// Keys of ROM pointers: the oracle prints a fixed number of entries, reading past the end of
    /// a short table, so these compare as a prefix (empty only against NULL).
    pub rom_keys: std::collections::BTreeSet<String>,
}

impl StateVisitor<'_> {
    fn loaded(&self, key: &str) -> Option<&[i64]> {
        match &self.mode {
            Mode::Load(map) => Some(
                map.get(key)
                    .unwrap_or_else(|| panic!("no {key} in the oracle dump")),
            ),
            _ => None,
        }
    }

    fn push(&mut self, key: String, values: Vec<i64>) {
        if let Mode::Dump(out) = &mut self.mode {
            out.push((key, values));
        }
    }

    fn leaf_inner<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T, fill: bool) {
        let key = format!("{pre}{name}");
        match &mut self.mode {
            Mode::Dump(out) => {
                let mut values = Vec::new();
                x.put(&mut values);
                out.push((key, values));
            }
            Mode::Fill(pattern) => {
                if fill {
                    x.fill(pattern);
                }
            }
            Mode::Load(map) => {
                let values = map
                    .get(&key)
                    .unwrap_or_else(|| panic!("no {key} in the oracle dump"));
                let mut it = values.iter();
                x.take(&mut it);
                assert!(it.next().is_none(), "{key}: too many values");
            }
        }
    }

    pub fn leaf<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T) {
        self.leaf_inner(pre, name, x, true);
    }

    /// A field the pattern fill leaves alone (an input set before the call).
    pub fn leaf_no_fill<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T) {
        self.leaf_inner(pre, name, x, false);
    }

    pub fn rom16(&mut self, pre: &str, name: &str, table: &'static [i16]) {
        let values = table.iter().take(8).map(|&v| i64::from(v)).collect();
        self.rom_keys.insert(format!("{pre}{name}"));
        self.push(format!("{pre}{name}"), values);
    }

    pub fn romp16(&mut self, pre: &str, name: &str, table: &'static [PWord16]) {
        let mut values = Vec::new();
        for x in table.iter().take(8) {
            x.put(&mut values);
        }
        self.rom_keys.insert(format!("{pre}{name}"));
        self.push(format!("{pre}{name}"), values);
    }

    pub fn tns(&mut self, pre: &str, name: &str, table: &mut &'static [TnsParameters]) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *table = table_from_id(values[0] as i16);
        } else {
            self.push(key, vec![i64::from(table_id(table))]);
        }
    }

    pub fn tns_pointer(&mut self, pre: &str, name: &str, pointer: &mut Option<(usize, usize)>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *pointer = usize::try_from(values[0]).ok().map(|i| (i / 2, i % 2));
        } else {
            let value = pointer.map_or(-1, |(i, j)| (i * 2 + j) as i64);
            self.push(key, vec![value]);
        }
    }

    pub fn offset(&mut self, pre: &str, name: &str, offset: &mut usize) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *offset = usize::try_from(values[0]).expect("an offset");
        } else {
            self.push(key, vec![*offset as i64]);
        }
    }

    pub fn offset_opt(&mut self, pre: &str, name: &str, offset: &mut Option<usize>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *offset = usize::try_from(values[0]).ok();
        } else {
            self.push(key, vec![offset.map_or(-1, |o| o as i64)]);
        }
    }

    pub fn vec16(&mut self, pre: &str, name: &str, buffer: &mut Vec<i16>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            buffer.clear();
            buffer.extend(values.iter().map(|&v| v as i16));
        } else {
            let values = buffer.iter().map(|&v| i64::from(v)).collect();
            self.push(key, values);
        }
    }

    pub fn handle<'h, T>(
        &mut self,
        pre: &str,
        name: &str,
        handle: &'h mut Option<Box<T>>,
    ) -> Option<&'h mut T> {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            assert_eq!(
                values[0] != 0,
                handle.is_some(),
                "{key}: handle presence differs from the dump"
            );
        } else {
            self.push(key, vec![i64::from(handle.is_some())]);
        }
        handle.as_deref_mut()
    }
}

/// The whole state as the oracle prints it, keyed `st.<C path>`.
pub fn dump(st: &mut DecoderState) -> Vec<(String, Vec<i64>)> {
    let mut v = StateVisitor {
        mode: Mode::Dump(Vec::new()),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, "st.", st);
    match v.mode {
        Mode::Dump(out) => out,
        _ => unreachable!(),
    }
}

/// Fill every integer field with the oracle's pattern from `seed`, as `rd_fill_DecoderState`.
pub fn fill(st: &mut DecoderState, seed: u32) {
    let mut v = StateVisitor {
        mode: Mode::Fill(Pattern(seed)),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, "st.", st);
}

/// Load a state the oracle printed with prefix `pre` (handles must already exist).
pub fn load(st: &mut DecoderState, side: &BTreeMap<String, Vec<i64>>, pre: &str) {
    let mut v = StateVisitor {
        mode: Mode::Load(side),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, pre, st);
}

/// Compare the whole state with an oracle dump printed with prefix `pre`; panics listing the
/// first differing fields (and any field one side has and the other lacks).
pub fn check(st: &mut DecoderState, side: &BTreeMap<String, Vec<i64>>, pre: &str, context: &str) {
    let mut v = StateVisitor {
        mode: Mode::Dump(Vec::new()),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, pre, st);
    let rom_keys = v.rom_keys;
    let Mode::Dump(rust) = v.mode else {
        unreachable!()
    };
    let mut differences = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (key, values) in &rust {
        seen.insert(key.as_str());
        match side.get(key) {
            None => differences.push(format!("{key}: missing from the oracle dump")),
            Some(reference)
                if rom_keys.contains(key)
                    && reference.starts_with(values)
                    && values.is_empty() == reference.is_empty() => {}
            Some(reference) if reference != values => {
                let first = values
                    .iter()
                    .zip(reference)
                    .position(|(a, b)| a != b)
                    .unwrap_or(values.len().min(reference.len()));
                differences.push(format!(
                    "{key}: first difference at [{first}] (len rust {} ref {}): rust {:?} ref {:?}",
                    values.len(),
                    reference.len(),
                    values.get(first..(first + 8).min(values.len())),
                    reference.get(first..(first + 8).min(reference.len())),
                ));
            }
            Some(_) => {}
        }
    }
    for key in side.keys() {
        if key.starts_with(pre) && !seen.contains(key.as_str()) {
            differences.push(format!("{key}: in the oracle dump, not in the Rust walk"));
        }
    }
    assert!(
        differences.is_empty(),
        "{context}: {} fields differ:\n  {}",
        differences.len(),
        differences
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

// ---------------- generated ----------------

#[allow(clippy::too_many_lines)]
fn visit_disp_mem(v: &mut StateVisitor, pre: &str, p: &mut DispMem) {
    v.leaf(pre, "prev_state", &mut p.prev_state);
    v.leaf(pre, "prev_gain_code", &mut p.prev_gain_code);
    v.leaf(pre, "prev_gain_pit", &mut p.prev_gain_pit);
}

#[allow(clippy::too_many_lines)]
fn visit_cldfb_filter_bank(v: &mut StateVisitor, pre: &str, p: &mut CldfbFilterBank) {
    v.rom16(pre, "p_filter", p.p_filter);
    v.vec16(pre, "FilterStates", &mut p.filter_states);
    v.leaf(pre, "FilterStates_e", &mut p.filter_states_e);
    v.leaf(pre, "FilterStates_eg", &mut p.filter_states_eg);
    v.leaf(pre, "p_filter_length", &mut p.p_filter_length);
    v.rom16(pre, "rRotVctr", p.r_rot_vctr);
    v.rom16(pre, "iRotVctr", p.i_rot_vctr);
    v.leaf(pre, "filterScale", &mut p.filter_scale);
    v.leaf(pre, "synGain", &mut p.syn_gain);
    v.leaf(pre, "no_channels", &mut p.no_channels);
    v.leaf(pre, "no_col", &mut p.no_col);
    v.leaf(pre, "lsb", &mut p.lsb);
    v.leaf(pre, "usb", &mut p.usb);
    v.leaf(pre, "zeros", &mut p.zeros);
    v.leaf(pre, "anaScalefactor", &mut p.ana_scalefactor);
    v.leaf(pre, "synScalefactor", &mut p.syn_scalefactor);
    v.leaf(pre, "outScalefactor", &mut p.out_scalefactor);
    v.leaf(pre, "synFilterHeadroom", &mut p.syn_filter_headroom);
    v.leaf(pre, "flags", &mut p.flags);
    v.leaf(pre, "bandsToZero", &mut p.bands_to_zero);
    v.leaf(pre, "filtermode", &mut p.filtermode);
    v.leaf(pre, "type", &mut p.r#type);
    v.vec16(pre, "memory", &mut p.memory);
    v.leaf(pre, "memory_length", &mut p.memory_length);
    v.leaf(pre, "scale", &mut p.scale);
}

#[allow(clippy::too_many_lines)]
fn visit_fd_cng_com(v: &mut StateVisitor, pre: &str, p: &mut FdCngCom) {
    {
        let b = format!("{pre}FdCngSetup.");
        let s = &mut p.fd_cng_setup;
        v.leaf(&b, "fftlen", &mut s.fftlen);
        v.leaf(&b, "stopFFTbin", &mut s.stop_fftbin);
        v.leaf(&b, "numPartitions", &mut s.num_partitions);
        v.rom16(&b, "sidPartitions", s.sid_partitions);
        v.leaf(&b, "numShapingPartitions", &mut s.num_shaping_partitions);
        v.rom16(&b, "shapingPartitions", s.shaping_partitions);
    }
    v.leaf(pre, "numSlots", &mut p.num_slots);
    v.leaf(pre, "regularStopBand", &mut p.regular_stop_band);
    v.leaf(pre, "numCoreBands", &mut p.num_core_bands);
    v.leaf(pre, "stopBand", &mut p.stop_band);
    v.leaf(pre, "startBand", &mut p.start_band);
    v.leaf(pre, "stopFFTbin", &mut p.stop_ff_tbin);
    v.leaf(pre, "frameSize", &mut p.frame_size);
    v.leaf(pre, "fftlen", &mut p.fftlen);
    v.leaf(pre, "fftlenShift", &mut p.fftlen_shift);
    v.leaf(pre, "fftlenFac", &mut p.fftlen_fac);
    v.leaf(pre, "timeDomainBuffer", &mut p.time_domain_buffer);
    v.leaf(pre, "fftBuffer", &mut p.fft_buffer);
    v.offset_opt(pre, "olapBufferAna", &mut p.olap_buffer_ana);
    v.leaf(pre, "olapBufferSynth", &mut p.olap_buffer_synth);
    v.offset_opt(pre, "olapBufferSynth2", &mut p.olap_buffer_synth2);
    v.romp16(pre, "olapWinAna", p.olap_win_ana);
    v.romp16(pre, "olapWinSyn", p.olap_win_syn);
    v.leaf(pre, "msM_win", &mut p.ms_m_win);
    v.leaf(pre, "msM_subwin", &mut p.ms_m_subwin);
    v.leaf(pre, "msFrCnt_init_counter", &mut p.ms_fr_cnt_init_counter);
    v.leaf(pre, "init_old", &mut p.init_old);
    v.leaf(pre, "msFrCnt_init_thresh", &mut p.ms_fr_cnt_init_thresh);
    v.leaf(pre, "msFrCnt", &mut p.ms_fr_cnt);
    v.leaf(pre, "msAlphaCor", &mut p.ms_alpha_cor);
    v.leaf(pre, "msSlope", &mut p.ms_slope);
    v.leaf(pre, "msQeqInvAv", &mut p.ms_qeq_inv_av);
    v.leaf(pre, "msQeqInvAv_exp", &mut p.ms_qeq_inv_av_exp);
    v.leaf(pre, "msMinBufferPtr", &mut p.ms_min_buffer_ptr);
    v.leaf(pre, "msPsdSum", &mut p.ms_psd_sum);
    v.leaf(pre, "msPeriodogSum", &mut p.ms_periodog_sum);
    v.leaf(pre, "msPeriodogSum_exp", &mut p.ms_periodog_sum_exp);
    v.leaf(pre, "offsetflag", &mut p.offsetflag);
    v.leaf(pre, "periodog", &mut p.periodog);
    v.leaf(pre, "periodog_exp", &mut p.periodog_exp);
    v.leaf(pre, "exp_cldfb_periodog", &mut p.exp_cldfb_periodog);
    v.leaf(pre, "cngNoiseLevel", &mut p.cng_noise_level);
    v.leaf(pre, "cngNoiseLevelExp", &mut p.cng_noise_level_exp);
    v.leaf(pre, "seed", &mut p.seed);
    v.leaf(pre, "npart", &mut p.npart);
    v.leaf(pre, "midband", &mut p.midband);
    v.leaf(pre, "nFFTpart", &mut p.n_ff_tpart);
    v.leaf(pre, "part", &mut p.part);
    v.leaf(pre, "psize", &mut p.psize);
    v.leaf(pre, "psize_norm", &mut p.psize_norm);
    v.leaf(pre, "psize_norm_exp", &mut p.psize_norm_exp);
    v.leaf(pre, "psize_inv", &mut p.psize_inv);
    v.leaf(pre, "FFTscalingFactor", &mut p.ff_tscaling_factor);
    v.leaf(pre, "scalingFactor", &mut p.scaling_factor);
    v.leaf(pre, "invScalingFactor", &mut p.inv_scaling_factor);
    v.leaf(pre, "nCLDFBpart", &mut p.n_cldf_bpart);
    v.leaf(pre, "CLDFBpart", &mut p.cldf_bpart);
    v.leaf(pre, "CLDFBpsize_inv", &mut p.cldf_bpsize_inv);
    v.leaf(pre, "inactive_frame_counter", &mut p.inactive_frame_counter);
    v.leaf(pre, "sid_frame_counter", &mut p.sid_frame_counter);
    v.leaf(pre, "active_frame_counter", &mut p.active_frame_counter);
    v.leaf(pre, "sidNoiseEst", &mut p.sid_noise_est);
    v.leaf(pre, "sidNoiseEstExp", &mut p.sid_noise_est_exp);
    v.leaf(pre, "frame_type_previous", &mut p.frame_type_previous);
    v.leaf(pre, "A_cng", &mut p.a_cng);
    v.leaf(pre, "exc_cng", &mut p.exc_cng);
    v.leaf(pre, "CngBitrate", &mut p.cng_bitrate);
    v.leaf(pre, "CngBandwidth", &mut p.cng_bandwidth);
    v.leaf(pre, "flag_noisy_speech", &mut p.flag_noisy_speech);
    v.leaf(
        pre,
        "likelihood_noisy_speech",
        &mut p.likelihood_noisy_speech,
    );
}

#[allow(clippy::too_many_lines)]
fn visit_fd_cng_dec(v: &mut StateVisitor, pre: &str, p: &mut FdCngDec) {
    if let Some(h) = v.handle(pre, "hFdCngCom", &mut p.h_fd_cng_com) {
        let b = format!("{pre}hFdCngCom.");
        visit_fd_cng_com(v, &b, h);
    }
    v.leaf(pre, "olapBufferAna", &mut p.olap_buffer_ana);
    v.leaf(pre, "olapBufferSynth2", &mut p.olap_buffer_synth2);
    v.leaf(pre, "msPeriodog", &mut p.ms_periodog);
    v.leaf(pre, "msPeriodog_exp", &mut p.ms_periodog_exp);
    v.leaf(pre, "msPeriodog_exp_fft", &mut p.ms_periodog_exp_fft);
    v.leaf(pre, "msPeriodog_exp_cldfb", &mut p.ms_periodog_exp_cldfb);
    v.leaf(pre, "msBminWin", &mut p.ms_bmin_win);
    v.leaf(pre, "msBminSubWin", &mut p.ms_bmin_sub_win);
    v.leaf(pre, "msPsd", &mut p.ms_psd);
    v.leaf(pre, "msPsd_exp_fft", &mut p.ms_psd_exp_fft);
    v.leaf(pre, "msAlpha", &mut p.ms_alpha);
    v.leaf(pre, "msMinBuf", &mut p.ms_min_buf);
    v.leaf(pre, "msCurrentMinOut", &mut p.ms_current_min_out);
    v.leaf(pre, "msCurrentMin", &mut p.ms_current_min);
    v.leaf(
        pre,
        "msCurrentMinSubWindow",
        &mut p.ms_current_min_sub_window,
    );
    v.leaf(pre, "msLocalMinFlag", &mut p.ms_local_min_flag);
    v.leaf(pre, "msNewMinFlag", &mut p.ms_new_min_flag);
    v.leaf(pre, "msPsdFirstMoment", &mut p.ms_psd_first_moment);
    v.leaf(pre, "msPsdSecondMoment", &mut p.ms_psd_second_moment);
    v.leaf(pre, "msNoiseFloor", &mut p.ms_noise_floor);
    v.leaf(pre, "msNoiseEst", &mut p.ms_noise_est);
    v.leaf(pre, "msNoiseEst_exp", &mut p.ms_noise_est_exp);
    v.leaf(pre, "npart_shaping", &mut p.npart_shaping);
    v.leaf(pre, "nFFTpart_shaping", &mut p.n_ff_tpart_shaping);
    v.leaf(pre, "part_shaping", &mut p.part_shaping);
    v.leaf(pre, "midband_shaping", &mut p.midband_shaping);
    v.leaf(pre, "psize_shaping", &mut p.psize_shaping);
    v.leaf(pre, "psize_shaping_norm", &mut p.psize_shaping_norm);
    v.leaf(pre, "psize_shaping_norm_exp", &mut p.psize_shaping_norm_exp);
    v.leaf(pre, "psize_inv_shaping", &mut p.psize_inv_shaping);
    v.leaf(pre, "bandNoiseShape", &mut p.band_noise_shape);
    v.leaf(pre, "bandNoiseShape_exp", &mut p.band_noise_shape_exp);
    v.leaf(pre, "partNoiseShape", &mut p.part_noise_shape);
    v.leaf(pre, "partNoiseShape_exp", &mut p.part_noise_shape_exp);
    v.leaf(pre, "flag_dtx_mode", &mut p.flag_dtx_mode);
    v.leaf(pre, "lp_speech", &mut p.lp_speech);
    v.leaf(pre, "lp_noise", &mut p.lp_noise);
    v.leaf(pre, "msPeriodogBuf", &mut p.ms_periodog_buf);
    v.leaf(pre, "msPeriodogBufPtr", &mut p.ms_periodog_buf_ptr);
    v.leaf(pre, "msLogPeriodog", &mut p.ms_log_periodog);
    v.leaf(pre, "msLogNoiseEst", &mut p.ms_log_noise_est);
}

#[allow(clippy::too_many_lines)]
fn visit_acelp_config(v: &mut StateVisitor, pre: &str, p: &mut AcelpConfig) {
    v.leaf(pre, "mode_index", &mut p.mode_index);
    v.leaf(pre, "midLpc", &mut p.mid_lpc);
    v.leaf(pre, "midLpc_enable", &mut p.mid_lpc_enable);
    v.leaf(pre, "pre_emphasis", &mut p.pre_emphasis);
    v.leaf(pre, "pitch_sharpening", &mut p.pitch_sharpening);
    v.leaf(pre, "phase_scrambling", &mut p.phase_scrambling);
    v.leaf(pre, "formant_enh", &mut p.formant_enh);
    v.leaf(pre, "formant_tilt", &mut p.formant_tilt);
    v.leaf(pre, "voice_tilt", &mut p.voice_tilt);
    v.leaf(pre, "formant_enh_num", &mut p.formant_enh_num);
    v.leaf(pre, "formant_enh_den", &mut p.formant_enh_den);
    v.leaf(pre, "bpf_mode", &mut p.bpf_mode);
    v.leaf(pre, "nrg_mode", &mut p.nrg_mode);
    v.leaf(pre, "nrg_bits", &mut p.nrg_bits);
    v.leaf(pre, "ltp_mode", &mut p.ltp_mode);
    v.leaf(pre, "ltp_bits", &mut p.ltp_bits);
    v.leaf(pre, "ltf_mode", &mut p.ltf_mode);
    v.leaf(pre, "ltf_bits", &mut p.ltf_bits);
    v.leaf(pre, "gains_mode", &mut p.gains_mode);
    v.leaf(pre, "fixed_cdk_index", &mut p.fixed_cdk_index);
}

#[allow(clippy::too_many_lines)]
fn visit_s_tns_config(v: &mut StateVisitor, pre: &str, p: &mut STnsConfig) {
    v.leaf(pre, "maxOrder", &mut p.max_order);
    v.leaf(pre, "nMaxFilters", &mut p.n_max_filters);
    v.tns(pre, "pTnsParameters", &mut p.p_tns_parameters);
    v.leaf(pre, "iFilterBorders", &mut p.i_filter_borders);
}

#[allow(clippy::too_many_lines)]
fn visit_tcx_config(v: &mut StateVisitor, pre: &str, p: &mut TcxConfig) {
    v.romp16(pre, "tcx_mdct_window", p.tcx_mdct_window);
    v.romp16(pre, "tcx_mdct_window_half", p.tcx_mdct_window_half);
    v.romp16(pre, "tcx_mdct_window_minimum", p.tcx_mdct_window_minimum);
    v.romp16(pre, "tcx_mdct_window_trans", p.tcx_mdct_window_trans);
    v.leaf(pre, "tcx_aldo_window_1", &mut p.tcx_aldo_window_1);
    v.leaf(
        pre,
        "tcx_aldo_window_1_trunc",
        &mut p.tcx_aldo_window_1_trunc,
    );
    v.leaf(pre, "tcx_aldo_window_2", &mut p.tcx_aldo_window_2);
    v.leaf(pre, "last_aldo", &mut p.last_aldo);
    v.leaf(pre, "tcx5Size", &mut p.tcx5_size);
    v.leaf(pre, "tcx_mdct_window_length", &mut p.tcx_mdct_window_length);
    v.leaf(
        pre,
        "tcx_mdct_window_half_length",
        &mut p.tcx_mdct_window_half_length,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_min_length",
        &mut p.tcx_mdct_window_min_length,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_trans_length",
        &mut p.tcx_mdct_window_trans_length,
    );
    v.leaf(pre, "tcx_mdct_window_delay", &mut p.tcx_mdct_window_delay);
    v.leaf(pre, "tcx_offset", &mut p.tcx_offset);
    v.leaf(
        pre,
        "tcx_mdct_window_length_old",
        &mut p.tcx_mdct_window_length_old,
    );
    v.romp16(pre, "tcx_mdct_windowFB", p.tcx_mdct_window_fb);
    v.romp16(pre, "tcx_mdct_window_halfFB", p.tcx_mdct_window_half_fb);
    v.romp16(
        pre,
        "tcx_mdct_window_minimumFB",
        p.tcx_mdct_window_minimum_fb,
    );
    v.romp16(pre, "tcx_mdct_window_transFB", p.tcx_mdct_window_trans_fb);
    v.leaf(pre, "tcx_aldo_window_1_FB", &mut p.tcx_aldo_window_1_fb);
    v.leaf(
        pre,
        "tcx_aldo_window_1_FB_trunc",
        &mut p.tcx_aldo_window_1_fb_trunc,
    );
    v.leaf(pre, "tcx_aldo_window_2_FB", &mut p.tcx_aldo_window_2_fb);
    v.leaf(pre, "tcx5SizeFB", &mut p.tcx5_size_fb);
    v.leaf(
        pre,
        "tcx_mdct_window_lengthFB",
        &mut p.tcx_mdct_window_length_fb,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_half_lengthFB",
        &mut p.tcx_mdct_window_half_length_fb,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_min_lengthFB",
        &mut p.tcx_mdct_window_min_length_fb,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_trans_lengthFB",
        &mut p.tcx_mdct_window_trans_length_fb,
    );
    v.leaf(
        pre,
        "tcx_mdct_window_delayFB",
        &mut p.tcx_mdct_window_delay_fb,
    );
    v.leaf(pre, "tcx_offsetFB", &mut p.tcx_offset_fb);
    v.leaf(pre, "tcx_coded_lines", &mut p.tcx_coded_lines);
    v.leaf(pre, "tcx_curr_overlap_mode", &mut p.tcx_curr_overlap_mode);
    v.leaf(pre, "tcx_last_overlap_mode", &mut p.tcx_last_overlap_mode);
    v.leaf(pre, "lfacNext", &mut p.lfac_next);
    v.leaf(pre, "lfacNextFB", &mut p.lfac_next_fb);
    v.leaf(pre, "fIsTNSAllowed", &mut p.f_is_tns_allowed);
    for i0 in 0..2 {
        for i1 in 0..2 {
            let b = format!("{pre}tnsConfig[{i0}][{i1}].");
            visit_s_tns_config(v, &b, &mut p.tns_config[i0][i1]);
        }
    }
    v.tns_pointer(pre, "pCurrentTnsConfig", &mut p.p_current_tns_config);
    v.leaf(pre, "sq_rounding", &mut p.sq_rounding);
    v.leaf(pre, "tcxRateLoopOpt", &mut p.tcx_rate_loop_opt);
    v.leaf(pre, "preemph_fac", &mut p.preemph_fac);
    v.leaf(pre, "bandwidth", &mut p.bandwidth);
    v.leaf(pre, "ctx_hm", &mut p.ctx_hm);
    v.leaf(pre, "resq", &mut p.resq);
    v.leaf(pre, "coder_type", &mut p.coder_type);
    v.leaf(pre, "na_scale", &mut p.na_scale);
    v.leaf(pre, "SFM2", &mut p.sfm2);
}

#[allow(clippy::too_many_lines)]
fn visit_pfstat(v: &mut StateVisitor, pre: &str, p: &mut Pfstat) {
    v.leaf(pre, "on", &mut p.on);
    v.leaf(pre, "reset", &mut p.reset);
    v.leaf(pre, "mem_pf_in", &mut p.mem_pf_in);
    v.leaf(pre, "mem_stp", &mut p.mem_stp);
    v.leaf(pre, "mem_res2", &mut p.mem_res2);
    v.leaf(pre, "mem_zero", &mut p.mem_zero);
    v.leaf(pre, "gain_prec", &mut p.gain_prec);
}

#[allow(clippy::too_many_lines)]
fn visit_block_data(v: &mut StateVisitor, pre: &str, p: &mut BlockData) {
    v.leaf(pre, "nSamples", &mut p.n_samples);
    v.leaf(pre, "nSamplesCore", &mut p.n_samples_core);
    v.offset_opt(pre, "spectralData", &mut p.spectral_data);
    v.leaf(pre, "spectralData_exp", &mut p.spectral_data_exp);
    v.offset_opt(pre, "scaleFactors", &mut p.scale_factors);
    v.offset_opt(pre, "scaleFactors_exp", &mut p.scale_factors_exp);
    v.leaf(pre, "scaleFactors_max_e", &mut p.scale_factors_max_e);
    v.leaf(pre, "gain_tcx_exp", &mut p.gain_tcx_exp);
    v.leaf(pre, "blockIsValid", &mut p.block_is_valid);
    v.leaf(pre, "blockIsConcealed", &mut p.block_is_concealed);
    v.leaf(
        pre,
        "tonalConcealmentActive",
        &mut p.tonal_concealment_active,
    );
}

#[allow(clippy::too_many_lines)]
fn visit_tonalmdctconceal(v: &mut StateVisitor, pre: &str, p: &mut Tonalmdctconceal) {
    v.offset_opt(pre, "pMDSTData", &mut p.p_mdst_data);
    v.leaf(pre, "nSamples", &mut p.n_samples);
    v.leaf(pre, "nSamplesCore", &mut p.n_samples_core);
    v.leaf(pre, "nNonZeroSamples", &mut p.n_non_zero_samples);
    v.leaf(pre, "nScaleFactors", &mut p.n_scale_factors);
    v.leaf(pre, "lastPitchLag", &mut p.last_pitch_lag);
    let b = format!("{pre}lastBlockData.");
    visit_block_data(v, &b, &mut p.last_block_data);
    let b = format!("{pre}secondLastBlockData.");
    visit_block_data(v, &b, &mut p.second_last_block_data);
    v.leaf(pre, "scaleFactorsBuffers", &mut p.scale_factors_buffers);
    v.leaf(
        pre,
        "scaleFactorsBuffers_exp",
        &mut p.scale_factors_buffers_exp,
    );
    v.leaf(pre, "spectralDataBuffers", &mut p.spectral_data_buffers);
    v.leaf(pre, "timeDataBuffer", &mut p.time_data_buffer);
    v.offset_opt(pre, "lastPcmOut", &mut p.last_pcm_out);
    v.offset_opt(pre, "secondLastPcmOut", &mut p.second_last_pcm_out);
    v.offset_opt(
        pre,
        "secondLastPowerSpectrum",
        &mut p.second_last_power_spectrum,
    );
    v.leaf(
        pre,
        "secondLastPowerSpectrum_exp",
        &mut p.second_last_power_spectrum_exp,
    );
    v.leaf(pre, "nFramesLost", &mut p.n_frames_lost);
}

#[allow(clippy::too_many_lines)]
fn visit_tplc_info(v: &mut StateVisitor, pre: &str, p: &mut TPLCInfo) {
    v.leaf(pre, "FrameSize", &mut p.frame_size);
    v.leaf(pre, "Pitch_fx", &mut p.pitch);
    v.leaf(pre, "T_bfi_fx", &mut p.t_bfi);
    v.leaf(pre, "Transient", &mut p.transient);
    v.leaf(pre, "TCX_Tonality", &mut p.tcx_tonality);
    v.leaf(pre, "outx_new_n1_fx", &mut p.outx_new_n1);
    v.leaf(pre, "nsapp_gain_fx", &mut p.nsapp_gain);
    v.leaf(pre, "nsapp_gain_n_fx", &mut p.nsapp_gain_n);
    v.leaf(pre, "data_reci2_fx", &mut p.data_reci2);
    v.leaf(pre, "data_reci2_scale", &mut p.data_reci2_scale);
    v.leaf(pre, "data_noise", &mut p.data_noise);
    v.leaf(pre, "ener_mean_fx", &mut p.ener_mean);
    v.leaf(pre, "ener_fx", &mut p.ener);
    v.leaf(pre, "zp_fx", &mut p.zp);
    v.leaf(pre, "recovery_gain", &mut p.recovery_gain);
    v.leaf(pre, "step_concealgain_fx", &mut p.step_concealgain);
    v.leaf(pre, "concealment_method", &mut p.concealment_method);
    v.leaf(pre, "subframe_fx", &mut p.subframe);
    v.leaf(pre, "nbLostCmpt", &mut p.nb_lost_cmpt);
    v.leaf(pre, "seed", &mut p.seed);
}

#[allow(clippy::too_many_lines)]
fn visit_igf_grid(v: &mut StateVisitor, pre: &str, p: &mut IgfGrid) {
    v.leaf(pre, "swb_offset", &mut p.swb_offset);
    v.leaf(pre, "swb_offset_len", &mut p.swb_offset_len);
    v.leaf(pre, "startFrequency", &mut p.start_frequency);
    v.leaf(pre, "stopFrequency", &mut p.stop_frequency);
    v.leaf(pre, "startLine", &mut p.start_line);
    v.leaf(pre, "stopLine", &mut p.stop_line);
    v.leaf(pre, "startSfb", &mut p.start_sfb);
    v.leaf(pre, "stopSfb", &mut p.stop_sfb);
    v.leaf(pre, "sfbWrap", &mut p.sfb_wrap);
    v.leaf(pre, "sbWrap", &mut p.sb_wrap);
    v.leaf(pre, "nTiles", &mut p.n_tiles);
    v.leaf(pre, "minSrcSubband", &mut p.min_src_subband);
    v.leaf(pre, "minSrcFrequency", &mut p.min_src_frequency);
    v.leaf(pre, "tile", &mut p.tile);
    v.leaf(pre, "infoIsRefined", &mut p.info_is_refined);
    v.leaf(pre, "infoGranuleLen", &mut p.info_granule_len);
    v.leaf(pre, "infoTransFac", &mut p.info_trans_fac);
    v.leaf(pre, "whiteningThreshold", &mut p.whitening_threshold);
    v.leaf(pre, "gFactor", &mut p.g_factor);
    v.leaf(pre, "fFactor", &mut p.f_factor);
    v.leaf(pre, "lFactor", &mut p.l_factor);
}

#[allow(clippy::too_many_lines)]
fn visit_igf_info(v: &mut StateVisitor, pre: &str, p: &mut IgfInfo) {
    v.leaf(pre, "nfSeed", &mut p.nf_seed);
    v.leaf(pre, "sampleRate", &mut p.sample_rate);
    v.leaf(pre, "frameLength", &mut p.frame_length);
    v.leaf(pre, "maxHopsize", &mut p.max_hopsize);
    for i0 in 0..3 {
        let b = format!("{pre}grid[{i0}].");
        visit_igf_grid(v, &b, &mut p.grid[i0]);
    }
    v.leaf(pre, "bitRateIndex", &mut p.bit_rate_index);
}

#[allow(clippy::too_many_lines)]
fn visit_tastat_dec(v: &mut StateVisitor, pre: &str, p: &mut TastatDec) {
    v.leaf(pre, "low", &mut p.low);
    v.leaf(pre, "high", &mut p.high);
    v.leaf(pre, "vobf", &mut p.vobf);
}

#[allow(clippy::too_many_lines)]
fn visit_igfscfdec_instance(v: &mut StateVisitor, pre: &str, p: &mut IgfscfdecInstance) {
    v.leaf(pre, "bitsRead", &mut p.bits_read);
    v.leaf(pre, "prev", &mut p.prev);
    v.leaf(pre, "scfCountLongBlock", &mut p.scf_count_long_block);
    v.leaf(pre, "t", &mut p.t);
    v.rom16(pre, "cf_se00", p.cf_se00);
    v.rom16(pre, "cf_se01", p.cf_se01);
    v.leaf(pre, "cf_off_se01", &mut p.cf_off_se01);
    v.rom16(pre, "cf_se02", p.cf_se02);
    v.rom16(pre, "cf_off_se02", p.cf_off_se02);
    v.rom16(pre, "cf_se10", p.cf_se10);
    v.leaf(pre, "cf_off_se10", &mut p.cf_off_se10);
    v.rom16(pre, "cf_se11", p.cf_se11);
    v.rom16(pre, "cf_off_se11", p.cf_off_se11);
    let b = format!("{pre}acState.");
    visit_tastat_dec(v, &b, &mut p.ac_state);
}

#[allow(clippy::too_many_lines)]
fn visit_igfdec_private_data(v: &mut StateVisitor, pre: &str, p: &mut IgfdecPrivateData) {
    let b = format!("{pre}igfInfo.");
    visit_igf_info(v, &b, &mut p.igf_info);
    v.leaf(pre, "igf_sN", &mut p.igf_s_n);
    v.leaf(pre, "igf_sN_e", &mut p.igf_s_n_e);
    v.leaf(pre, "igf_pN", &mut p.igf_p_n);
    v.leaf(pre, "igf_pN_e", &mut p.igf_p_n_e);
    v.leaf(pre, "igf_curr", &mut p.igf_curr);
    v.leaf(pre, "igf_prev", &mut p.igf_prev);
    v.leaf(pre, "igf_curr_subframe", &mut p.igf_curr_subframe);
    v.leaf(pre, "igf_prev_subframe", &mut p.igf_prev_subframe);
    v.leaf(
        pre,
        "igf_flatteningTrigger_subframe",
        &mut p.igf_flattening_trigger_subframe,
    );
    v.leaf(pre, "pSpecFlat", &mut p.p_spec_flat);
    v.leaf(pre, "pSpecFlat_exp", &mut p.p_spec_flat_exp);
    v.leaf(pre, "currWhiteningLevel", &mut p.curr_whitening_level);
    v.leaf(pre, "prevWhiteningLevel", &mut p.prev_whitening_level);
    v.leaf(
        pre,
        "currWhiteningLevel_subframe",
        &mut p.curr_whitening_level_subframe,
    );
    v.leaf(
        pre,
        "prevWhiteningLevel_subframe",
        &mut p.prev_whitening_level_subframe,
    );
    v.leaf(pre, "totalNoiseNrg", &mut p.total_noise_nrg);
    v.leaf(pre, "n_noise_bands", &mut p.n_noise_bands);
    v.leaf(
        pre,
        "headroom_TCX_noise_white",
        &mut p.headroom_tcx_noise_white,
    );
    v.leaf(pre, "headroom_TCX_noise", &mut p.headroom_tcx_noise);
    v.leaf(pre, "totalNoiseNrg_off", &mut p.total_noise_nrg_off);
    v.leaf(pre, "n_noise_bands_off", &mut p.n_noise_bands_off);
    let b = format!("{pre}hArithSCFdec.");
    visit_igfscfdec_instance(v, &b, &mut p.h_arith_sc_fdec);
    v.leaf(pre, "frameLossCounter", &mut p.frame_loss_counter);
}

#[allow(clippy::too_many_lines)]
fn visit_igfdec_instance(v: &mut StateVisitor, pre: &str, p: &mut IgfdecInstance) {
    v.leaf(pre, "isIGFActive", &mut p.is_igf_active);
    v.leaf(pre, "infoIGFAllZero", &mut p.info_igf_all_zero);
    v.leaf(pre, "infoIGFStopLine", &mut p.info_igf_stop_line);
    v.leaf(pre, "infoIGFStartLine", &mut p.info_igf_start_line);
    v.leaf(pre, "infoIGFStopFreq", &mut p.info_igf_stop_freq);
    v.leaf(pre, "infoIGFStartFreq", &mut p.info_igf_start_freq);
    v.leaf(pre, "infoTCXNoise", &mut p.info_tcx_noise);
    v.leaf(pre, "flag_sparse", &mut p.flag_sparse);
    v.leaf(pre, "virtualSpec", &mut p.virtual_spec);
    v.leaf(pre, "virtualSpec_e", &mut p.virtual_spec_e);
    v.leaf(pre, "flatteningTrigger", &mut p.flattening_trigger);
    let b = format!("{pre}igfData.");
    visit_igfdec_private_data(v, &b, &mut p.igf_data);
}

#[allow(clippy::too_many_lines)]
fn visit_cldfb_scale_factor(v: &mut StateVisitor, pre: &str, p: &mut CldfbScaleFactor) {
    v.leaf(pre, "lb_scale", &mut p.lb_scale);
    v.leaf(pre, "lb_scale16", &mut p.lb_scale16);
    v.leaf(pre, "ov_lb_scale", &mut p.ov_lb_scale);
    v.leaf(pre, "hb_scale", &mut p.hb_scale);
    v.leaf(pre, "ov_hb_scale", &mut p.ov_hb_scale);
}

#[allow(clippy::too_many_lines)]
fn visit_temporal_envelope_coding_decoder_fx(
    v: &mut StateVisitor,
    pre: &str,
    p: &mut TemporalEnvelopeCodingDecoderFx,
) {
    v.leaf(pre, "pGainTemp_m", &mut p.p_gain_temp_m);
    v.leaf(pre, "pGainTemp_e", &mut p.p_gain_temp_e);
    v.leaf(pre, "loBuffer", &mut p.lo_buffer);
    v.leaf(pre, "cldfbExp", &mut p.cldfb_exp);
    v.leaf(pre, "lastCldfbExp", &mut p.last_cldfb_exp);
}

#[allow(clippy::too_many_lines)]
fn visit_decoder_state(v: &mut StateVisitor, pre: &str, p: &mut DecoderState) {
    v.leaf(pre, "codec_mode", &mut p.codec_mode);
    v.leaf(pre, "mdct_sw_enable", &mut p.mdct_sw_enable);
    v.leaf(pre, "mdct_sw", &mut p.mdct_sw);
    v.leaf(pre, "last_codec_mode", &mut p.last_codec_mode);
    v.leaf(pre, "next_bit_pos_fx", &mut p.next_bit_pos);
    v.leaf(pre, "bitstreamformat", &mut p.bitstreamformat);
    v.leaf(pre, "sdp_hf_only", &mut p.sdp_hf_only);
    v.leaf(pre, "amrwb_rfc4867_flag", &mut p.amrwb_rfc4867_flag);
    v.leaf(pre, "total_num_bits", &mut p.total_num_bits);
    v.leaf(pre, "BER_detect", &mut p.ber_detect);
    v.leaf_no_fill(pre, "output_Fs_fx", &mut p.output_fs);
    v.leaf_no_fill(pre, "output_frame_fx", &mut p.output_frame);
    v.leaf(pre, "total_brate_fx", &mut p.total_brate);
    v.leaf(pre, "last_total_brate_fx", &mut p.last_total_brate);
    v.leaf(pre, "last_total_brate_ber_fx", &mut p.last_total_brate_ber);
    v.leaf(pre, "core_fx", &mut p.core);
    v.leaf(pre, "core_brate_fx", &mut p.core_brate);
    v.leaf(pre, "last_core_brate_fx", &mut p.last_core_brate);
    v.leaf(pre, "extl_fx", &mut p.extl);
    v.leaf(pre, "last_extl_fx", &mut p.last_extl);
    v.leaf(pre, "extl_brate_fx", &mut p.extl_brate);
    v.leaf(pre, "L_frame_fx", &mut p.l_frame);
    v.leaf(pre, "bwidth_fx", &mut p.bwidth);
    v.leaf(pre, "Opt_AMR_WB_fx", &mut p.opt_amr_wb);
    v.leaf(pre, "Opt_VOIP_fx", &mut p.opt_voip);
    v.leaf(pre, "ini_frame_fx", &mut p.ini_frame);
    v.leaf(pre, "CNG_fx", &mut p.cng);
    v.leaf(pre, "prev_ft_speech_fx", &mut p.prev_ft_speech);
    v.leaf(pre, "old_exc_fx", &mut p.old_exc);
    v.leaf(pre, "old_excFB_fx", &mut p.old_exc_fb);
    v.leaf(pre, "lsp_old_fx", &mut p.lsp_old);
    v.leaf(pre, "lsf_old_fx", &mut p.lsf_old);
    v.leaf(pre, "offset_scale1_fx", &mut p.offset_scale1);
    v.leaf(pre, "offset_scale2_fx", &mut p.offset_scale2);
    v.leaf(pre, "offset_scale1_p_fx", &mut p.offset_scale1_p);
    v.leaf(pre, "offset_scale2_p_fx", &mut p.offset_scale2_p);
    v.leaf(pre, "no_scales_fx", &mut p.no_scales);
    v.leaf(pre, "no_scales_p_fx", &mut p.no_scales_p);
    v.leaf(pre, "tilt_code_fx", &mut p.tilt_code);
    v.leaf(pre, "mem_syn2_fx", &mut p.mem_syn2);
    v.leaf(pre, "mem_syn1_fx", &mut p.mem_syn1);
    v.leaf(pre, "mem_syn3_fx", &mut p.mem_syn3);
    v.leaf(pre, "mem_deemph_fx", &mut p.mem_deemph);
    v.leaf(pre, "L_mem_hp_out_fx", &mut p.l_mem_hp_out);
    v.leaf(pre, "mem_MA_fx", &mut p.mem_ma);
    v.leaf(pre, "mem_AR_fx", &mut p.mem_ar);
    v.leaf(pre, "stab_fac_fx", &mut p.stab_fac);
    v.leaf(pre, "stab_fac_smooth_fx", &mut p.stab_fac_smooth);
    v.leaf(pre, "last_coder_type_fx", &mut p.last_coder_type);
    v.leaf(pre, "agc_mem_fx", &mut p.agc_mem);
    v.leaf(pre, "past_qua_en_fx", &mut p.past_qua_en);
    v.leaf(pre, "mid_lsf_int_fx", &mut p.mid_lsf_int);
    v.leaf(pre, "safety_net_fx", &mut p.safety_net);
    v.leaf(pre, "seed_tcx_fx", &mut p.seed_tcx);
    v.leaf(pre, "GSC_noisy_speech_fx", &mut p.gsc_noisy_speech);
    v.leaf(
        pre,
        "Last_GSC_noisy_speech_flag_fx",
        &mut p.last_gsc_noisy_speech_flag,
    );
    v.leaf(pre, "cor_strong_limit_fx", &mut p.cor_strong_limit);
    v.leaf(pre, "old_y_gain_fx", &mut p.old_y_gain);
    v.leaf(pre, "noise_lev_fx", &mut p.noise_lev);
    v.leaf(pre, "lt_ener_per_band_fx", &mut p.lt_ener_per_band);
    v.leaf(pre, "Last_frame_ener_fx", &mut p.last_frame_ener);
    v.leaf(pre, "Last_GSC_spectrum_fx", &mut p.last_gsc_spectrum);
    v.leaf(
        pre,
        "Last_GSC_pit_band_idx_fx",
        &mut p.last_gsc_pit_band_idx,
    );
    v.leaf(pre, "last_exc_dct_in_fx", &mut p.last_exc_dct_in);
    v.leaf(pre, "last_ener_fx", &mut p.last_ener);
    v.leaf(
        pre,
        "last_bitallocation_band_fx",
        &mut p.last_bitallocation_band,
    );
    v.leaf(pre, "gc_threshold_fx", &mut p.gc_threshold);
    let b = format!("{pre}dm_fx.");
    visit_disp_mem(v, &b, &mut p.dm);
    v.leaf(pre, "prev_r_fx", &mut p.prev_r);
    v.leaf(pre, "fmerit_w_sm_fx", &mut p.fmerit_w_sm);
    v.leaf(pre, "frame_count_fx", &mut p.frame_count);
    v.leaf(pre, "ne_min_fx", &mut p.ne_min);
    v.leaf(pre, "fmerit_m_sm_fx", &mut p.fmerit_m_sm);
    v.leaf(pre, "voice_fac_amr_wb_hf", &mut p.voice_fac_amr_wb_hf);
    v.leaf(pre, "unvoicing_fx", &mut p.unvoicing);
    v.leaf(pre, "unvoicing_sm_fx", &mut p.unvoicing_sm);
    v.leaf(pre, "unvoicing_flag_fx", &mut p.unvoicing_flag);
    v.leaf(pre, "voicing_flag_fx", &mut p.voicing_flag);
    v.leaf(pre, "start_band_old_fx", &mut p.start_band_old);
    v.leaf(pre, "OptCrit_old_fx", &mut p.opt_crit_old);
    v.leaf(pre, "seed2_fx", &mut p.seed2);
    v.leaf(pre, "mem_hp400_fx", &mut p.mem_hp400);
    v.leaf(pre, "mem_hf_fx", &mut p.mem_hf);
    v.leaf(pre, "mem_syn_hf_fx", &mut p.mem_syn_hf);
    v.leaf(pre, "delay_syn_hf_fx", &mut p.delay_syn_hf);
    v.leaf(pre, "mem_hp_interp_fx", &mut p.mem_hp_interp);
    v.leaf(pre, "unv_cnt_fx", &mut p.unv_cnt);
    v.leaf(pre, "uv_count_fx", &mut p.uv_count);
    v.leaf(pre, "act_count_fx", &mut p.act_count);
    v.leaf(pre, "ge_sm_fx", &mut p.ge_sm);
    v.leaf(pre, "lspold_s_fx", &mut p.lspold_s);
    v.leaf(pre, "noimix_seed_fx", &mut p.noimix_seed);
    v.leaf(pre, "min_alpha_fx", &mut p.min_alpha);
    v.leaf(pre, "Q_stat_noise", &mut p.q_stat_noise);
    v.leaf(pre, "exc_pe_fx", &mut p.exc_pe);
    v.leaf(pre, "Q_stat_noise_ge", &mut p.q_stat_noise_ge);
    v.leaf(pre, "bfi_fx", &mut p.bfi);
    v.leaf(pre, "prev_bfi_fx", &mut p.prev_bfi);
    v.leaf(pre, "seed_fx", &mut p.seed);
    v.leaf(pre, "lp_ener_FER_fx", &mut p.lp_ener_fer);
    v.leaf(pre, "last_good_fx", &mut p.last_good);
    v.leaf(pre, "lp_gainc_fx", &mut p.lp_gainc);
    v.leaf(pre, "lp_gainp_fx", &mut p.lp_gainp);
    v.leaf(pre, "lp_ener_fx", &mut p.lp_ener);
    v.leaf(pre, "enr_old_fx", &mut p.enr_old);
    v.leaf(pre, "bfi_pitch_fx", &mut p.bfi_pitch);
    v.leaf(pre, "bfi_pitch_frame_fx", &mut p.bfi_pitch_frame);
    v.leaf(pre, "old_pitch_buf_fx", &mut p.old_pitch_buf);
    v.leaf(pre, "upd_cnt_fx", &mut p.upd_cnt);
    v.leaf(pre, "scaling_flag", &mut p.scaling_flag);
    v.leaf(pre, "lp_ener_FEC_av", &mut p.lp_ener_fec_av);
    v.leaf(pre, "lp_ener_FEC_max", &mut p.lp_ener_fec_max);
    v.leaf(pre, "old_enr_LP", &mut p.old_enr_lp);
    v.leaf(pre, "lsfoldbfi0_fx", &mut p.lsfoldbfi0);
    v.leaf(pre, "lsfoldbfi1_fx", &mut p.lsfoldbfi1);
    v.leaf(pre, "lsf_adaptive_mean_fx", &mut p.lsf_adaptive_mean);
    v.leaf(pre, "decision_hyst_fx", &mut p.decision_hyst);
    v.leaf(pre, "old_exc2_fx", &mut p.old_exc2);
    v.leaf(pre, "old_syn2_fx", &mut p.old_syn2);
    v.leaf(
        pre,
        "relax_prev_lsf_interp_fx",
        &mut p.relax_prev_lsf_interp,
    );
    v.leaf(pre, "mem_syn_clas_estim_fx", &mut p.mem_syn_clas_estim);
    v.leaf(pre, "tilt_swb_fec_fx", &mut p.tilt_swb_fec);
    v.leaf(pre, "cng_seed_fx", &mut p.cng_seed);
    v.leaf(pre, "lspCNG_fx", &mut p.lsp_cng);
    v.leaf(pre, "first_CNG_fx", &mut p.first_cng);
    v.leaf(pre, "Enew_fx", &mut p.enew);
    v.leaf(pre, "old_enr_index_fx", &mut p.old_enr_index);
    v.leaf(pre, "cng_ener_seed_fx", &mut p.cng_ener_seed);
    v.leaf(pre, "cng_ener_seed1_fx", &mut p.cng_ener_seed1);
    v.leaf(pre, "last_allow_cn_step_fx", &mut p.last_allow_cn_step);
    v.leaf(pre, "ho_hist_size_fx", &mut p.ho_hist_size);
    v.leaf(pre, "ho_hist_ptr_fx", &mut p.ho_hist_ptr);
    v.leaf(pre, "ho_sid_bw_fx", &mut p.ho_sid_bw);
    v.leaf(pre, "ho_lsp_hist_fx", &mut p.ho_lsp_hist);
    v.leaf(pre, "ho_ener_hist_fx", &mut p.ho_ener_hist);
    v.leaf(pre, "ho_env_hist_fx", &mut p.ho_env_hist);
    v.leaf(pre, "act_cnt_fx", &mut p.act_cnt);
    v.leaf(pre, "ho_circ_size_fx", &mut p.ho_circ_size);
    v.leaf(pre, "ho_circ_ptr_fx", &mut p.ho_circ_ptr);
    v.leaf(pre, "ho_lsp_circ_fx", &mut p.ho_lsp_circ);
    v.leaf(pre, "ho_ener_circ_fx", &mut p.ho_ener_circ);
    v.leaf(pre, "ho_env_circ_fx", &mut p.ho_env_circ);
    v.leaf(pre, "num_ho_fx", &mut p.num_ho);
    v.leaf(pre, "ho_16k_lsp_fx", &mut p.ho_16k_lsp);
    v.leaf(pre, "CNG_mode_fx", &mut p.cng_mode);
    v.leaf(pre, "last_active_brate_fx", &mut p.last_active_brate);
    v.leaf(pre, "last_CNG_L_frame_fx", &mut p.last_cng_l_frame);
    v.leaf(pre, "act_cnt2_fx", &mut p.act_cnt2);
    v.leaf(pre, "cng_type_fx", &mut p.cng_type);
    v.leaf(pre, "last_cng_type_fx", &mut p.last_cng_type);
    v.leaf(pre, "old_env_fx", &mut p.old_env);
    v.leaf(pre, "lp_env_fx", &mut p.lp_env);
    v.leaf(pre, "exc_mem_fx", &mut p.exc_mem);
    v.leaf(pre, "exc_mem1_fx", &mut p.exc_mem1);
    v.leaf(pre, "bpf_off_fx", &mut p.bpf_off);
    v.leaf(pre, "pst_old_syn_fx", &mut p.pst_old_syn);
    v.leaf(pre, "pst_mem_deemp_err_fx", &mut p.pst_mem_deemp_err);
    v.leaf(pre, "pst_lp_ener_fx", &mut p.pst_lp_ener);
    v.leaf(pre, "Track_on_hist_fx", &mut p.track_on_hist);
    v.leaf(pre, "vibrato_hist_fx", &mut p.vibrato_hist);
    v.leaf(pre, "psf_att_fx", &mut p.psf_att);
    v.leaf(pre, "mem_mean_pit_fx", &mut p.mem_mean_pit);
    v.leaf(pre, "Ng_ener_ST_fx", &mut p.ng_ener_st);
    v.leaf(pre, "last_L_frame_fx", &mut p.last_l_frame);
    v.leaf(pre, "mem_preemp_preQ_fx", &mut p.mem_preemp_pre_q);
    v.leaf(pre, "last_nq_preQ_fx", &mut p.last_nq_pre_q);
    v.leaf(pre, "use_acelp_preq", &mut p.use_acelp_preq);
    v.leaf(pre, "UV_cnt_fx", &mut p.uv_cnt);
    v.leaf(pre, "LT_UV_cnt_fx", &mut p.lt_uv_cnt);
    v.leaf(pre, "Last_ener_fx", &mut p.Last_ener);
    v.leaf(pre, "lt_diff_etot_fx", &mut p.lt_diff_etot);
    v.leaf(pre, "old_Aq_fx", &mut p.old_aq);
    v.leaf(pre, "lt_voice_fac_fx", &mut p.lt_voice_fac);
    v.leaf(pre, "last_ppp_mode_dec_fx", &mut p.last_ppp_mode_dec);
    v.leaf(pre, "ppp_mode_dec_fx", &mut p.ppp_mode_dec);
    v.leaf(pre, "last_nelp_mode_dec_fx", &mut p.last_nelp_mode_dec);
    v.leaf(pre, "nelp_mode_dec_fx", &mut p.nelp_mode_dec);
    v.leaf(pre, "firstTime_voiceddec_fx", &mut p.first_time_voiceddec);
    v.leaf(pre, "dtfs_dec_a_fx", &mut p.dtfs_dec_a);
    v.leaf(pre, "dtfs_dec_b_fx", &mut p.dtfs_dec_b);
    v.leaf(pre, "dtfs_dec_lag_fx", &mut p.dtfs_dec_lag);
    v.leaf(pre, "dtfs_dec_nH_fx", &mut p.dtfs_dec_n_h);
    v.leaf(pre, "dtfs_dec_nH_4kHz_fx", &mut p.dtfs_dec_n_h_4k_hz);
    v.leaf(
        pre,
        "dtfs_dec_upper_cut_off_freq_of_interest_fx",
        &mut p.dtfs_dec_upper_cut_off_freq_of_interest,
    );
    v.leaf(
        pre,
        "dtfs_dec_upper_cut_off_freq_fx",
        &mut p.dtfs_dec_upper_cut_off_freq,
    );
    v.leaf(pre, "ph_offset_D_fx", &mut p.ph_offset_d);
    v.leaf(pre, "lastLgainD_fx", &mut p.last_lgain_d);
    v.leaf(pre, "lastHgainD_fx", &mut p.last_hgain_d);
    v.leaf(pre, "lasterbD_fx", &mut p.lasterb_d);
    v.leaf(pre, "dtfs_dec_Q", &mut p.dtfs_dec_q);
    v.leaf(pre, "bp1_filt_mem_nb_dec_fx", &mut p.bp1_filt_mem_nb_dec);
    v.leaf(pre, "bp1_filt_mem_wb_dec_fx", &mut p.bp1_filt_mem_wb_dec);
    v.leaf(pre, "shape1_filt_mem_dec_fx", &mut p.shape1_filt_mem_dec);
    v.leaf(pre, "shape2_filt_mem_dec_fx", &mut p.shape2_filt_mem_dec);
    v.leaf(pre, "shape3_filt_mem_dec_fx", &mut p.shape3_filt_mem_dec);
    v.leaf(pre, "nelp_dec_seed_fx", &mut p.nelp_dec_seed);
    v.leaf(pre, "FadeScale_fx", &mut p.fade_scale);
    v.leaf(pre, "prev_gain_pit_dec_fx", &mut p.prev_gain_pit_dec);
    v.leaf(pre, "prev_tilt_code_dec_fx", &mut p.prev_tilt_code_dec);
    v.leaf(pre, "tilt_code_dec_fx", &mut p.tilt_code_dec);
    v.leaf(pre, "rf_frame_type", &mut p.rf_frame_type);
    v.leaf(pre, "use_partial_copy", &mut p.use_partial_copy);
    v.leaf(pre, "prev_use_partial_copy", &mut p.prev_use_partial_copy);
    v.leaf(pre, "rf_flag", &mut p.rf_flag);
    v.leaf(pre, "rf_flag_last", &mut p.rf_flag_last);
    v.leaf(pre, "rf_fec_offset", &mut p.rf_fec_offset);
    v.leaf(pre, "next_coder_type", &mut p.next_coder_type);
    v.leaf(pre, "prev_rf_frame_type", &mut p.prev_rf_frame_type);
    v.leaf(pre, "rf_target_bits", &mut p.rf_target_bits);
    v.leaf(pre, "rf_indx_nelp_fid", &mut p.rf_indx_nelp_fid);
    v.leaf(pre, "rf_indx_nelp_iG1", &mut p.rf_indx_nelp_i_g1);
    v.leaf(pre, "rf_indx_nelp_iG2", &mut p.rf_indx_nelp_i_g2);
    v.leaf(pre, "rf_indx_tbeGainFr", &mut p.rf_indx_tbe_gain_fr);
    v.leaf(pre, "bwe_highrate_seed_fx", &mut p.bwe_highrate_seed);
    v.leaf(pre, "t_audio_prev_fx", &mut p.t_audio_prev);
    v.leaf(pre, "t_audio_prev_fx_exp", &mut p.t_audio_prev_fx_exp);
    v.leaf(
        pre,
        "old_is_transient_hr_bwe_fx",
        &mut p.old_is_transient_hr_bwe,
    );
    v.leaf(pre, "L_mem_EnergyLT_fx", &mut p.l_mem_energy_lt);
    v.leaf(pre, "mem_EnergyLT_fx_exp", &mut p.mem_energy_lt_fx_exp);
    v.leaf(pre, "synth_history_fx", &mut p.synth_history);
    v.offset(pre, "old_synthFB_fx", &mut p.old_synth_fb);
    v.leaf(pre, "old_out_fx", &mut p.old_out);
    v.leaf(pre, "old_out_LB_fx", &mut p.old_out_lb);
    v.leaf(pre, "Q_old_wtda_LB", &mut p.q_old_wtda_lb);
    v.leaf(pre, "Q_old_wtda", &mut p.q_old_wtda);
    v.leaf(pre, "Q_old_postdec", &mut p.q_old_postdec);
    v.leaf(pre, "Qprev_synth_buffer_fx", &mut p.qprev_synth_buffer);
    v.leaf(pre, "oldIMDCTout_fx", &mut p.old_imdc_tout);
    v.leaf(pre, "prev_oldauOut_fx", &mut p.prev_oldau_out);
    v.leaf(pre, "old_auOut_2fr_fx", &mut p.old_au_out_2fr);
    v.leaf(pre, "old_out_pha_fx", &mut p.old_out_pha);
    v.leaf(pre, "diff_energy_fx", &mut p.diff_energy);
    v.leaf(pre, "old_coeffs_fx", &mut p.old_coeffs);
    v.leaf(pre, "stat_mode_out_fx", &mut p.stat_mode_out);
    v.leaf(pre, "stat_mode_old_fx", &mut p.stat_mode_old);
    v.leaf(pre, "phase_mat_flag_fx", &mut p.phase_mat_flag);
    v.leaf(pre, "phase_mat_next_fx", &mut p.phase_mat_next);
    v.leaf(pre, "old_Min_ind_fx", &mut p.old_min_ind);
    v.leaf(pre, "old_is_transient_fx", &mut p.old_is_transient);
    v.leaf(pre, "old_bfi_cnt_fx", &mut p.old_bfi_cnt);
    v.leaf(pre, "prev_old_bfi_fx", &mut p.prev_old_bfi);
    v.leaf(pre, "ynrm_values_fx", &mut p.ynrm_values);
    v.leaf(pre, "r_p_values_fx", &mut p.r_p_values);
    v.leaf(pre, "Norm_gain_fx", &mut p.norm_gain);
    v.leaf(pre, "HQ_FEC_seed_fx", &mut p.hq_fec_seed);
    v.leaf(pre, "energy_MA_Curr_fx", &mut p.energy_ma_curr);
    v.leaf(pre, "last_core_fx", &mut p.last_core);
    v.leaf(pre, "last_core_bs_fx", &mut p.last_core_bs);
    v.leaf(pre, "prev_last_core_fx", &mut p.prev_last_core);
    v.leaf(pre, "last_hq_core_type_fx", &mut p.last_hq_core_type);
    v.leaf(pre, "last_L_frame_ori_fx", &mut p.last_l_frame_ori);
    v.leaf(pre, "previoussynth_fx", &mut p.previoussynth);
    v.leaf(pre, "old_synth_sw_fx", &mut p.old_synth_sw);
    v.leaf(pre, "delay_buf_out_fx", &mut p.delay_buf_out);
    v.leaf(pre, "mem_norm_fx", &mut p.mem_norm);
    v.leaf(pre, "mem_env_delta_fx", &mut p.mem_env_delta);
    v.leaf(pre, "no_att_hangover_fx", &mut p.no_att_hangover);
    v.leaf(pre, "energy_lt_fx", &mut p.energy_lt);
    v.leaf(pre, "hq_generic_seed_fx", &mut p.hq_generic_seed);
    v.leaf(pre, "prev_noise_level_fx", &mut p.prev_noise_level);
    v.leaf(pre, "prev_hqswb_clas_fx", &mut p.prev_hqswb_clas);
    v.leaf(pre, "prev_R_fx", &mut p.prev_R);
    v.leaf(pre, "prev_coeff_out_fx", &mut p.prev_coeff_out);
    v.leaf(pre, "prev_SWB_peak_pos_fx", &mut p.prev_swb_peak_pos);
    v.leaf(pre, "old_Aq_12_8_fx", &mut p.old_aq_12_8);
    v.leaf(pre, "old_Es_pred_fx", &mut p.old_es_pred);
    v.leaf(pre, "HqVoicing_fx", &mut p.hq_voicing);
    v.leaf(pre, "fer_samples_fx", &mut p.fer_samples);
    v.leaf(pre, "prev_normq_fx", &mut p.prev_normq);
    v.leaf(pre, "prev_env_fx", &mut p.prev_env);
    v.leaf(pre, "last_ni_gain_fx", &mut p.last_ni_gain);
    v.leaf(pre, "last_env_fx", &mut p.last_env);
    v.leaf(pre, "last_max_pos_pulse_fx", &mut p.last_max_pos_pulse);
    v.leaf(pre, "memfilt_lb_fx", &mut p.memfilt_lb);
    v.leaf(pre, "mean_prev_hb_fx", &mut p.mean_prev_hb);
    v.leaf(pre, "smoothmem_fx", &mut p.smoothmem);
    v.leaf(pre, "mean_prev_fx", &mut p.mean_prev);
    v.leaf(pre, "mean_prev_nc_fx", &mut p.mean_prev_nc);
    v.leaf(pre, "wmold_hb_fx", &mut p.wmold_hb);
    v.leaf(pre, "prevflag_fx", &mut p.prevflag);
    v.leaf(pre, "pastpre_fx", &mut p.pastpre);
    v.leaf(pre, "prev_frm_hfe2_fx", &mut p.prev_frm_hfe2);
    v.leaf(pre, "prev_stab_hfe2_fx", &mut p.prev_stab_hfe2);
    v.leaf(pre, "prev_ni_ratio_fx", &mut p.prev_ni_ratio);
    v.leaf(pre, "prev_En_sb_fx", &mut p.prev_en_sb);
    v.leaf(pre, "rc_low_fx", &mut p.rc_low);
    v.leaf(pre, "rc_range_fx", &mut p.rc_range);
    v.leaf(pre, "rc_help_fx", &mut p.rc_help);
    v.leaf(pre, "rc_num_bits_fx", &mut p.rc_num_bits);
    v.leaf(pre, "rc_offset_fx", &mut p.rc_offset);
    v.leaf(pre, "rc_end_fx", &mut p.rc_end);
    v.leaf(pre, "prev_env_Q", &mut p.prev_env_q);
    v.leaf(pre, "state_lpc_syn_fx", &mut p.state_lpc_syn);
    v.leaf(pre, "mem_csfilt_fx", &mut p.mem_csfilt);
    v.leaf(pre, "state_syn_shbexc_fx", &mut p.state_syn_shbexc);
    v.leaf(pre, "syn_overlap_fx", &mut p.syn_overlap);
    v.leaf(pre, "lsp_prevfrm_fx", &mut p.lsp_prevfrm);
    v.leaf(pre, "GainFrame_prevfrm_fx", &mut p.gain_frame_prevfrm);
    v.leaf(pre, "GainAttn_fx", &mut p.gain_attn);
    v.leaf(pre, "old_bwe_exc_fx", &mut p.old_bwe_exc);
    v.leaf(pre, "bwe_seed_fx", &mut p.bwe_seed);
    v.leaf(
        pre,
        "bwe_non_lin_prev_scale_fx",
        &mut p.bwe_non_lin_prev_scale,
    );
    v.leaf(pre, "old_bwe_exc_extended_fx", &mut p.old_bwe_exc_extended);
    v.leaf(pre, "last_voice_factor_fx", &mut p.last_voice_factor);
    v.leaf(
        pre,
        "genSHBsynth_Hilbert_Mem_fx",
        &mut p.gen_sh_bsynth_hilbert_mem,
    );
    v.leaf(
        pre,
        "mem_genSHBexc_filt_down_shb_fx",
        &mut p.mem_gen_sh_bexc_filt_down_shb,
    );
    v.leaf(
        pre,
        "mem_genSHBexc_filt_down_wb2_fx",
        &mut p.mem_gen_sh_bexc_filt_down_wb2,
    );
    v.leaf(
        pre,
        "mem_genSHBexc_filt_down_wb3_fx",
        &mut p.mem_gen_sh_bexc_filt_down_wb3,
    );
    v.leaf(
        pre,
        "genSHBsynth_state_lsyn_filt_shb_local_fx",
        &mut p.gen_sh_bsynth_state_lsyn_filt_shb_local,
    );
    v.leaf(pre, "state_lsyn_filt_shb_fx", &mut p.state_lsyn_filt_shb);
    v.leaf(
        pre,
        "state_lsyn_filt_dwn_shb_fx",
        &mut p.state_lsyn_filt_dwn_shb,
    );
    v.leaf(
        pre,
        "state_32and48k_WB_upsample_fx",
        &mut p.state_32and48k_wb_upsample,
    );
    v.leaf(pre, "hb_prev_synth_buffer_fx", &mut p.hb_prev_synth_buffer);
    v.leaf(pre, "old_bwe_delay_fx", &mut p.old_bwe_delay);
    v.leaf(pre, "syn_dm_phase_fx", &mut p.syn_dm_phase);
    v.leaf(pre, "fbbwe_hpf_mem_fx", &mut p.fbbwe_hpf_mem);
    v.leaf(pre, "fbbwe_hpf_mem_fx_Q", &mut p.fbbwe_hpf_mem_fx_q);
    v.leaf(
        pre,
        "prev_wb_bwe_frame_pow_fx",
        &mut p.prev_wb_bwe_frame_pow,
    );
    v.leaf(
        pre,
        "prev_swb_bwe_frame_pow_fx",
        &mut p.prev_swb_bwe_frame_pow,
    );
    v.leaf(pre, "prev_ener_fx", &mut p.prev_ener);
    v.leaf(pre, "prev_ener_fx_Q", &mut p.prev_ener_fx_q);
    v.leaf(pre, "prev_GainShape_fx", &mut p.prev_gain_shape);
    v.leaf(pre, "fb_state_lpc_syn_fx", &mut p.fb_state_lpc_syn);
    v.leaf(pre, "prev_Q_bwe_exc_fb", &mut p.prev_q_bwe_exc_fb);
    v.leaf(pre, "fb_tbe_demph_fx", &mut p.fb_tbe_demph);
    v.leaf(pre, "prev_fbbwe_ratio_fx", &mut p.prev_fbbwe_ratio);
    v.leaf(pre, "tilt_wb_fx", &mut p.tilt_wb);
    v.leaf(pre, "tilt_swb_fx", &mut p.tilt_swb);
    v.leaf(pre, "prev_ener_shb_fx", &mut p.prev_ener_shb);
    v.leaf(pre, "enerLH_fx", &mut p.ener_lh);
    v.leaf(pre, "prev_enerLH_fx", &mut p.prev_ener_lh);
    v.leaf(pre, "enerLL_fx", &mut p.ener_ll);
    v.leaf(pre, "prev_enerLL_fx", &mut p.prev_ener_ll);
    v.leaf(pre, "prev_fractive_fx", &mut p.prev_fractive);
    v.leaf(pre, "prev_bws_cnt_fx", &mut p.prev_bws_cnt);
    v.leaf(pre, "bws_cnt_fx", &mut p.bws_cnt);
    v.leaf(pre, "bws_cnt1_fx", &mut p.bws_cnt1);
    v.leaf(pre, "attenu_fx", &mut p.attenu);
    v.leaf(pre, "last_inner_frame_fx", &mut p.last_inner_frame);
    v.leaf(pre, "last_bwidth_fx", &mut p.last_bwidth);
    v.leaf(pre, "prev_weight1_fx", &mut p.prev_weight1);
    v.leaf(pre, "t_audio_q_fx", &mut p.t_audio_q);
    v.leaf(pre, "tbe_demph_fx", &mut p.tbe_demph);
    v.leaf(pre, "tbe_premph_fx", &mut p.tbe_premph);
    v.leaf(pre, "mem_stp_swb_fx", &mut p.mem_stp_swb);
    v.offset(pre, "ptr_mem_stp_swb_fx", &mut p.ptr_mem_stp_swb);
    v.leaf(pre, "gain_prec_swb_fx", &mut p.gain_prec_swb);
    v.leaf(pre, "mem_zero_swb_fx", &mut p.mem_zero_swb);
    v.leaf(pre, "swb_lsp_prev_interp_fx", &mut p.swb_lsp_prev_interp);
    v.leaf(pre, "prev1_shb_ener_sf_fx", &mut p.prev1_shb_ener_sf);
    v.leaf(pre, "prev2_shb_ener_sf_fx", &mut p.prev2_shb_ener_sf);
    v.leaf(pre, "prev3_shb_ener_sf_fx", &mut p.prev3_shb_ener_sf);
    v.leaf(pre, "prev_res_shb_gshape_fx", &mut p.prev_res_shb_gshape);
    v.leaf(pre, "prev_mixFactors_fx", &mut p.prev_mix_factors);
    v.leaf(pre, "tilt_mem_fx", &mut p.tilt_mem);
    v.leaf(pre, "prev_lsf_diff_fx", &mut p.prev_lsf_diff);
    v.leaf(pre, "prev_tilt_para_fx", &mut p.prev_tilt_para);
    v.leaf(pre, "cur_sub_Aq_fx", &mut p.cur_sub_aq);
    v.leaf(pre, "lsf_idx_fx", &mut p.lsf_idx);
    v.leaf(pre, "m_idx_fx", &mut p.m_idx);
    v.leaf(pre, "grid_idx_fx", &mut p.grid_idx);
    v.leaf(pre, "idxSubGains_fx", &mut p.idx_sub_gains);
    v.leaf(pre, "idxFrameGain_fx", &mut p.idx_frame_gain);
    v.leaf(pre, "idx_shb_fr_gain_fx", &mut p.idx_shb_fr_gain);
    v.leaf(pre, "idx_res_gs_fx", &mut p.idx_res_gs);
    v.leaf(pre, "idx_mixFac_fx", &mut p.idx_mix_fac);
    v.leaf(pre, "lsf_WB_fx", &mut p.lsf_wb);
    v.leaf(pre, "gFrame_WB_fx", &mut p.g_frame_wb);
    v.leaf(pre, "idxGain_fx", &mut p.idx_gain);
    v.leaf(pre, "old_core_synth_fx", &mut p.old_core_synth);
    v.leaf(pre, "old_tbe_synth_fx", &mut p.old_tbe_synth);
    v.leaf(
        pre,
        "int_3_over_2_tbemem_dec_fx",
        &mut p.int_3_over_2_tbemem_dec,
    );
    v.leaf(pre, "interpol_3_2_cng_dec_fx", &mut p.interpol_3_2_cng_dec);
    v.leaf(pre, "mem_resamp_HB_fx", &mut p.mem_resamp_hb);
    v.leaf(pre, "mem_resamp_HB_32k_fx", &mut p.mem_resamp_hb_32k);
    v.leaf(pre, "old_wtda_wb_fx_exp", &mut p.old_wtda_wb_fx_exp);
    v.leaf(pre, "L_old_wtda_swb_fx", &mut p.l_old_wtda_swb);
    v.leaf(pre, "old_wtda_swb_fx_exp", &mut p.old_wtda_swb_fx_exp);
    v.leaf(pre, "mem_imdct_exp_fx", &mut p.mem_imdct_exp);
    v.leaf(pre, "old_syn_12k8_16k_fx", &mut p.old_syn_12k8_16k);
    v.leaf(pre, "mem_deemph_old_syn_fx", &mut p.mem_deemph_old_syn);
    v.leaf(pre, "prev_mode_fx", &mut p.prev_mode);
    v.leaf(pre, "prev_SWB_fenv_fx", &mut p.prev_swb_fenv);
    v.leaf(pre, "prev_Energy_fx", &mut p.prev_energy);
    v.leaf(pre, "prev_Energy_wb_fx", &mut p.prev_energy_wb);
    v.leaf(pre, "prev_L_swb_norm_fx", &mut p.prev_l_swb_norm);
    v.leaf(pre, "Seed_fx", &mut p.Seed);
    v.leaf(pre, "memExp1", &mut p.mem_exp1);
    v.leaf(pre, "prev_frica_flag_fx", &mut p.prev_frica_flag);
    v.leaf(pre, "mem_imdct_fx", &mut p.mem_imdct);
    v.leaf(pre, "prev_td_energy_fx", &mut p.prev_td_energy);
    v.leaf(pre, "prev_weight_fx", &mut p.prev_weight);
    v.leaf(pre, "prev_coder_type_fx", &mut p.prev_coder_type);
    v.leaf(pre, "prev_flag_fx", &mut p.prev_flag);
    v.leaf(pre, "last_wb_bwe_ener_fx", &mut p.last_wb_bwe_ener);
    v.leaf(pre, "prev_frame_pow_exp", &mut p.prev_frame_pow_exp);
    v.leaf(pre, "prev_Qx", &mut p.prev_qx);
    v.leaf(pre, "prev_Q_bwe_exc", &mut p.prev_q_bwe_exc);
    v.leaf(pre, "prev_Q_synth", &mut p.prev_q_synth);
    v.leaf(pre, "prev_fb_ener_adjust_fx", &mut p.prev_fb_ener_adjust);
    v.leaf(pre, "shb_cng_ener_fx", &mut p.shb_cng_ener);
    v.leaf(pre, "wb_cng_ener_fx", &mut p.wb_cng_ener);
    v.leaf(pre, "last_wb_cng_ener_fx", &mut p.last_wb_cng_ener);
    v.leaf(pre, "last_shb_cng_ener_fx", &mut p.last_shb_cng_ener);
    v.leaf(pre, "swb_cng_seed_fx", &mut p.swb_cng_seed);
    v.leaf(pre, "lsp_shb_prev_prev_fx", &mut p.lsp_shb_prev_prev);
    v.leaf(pre, "lsp_shb_prev_fx", &mut p.lsp_shb_prev);
    v.leaf(pre, "shb_dtx_count_fx", &mut p.shb_dtx_count);
    v.leaf(pre, "last_vad_fx", &mut p.last_vad);
    v.leaf(pre, "trans_cnt_fx", &mut p.trans_cnt);
    v.leaf(pre, "burst_cnt_fx", &mut p.burst_cnt);
    v.leaf(pre, "last_shb_ener_fx", &mut p.last_shb_ener);
    v.offset(pre, "prev_good_synth_fx", &mut p.prev_good_synth);
    v.leaf(pre, "prev_sign_switch_fx", &mut p.prev_sign_switch);
    v.leaf(pre, "prev_sign_switch_2_fx", &mut p.prev_sign_switch_2);
    v.leaf(pre, "time_offs_fx", &mut p.time_offs);
    v.leaf(pre, "X_sav_fx", &mut p.x_sav);
    v.leaf(pre, "Q_X_sav", &mut p.q_x_sav);
    v.leaf(pre, "num_p_fx", &mut p.num_p);
    v.leaf(pre, "plocs_fx", &mut p.plocs);
    v.leaf(pre, "plocsi_fx", &mut p.plocsi);
    v.leaf(pre, "env_stab_fx", &mut p.env_stab);
    v.leaf(pre, "mem_norm_hqfec_fx", &mut p.mem_norm_hqfec);
    v.leaf(pre, "mem_env_delta_hqfec_fx", &mut p.mem_env_delta_hqfec);
    v.leaf(pre, "env_stab_plc_fx", &mut p.env_stab_plc);
    v.leaf(pre, "env_stab_state_p_fx", &mut p.env_stab_state_p);
    v.leaf(pre, "envstabplc_hocnt_fx", &mut p.envstabplc_hocnt);
    v.leaf(pre, "mag_chg_1st_fx", &mut p.mag_chg_1st);
    v.leaf(pre, "Xavg_fx", &mut p.xavg);
    v.leaf(pre, "beta_mute_fx", &mut p.beta_mute);
    v.leaf(pre, "last_fec_fx", &mut p.last_fec);
    v.leaf(pre, "ph_ecu_HqVoicing_fx", &mut p.ph_ecu_hq_voicing);
    v.leaf(pre, "oldHqVoicing_fx", &mut p.old_hq_voicing);
    v.leaf(pre, "oldgapsynth_fx", &mut p.oldgapsynth);
    v.leaf(pre, "ph_ecu_active_fx", &mut p.ph_ecu_active);
    v.leaf(pre, "ni_seed_forfec", &mut p.ni_seed_forfec);
    v.leaf(pre, "ber_occured_in_pvq", &mut p.ber_occured_in_pvq);
    v.leaf(pre, "LDm_mem_etot_fx", &mut p.l_dm_mem_etot);
    v.leaf(pre, "LDm_last_music_flag_fx", &mut p.l_dm_last_music_flag);
    v.leaf(pre, "LDm_nb_thr_1_fx", &mut p.l_dm_nb_thr_1);
    v.leaf(pre, "LDm_nb_thr_3_fx", &mut p.l_dm_nb_thr_3);
    v.leaf(pre, "dct_post_old_exc_fx", &mut p.dct_post_old_exc);
    v.leaf(pre, "LDm_thres_fx", &mut p.l_dm_thres);
    v.leaf(pre, "LDm_lt_diff_etot_fx", &mut p.l_dm_lt_diff_etot);
    v.leaf(pre, "LDm_enh_lp_gbin_fx", &mut p.l_dm_enh_lp_gbin);
    v.leaf(pre, "LDm_enh_lf_EO_fx", &mut p.l_dm_enh_lf_eo);
    v.leaf(pre, "LDm_enh_min_ns_gain_fx", &mut p.l_dm_enh_min_ns_gain);
    v.leaf(pre, "LDm_bckr_noise_fx", &mut p.l_dm_bckr_noise);
    v.leaf(pre, "filt_lfE_fx", &mut p.filt_lf_e);
    v.leaf(pre, "last_nonfull_music_fx", &mut p.last_nonfull_music);
    v.leaf(pre, "Old_ener_Q", &mut p.old_ener_q);
    v.leaf(pre, "Q_exc", &mut p.q_exc);
    v.leaf(pre, "prev_Q_exc", &mut p.prev_q_exc);
    v.leaf(pre, "Q_subfr", &mut p.q_subfr);
    v.leaf(pre, "prev_Q_bwe_syn", &mut p.prev_q_bwe_syn);
    v.leaf(pre, "prev_Q_bwe_syn2", &mut p.prev_q_bwe_syn2);
    v.leaf(pre, "Q_syn2", &mut p.q_syn2);
    v.leaf(pre, "Q_syn", &mut p.q_syn);
    v.leaf(pre, "prev_Q_syn", &mut p.prev_q_syn);
    v.leaf(pre, "prev_hb_synth_fx_exp", &mut p.prev_hb_synth_fx_exp);
    v.leaf(pre, "prev_synth_buffer_fx", &mut p.prev_synth_buffer);
    v.leaf(pre, "prev_lpc_wb_fx", &mut p.prev_lpc_wb);
    v.leaf(pre, "GainShape_Delay", &mut p.gain_shape_delay);
    v.leaf(
        pre,
        "vbr_hw_BWE_disable_dec_fx",
        &mut p.vbr_hw_bwe_disable_dec,
    );
    v.leaf(
        pre,
        "last_vbr_hw_BWE_disable_dec_fx",
        &mut p.last_vbr_hw_bwe_disable_dec,
    );
    if let Some(h) = v.handle(pre, "cldfbAna_fx", &mut p.cldfb_ana) {
        let b = format!("{pre}cldfbAna_fx.");
        visit_cldfb_filter_bank(v, &b, h);
    }
    if let Some(h) = v.handle(pre, "cldfbBPF_fx", &mut p.cldfb_bpf) {
        let b = format!("{pre}cldfbBPF_fx.");
        visit_cldfb_filter_bank(v, &b, h);
    }
    if let Some(h) = v.handle(pre, "cldfbSyn_fx", &mut p.cldfb_syn) {
        let b = format!("{pre}cldfbSyn_fx.");
        visit_cldfb_filter_bank(v, &b, h);
    }
    v.leaf(
        pre,
        "last_active_bandsToZero_bwdec",
        &mut p.last_active_bands_to_zero_bwdec,
    );
    v.leaf(pre, "flag_NB_bwddec", &mut p.flag_nb_bwddec);
    v.leaf(pre, "last_flag_filter_NB", &mut p.last_flag_filter_nb);
    v.leaf(pre, "perc_bwddec", &mut p.perc_bwddec);
    v.leaf(
        pre,
        "active_frame_cnt_bwddec",
        &mut p.active_frame_cnt_bwddec,
    );
    v.leaf(pre, "flag_buffer", &mut p.flag_buffer);
    v.leaf(pre, "total_frame_cnt_bwddec", &mut p.total_frame_cnt_bwddec);
    v.leaf(pre, "avg_nrg_LT", &mut p.avg_nrg_lt);
    if let Some(h) = v.handle(pre, "hFdCngDec_fx", &mut p.h_fd_cng_dec) {
        let b = format!("{pre}hFdCngDec_fx.");
        visit_fd_cng_dec(v, &b, h);
    }
    v.leaf(pre, "force_lpd_reset", &mut p.force_lpd_reset);
    let b = format!("{pre}acelp_cfg.");
    visit_acelp_config(v, &b, &mut p.acelp_cfg);
    let b = format!("{pre}acelp_cfg_rf.");
    visit_acelp_config(v, &b, &mut p.acelp_cfg_rf);
    let b = format!("{pre}tcx_cfg.");
    visit_tcx_config(v, &b, &mut p.tcx_cfg);
    v.leaf(pre, "L_frameTCX", &mut p.l_frame_tcx);
    v.leaf(pre, "m_decodeMode", &mut p.m_decode_mode);
    v.leaf(pre, "m_frame_type", &mut p.m_frame_type);
    v.leaf(pre, "m_old_frame_type", &mut p.m_old_frame_type);
    v.leaf(pre, "bits_frame", &mut p.bits_frame);
    v.leaf(pre, "bits_frame_core", &mut p.bits_frame_core);
    v.leaf(pre, "narrowBand", &mut p.narrow_band);
    v.leaf(pre, "bits_common", &mut p.bits_common);
    v.leaf(pre, "last_is_cng", &mut p.last_is_cng);
    v.leaf(pre, "old_syn_Overl", &mut p.old_syn_overl);
    v.leaf(pre, "syn_Overl_TDAC", &mut p.syn_overl_tdac);
    v.leaf(pre, "syn_Overl_TDACFB", &mut p.syn_overl_tdacfb);
    v.leaf(pre, "syn_Overl", &mut p.syn_overl);
    v.leaf(pre, "syn_OverlFB", &mut p.syn_overl_fb);
    v.leaf(pre, "old_synth", &mut p.old_synth);
    v.leaf(pre, "old_synth_len", &mut p.old_synth_len);
    v.leaf(pre, "old_synth_lenFB", &mut p.old_synth_len_fb);
    v.leaf(pre, "syn", &mut p.syn);
    v.leaf(pre, "bpf_gain_param", &mut p.bpf_gain_param);
    v.leaf(pre, "L_frame_past", &mut p.l_frame_past);
    v.leaf(pre, "L_frameTCX_past", &mut p.l_frame_tcx_past);
    v.leaf(pre, "lsfold_uw", &mut p.lsfold_uw);
    v.leaf(pre, "lspold_uw", &mut p.lspold_uw);
    v.leaf(pre, "seed_tcx_plc", &mut p.seed_tcx_plc);
    v.leaf(pre, "past_gpit", &mut p.past_gpit);
    v.leaf(pre, "past_gcode", &mut p.past_gcode);
    v.leaf(pre, "lsf_cng", &mut p.lsf_cng);
    v.leaf(pre, "lspold_cng", &mut p.lspold_cng);
    v.leaf(
        pre,
        "plcBackgroundNoiseUpdated",
        &mut p.plc_background_noise_updated,
    );
    v.leaf(pre, "lsp_q_cng", &mut p.lsp_q_cng);
    v.leaf(pre, "old_lsp_q_cng", &mut p.old_lsp_q_cng);
    v.leaf(pre, "lsf_q_cng", &mut p.lsf_q_cng);
    v.leaf(pre, "old_lsf_q_cng", &mut p.old_lsf_q_cng);
    v.leaf(pre, "Aq_cng", &mut p.aq_cng);
    v.leaf(pre, "mem_syn_unv_back", &mut p.mem_syn_unv_back);
    v.leaf(pre, "last_gain_syn_deemph", &mut p.last_gain_syn_deemph);
    v.leaf(pre, "last_gain_syn_deemph_e", &mut p.last_gain_syn_deemph_e);
    v.leaf(
        pre,
        "last_concealed_gain_syn_deemph",
        &mut p.last_concealed_gain_syn_deemph,
    );
    v.leaf(
        pre,
        "last_concealed_gain_syn_deemph_e",
        &mut p.last_concealed_gain_syn_deemph_e,
    );
    v.leaf(pre, "enableTcxLpc", &mut p.enable_tcx_lpc);
    v.leaf(pre, "envWeighted", &mut p.env_weighted);
    v.leaf(pre, "nb_subfr", &mut p.nb_subfr);
    v.leaf(pre, "fscale", &mut p.fscale);
    v.leaf(pre, "fscale_old", &mut p.fscale_old);
    v.leaf(pre, "sr_core", &mut p.sr_core);
    v.leaf(pre, "pit_min", &mut p.pit_min);
    v.leaf(pre, "pit_fr1", &mut p.pit_fr1);
    v.leaf(pre, "pit_fr1b", &mut p.pit_fr1b);
    v.leaf(pre, "pit_fr2", &mut p.pit_fr2);
    v.leaf(pre, "pit_max", &mut p.pit_max);
    v.leaf(pre, "pit_res_max", &mut p.pit_res_max);
    v.leaf(pre, "pit_res_max_past", &mut p.pit_res_max_past);
    v.leaf(pre, "pit_max_TCX", &mut p.pit_max_tcx);
    v.leaf(pre, "pit_min_TCX", &mut p.pit_min_tcx);
    v.leaf(pre, "preemph_fac", &mut p.preemph_fac);
    v.leaf(pre, "gamma", &mut p.gamma);
    v.leaf(pre, "inv_gamma", &mut p.inv_gamma);
    v.leaf(pre, "mem_Aq", &mut p.mem_aq);
    v.leaf(pre, "last_core_bfi", &mut p.last_core_bfi);
    v.leaf(pre, "nbLostCmpt", &mut p.nb_lost_cmpt);
    v.leaf(pre, "prev_nbLostCmpt", &mut p.prev_nb_lost_cmpt);
    v.leaf(pre, "mode_lvq", &mut p.mode_lvq);
    v.leaf(pre, "old_fpitch", &mut p.old_fpitch);
    v.leaf(pre, "old_fpitchFB", &mut p.old_fpitch_fb);
    v.leaf(pre, "clas_dec", &mut p.clas_dec);
    v.leaf(pre, "mem_pitch_gain", &mut p.mem_pitch_gain);
    v.leaf(pre, "plc_use_future_lag", &mut p.plc_use_future_lag);
    v.leaf(pre, "prev_widow_left_rect", &mut p.prev_widow_left_rect);
    v.leaf(pre, "Mode2_lp_gainc", &mut p.mode2_lp_gainc);
    v.leaf(pre, "Mode2_lp_gainp", &mut p.mode2_lp_gainp);
    v.leaf(
        pre,
        "conCngLevelBackgroundTrace",
        &mut p.con_cng_level_background_trace,
    );
    v.leaf(
        pre,
        "conCngLevelBackgroundTrace_e",
        &mut p.con_cng_level_background_trace_e,
    );
    v.leaf(pre, "conNoiseLevelMemory", &mut p.con_noise_level_memory);
    v.leaf(
        pre,
        "conNoiseLevelMemory_e",
        &mut p.con_noise_level_memory_e,
    );
    v.leaf(pre, "conNoiseLevelIndex", &mut p.con_noise_level_index);
    v.leaf(pre, "conCurrLevelIndex", &mut p.con_curr_level_index);
    v.leaf(pre, "conLastFrameLevel", &mut p.con_last_frame_level);
    v.leaf(pre, "conLastFrameLevel_e", &mut p.con_last_frame_level_e);
    v.leaf(pre, "old_gaintcx_bfi", &mut p.old_gaintcx_bfi);
    v.leaf(pre, "old_gaintcx_bfi_e", &mut p.old_gaintcx_bfi_e);
    v.leaf(
        pre,
        "cummulative_damping_tcx",
        &mut p.cummulative_damping_tcx,
    );
    v.leaf(pre, "cummulative_damping", &mut p.cummulative_damping);
    v.leaf(pre, "cngTDLevel", &mut p.cng_td_level);
    v.leaf(pre, "cngTDLevel_e", &mut p.cng_td_level_e);
    v.leaf(pre, "conceal_eof_gain", &mut p.conceal_eof_gain);
    v.leaf(pre, "damping", &mut p.damping);
    v.leaf(pre, "gainHelper", &mut p.gain_helper);
    v.leaf(pre, "gainHelper_e", &mut p.gain_helper_e);
    v.leaf(pre, "stepCompensate", &mut p.step_compensate);
    v.leaf(pre, "stepCompensate_e", &mut p.step_compensate_e);
    v.leaf(pre, "reset_mem_AR", &mut p.reset_mem_ar);
    v.leaf(pre, "tcxConceal_recalc_exc", &mut p.tcx_conceal_recalc_exc);
    v.leaf(pre, "classifier_Q_mem_syn", &mut p.classifier_q_mem_syn);
    v.leaf(pre, "rate_switching_init", &mut p.rate_switching_init);
    v.leaf(pre, "lpcQuantization", &mut p.lpc_quantization);
    v.leaf(pre, "numlpc", &mut p.numlpc);
    v.leaf(pre, "TcxBandwidth", &mut p.tcx_bandwidth);
    let b = format!("{pre}pfstat.");
    visit_pfstat(v, &b, &mut p.pfstat);
    v.leaf(pre, "psf_lp_noise_fx", &mut p.psf_lp_noise);
    v.leaf(pre, "voice_fac", &mut p.voice_fac);
    v.leaf(pre, "tcxonly", &mut p.tcxonly);
    v.leaf(pre, "resQBits", &mut p.res_q_bits);
    v.leaf(pre, "last_ctx_hm_enabled", &mut p.last_ctx_hm_enabled);
    v.leaf(pre, "tcxltp", &mut p.tcxltp);
    v.leaf(pre, "tcxltp_gain", &mut p.tcxltp_gain);
    v.leaf(pre, "tcxltp_pitch_int", &mut p.tcxltp_pitch_int);
    v.leaf(pre, "tcxltp_pitch_fr", &mut p.tcxltp_pitch_fr);
    v.leaf(pre, "tcxltp_mem_in", &mut p.tcxltp_mem_in);
    v.leaf(pre, "tcxltp_mem_out", &mut p.tcxltp_mem_out);
    v.leaf(
        pre,
        "tcxltp_pitch_int_post_prev",
        &mut p.tcxltp_pitch_int_post_prev,
    );
    v.leaf(
        pre,
        "tcxltp_pitch_fr_post_prev",
        &mut p.tcxltp_pitch_fr_post_prev,
    );
    v.leaf(pre, "tcxltp_gain_post_prev", &mut p.tcxltp_gain_post_prev);
    v.leaf(pre, "tcxltp_filt_idx_prev", &mut p.tcxltp_filt_idx_prev);
    let b = format!("{pre}tonalMDCTconceal.");
    visit_tonalmdctconceal(v, &b, &mut p.tonal_mdc_tconceal);
    v.leaf(pre, "tonal_mdct_plc_active", &mut p.tonal_mdct_plc_active);
    v.leaf(pre, "last_tns_active", &mut p.last_tns_active);
    v.leaf(pre, "second_last_tns_active", &mut p.second_last_tns_active);
    v.leaf(pre, "second_last_core", &mut p.second_last_core);
    v.leaf(
        pre,
        "tcxltp_second_last_pitch",
        &mut p.tcxltp_second_last_pitch,
    );
    v.leaf(
        pre,
        "tcxltp_third_last_pitch",
        &mut p.tcxltp_third_last_pitch,
    );
    v.leaf(
        pre,
        "tcxltp_last_gain_unmodified",
        &mut p.tcxltp_last_gain_unmodified,
    );
    v.leaf(pre, "FBTCXdelayBuf", &mut p.fbtc_xdelay_buf);
    v.leaf(pre, "mem_syn_r", &mut p.mem_syn_r);
    v.leaf(pre, "rate_switching_reset", &mut p.rate_switching_reset);
    v.leaf(pre, "lp_error_ener", &mut p.lp_error_ener);
    v.leaf(pre, "mem_error", &mut p.mem_error);
    v.leaf(pre, "bpf_noise_buf", &mut p.bpf_noise_buf);
    v.offset_opt(pre, "p_bpf_noise_buf", &mut p.p_bpf_noise_buf);
    v.leaf(pre, "enableGplc", &mut p.enable_gplc);
    v.leaf(pre, "flagGuidedAcelp", &mut p.flag_guided_acelp);
    v.leaf(pre, "T0_4th", &mut p.t0_4th);
    v.leaf(pre, "guidedT0", &mut p.guided_t0);
    v.leaf(pre, "enablePlcWaveadjust", &mut p.enable_plc_waveadjust);
    v.leaf(pre, "tonality_flag", &mut p.tonality_flag);
    let b = format!("{pre}plcInfo.");
    visit_tplc_info(v, &b, &mut p.plc_info);
    v.leaf(pre, "VAD", &mut p.vad);
    v.leaf(pre, "flag_cna", &mut p.flag_cna);
    v.leaf(pre, "last_flag_cna", &mut p.last_flag_cna);
    v.leaf(pre, "lp_noise", &mut p.lp_noise);
    v.leaf(pre, "seed_acelp", &mut p.seed_acelp);
    v.leaf(pre, "core_ext_mode", &mut p.core_ext_mode);
    v.leaf(pre, "dec_glr", &mut p.dec_glr);
    v.leaf(pre, "dec_glr_idx", &mut p.dec_glr_idx);
    v.leaf(pre, "tcx_hm_LtpPitchLag", &mut p.tcx_hm_ltp_pitch_lag);
    v.leaf(pre, "tcx_lpc_shaped_ari", &mut p.tcx_lpc_shaped_ari);
    v.leaf(pre, "igf", &mut p.igf);
    let b = format!("{pre}hIGFDec.");
    visit_igfdec_instance(v, &b, &mut p.h_igf_dec);
    let b = format!("{pre}scaleFactor.");
    visit_cldfb_scale_factor(v, &b, &mut p.scale_factor);
    v.leaf(pre, "tec_tfa", &mut p.tec_tfa);
    v.leaf(pre, "tec_flag", &mut p.tec_flag);
    v.leaf(pre, "tfa_flag", &mut p.tfa_flag);
    let b = format!("{pre}tecDec_fx.");
    visit_temporal_envelope_coding_decoder_fx(v, &b, &mut p.tec_dec);
    v.leaf(pre, "con_tcx", &mut p.con_tcx);
    v.leaf(pre, "last_con_tcx", &mut p.last_con_tcx);
    v.leaf(pre, "old_ppp_mode_fx", &mut p.old_ppp_mode);
    v.leaf(pre, "old_hb_synth_fx", &mut p.old_hb_synth);
    v.leaf(pre, "prev_Q_exc_fr", &mut p.prev_q_exc_fr);
    v.leaf(pre, "prev_Q_syn_fr", &mut p.prev_q_syn_fr);
    v.leaf(pre, "writeFECoffset", &mut p.write_fe_coffset);
}
