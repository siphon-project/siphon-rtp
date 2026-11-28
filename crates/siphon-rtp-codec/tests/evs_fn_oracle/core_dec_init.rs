//! `lib_dec/core_dec_init.c` against `fn_core_dec_init` (`open_decoder_LPD`).
//!
//! The oracle prints every field `open_decoder_LPD` reads or writes before and after the last of
//! one to four consecutive calls (a fresh decoder, then switches of bit rate, bandwidth, core rate
//! and codec mode). Arrays it only writes are filled with a deterministic pattern on both sides
//! and compared by an FNV-1a hash; the CLDFB banks likewise.

use siphon_rtp_codec::evs::cnst::{CLDFB_ANALYSIS, CLDFB_SYNTHESIS};
use siphon_rtp_codec::evs::com::cldfb::{cldfb_get_num_channels, open_cldfb};
use siphon_rtp_codec::evs::dec::core_dec_init::open_decoder_lpd;
use siphon_rtp_codec::evs::dec::state::{CldfbFilterBank, DecoderState};

use crate::common::{corpus_sized, Case};
use crate::tns_base::{table_from_id, table_id};

/// `STATE_BUFFER_SIZE` of `cldfb.c`.
const CLDFB_STATE_BUFFER_SIZE: usize = 9 + 16;

/// A state field as the oracle prints it: a list of integers.
trait Field {
    fn load(&mut self, values: &[i64]);
    fn dump(&self) -> Vec<i64>;
}

macro_rules! scalar_field {
    ($($t:ty),*) => {$(
        impl Field for $t {
            fn load(&mut self, values: &[i64]) {
                *self = values[0] as $t;
            }
            fn dump(&self) -> Vec<i64> {
                vec![i64::from(*self)]
            }
        }
        impl<const N: usize> Field for [$t; N] {
            fn load(&mut self, values: &[i64]) {
                assert_eq!(values.len(), N);
                for (slot, &value) in self.iter_mut().zip(values) {
                    *slot = value as $t;
                }
            }
            fn dump(&self) -> Vec<i64> {
                self.iter().map(|&value| i64::from(value)).collect()
            }
        }
    )*};
}
scalar_field!(i8, i16, i32);

/// A pointer printed as an offset into its buffer, -1 for NULL.
impl Field for Option<usize> {
    fn load(&mut self, values: &[i64]) {
        *self = usize::try_from(values[0]).ok();
    }
    fn dump(&self) -> Vec<i64> {
        vec![self.map_or(-1, |offset| offset as i64)]
    }
}

/// The value the oracle's `fill_pattern16` / `fill_pattern32` stores at `i`.
fn pattern(i: usize, salt: i64) -> i64 {
    (i as i64 * 31 + salt * 17) % 2001 - 1000
}

/// An array filled with the oracle's pattern and compared by its FNV-1a hash.
trait Hashed {
    fn fill_pattern(&mut self, salt: i64);
    fn pattern_hash(&self) -> i64;
}

impl Hashed for [i16] {
    fn fill_pattern(&mut self, salt: i64) {
        for (i, slot) in self.iter_mut().enumerate() {
            *slot = pattern(i, salt) as i16;
        }
    }
    fn pattern_hash(&self) -> i64 {
        let mut h: u32 = 2_166_136_261;
        for &value in self {
            h ^= u32::from(value as u16);
            h = h.wrapping_mul(16_777_619);
        }
        i64::from(h)
    }
}

impl Hashed for [i32] {
    fn fill_pattern(&mut self, salt: i64) {
        for (i, slot) in self.iter_mut().enumerate() {
            *slot = (pattern(i, salt) * 65537) as i32;
        }
    }
    fn pattern_hash(&self) -> i64 {
        let mut h: u32 = 2_166_136_261;
        for &value in self {
            h ^= value as u32;
            h = h.wrapping_mul(16_777_619);
        }
        i64::from(h)
    }
}

/// Loads the inputs of a case into the state, or compares the state with its outputs.
struct Visitor<'a> {
    case: &'a Case,
    load: bool,
}

impl Visitor<'_> {
    fn values(&self, name: &str) -> &[i64] {
        let side = if self.load {
            &self.case.inputs
        } else {
            &self.case.outputs
        };
        side.get(name).unwrap_or_else(|| panic!("no field {name}"))
    }

    fn check(&self, name: &str, rust: &[i64]) {
        let reference = self.values(name);
        assert!(
            rust == reference,
            "{name} differs\n  rust: {rust:?}\n  ref:  {reference:?}\n  case inputs: bitrate={:?} bandwidth={:?} output_fs={:?} ini_frame={:?} last_l_frame={:?} last_codec_mode={:?} last_core={:?}",
            self.case.inputs.get("bitrate"),
            self.case.inputs.get("bandwidth"),
            self.case.inputs.get("output_fs"),
            self.case.inputs.get("ini_frame"),
            self.case.inputs.get("last_l_frame"),
            self.case.inputs.get("last_codec_mode"),
            self.case.inputs.get("last_core"),
        );
    }

    fn visit(&self, name: &str, field: &mut dyn Field) {
        if self.load {
            field.load(self.values(name));
        } else {
            self.check(name, &field.dump());
        }
    }

    fn visit_hashed<T: Hashed + ?Sized>(&self, name: &str, field: &mut T, salt: i64) {
        if self.load {
            field.fill_pattern(salt);
        } else {
            self.check(name, &[field.pattern_hash()]);
        }
    }

    fn visit_tns_pointer(&self, name: &str, field: &mut Option<(usize, usize)>) {
        if self.load {
            *field = usize::try_from(self.values(name)[0])
                .ok()
                .map(|index| (index / 2, index % 2));
        } else {
            let dumped = field.map_or(-1, |(i, j)| (i * 2 + j) as i64);
            self.check(name, &[dumped]);
        }
    }

    fn visit_tns(&self, st: &mut DecoderState) {
        for (i, row) in st.tcx_cfg.tns_config.iter_mut().enumerate() {
            for (j, config) in row.iter_mut().enumerate() {
                let name = format!("tns{i}{j}");
                if self.load {
                    let v = self.values(&name);
                    config.max_order = v[0] as i16;
                    config.n_max_filters = v[1] as i16;
                    config.p_tns_parameters = table_from_id(v[2] as i16);
                    for (k, border) in config.i_filter_borders.iter_mut().enumerate() {
                        *border = v[3 + k] as i16;
                    }
                } else {
                    let mut rust = vec![
                        i64::from(config.max_order),
                        i64::from(config.n_max_filters),
                        i64::from(table_id(config.p_tns_parameters)),
                    ];
                    rust.extend(config.i_filter_borders.iter().map(|&b| i64::from(b)));
                    self.check(&name, &rust);
                }
            }
        }
    }
}

/// The fields `open_decoder_LPD` reads or writes, in the oracle's order.
fn visit_fields(st: &mut DecoderState, v: &Visitor) {
    visit_fields_configuration(st, v);
    visit_fields_memories(st, v);
}

/// The inputs, frame configuration and switching memories.
fn visit_fields_configuration(st: &mut DecoderState, v: &Visitor) {
    v.visit("ini_frame", &mut st.ini_frame);
    v.visit("output_fs", &mut st.output_fs);
    v.visit("output_frame", &mut st.output_frame);
    v.visit("rf_flag", &mut st.rf_flag);
    v.visit("igf", &mut st.igf);
    v.visit("bwidth", &mut st.bwidth);
    v.visit("last_bwidth", &mut st.last_bwidth);
    v.visit(
        "h_igf_dec.info_igf_stop_freq",
        &mut st.h_igf_dec.info_igf_stop_freq,
    );
    v.visit("last_codec_mode", &mut st.last_codec_mode);
    v.visit("core", &mut st.core);
    v.visit("m_frame_type", &mut st.m_frame_type);
    v.visit("last_con_tcx", &mut st.last_con_tcx);
    v.visit("last_total_brate", &mut st.last_total_brate);
    v.visit("q_syn", &mut st.q_syn);
    v.visit("pst_lp_ener", &mut st.pst_lp_ener);
    v.visit("force_lpd_reset", &mut st.force_lpd_reset);
    v.visit("fer_samples", &mut st.fer_samples);
    v.visit("previoussynth", &mut st.previoussynth);
    v.visit("total_brate", &mut st.total_brate);
    v.visit("fscale_old", &mut st.fscale_old);
    v.visit("sr_core", &mut st.sr_core);
    v.visit("fscale", &mut st.fscale);
    v.visit("l_frame", &mut st.l_frame);
    v.visit("l_frame_tcx", &mut st.l_frame_tcx);
    v.visit("last_l_frame", &mut st.last_l_frame);
    v.visit("l_frame_past", &mut st.l_frame_past);
    v.visit("l_frame_tcx_past", &mut st.l_frame_tcx_past);
    v.visit("tcxonly", &mut st.tcxonly);
    v.visit("nb_subfr", &mut st.nb_subfr);
    v.visit("bits_frame", &mut st.bits_frame);
    v.visit("tcx_bandwidth", &mut st.tcx_bandwidth);
    v.visit("narrow_band", &mut st.narrow_band);
    v.visit("pit_min", &mut st.pit_min);
    v.visit("pit_fr1", &mut st.pit_fr1);
    v.visit("pit_fr1b", &mut st.pit_fr1b);
    v.visit("pit_fr2", &mut st.pit_fr2);
    v.visit("pit_max", &mut st.pit_max);
    v.visit("pit_res_max", &mut st.pit_res_max);
    v.visit("pit_res_max_past", &mut st.pit_res_max_past);
    v.visit("pit_max_tcx", &mut st.pit_max_tcx);
    v.visit("pit_min_tcx", &mut st.pit_min_tcx);
    v.visit("preemph_fac", &mut st.preemph_fac);
    v.visit("gamma", &mut st.gamma);
    v.visit("inv_gamma", &mut st.inv_gamma);
    v.visit("lpc_quantization", &mut st.lpc_quantization);
    v.visit("numlpc", &mut st.numlpc);
    v.visit("prev_coder_type", &mut st.prev_coder_type);
    v.visit("prev_lsf_diff", &mut st.prev_lsf_diff);
    v.visit("prev_tilt_para", &mut st.prev_tilt_para);
    v.visit("cur_sub_aq", &mut st.cur_sub_aq);
    v.visit("tcx_cfg.preemph_fac", &mut st.tcx_cfg.preemph_fac);
    v.visit(
        "tcx_cfg.tcx_mdct_window_length",
        &mut st.tcx_cfg.tcx_mdct_window_length,
    );
    v.visit(
        "tcx_cfg.tcx_mdct_window_length_old",
        &mut st.tcx_cfg.tcx_mdct_window_length_old,
    );
    v.visit(
        "tcx_cfg.tcx_mdct_window_delay",
        &mut st.tcx_cfg.tcx_mdct_window_delay,
    );
    v.visit(
        "tcx_cfg.tcx_mdct_window_length_fb",
        &mut st.tcx_cfg.tcx_mdct_window_length_fb,
    );
    v.visit(
        "tcx_cfg.tcx_mdct_window_delay_fb",
        &mut st.tcx_cfg.tcx_mdct_window_delay_fb,
    );
    v.visit(
        "tcx_cfg.tcx_last_overlap_mode",
        &mut st.tcx_cfg.tcx_last_overlap_mode,
    );
    v.visit(
        "tcx_cfg.tcx_curr_overlap_mode",
        &mut st.tcx_cfg.tcx_curr_overlap_mode,
    );
    v.visit("tcx_cfg.tcx_offset", &mut st.tcx_cfg.tcx_offset);
    v.visit("tcx_cfg.tcx_offset_fb", &mut st.tcx_cfg.tcx_offset_fb);
    v.visit("tcx_cfg.lfac_next", &mut st.tcx_cfg.lfac_next);
    v.visit("tcx_cfg.lfac_next_fb", &mut st.tcx_cfg.lfac_next_fb);
    v.visit("tcx_cfg.tcx_coded_lines", &mut st.tcx_cfg.tcx_coded_lines);
    v.visit("tcx_cfg.f_is_tns_allowed", &mut st.tcx_cfg.f_is_tns_allowed);
    v.visit("tcx_cfg.last_aldo", &mut st.tcx_cfg.last_aldo);
    v.visit("tcx_cfg.ctx_hm", &mut st.tcx_cfg.ctx_hm);
    v.visit("tcx_cfg.resq", &mut st.tcx_cfg.resq);
    v.visit("tcx_cfg.sq_rounding", &mut st.tcx_cfg.sq_rounding);
    v.visit("tcx_cfg.na_scale", &mut st.tcx_cfg.na_scale);
    v.visit("tec_dec.p_gain_temp_m", &mut st.tec_dec.p_gain_temp_m);
    v.visit("tec_dec.p_gain_temp_e", &mut st.tec_dec.p_gain_temp_e);
    v.visit("tec_dec.lo_buffer", &mut st.tec_dec.lo_buffer);
    v.visit("flag_cna", &mut st.flag_cna);
    v.visit("last_flag_cna", &mut st.last_flag_cna);
    v.visit("last_is_cng", &mut st.last_is_cng);
    v.visit("rate_switching_reset", &mut st.rate_switching_reset);
    v.visit_hashed("old_syn_overl", &mut st.old_syn_overl[..], 1);
    v.visit_hashed("syn_overl_tdac", &mut st.syn_overl_tdac[..], 2);
    v.visit_hashed("syn_overl_fb", &mut st.syn_overl_fb[..], 3);
    v.visit_hashed("syn_overl_tdacfb", &mut st.syn_overl_tdacfb[..], 4);
    v.visit_hashed("syn_overl", &mut st.syn_overl[..], 5);
    v.visit_hashed("old_synth", &mut st.old_synth[..], 6);
    v.visit_hashed("synth_history", &mut st.synth_history[..], 7);
    v.visit("syn", &mut st.syn);
    v.visit("mem_syn_r", &mut st.mem_syn_r);
    v.visit("con_tcx", &mut st.con_tcx);
    v.visit("mem_ma", &mut st.mem_ma);
    v.visit("mem_ar", &mut st.mem_ar);
    v.visit("lspold_uw", &mut st.lspold_uw);
    v.visit("lsfold_uw", &mut st.lsfold_uw);
    v.visit("last_core", &mut st.last_core);
    v.visit("last_core_bfi", &mut st.last_core_bfi);
    v.visit("q_old_wtda", &mut st.q_old_wtda);
    v.visit("old_out", &mut st.old_out);
    v.visit("old_out_lb", &mut st.old_out_lb);
    v.visit("q_old_wtda_lb", &mut st.q_old_wtda_lb);
    v.visit("tilt_code", &mut st.tilt_code);
    v.visit("old_exc", &mut st.old_exc);
    v.visit("mem_syn2", &mut st.mem_syn2);
    v.visit("pfstat.on", &mut st.pfstat.on);
    v.visit("pfstat.reset", &mut st.pfstat.reset);
    v.visit("pfstat.mem_pf_in", &mut st.pfstat.mem_pf_in);
    v.visit("pfstat.mem_stp", &mut st.pfstat.mem_stp);
    v.visit("pfstat.mem_res2", &mut st.pfstat.mem_res2);
    v.visit("pfstat.gain_prec", &mut st.pfstat.gain_prec);
}

/// The LSF, concealment, TCX-LTP and tool state.
fn visit_fields_memories(st: &mut DecoderState, v: &Visitor) {
    v.visit("lsp_old", &mut st.lsp_old);
    v.visit("lsf_old", &mut st.lsf_old);
    v.visit("old_aq_12_8", &mut st.old_aq_12_8);
    v.visit("old_synth_len", &mut st.old_synth_len);
    v.visit("old_synth_len_fb", &mut st.old_synth_len_fb);
    v.visit("bpf_gain_param", &mut st.bpf_gain_param);
    v.visit("pst_old_syn", &mut st.pst_old_syn);
    v.visit("lsf_cng", &mut st.lsf_cng);
    v.visit("seed_tcx_plc", &mut st.seed_tcx_plc);
    v.visit("past_gpit", &mut st.past_gpit);
    v.visit("past_gcode", &mut st.past_gcode);
    v.visit("gc_threshold", &mut st.gc_threshold);
    v.visit("lspold_cng", &mut st.lspold_cng);
    v.visit_hashed("aq_cng", &mut st.aq_cng[..], 8);
    v.visit(
        "plc_background_noise_updated",
        &mut st.plc_background_noise_updated,
    );
    v.visit("lsf_q_cng", &mut st.lsf_q_cng);
    v.visit("old_lsf_q_cng", &mut st.old_lsf_q_cng);
    v.visit("lsp_q_cng", &mut st.lsp_q_cng);
    v.visit("old_lsp_q_cng", &mut st.old_lsp_q_cng);
    v.visit("mem_syn_unv_back", &mut st.mem_syn_unv_back);
    v.visit("last_gain_syn_deemph", &mut st.last_gain_syn_deemph);
    v.visit("last_gain_syn_deemph_e", &mut st.last_gain_syn_deemph_e);
    v.visit(
        "last_concealed_gain_syn_deemph",
        &mut st.last_concealed_gain_syn_deemph,
    );
    v.visit(
        "last_concealed_gain_syn_deemph_e",
        &mut st.last_concealed_gain_syn_deemph_e,
    );
    v.visit("conceal_eof_gain", &mut st.conceal_eof_gain);
    v.visit_hashed("mem_aq", &mut st.mem_aq[..], 9);
    v.visit("lp_ener_fer", &mut st.lp_ener_fer);
    v.visit("prev_bfi", &mut st.prev_bfi);
    v.visit("prev_old_bfi", &mut st.prev_old_bfi);
    v.visit("lsf_adaptive_mean", &mut st.lsf_adaptive_mean);
    v.visit("lsfoldbfi0", &mut st.lsfoldbfi0);
    v.visit("lsfoldbfi1", &mut st.lsfoldbfi1);
    v.visit("clas_dec", &mut st.clas_dec);
    v.visit("old_enr_lp", &mut st.old_enr_lp);
    v.visit("enr_old", &mut st.enr_old);
    v.visit("last_good", &mut st.last_good);
    v.visit("mode2_lp_gainc", &mut st.mode2_lp_gainc);
    v.visit("mode2_lp_gainp", &mut st.mode2_lp_gainp);
    v.visit("prev_widow_left_rect", &mut st.prev_widow_left_rect);
    v.visit(
        "con_cng_level_background_trace",
        &mut st.con_cng_level_background_trace,
    );
    v.visit(
        "con_cng_level_background_trace_e",
        &mut st.con_cng_level_background_trace_e,
    );
    v.visit("con_noise_level_index", &mut st.con_noise_level_index);
    v.visit("con_curr_level_index", &mut st.con_curr_level_index);
    v.visit("con_last_frame_level", &mut st.con_last_frame_level);
    v.visit("con_last_frame_level_e", &mut st.con_last_frame_level_e);
    v.visit("con_noise_level_memory", &mut st.con_noise_level_memory);
    v.visit("con_noise_level_memory_e", &mut st.con_noise_level_memory_e);
    v.visit("cummulative_damping_tcx", &mut st.cummulative_damping_tcx);
    v.visit("cummulative_damping", &mut st.cummulative_damping);
    v.visit("old_pitch_buf", &mut st.old_pitch_buf);
    v.visit("mem_pitch_gain", &mut st.mem_pitch_gain);
    v.visit("old_fpitch", &mut st.old_fpitch);
    v.visit("old_fpitch_fb", &mut st.old_fpitch_fb);
    v.visit("rate_switching_init", &mut st.rate_switching_init);
    v.visit("reset_mem_ar", &mut st.reset_mem_ar);
    v.visit("dm.prev_gain_code", &mut st.dm.prev_gain_code);
    v.visit("dm.prev_gain_pit", &mut st.dm.prev_gain_pit);
    v.visit("dm.prev_state", &mut st.dm.prev_state);
    v.visit("voice_fac", &mut st.voice_fac);
    v.visit("tcxltp", &mut st.tcxltp);
    v.visit("tcxltp_pitch_int", &mut st.tcxltp_pitch_int);
    v.visit("tcxltp_pitch_fr", &mut st.tcxltp_pitch_fr);
    v.visit(
        "tcxltp_last_gain_unmodified",
        &mut st.tcxltp_last_gain_unmodified,
    );
    v.visit("tcxltp_mem_in", &mut st.tcxltp_mem_in);
    v.visit_hashed("tcxltp_mem_out", &mut st.tcxltp_mem_out[..], 10);
    v.visit(
        "tcxltp_pitch_int_post_prev",
        &mut st.tcxltp_pitch_int_post_prev,
    );
    v.visit(
        "tcxltp_pitch_fr_post_prev",
        &mut st.tcxltp_pitch_fr_post_prev,
    );
    v.visit("tcxltp_gain_post_prev", &mut st.tcxltp_gain_post_prev);
    v.visit("tcxltp_filt_idx_prev", &mut st.tcxltp_filt_idx_prev);
    v.visit("lp_error_ener", &mut st.lp_error_ener);
    v.visit("mem_error", &mut st.mem_error);
    v.visit("last_ctx_hm_enabled", &mut st.last_ctx_hm_enabled);
    v.visit("tcx_lpc_shaped_ari", &mut st.tcx_lpc_shaped_ari);
    v.visit("env_weighted", &mut st.env_weighted);
    v.visit("tec_tfa", &mut st.tec_tfa);
    v.visit("tec_flag", &mut st.tec_flag);
    v.visit("tfa_flag", &mut st.tfa_flag);
    v.visit("enable_gplc", &mut st.enable_gplc);
    v.visit("flag_guided_acelp", &mut st.flag_guided_acelp);
    v.visit("t0_4th", &mut st.t0_4th);
    v.visit("guided_t0", &mut st.guided_t0);
    v.visit("enable_plc_waveadjust", &mut st.enable_plc_waveadjust);
    v.visit("plc_info.frame_size", &mut st.plc_info.frame_size);
    v.visit("plc_info.pitch", &mut st.plc_info.pitch);
    v.visit("plc_info.t_bfi", &mut st.plc_info.t_bfi);
    v.visit("plc_info.transient", &mut st.plc_info.transient);
    v.visit("plc_info.tcx_tonality", &mut st.plc_info.tcx_tonality);
    v.visit("plc_info.outx_new_n1", &mut st.plc_info.outx_new_n1);
    v.visit("plc_info.nsapp_gain", &mut st.plc_info.nsapp_gain);
    v.visit("plc_info.nsapp_gain_n", &mut st.plc_info.nsapp_gain_n);
    v.visit_hashed("plc_info.data_reci2", &mut st.plc_info.data_reci2[..], 11);
    v.visit("plc_info.ener_mean", &mut st.plc_info.ener_mean);
    v.visit("plc_info.ener", &mut st.plc_info.ener);
    v.visit("plc_info.zp", &mut st.plc_info.zp);
    v.visit("plc_info.recovery_gain", &mut st.plc_info.recovery_gain);
    v.visit(
        "plc_info.step_concealgain",
        &mut st.plc_info.step_concealgain,
    );
    v.visit(
        "plc_info.concealment_method",
        &mut st.plc_info.concealment_method,
    );
    v.visit("plc_info.subframe", &mut st.plc_info.subframe);
    v.visit("plc_info.nb_lost_cmpt", &mut st.plc_info.nb_lost_cmpt);
    v.visit("plc_info.seed", &mut st.plc_info.seed);
    v.visit(
        "tonal_mdc_tconceal.n_scale_factors",
        &mut st.tonal_mdc_tconceal.n_scale_factors,
    );
    v.visit(
        "tonal_mdc_tconceal.n_samples",
        &mut st.tonal_mdc_tconceal.n_samples,
    );
    v.visit(
        "tonal_mdc_tconceal.n_samples_core",
        &mut st.tonal_mdc_tconceal.n_samples_core,
    );
    v.visit(
        "tonal_mdc_tconceal.last_block_data.tonal_concealment_active",
        &mut st
            .tonal_mdc_tconceal
            .last_block_data
            .tonal_concealment_active,
    );
    v.visit(
        "tonal_mdc_tconceal.last_block_data.n_samples",
        &mut st.tonal_mdc_tconceal.last_block_data.n_samples,
    );
    v.visit(
        "tonal_mdc_tconceal.last_block_data.block_is_valid",
        &mut st.tonal_mdc_tconceal.last_block_data.block_is_valid,
    );
    v.visit(
        "tonal_mdc_tconceal.second_last_block_data.block_is_valid",
        &mut st.tonal_mdc_tconceal.second_last_block_data.block_is_valid,
    );
    v.visit("last_tns_active", &mut st.last_tns_active);
    v.visit("second_last_tns_active", &mut st.second_last_tns_active);
    v.visit("second_last_core", &mut st.second_last_core);
    v.visit("tcxltp_second_last_pitch", &mut st.tcxltp_second_last_pitch);
    v.visit("tcxltp_third_last_pitch", &mut st.tcxltp_third_last_pitch);
    v.visit("dec_glr", &mut st.dec_glr);
    v.visit("dec_glr_idx", &mut st.dec_glr_idx);
    v.visit("enable_tcx_lpc", &mut st.enable_tcx_lpc);
    v.visit("vad", &mut st.vad);
    v.visit("old_gaintcx_bfi", &mut st.old_gaintcx_bfi);
    v.visit("old_gaintcx_bfi_e", &mut st.old_gaintcx_bfi_e);
    v.visit("tcx_hm_ltp_pitch_lag", &mut st.tcx_hm_ltp_pitch_lag);
    v.visit("tcxltp_gain", &mut st.tcxltp_gain);
    v.visit("p_bpf_noise_buf", &mut st.p_bpf_noise_buf);
    v.visit(
        "tonal_mdc_tconceal.last_pcm_out",
        &mut st.tonal_mdc_tconceal.last_pcm_out,
    );
    v.visit(
        "tonal_mdc_tconceal.second_last_pcm_out",
        &mut st.tonal_mdc_tconceal.second_last_pcm_out,
    );
    v.visit_tns_pointer(
        "tcx_cfg.p_current_tns_config",
        &mut st.tcx_cfg.p_current_tns_config,
    );
    v.visit_tns(st);
}

fn cldfb_buffer_length(bank: &CldfbFilterBank) -> usize {
    let per_channel = if bank.r#type == CLDFB_ANALYSIS {
        CLDFB_STATE_BUFFER_SIZE
    } else {
        2 * CLDFB_STATE_BUFFER_SIZE
    };
    per_channel * bank.no_channels as usize
}

fn banks(st: &mut DecoderState) -> [(&'static str, &mut CldfbFilterBank); 3] {
    let ana = st.cldfb_ana.as_deref_mut().expect("opened");
    let bpf = st.cldfb_bpf.as_deref_mut().expect("opened");
    let syn = st.cldfb_syn.as_deref_mut().expect("opened");
    [("cldfb_ana", ana), ("cldfb_bpf", bpf), ("cldfb_syn", syn)]
}

#[test]
fn open_decoder_lpd_matches_the_reference() {
    let Some(cases) = corpus_sized("core_dec_init", "open_decoder_lpd", 400) else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let output_fs = case.i32("output_fs");
        let output_frame = case.i16("output_frame");
        open_cldfb(
            &mut st.cldfb_ana,
            CLDFB_ANALYSIS,
            cldfb_get_num_channels(48000),
            320,
        );
        open_cldfb(
            &mut st.cldfb_bpf,
            CLDFB_ANALYSIS,
            cldfb_get_num_channels(16000),
            320,
        );
        open_cldfb(
            &mut st.cldfb_syn,
            CLDFB_SYNTHESIS,
            cldfb_get_num_channels(output_fs),
            output_frame,
        );
        for (b, (_, bank)) in banks(&mut st).into_iter().enumerate() {
            let length = cldfb_buffer_length(bank);
            bank.filter_states[..length].fill_pattern(100 + b as i64);
            for (i, e) in bank.filter_states_e.iter_mut().enumerate() {
                *e = (i % 5 + b) as i16;
            }
            bank.filter_states_eg = 3 + b as i16;
        }

        visit_fields(&mut st, &Visitor { case, load: true });
        open_decoder_lpd(&mut st, case.i32("bitrate"), case.i16("bandwidth"));
        let compare = Visitor { case, load: false };
        visit_fields(&mut st, &compare);
        for (name, bank) in banks(&mut st) {
            let length = cldfb_buffer_length(bank);
            compare.check(
                &format!("{name}_states"),
                &[bank.filter_states[..length].pattern_hash()],
            );
            compare.check(
                &format!("{name}_e"),
                &bank
                    .filter_states_e
                    .iter()
                    .map(|&e| i64::from(e))
                    .collect::<Vec<_>>(),
            );
            compare.check(&format!("{name}_eg"), &[i64::from(bank.filter_states_eg)]);
        }
    }
}
