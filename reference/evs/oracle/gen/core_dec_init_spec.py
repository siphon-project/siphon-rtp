# Field spec for the open_decoder_LPD oracle: (rust path under st, C expression under st->, kind, length)
# kinds: s = scalar, a16/a32 = array printed in full (in and out), h16/h32 = array filled with a
# deterministic pattern before the call and compared by hash after, o = pointer offset (-1 = NULL)
S = [
 # read-only inputs (also compared after, unchanged)
 ("ini_frame","ini_frame_fx","s"),("output_fs","output_Fs_fx","s"),("output_frame","output_frame_fx","s"),
 ("rf_flag","rf_flag","s"),("igf","igf","s"),("bwidth","bwidth_fx","s"),("last_bwidth","last_bwidth_fx","s"),
 ("h_igf_dec.info_igf_stop_freq","hIGFDec.infoIGFStopFreq","s"),("last_codec_mode","last_codec_mode","s"),
 ("core","core_fx","s"),("m_frame_type","m_frame_type","s"),("last_con_tcx","last_con_tcx","s"),
 ("last_total_brate","last_total_brate_fx","s"),("q_syn","Q_syn","s"),("pst_lp_ener","pst_lp_ener_fx","s"),
 ("force_lpd_reset","force_lpd_reset","s"),
 ("fer_samples","fer_samples_fx","a16",960),("previoussynth","previoussynth_fx","a16",960),
 # written
 ("total_brate","total_brate_fx","s"),("fscale_old","fscale_old","s"),("sr_core","sr_core","s"),("fscale","fscale","s"),
 ("l_frame","L_frame_fx","s"),("l_frame_tcx","L_frameTCX","s"),("last_l_frame","last_L_frame_fx","s"),
 ("l_frame_past","L_frame_past","s"),("l_frame_tcx_past","L_frameTCX_past","s"),("tcxonly","tcxonly","s"),
 ("nb_subfr","nb_subfr","s"),("bits_frame","bits_frame","s"),("tcx_bandwidth","TcxBandwidth","s"),
 ("narrow_band","narrowBand","s"),("pit_min","pit_min","s"),("pit_fr1","pit_fr1","s"),("pit_fr1b","pit_fr1b","s"),
 ("pit_fr2","pit_fr2","s"),("pit_max","pit_max","s"),("pit_res_max","pit_res_max","s"),
 ("pit_res_max_past","pit_res_max_past","s"),("pit_max_tcx","pit_max_TCX","s"),("pit_min_tcx","pit_min_TCX","s"),
 ("preemph_fac","preemph_fac","s"),("gamma","gamma","s"),("inv_gamma","inv_gamma","s"),
 ("lpc_quantization","lpcQuantization","s"),("numlpc","numlpc","s"),("prev_coder_type","prev_coder_type_fx","s"),
 ("prev_lsf_diff","prev_lsf_diff_fx","a16",8),("prev_tilt_para","prev_tilt_para_fx","s"),
 ("cur_sub_aq","cur_sub_Aq_fx","a16",17),
 ("tcx_cfg.preemph_fac","tcx_cfg.preemph_fac","s"),("tcx_cfg.tcx_mdct_window_length","tcx_cfg.tcx_mdct_window_length","s"),
 ("tcx_cfg.tcx_mdct_window_length_old","tcx_cfg.tcx_mdct_window_length_old","s"),
 ("tcx_cfg.tcx_mdct_window_delay","tcx_cfg.tcx_mdct_window_delay","s"),
 ("tcx_cfg.tcx_mdct_window_length_fb","tcx_cfg.tcx_mdct_window_lengthFB","s"),
 ("tcx_cfg.tcx_mdct_window_delay_fb","tcx_cfg.tcx_mdct_window_delayFB","s"),
 ("tcx_cfg.tcx_last_overlap_mode","tcx_cfg.tcx_last_overlap_mode","s"),
 ("tcx_cfg.tcx_curr_overlap_mode","tcx_cfg.tcx_curr_overlap_mode","s"),("tcx_cfg.tcx_offset","tcx_cfg.tcx_offset","s"),
 ("tcx_cfg.tcx_offset_fb","tcx_cfg.tcx_offsetFB","s"),("tcx_cfg.lfac_next","tcx_cfg.lfacNext","s"),
 ("tcx_cfg.lfac_next_fb","tcx_cfg.lfacNextFB","s"),("tcx_cfg.tcx_coded_lines","tcx_cfg.tcx_coded_lines","s"),
 ("tcx_cfg.f_is_tns_allowed","tcx_cfg.fIsTNSAllowed","s"),("tcx_cfg.last_aldo","tcx_cfg.last_aldo","s"),
 ("tcx_cfg.ctx_hm","tcx_cfg.ctx_hm","s"),("tcx_cfg.resq","tcx_cfg.resq","s"),("tcx_cfg.sq_rounding","tcx_cfg.sq_rounding","s"),
 ("tcx_cfg.na_scale","tcx_cfg.na_scale","s"),
 ("tec_dec.p_gain_temp_m","tecDec_fx.pGainTemp_m","a16",16),("tec_dec.p_gain_temp_e","tecDec_fx.pGainTemp_e","a16",16),
 ("tec_dec.lo_buffer","tecDec_fx.loBuffer","a16",22),
 ("flag_cna","flag_cna","s"),("last_flag_cna","last_flag_cna","s"),("last_is_cng","last_is_cng","s"),
 ("rate_switching_reset","rate_switching_reset","s"),
 ("old_syn_overl","old_syn_Overl","h16",320),("syn_overl_tdac","syn_Overl_TDAC","h16",320),
 ("syn_overl_fb","syn_OverlFB","h16",480),("syn_overl_tdacfb","syn_Overl_TDACFB","h16",480),
 ("syn_overl","syn_Overl","h16",320),("old_synth","old_synth","h16",1280),("synth_history","synth_history_fx","h16",2496),
 ("syn","syn","a16",17),("mem_syn_r","mem_syn_r","a16",60),("con_tcx","con_tcx","s"),
 ("mem_ma","mem_MA_fx","a16",16),("mem_ar","mem_AR_fx","a16",16),("lspold_uw","lspold_uw","a16",16),
 ("lsfold_uw","lsfold_uw","a16",16),("last_core","last_core_fx","s"),("last_core_bfi","last_core_bfi","s"),
 ("q_old_wtda","Q_old_wtda","s"),("old_out","old_out_fx","a16",960),("old_out_lb","old_out_LB_fx","a16",640),
 ("q_old_wtda_lb","Q_old_wtda_LB","s"),("tilt_code","tilt_code_fx","s"),("old_exc","old_exc_fx","a16",480),
 ("mem_syn2","mem_syn2_fx","a16",16),("pfstat.on","pfstat.on","s"),("pfstat.reset","pfstat.reset","s"),
 ("pfstat.mem_pf_in","pfstat.mem_pf_in","a16",64),("pfstat.mem_stp","pfstat.mem_stp","a16",64),
 ("pfstat.mem_res2","pfstat.mem_res2","a16",299),("pfstat.gain_prec","pfstat.gain_prec","s"),
 ("lsp_old","lsp_old_fx","a16",16),("lsf_old","lsf_old_fx","a16",16),("old_aq_12_8","old_Aq_12_8_fx","a16",17),
 ("old_synth_len","old_synth_len","s"),("old_synth_len_fb","old_synth_lenFB","s"),("bpf_gain_param","bpf_gain_param","s"),
 ("pst_old_syn","pst_old_syn_fx","a16",290),("lsf_cng","lsf_cng","a16",16),("seed_tcx_plc","seed_tcx_plc","s"),
 ("past_gpit","past_gpit","s"),("past_gcode","past_gcode","s"),("gc_threshold","gc_threshold_fx","s"),
 ("lspold_cng","lspold_cng","a16",16),("aq_cng","Aq_cng","h16",102),
 ("plc_background_noise_updated","plcBackgroundNoiseUpdated","s"),("lsf_q_cng","lsf_q_cng","a16",16),
 ("old_lsf_q_cng","old_lsf_q_cng","a16",16),("lsp_q_cng","lsp_q_cng","a16",16),("old_lsp_q_cng","old_lsp_q_cng","a16",16),
 ("mem_syn_unv_back","mem_syn_unv_back","a16",16),("last_gain_syn_deemph","last_gain_syn_deemph","s"),
 ("last_gain_syn_deemph_e","last_gain_syn_deemph_e","s"),("last_concealed_gain_syn_deemph","last_concealed_gain_syn_deemph","s"),
 ("last_concealed_gain_syn_deemph_e","last_concealed_gain_syn_deemph_e","s"),("conceal_eof_gain","conceal_eof_gain","s"),
 ("mem_aq","mem_Aq","h16",85),("lp_ener_fer","lp_ener_FER_fx","s"),("prev_bfi","prev_bfi_fx","s"),
 ("prev_old_bfi","prev_old_bfi_fx","s"),("lsf_adaptive_mean","lsf_adaptive_mean_fx","a16",16),
 ("lsfoldbfi0","lsfoldbfi0_fx","a16",16),("lsfoldbfi1","lsfoldbfi1_fx","a16",16),("clas_dec","clas_dec","s"),
 ("old_enr_lp","old_enr_LP","s"),("enr_old","enr_old_fx","s"),("last_good","last_good_fx","s"),
 ("mode2_lp_gainc","Mode2_lp_gainc","s"),("mode2_lp_gainp","Mode2_lp_gainp","s"),
 ("prev_widow_left_rect","prev_widow_left_rect","s"),
 ("con_cng_level_background_trace","conCngLevelBackgroundTrace","s"),
 ("con_cng_level_background_trace_e","conCngLevelBackgroundTrace_e","s"),("con_noise_level_index","conNoiseLevelIndex","s"),
 ("con_curr_level_index","conCurrLevelIndex","s"),("con_last_frame_level","conLastFrameLevel","s"),
 ("con_last_frame_level_e","conLastFrameLevel_e","s"),("con_noise_level_memory","conNoiseLevelMemory","a16",50),
 ("con_noise_level_memory_e","conNoiseLevelMemory_e","a16",50),
 ("cummulative_damping_tcx","cummulative_damping_tcx","s"),("cummulative_damping","cummulative_damping","s"),
 ("old_pitch_buf","old_pitch_buf_fx","a32",12),("mem_pitch_gain","mem_pitch_gain","a16",12),
 ("old_fpitch","old_fpitch","s"),("old_fpitch_fb","old_fpitchFB","s"),("rate_switching_init","rate_switching_init","s"),
 ("reset_mem_ar","reset_mem_AR","s"),("dm.prev_gain_code","dm_fx.prev_gain_code","s"),
 ("dm.prev_gain_pit","dm_fx.prev_gain_pit","a16",6),("dm.prev_state","dm_fx.prev_state","s"),("voice_fac","voice_fac","s"),
 ("tcxltp","tcxltp","s"),("tcxltp_pitch_int","tcxltp_pitch_int","s"),("tcxltp_pitch_fr","tcxltp_pitch_fr","s"),
 ("tcxltp_last_gain_unmodified","tcxltp_last_gain_unmodified","s"),("tcxltp_mem_in","tcxltp_mem_in","a16",12),
 ("tcxltp_mem_out","tcxltp_mem_out","h16",960),("tcxltp_pitch_int_post_prev","tcxltp_pitch_int_post_prev","s"),
 ("tcxltp_pitch_fr_post_prev","tcxltp_pitch_fr_post_prev","s"),("tcxltp_gain_post_prev","tcxltp_gain_post_prev","s"),
 ("tcxltp_filt_idx_prev","tcxltp_filt_idx_prev","s"),("lp_error_ener","lp_error_ener","s"),("mem_error","mem_error","s"),
 ("last_ctx_hm_enabled","last_ctx_hm_enabled","s"),("tcx_lpc_shaped_ari","tcx_lpc_shaped_ari","s"),
 ("env_weighted","envWeighted","s"),("tec_tfa","tec_tfa","s"),("tec_flag","tec_flag","s"),("tfa_flag","tfa_flag","s"),
 ("enable_gplc","enableGplc","s"),("flag_guided_acelp","flagGuidedAcelp","s"),("t0_4th","T0_4th","s"),
 ("guided_t0","guidedT0","s"),("enable_plc_waveadjust","enablePlcWaveadjust","s"),
 ("plc_info.frame_size","plcInfo.FrameSize","s"),("plc_info.pitch","plcInfo.Pitch_fx","s"),("plc_info.t_bfi","plcInfo.T_bfi_fx","s"),
 ("plc_info.transient","plcInfo.Transient","a16",3),("plc_info.tcx_tonality","plcInfo.TCX_Tonality","a16",10),
 ("plc_info.outx_new_n1","plcInfo.outx_new_n1_fx","s"),("plc_info.nsapp_gain","plcInfo.nsapp_gain_fx","s"),
 ("plc_info.nsapp_gain_n","plcInfo.nsapp_gain_n_fx","s"),("plc_info.data_reci2","plcInfo.data_reci2_fx","h32",960),
 ("plc_info.ener_mean","plcInfo.ener_mean_fx","s"),("plc_info.ener","plcInfo.ener_fx","s"),("plc_info.zp","plcInfo.zp_fx","s"),
 ("plc_info.recovery_gain","plcInfo.recovery_gain","s"),("plc_info.step_concealgain","plcInfo.step_concealgain_fx","s"),
 ("plc_info.concealment_method","plcInfo.concealment_method","s"),("plc_info.subframe","plcInfo.subframe_fx","s"),
 ("plc_info.nb_lost_cmpt","plcInfo.nbLostCmpt","s"),("plc_info.seed","plcInfo.seed","s"),
 ("tonal_mdc_tconceal.n_scale_factors","tonalMDCTconceal.nScaleFactors","s"),
 ("tonal_mdc_tconceal.n_samples","tonalMDCTconceal.nSamples","s"),
 ("tonal_mdc_tconceal.n_samples_core","tonalMDCTconceal.nSamplesCore","s"),
 ("tonal_mdc_tconceal.last_block_data.tonal_concealment_active","tonalMDCTconceal.lastBlockData.tonalConcealmentActive","s"),
 ("tonal_mdc_tconceal.last_block_data.n_samples","tonalMDCTconceal.lastBlockData.nSamples","s"),
 ("tonal_mdc_tconceal.last_block_data.block_is_valid","tonalMDCTconceal.lastBlockData.blockIsValid","s"),
 ("tonal_mdc_tconceal.second_last_block_data.block_is_valid","tonalMDCTconceal.secondLastBlockData.blockIsValid","s"),
 ("last_tns_active","last_tns_active","s"),("second_last_tns_active","second_last_tns_active","s"),
 ("second_last_core","second_last_core","s"),("tcxltp_second_last_pitch","tcxltp_second_last_pitch","s"),
 ("tcxltp_third_last_pitch","tcxltp_third_last_pitch","s"),("dec_glr","dec_glr","s"),("dec_glr_idx","dec_glr_idx","s"),
 ("enable_tcx_lpc","enableTcxLpc","s"),("vad","VAD","s"),("old_gaintcx_bfi","old_gaintcx_bfi","s"),
 ("old_gaintcx_bfi_e","old_gaintcx_bfi_e","s"),("tcx_hm_ltp_pitch_lag","tcx_hm_LtpPitchLag","s"),("tcxltp_gain","tcxltp_gain","s"),
 # pointers
 ("p_bpf_noise_buf","p_bpf_noise_buf - st->bpf_noise_buf","o"),
 ("tonal_mdc_tconceal.last_pcm_out","tonalMDCTconceal.lastPcmOut - st->tonalMDCTconceal.timeDataBuffer","o"),
 ("tonal_mdc_tconceal.second_last_pcm_out","tonalMDCTconceal.secondLastPcmOut - st->tonalMDCTconceal.timeDataBuffer","o"),
 ("tcx_cfg.p_current_tns_config","pCurrentTnsConfigIndex","o"),
]
import sys
def c():
    out=[]
    for e in S:
        r,cx,k=e[0],e[1],e[2]
        if k=="s": out.append(f'    put1("{r}", st->{cx});')
        elif k=="a16": out.append(f'    put16("{r}", st->{cx}, {e[3]});')
        elif k=="a32": out.append(f'    put32("{r}", st->{cx}, {e[3]});')
        elif k=="h16": out.append(f'    put1("{r}", hash16(st->{cx}, {e[3]}));')
        elif k=="h32": out.append(f'    put1("{r}", hash32(st->{cx}, {e[3]}));')
        elif k=="o":
            if r=="tcx_cfg.p_current_tns_config":
                out.append(f'    put1("{r}", st->tcx_cfg.pCurrentTnsConfig == NULL ? -1 : (long long)(st->tcx_cfg.pCurrentTnsConfig - &st->tcx_cfg.tnsConfig[0][0]));')
            else:
                base=cx.split(' - ')[0]
                out.append(f'    put1("{r}", st->{base} == NULL ? -1 : (long long)(st->{cx}));')
    return "\n".join(out)
def fill():
    out=[]
    for e in S:
        if e[2] in("h16","h32"):
            out.append(f'    fill_pattern{e[2][1:]}(st->{e[1]}, {e[3]}, {len(out)+1});')
    return "\n".join(out)
def rust():
    out=[]
    salt=0
    for e in S:
        r,k=e[0],e[2]
        if k in ("s","a16","a32"): out.append(f'    visit("{r}", &mut st.{r});')
        elif k in ("h16","h32"):
            salt+=1
            out.append(f'    visit_hashed("{r}", &mut st.{r}[..], {salt});')
        elif k=="o":
            if r=="tcx_cfg.p_current_tns_config": out.append(f'    visit_tns_pointer("{r}", &mut st.{r});')
            else: out.append(f'    visit("{r}", &mut st.{r});')
    return "\n".join(out)
print({"c":c,"fill":fill,"rust":rust}[sys.argv[1]]())
