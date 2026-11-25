//! The AMR-WB interoperable (IO) decoder of one frame (TS 26.442 `lib_dec/amr_wb_dec_fx.c`;
//! TS 26.445 §6.2 "AMR-WB IO mode", TS 26.190): ISF and excitation decoding of a good frame
//! (`decod_amr_wb_fx`), comfort-noise generation of a SID / no-data frame, frame-erasure
//! concealment, LP synthesis at 12.8 kHz, post-filtering, comfort-noise addition and the CLDFB
//! resampling to the output rate with the 6 - 8 kHz band extension.
//!
//! The reference's one 1100-line function is split into the phases it comments: initialisation
//! and the switches from the EVS primary modes (`start`), a good frame (the CNG path and the
//! active path), a bad frame, the post-processing of the synthesis (`post`), the resampling and
//! band extension (`resample`) and the end-of-frame updates and output (`finish`); the locals
//! they share live in `AmrWork`.
//!
//! Buffers. `old_exc` (history `L_EXC_MEM_DEC`, then the frame) and the synthesis buffer keep the
//! reference's layout, so the functions that read the history in front of a frame take the buffer
//! and the frame's offset.

mod finish;
mod frame;
mod post;
mod resample;
mod start;

use crate::evs::cnst::{
    CLDFB_NO_COL_MAX, GENERIC, L_EXC_DEC, L_FRAME, L_FRAME32K, L_FRAME48K, M, NB_SUBFR,
    NB_SUBFR16K, NUM_ENV_CNG, UNVOICED_CLAS,
};
use crate::evs::com::cldfb::CLDFB_ROW;
use crate::evs::dec::state::DecoderState;

/// Where the frame starts in `old_exc` (`exc_fx = old_exc_fx + L_EXC_MEM_DEC`).
const EXC_AT: usize = crate::evs::cnst::L_EXC_MEM_DEC as usize;
/// The two history zeros in front of the synthesis of the frame (`syn_tmp_fx`).
const SYN_AT: usize = 2;

/// The locals of `amr_wb_dec_fx` that its phases share.
struct AmrWork {
    /// `old_exc_fx` (`exc_fx` = `old_exc[EXC_AT..]`).
    old_exc: [i16; L_EXC_DEC as usize],
    /// `exc2_fx`: the total excitation.
    exc2: [i16; L_FRAME as usize],
    /// `syn_tmp_fx` (`syn_fx` = `syn_tmp[SYN_AT..]`).
    syn_tmp: [i16; L_FRAME as usize + SYN_AT],
    /// `tmp_buffer_fx`.
    tmp_buffer: [i16; L_FRAME48K as usize],
    /// `dummy_buf_fx`: the buffer the reference hands to the outputs it does not use.
    dummy_buf: [i16; L_FRAME32K as usize],
    /// `Aq_fx`.
    aq: [i16; NB_SUBFR as usize * (M as usize + 1)],
    lsp_new: [i16; M as usize],
    lsf_new: [i16; M as usize],
    /// `mem_tmp_fx`.
    mem_tmp: [i16; M as usize],
    pitch_buf: [i16; NB_SUBFR as usize],
    hf_gain: [i16; NB_SUBFR as usize],
    voice_factors: [i16; NB_SUBFR as usize],
    gain_buf: [i16; NB_SUBFR16K as usize],
    /// `synth_out_fx`.
    synth_out: [i16; L_FRAME48K as usize],
    /// `realBufferTmp`.
    real_buffer: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    /// `imagBufferTmp`.
    imag_buffer: [[i32; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
    q_env: [i32; NUM_ENV_CNG as usize],
    /// `exc_buffer_fx` of the LD music post-filter.
    exc_buffer: [i16; crate::evs::cnst::DCT_L_POST as usize],
    /// `dct_buffer_fx` of the LD music post-filter.
    dct_buffer: [i16; crate::evs::cnst::DCT_L_POST as usize],
    sid_bw: i16,
    class_para: i16,
    amr_io_class: i16,
    coder_type: i16,
    vad_flag: i16,
    locattack: i16,
    tmp_noise: i16,
    avoid_lpc_burst_on_recovery: i16,
    flag_cna: i16,
    last_core_ori: i16,
    output_frame: i16,
}

impl AmrWork {
    /// The locals as the C function starts them, on the stack: nothing here touches the heap.
    fn new() -> Self {
        Self {
            old_exc: [0; L_EXC_DEC as usize],
            exc2: [0; L_FRAME as usize],
            syn_tmp: [0; L_FRAME as usize + SYN_AT],
            tmp_buffer: [0; L_FRAME48K as usize],
            dummy_buf: [0; L_FRAME32K as usize],
            aq: [0; NB_SUBFR as usize * (M as usize + 1)],
            lsp_new: [0; M as usize],
            lsf_new: [0; M as usize],
            mem_tmp: [0; M as usize],
            pitch_buf: [0; NB_SUBFR as usize],
            hf_gain: [0; NB_SUBFR as usize],
            voice_factors: [0; NB_SUBFR as usize],
            gain_buf: [0; NB_SUBFR16K as usize],
            synth_out: [0; L_FRAME48K as usize],
            real_buffer: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
            imag_buffer: [[0; CLDFB_ROW]; CLDFB_NO_COL_MAX as usize],
            q_env: [0; NUM_ENV_CNG as usize],
            exc_buffer: [0; crate::evs::cnst::DCT_L_POST as usize],
            dct_buffer: [0; crate::evs::cnst::DCT_L_POST as usize],
            sid_bw: 0,
            class_para: 0,
            amr_io_class: UNVOICED_CLAS,
            coder_type: GENERIC,
            vad_flag: 0,
            locattack: 0,
            tmp_noise: 0,
            avoid_lpc_burst_on_recovery: 0,
            flag_cna: 0,
            last_core_ori: 0,
            output_frame: 0,
        }
    }
}

/// `amr_wb_dec_fx`: decode the AMR-WB IO frame the decoder state holds (`st.bfi`, the indices
/// and bit stream `read_indices` left) into `output_sp` (`output_frame` samples at the output
/// rate, Q0) and update the decoder state.
pub fn amr_wb_dec(st: &mut DecoderState, output_sp: &mut [i16]) {
    let mut w = AmrWork::new();

    start::amr_wb_dec_start(st, &mut w);

    if st.bfi == 0 {
        // GOOD frame
        frame::good_frame(st, &mut w);
    } else {
        // BAD frame
        frame::bad_frame(st, &mut w);
    }

    post::post_process(st, &mut w);
    resample::resample_and_band_extension(st, &mut w);
    finish::update_and_output(st, &mut w, output_sp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_work_buffers_start_zeroed_with_the_reference_defaults() {
        let w = AmrWork::new();
        assert_eq!(w.amr_io_class, UNVOICED_CLAS);
        assert_eq!(w.coder_type, GENERIC);
        assert!(w.old_exc.iter().all(|&sample| sample == 0));
        assert_eq!(w.syn_tmp[..SYN_AT], [0, 0]);
    }
}
