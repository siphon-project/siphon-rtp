//! SILK decoder (RFC 6716 §4.2) — the linear-prediction "speech" layer of Opus.
//!
//! SILK decodes the SILK-only Opus configs (0–11: NB/MB/WB at 10/20/40/60 ms) and the low band of
//! every Hybrid config (12–15). Unlike CELT it is a **predictive, fixed-point** codec: the excitation
//! is entropy-coded, then run through a long-term (pitch) and a short-term (LPC) synthesis filter, and
//! nearly every symbol is coded relative to state the previous frame left behind. RFC 6716 §4.2.7.5
//! is explicit that an implementation SHOULD reproduce the reference fixed-point arithmetic exactly,
//! so this port is integer-faithful to libopus `silk/*.c` — not a float reinterpretation, unlike the
//! CELT side ([`super::celt`], which is deliberately the float build).
//!
//! # Decode pipeline
//!
//! One Opus frame's SILK layer, in bitstream order (RFC 6716 §4.2.2, Table 3 / Figure 16):
//!
//! ```text
//!   LP layer                       per SILK frame (RFC 6716 §4.2.7, Table 5)
//!   ────────────────────────────   ───────────────────────────────────────────────────────────
//!   VAD flags       (§4.2.3)       stereo prediction weights   (§4.2.7.1, mid of stereo only)
//!   LBRR flag       (§4.2.3)       mid-only flag               (§4.2.7.2, conditional)
//!   per-frame LBRR  (§4.2.4)       frame type                  (§4.2.7.3)
//!   LBRR frame(s)   (§4.2.5)       subframe gains              (§4.2.7.4)
//!   regular SILK    (§4.2.6)       normalized LSF stage 1/2    (§4.2.7.5.1-2)
//!   frame(s)                       LSF interpolation weight    (§4.2.7.5.5, 20 ms frames)
//!                                  primary pitch lag + contour (§4.2.7.6.1, voiced)
//!                                  LTP filter + periodicity    (§4.2.7.6.2, voiced)
//!                                  LTP scaling                 (§4.2.7.6.3, conditional)
//!                                  LCG seed                    (§4.2.7.7)
//!                                  excitation                  (§4.2.7.8)
//! ```
//!
//! and then, per frame: NLSF → LPC conversion + stabilisation (§4.2.7.5.3-8), LTP + LPC synthesis with
//! the subframe gains applied (§4.2.7.9), stereo unmixing (§4.2.8), and resampling from the internal
//! 8/12/16 kHz rate to the API rate (§4.2.9).
//!
//! # What is implemented here
//!
//! | Sub-phase | State |
//! |---|---|
//! | Shared constants and side-info types ([`types`]) | **landed** |
//! | Cross-frame decoder state ([`decoder`]) | **landed** |
//! | Header / stereo / frame-type / gain entropy tables ([`tables`]) | **landed** |
//! | Fixed-point primitives ([`fixed`]) | **landed** |
//! | LP-layer header: VAD / LBRR flags (§4.2.3-4) ([`header`]) | **landed** |
//! | Stereo prediction weights, mid-only flag (§4.2.7.1-2) ([`stereo_pred`]) | **landed** |
//! | Frame type (§4.2.7.3) ([`frame_type`]) | **landed** |
//! | Subframe gains (§4.2.7.4) ([`gains`]) | **landed** |
//! | NLSF codebooks and the LSF cosine table ([`nlsf_tables`]) | **landed** |
//! | NLSF stage 1/2, stabilisation, interpolation (§4.2.7.5.1-5) ([`nlsf`]) | **landed** |
//! | NLSF → Q12 LPC, stability limiting (§4.2.7.5.8) ([`lpc`]) | **landed** |
//! | Pitch lags, LTP filter, LTP scaling (§4.2.7.6) ([`ltp`]) | **landed** |
//! | LCG seed + excitation / shell coder (§4.2.7.7-8) ([`excitation`]) | **landed** |
//! | LTP + LPC synthesis, stereo unmixing, resampling (§4.2.7.9, §4.2.8-9) | pending |
//! | DTX / CNG and PLC (§4.4) | pending |
//!
//! Nothing above is stubbed: a sub-phase is either fully implemented and tested, or it has no module
//! and no function at all. There is deliberately no `decode_frame` entry point yet — one cannot exist
//! before the excitation and synthesis phases do, and a version that returned silence would read as
//! working.
//!
//! # Seams the remaining sub-phases build against
//!
//! The per-frame side info is **not** modelled as one shared mutable bag (the C's
//! `SideInfoIndices`). Each sub-phase instead exposes a free function over
//! [`super::range_coder::RangeDecoder`] that returns its own owned index/parameter struct, and the
//! integrator calls them in Table 5 order. That keeps every phase independently testable against a
//! libopus dump, and makes the bitstream order explicit at one call site instead of implicit in a
//! struct's field order.
//!
//! What exists today, in the order a frame is read — this is the call sequence the remaining phases
//! extend, not replace:
//!
//! ```text
//! decoder.configure(channels, InternalRate::from_bandwidth(toc.bandwidth()), duration_ms)
//! decoder.decode_lp_layer_header(range)                     // §4.2.3-4, once per Opus frame
//!   per 20 ms SILK frame, mid channel then side:
//!     stereo_pred::decode_stereo_weights(range)             // §4.2.7.1, stereo + mid channel only
//!     stereo_pred::decode_mid_only(range)                   // §4.2.7.2, iff mid_only_flag_is_coded()
//!     frame_type::decode_frame_type(range, flags.is_active(frame_index, is_lbrr))   // §4.2.7.3
//!     decoder.decode_subframe_gains(range, channel, signal_type, cond_coding)       // §4.2.7.4
//!     decoder.decode_nlsf(range, channel, signal_type)       // §4.2.7.5 -> LpcCoefficients
//!     ltp::decode_indices(range, rate, layout, cond_coding, prev_type, prev_lag)   // §4.2.7.6
//!     ltp::dequantize(&indices, rate)                        // -> LtpParameters
//!     excitation::decode_seed(range)                         // §4.2.7.7
//!     excitation::decode(range, signal_type, quant_offset, frame_length, seed, ..) // §4.2.7.8
//!     ── everything below is pending ──
//! ```
//!
//! Two conventions that are easy to get wrong and are already settled here:
//!
//! * **`cond_coding` is derived, never decoded.** Use [`decoder::ChannelState::cond_coding`] — it
//!   ports the `dec_API.c:342-354` decision table, including the
//!   [`types::CondCoding::IndependentlyNoLtpScaling`] case that only arises when the side channel
//!   skipped a frame earlier in the same packet.
//! * **A symbol that is not coded still has a defined value.** The mid-only flag is `false` when
//!   absent; the LTP scaling index is 0 when absent (`decode_indices.c:142`); the NLSF interpolation
//!   factor is 4 for a two-subframe frame (`decode_indices.c:97`). Never read the symbol "just in
//!   case" — every one of those costs bits and desynchronises the rest of the frame.
//!
//! Concretely, the pending phases are expected to add:
//!
//! * **NLSF (§4.2.7.5)** — landed as [`decoder::SilkDecoder::decode_nlsf`], returning
//!   [`nlsf::LpcCoefficients`] (both Q12 LPC halves, the Q15 NLSFs and the interpolation factor).
//!   [`types::InternalRate::lpc_order`] picks the order-10 (NB/MB) or order-16 (WB) codebook and
//!   [`types::SignalType`] picks the stage-1 PDF. The interpolation anchor is
//!   [`decoder::ChannelState::prev_nlsf_q15`], and interpolation is suppressed whenever
//!   [`decoder::ChannelState::first_frame_after_reset`] is set (`decode_parameters.c:59-61`) or the
//!   frame has two subframes (`decode_indices.c:94-98`). It deliberately does **not** clear
//!   `first_frame_after_reset` — that belongs to synthesis, at the end of a successfully decoded
//!   frame (`decode_frame.c:130`).
//! * **LTP (§4.2.7.6)** — landed as [`ltp::decode_indices`], with [`ltp::dequantize`] turning the
//!   indices into per-subframe pitch lags, Q14 filter taps and the Q14 LTP scale. A delta pitch lag is
//!   only legal when the frame is [`types::CondCoding::Conditionally`] coded *and* the previous frame
//!   was voiced, measured against [`decoder::ChannelState::ec_prev_lag_index`]; the LTP scaling symbol
//!   appears only for [`types::CondCoding::Independently`] (`decode_indices.c:139-143`). Both
//!   `ec_prev_*` fields must be updated by the caller even for frames that skip these symbols —
//!   `ec_prev_lag_index` only on a voiced frame (`decode_indices.c:121`), `ec_prev_signal_type` on
//!   every frame (`decode_indices.c:145`).
//! * **Excitation (§4.2.7.7-8)** — landed as [`excitation::decode_seed`] plus
//!   [`excitation::decode`], which writes the signed pulses into a caller-owned
//!   [`excitation::PULSE_BUFFER_LENGTH`] buffer and the reconstructed Q14 excitation into
//!   `&mut channel.excitation_q14[..frame_length]`. The quantization offset constant is
//!   [`types::QuantOffsetType::offset_q10`]. The **LCG seed** is a per-frame symbol (§4.2.7.7,
//!   `silk_uniform4_iCDF`) read immediately before the excitation, not cross-frame state — there is
//!   deliberately no seed field on [`decoder::ChannelState`], because on the normal decode path the
//!   generator is re-seeded every frame. The only PRNG seeds that *do* cross frames belong to PLC and
//!   CNG (`silk_PLC_struct.rand_seed`, `silk_CNG_struct.rand_seed`), and they land with §4.4.
//! * **Synthesis (§4.2.7.9, §4.2.8-9)** — consumes the subframe gains, the LPC/LTP coefficients and
//!   [`decoder::ChannelState::out_buf`] / [`decoder::ChannelState::lpc_state_q14`] /
//!   [`decoder::ChannelState::prev_gain_q16`], and the stereo weights against
//!   [`decoder::StereoState`]. This is the phase that ports the C's `silk_decoder_control`
//!   (`structs.h:342-350`) as its per-frame input aggregate; it is deliberately absent here rather
//!   than present with four of its five fields always zero. The short-term filter half of that
//!   aggregate already exists: [`nlsf::LpcCoefficients`] carries `PredCoef_Q12[0]` and
//!   `PredCoef_Q12[1]`, and it is synthesis' job to clear
//!   [`decoder::ChannelState::first_frame_after_reset`] once a frame has decoded without error
//!   (`decode_frame.c:130`) — the NLSF phase reads that flag but must not clear it.
//!
//! # Conformance
//!
//! The acceptance criterion is the same two-part oracle the CELT layer uses: exact per-packet
//! range-coder `final_range` equality against the value libopus stored with the packet, then the
//! RFC 6716 §6 `opus_compare` tolerance metric against libopus' own decode. Neither can run until a
//! whole SILK frame decodes — both need the decoder to consume the packet to its end.
//!
//! Until then, each sub-phase is diffed field by field against printf dumps from an **instrumented**
//! libopus build over `reference/opus/silk_only` (64 SILK-only streams generated by
//! `reference/opus/gen_silk_only.sh`, with `.trace` dumps from `reference/opus/dump_silk_trace.sh`;
//! recipe in CONTRIBUTING.md):
//!
//! * `tests/silk_header_conformance.rs` — the LP layer through the subframe gains (§4.2.3-§4.2.7.4).
//! * `tests/silk_excitation_conformance.rs` — the LTP and excitation stages (§4.2.7.6-8), for **every
//!   SILK frame of every packet**, including LBRR frames. It gets past the not-yet-ported NLSF stage
//!   by replaying the `(fl, fh)` of each NLSF symbol the dump records through the range decoder,
//!   which is state-equivalent to `ec_dec_icdf`; everything else is decoded for real. Because a SILK
//!   frame's bitstream ends at `silk_decode_pulses`, it can also assert the range coder's `rng` and
//!   bit position at the end of each frame — this layer's own `final_range` check, at finer
//!   resolution than the whole-packet one.
//!
//! * `tests/silk_nlsf_conformance.rs` — the NLSF stage (§4.2.7.5): the coded indices, the dequantized
//!   residual with its unpacked prediction weights and entropy-table selection, the reconstruction
//!   *before* and *after* stabilisation, the interpolated vector, and both Q12 LPC coefficient sets.
//!
//! Extending this for a new sub-phase is two steps: add the field group to
//! `reference/opus/silk_trace.patch` (it is one shared patch — **extend it, never replace it**, and
//! rebuild `build-trace` from the union), and decode one more symbol group per frame in the harness.
//! A harness must ignore field groups it does not own, or each new stage breaks its siblings the next
//! time the dumps are regenerated. Treat these as the working diagnostic and the two whole-packet
//! gates as the acceptance criterion — an intermediate-state diff proves the fields match, not that
//! the packet parses to its end.
//!
//! The tables have their own oracle, `tests/silk_nlsf_tables_vs_libopus.rs`, which re-parses the
//! libopus source and compares every ported NLSF codebook entry element by element.

pub mod decoder;
pub mod enc;
pub mod excitation;
pub mod fixed;
pub mod frame_type;
pub mod gains;
pub mod header;
pub mod lpc;
pub mod ltp;
pub mod nlsf;
pub mod nlsf_tables;
pub mod stereo_pred;
pub mod tables;
pub mod types;
