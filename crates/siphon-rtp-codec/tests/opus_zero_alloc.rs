//! Zero-per-packet-allocation gate for the top-level Opus decoder (a performance invariant).
//!
//! `cargo test -p siphon-rtp-codec --test opus_zero_alloc`
//!
//! Its own test binary because a process may have only one `#[global_allocator]`.
//!
//! A **counting** allocator, not a jemalloc byte delta: the invariant is about the number of calls
//! into the allocator, and allocate-then-free churn (invisible to a live-bytes delta) is exactly the
//! kind of regression a `Vec` slipped into `decode_frame` would cause.
//!
//! Both entry points are gated on each side: [`OpusDecoder`] directly, and the
//! [`siphon_rtp_codec::Decoder`] / [`siphon_rtp_codec::Encoder`] trait objects [`decoder_for`] /
//! [`encoder_for`] build for a negotiated leg — the ones the media slow path runs. (The bare
//! [`siphon_rtp_codec::opus::enc::encoder::OpusEncoder`] has its own file,
//! `opus_encode_zero_alloc.rs`, for the same one-`#[global_allocator]`-per-binary reason.)
//!
//! [`OpusDecoder`] allocates exactly once, at construction, for the whole-packet float scratch the
//! 16-bit entry point needs; everything else — the SILK PCM staging buffer, the redundancy frame,
//! the mode-transition cross-fade buffer, both layers' state — is a fixed-size array on the stack or
//! on the decoder. So a warmed-up decode loop must make **zero** allocations, in every mode, in both
//! entry points, and on the concealment and FEC paths too. Those last two matter most: they are the
//! paths a lossy leg takes under load, which is exactly when an allocator round-trip is least
//! affordable.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec, OpusParams};
use siphon_rtp_codec::opus::decoder::{OpusDecoder, MAX_PACKET_SAMPLES};

/// A pass-through allocator that counts allocations, so a test can assert a hot loop made none.
struct CountingAllocator;

thread_local! {
    // Both the arm flag *and* the counter are thread-local: libtest runs the tests in this binary
    // concurrently, and a global counter would let one test's allocations be charged to another's
    // measurement window. `const`-initialised so touching them inside `alloc` never itself allocates.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call delegates straight to the system allocator; we only bump a thread-local
// counter, and only when the current thread has armed counting.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.with(Cell::get) {
            ALLOCATIONS.with(|counter| counter.set(counter.get() + 1));
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout);
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Run `body` `iterations` times with allocation counting armed, returning the allocator-call count.
fn count_allocations(iterations: usize, mut body: impl FnMut()) -> usize {
    ARMED.with(|armed| armed.set(true));
    let before = ALLOCATIONS.with(Cell::get);
    for _ in 0..iterations {
        body();
    }
    let after = ALLOCATIONS.with(Cell::get);
    ARMED.with(|armed| armed.set(false));
    after - before
}

/// Config numbers for the three modes at 20 ms (RFC 6716 §3.1, Table 2).
const SILK_WB_20MS: u8 = 9;
const HYBRID_FB_20MS: u8 = 15;
const CELT_FB_20MS: u8 = 31;

/// A deterministic pseudo-random payload behind a TOC byte. The range coder reads any byte string,
/// so this drives every decode stage without needing an encoder or a gitignored vector — which is
/// what lets this gate run on a bare checkout.
fn packet(config: u8, stereo: bool) -> Vec<u8> {
    let mut payload = Vec::with_capacity(61);
    payload.push((config << 3) | (u8::from(stereo) << 2));
    for i in 0..60u32 {
        payload.push((i.wrapping_mul(2_654_435_761) >> 24) as u8);
    }
    payload[1] &= 0x7f; // bias away from the CELT silence flag so the full pipeline runs
    payload
}

/// Decoding a packet must not touch the allocator, in any mode, at any output rate or channel count.
#[test]
fn decoding_a_packet_allocates_nothing() {
    for (label, config) in [
        ("silk", SILK_WB_20MS),
        ("hybrid", HYBRID_FB_20MS),
        ("celt", CELT_FB_20MS),
    ] {
        for stereo in [false, true] {
            for rate in [8_000u32, 16_000, 48_000] {
                for channels in [1usize, 2] {
                    let mut decoder = OpusDecoder::new(rate, channels).expect("decoder");
                    let data = packet(config, stereo);
                    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * channels];
                    // Warm up outside the measurement: the first packet is what configures both
                    // layers, and construction is allowed to allocate.
                    decoder
                        .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                        .expect("warm-up decode");

                    let allocations = count_allocations(32, || {
                        decoder
                            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                            .expect("decode");
                    });
                    assert_eq!(
                        allocations, 0,
                        "{label} stereo={stereo} {rate} Hz {channels}ch: {allocations} allocations \
                         across 32 packets"
                    );
                }
            }
        }
    }
}

/// The float entry point skips the 16-bit conversion but must be just as allocation-free.
#[test]
fn the_float_entry_point_allocates_nothing() {
    for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
        let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
        let data = packet(config, true);
        let mut pcm = vec![0f32; MAX_PACKET_SAMPLES * 2];
        decoder
            .decode_float(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("warm-up decode");

        let allocations = count_allocations(32, || {
            decoder
                .decode_float(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
                .expect("decode");
        });
        assert_eq!(allocations, 0, "config {config}: {allocations} allocations");
    }
}

/// Concealment is the path a lossy leg takes under load — including the pitch-based CELT PLC, which
/// is the heaviest of them — so it must be allocation-free too.
#[test]
fn concealment_allocates_nothing() {
    for config in [SILK_WB_20MS, HYBRID_FB_20MS, CELT_FB_20MS] {
        let mut decoder = OpusDecoder::new(48_000, 2).expect("decoder");
        let data = packet(config, true);
        let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * 2];
        // Two good packets, so the CELT PLC clears `skip_plc` and the first concealed frame takes
        // the pitch path rather than the cheaper noise one.
        decoder
            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("decode");
        decoder
            .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("decode");
        decoder.decode(None, &mut pcm, 960, false).expect("warm-up");

        let allocations = count_allocations(32, || {
            decoder.decode(None, &mut pcm, 960, false).expect("conceal");
        });
        assert_eq!(
            allocations, 0,
            "config {config}: {allocations} allocations across 32 concealed frames"
        );

        // A gap longer than 20 ms recurses through the splitter; that must not allocate either.
        let allocations = count_allocations(8, || {
            decoder
                .decode(None, &mut pcm, 2880, false)
                .expect("conceal");
        });
        assert_eq!(
            allocations, 0,
            "config {config}: {allocations} allocations across 8 long concealed gaps"
        );
    }
}

/// In-band FEC decodes the previous frame from the LBRR copy *and* conceals the head of the request,
/// so it exercises both paths in one call. Neither may allocate.
#[test]
fn fec_decode_allocates_nothing() {
    let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
    let data = packet(SILK_WB_20MS, false);
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES];
    decoder
        .decode(Some(&data), &mut pcm, MAX_PACKET_SAMPLES, false)
        .expect("prime the decoder");
    decoder
        .decode(Some(&data), &mut pcm, 1920, true)
        .expect("warm-up fec");

    let allocations = count_allocations(32, || {
        decoder
            .decode(Some(&data), &mut pcm, 1920, true)
            .expect("fec decode");
    });
    assert_eq!(
        allocations, 0,
        "{allocations} allocations across 32 FEC decodes"
    );
}

/// Switching mode packet to packet runs the transition cross-fade, which conceals 5 ms of the
/// previous mode into a scratch buffer. That buffer is on the stack, so the switch is free too.
#[test]
fn mode_switching_allocates_nothing() {
    let order = [
        CELT_FB_20MS,
        SILK_WB_20MS,
        HYBRID_FB_20MS,
        CELT_FB_20MS,
        HYBRID_FB_20MS,
        SILK_WB_20MS,
    ];
    let packets: Vec<Vec<u8>> = order.iter().map(|&config| packet(config, false)).collect();
    let mut decoder = OpusDecoder::new(48_000, 1).expect("decoder");
    let mut pcm = vec![0i16; MAX_PACKET_SAMPLES];
    for data in &packets {
        decoder
            .decode(Some(data), &mut pcm, MAX_PACKET_SAMPLES, false)
            .expect("warm-up");
    }

    let allocations = count_allocations(8, || {
        for data in &packets {
            decoder
                .decode(Some(data), &mut pcm, MAX_PACKET_SAMPLES, false)
                .expect("decode");
        }
    });
    assert_eq!(
        allocations, 0,
        "{allocations} allocations across 8 passes over 6 mode switches"
    );
}

/// A real RFC 6716 §3.2.2 code-0 packet: a config-31 TOC (CELT-only, fullband, 20 ms) followed by
/// one CELT frame of deterministic audio. Unlike [`packet`] this decodes to genuine samples, so the
/// trait-path gate below measures the branches a live leg takes rather than a degenerate parse.
fn celt_audio_packet() -> Vec<u8> {
    use siphon_rtp_codec::opus::celt::encoder::{CeltEncoder, RateControl};

    const FRAME: usize = 960;
    let mut encoder = CeltEncoder::new().expect("celt encoder");
    encoder.set_bitrate(64_000);
    encoder.set_rate_control(RateControl::ConstrainedVbr);
    let mut state = 0x5EED_u32;
    let pcm: Vec<f32> = (0..FRAME)
        .map(|index| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 16) as f32 / 32768.0 - 1.0) * 0.02;
            let time = index as f32;
            0.35 * (time * 0.031).sin() + 0.18 * (time * 0.097).sin() + noise
        })
        .collect();
    let mut payload = vec![0u8; 1275];
    let written = encoder.encode(&pcm, FRAME, &mut payload).expect("encode");
    let mut packet = Vec::with_capacity(1 + written);
    packet.push(31 << 3);
    packet.extend_from_slice(&payload[..written]);
    packet
}

/// The **[`Decoder`] trait path** — the one the media slow path actually runs, built through
/// [`decoder_for`] exactly as a negotiated Opus leg is. `OpusDecoder` allocating nothing is
/// necessary but not sufficient: the bridge on top of it must not stage a frame through a `Vec`
/// either, in `decode` or in `conceal`.
#[test]
fn the_decoder_trait_path_allocates_nothing_per_frame() {
    for sprop_stereo in [false, true] {
        let spec = CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(OpusParams {
            sprop_stereo,
            ..OpusParams::default()
        }));
        let mut decoder = decoder_for(&spec).expect("Opus decoder from the factory");
        let packet = celt_audio_packet();
        // The size `Direction` hands the decoder: the 120 ms / stereo ceiling, not the ptime frame.
        let mut pcm = vec![0i16; MAX_PACKET_SAMPLES * 2];
        // Warm up outside the window: the first packet configures both layers, and construction is
        // allowed to allocate.
        decoder.decode(&packet, &mut pcm).expect("warm-up decode");
        decoder.decode(&packet, &mut pcm).expect("warm-up decode");
        decoder.conceal(&mut pcm).expect("warm-up conceal");

        let allocations = count_allocations(32, || {
            decoder.decode(&packet, &mut pcm).expect("decode");
        });
        assert_eq!(
            allocations, 0,
            "sprop-stereo={sprop_stereo}: {allocations} allocations across 32 decoded frames"
        );

        // Concealment is the lossy-leg path — the one under load, when an allocator round-trip is
        // least affordable.
        let allocations = count_allocations(32, || {
            decoder.conceal(&mut pcm).expect("conceal");
        });
        assert_eq!(
            allocations, 0,
            "sprop-stereo={sprop_stereo}: {allocations} allocations across 32 concealed frames"
        );

        // A zero-length payload (Opus DTX) routes through the same PLC and must be just as free.
        let allocations = count_allocations(32, || {
            decoder.decode(&[], &mut pcm).expect("dtx");
        });
        assert_eq!(
            allocations, 0,
            "sprop-stereo={sprop_stereo}: {allocations} allocations across 32 DTX frames"
        );
    }
}

/// Deterministic speech-like 48 kHz PCM — a pitch pulse train through a resonance plus noise, so the
/// encoder's mode / bandwidth / VAD decisions take realistic branches rather than the degenerate
/// ones a tone or silence would (and so the FEC and DTX paths below are actually reached).
fn speech(samples: usize) -> Vec<i16> {
    let mut state = 24_680u32;
    let mut history = [0.0f32; 2];
    (0..samples)
        .map(|index| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let noise = ((state >> 20) as i32 - 2048) as f32 * 1.5;
            let pulse = if index % 240 == 0 { 6000.0 } else { 0.0 };
            let value = pulse + noise + 1.5 * history[0] - 0.85 * history[1];
            history[1] = history[0];
            history[0] = value;
            value.clamp(-24_000.0, 24_000.0) as i16
        })
        .collect()
}

/// The **[`Encoder`] trait path** — the one a transcode toward an Opus leg runs, built through
/// [`encoder_for`] exactly as a negotiated Opus leg is.
///
/// `OpusEncoder` allocating nothing is necessary but not sufficient (that is
/// `opus_encode_zero_alloc.rs`): the bridge on top of it must not stage a frame through a `Vec`
/// either. Every RFC 7587 §6.1 posture is measured, because each selects a different operating point
/// inside the encoder — FEC adds the LBRR pass, a narrowband cap drops CELT entirely, and CBR takes
/// the padding path — and a `Vec` on any one of them is a per-packet allocator round-trip on a live
/// leg.
#[test]
fn the_encoder_trait_path_allocates_nothing_per_frame() {
    for (label, fmtp) in [
        ("default", OpusParams::default()),
        (
            "maxaveragebitrate",
            OpusParams {
                max_average_bitrate: Some(24_000),
                ..OpusParams::default()
            },
        ),
        (
            "maxplaybackrate",
            OpusParams {
                max_playback_rate_hz: 8_000,
                ..OpusParams::default()
            },
        ),
        (
            "cbr",
            OpusParams {
                cbr: true,
                ..OpusParams::default()
            },
        ),
        (
            "useinbandfec",
            OpusParams {
                use_inband_fec: true,
                ..OpusParams::default()
            },
        ),
        (
            "usedtx",
            OpusParams {
                use_dtx: true,
                ..OpusParams::default()
            },
        ),
    ] {
        let spec = CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(fmtp));
        let mut encoder = encoder_for(&spec).expect("Opus encoder from the factory");
        let frame = encoder.frame_samples();
        let pcm = speech(frame * 4);
        // The buffer `Direction::emit_encoded` hands the encoder.
        let mut payload = vec![0u8; 1500];
        // Warm up outside the window: construction is allowed to allocate, and the first frames are
        // what settle the mode / bandwidth / rate decisions.
        for index in 0..4 {
            encoder
                .encode(&pcm[index * frame..(index + 1) * frame], &mut payload)
                .expect("warm-up encode");
        }

        let allocations = count_allocations(32, || {
            encoder.encode(&pcm[..frame], &mut payload).expect("encode");
        });
        assert_eq!(
            allocations, 0,
            "{label}: {allocations} allocations across 32 encoded frames"
        );
    }
}

/// The DTX path specifically: a silent run collapses to a bare TOC through a different branch of
/// `opus_encode_native`, and that branch must be just as allocation-free — it is the one a leg takes
/// while nobody is talking, i.e. most of a call.
#[test]
fn the_encoder_trait_dtx_path_allocates_nothing_per_frame() {
    let spec = CodecSpec::new(111, "opus", 48_000, 2, 20).with_opus_params(Some(OpusParams {
        use_dtx: true,
        ..OpusParams::default()
    }));
    let mut encoder = encoder_for(&spec).expect("Opus encoder from the factory");
    let frame = encoder.frame_samples();
    let silence = vec![0i16; frame];
    let mut payload = vec![0u8; 1500];
    // libopus only enters DTX after ~10 frames of inactivity (`NB_SPEECH_FRAMES_BEFORE_DTX`), so
    // drive past that before measuring.
    let mut entered_dtx = false;
    for _ in 0..12 {
        entered_dtx |= encoder.encode(&silence, &mut payload).expect("encode") == 1;
    }
    assert!(
        entered_dtx,
        "the encoder must be in DTX before the window opens"
    );

    // Count inside the window with a plain counter rather than a `Vec`, which would itself allocate.
    let mut dtx_frames = 0usize;
    let allocations = count_allocations(32, || {
        if encoder.encode(&silence, &mut payload).expect("encode") == 1 {
            dtx_frames += 1;
        }
    });
    assert_eq!(
        allocations, 0,
        "{allocations} allocations across 32 DTX frames"
    );
    // Not every frame is a bare TOC: libopus refreshes with a real packet after
    // `MAX_CONSECUTIVE_DTX` (20) silent ones, so ~1 in 21 is full-size. The window must still be
    // overwhelmingly DTX, or it measured the ordinary encode path instead.
    assert!(
        dtx_frames >= 24,
        "only {dtx_frames} of 32 frames were DTX — the window is not measuring the DTX path"
    );
}

/// The counting allocator must actually see allocations, or every assertion above is vacuous.
#[test]
fn the_counting_allocator_is_wired() {
    let allocations = count_allocations(4, || {
        let buffer: Vec<u8> = Vec::with_capacity(4096);
        std::hint::black_box(&buffer);
    });
    assert!(
        allocations >= 4,
        "the counting allocator saw {allocations} allocations for 4 explicit `Vec::with_capacity` \
         calls — the gate is not measuring anything"
    );
}
