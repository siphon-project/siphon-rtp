#![cfg(test)]

//! The split bridge, end to end: both legs of a live call on one duplex stereo WebSocket, against a
//! loopback bot, on real sockets with the redirect dispatcher live.
//!
//! Every scenario drives the same cycle on one call shape: audio crosses directly, the split is
//! attached, each party hears only its own channel of the bot while the bot hears both, the bot goes
//! quiet on one channel, the bot hangs up, the split is detached, and audio crosses directly again.
//! The parties are told apart by **frequency** (a Goertzel filter over what each phone decodes), so a
//! leak of one party's voice into the other's earpiece shows as energy at the wrong tone. Each phone
//! holds its own SRTP context, built from the key material and never from the engine's, so a
//! hand-over that disturbed a key, a rollover counter or a stream position shows as a datagram that
//! does not decrypt, or a sequence number that jumps.

use super::secure_hold::*;
use super::*;
use crate::media_pipeline::MediaControl;
use futures_util::{SinkExt, StreamExt};
use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_proto::{
    RecordingChannels, RecordingDirection, WsSplitAttach, WsSplitDetach, WsSplitEndReason,
};
use std::sync::Mutex as StdMutex;
use tokio_tungstenite::tungstenite::Message;

/// What each party says on the phone, in Hz.
pub(super) const A_TONE: f32 = 600.0;
pub(super) const B_TONE: f32 = 1_400.0;
/// What the bot says to each party, in Hz (channel 0 to the offerer, channel 1 to the answerer).
pub(super) const TO_A_TONE: f32 = 1_000.0;
pub(super) const TO_B_TONE: f32 = 2_000.0;
pub(super) const WIRE_RATE: u32 = 16_000;

// ---- the bot ------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct BotSeen {
    pub(super) start: Option<serde_json::Value>,
    /// What the bot received on each channel, at the wire rate.
    uplink: [Vec<i16>; 2],
}

#[derive(Default)]
pub(super) struct BotControl {
    /// What the bot says on each channel (`None` is a channel it leaves silent: it sends zeros).
    tones: [Option<f32>; 2],
    /// Close the socket.
    pub(super) close: bool,
    /// Send nothing downlink at all.
    mute: bool,
    /// The wire rate the bot speaks at (0 is [`WIRE_RATE`]).
    rate: u32,
    /// Frames to send at once on the next tick, as a bot that answers faster than real time does.
    burst: usize,
}

pub(super) struct Bot {
    pub(super) uri: String,
    pub(super) seen: Arc<StdMutex<BotSeen>>,
    pub(super) control: Arc<StdMutex<BotControl>>,
}

impl Bot {
    pub(super) fn set_tones(&self, tones: [Option<f32>; 2]) {
        self.control.lock().expect("control").tones = tones;
    }

    pub(super) fn uplink(&self, channel: usize) -> Vec<i16> {
        self.seen.lock().expect("seen").uplink[channel].clone()
    }

    pub(super) fn take_uplink(&self) {
        let mut seen = self.seen.lock().expect("seen");
        seen.uplink = [Vec::new(), Vec::new()];
    }
}

/// A bot on a loopback socket: it records `start` and the uplink per channel, and sends a stereo
/// downlink at the wire rate in real time, one 20 ms frame per 20 ms.
pub(super) async fn bot() -> Bot {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bot");
    let uri = format!("ws://{}/split", listener.local_addr().expect("bot addr"));
    let seen = Arc::new(StdMutex::new(BotSeen::default()));
    let control = Arc::new(StdMutex::new(BotControl {
        tones: [Some(TO_A_TONE), Some(TO_B_TONE)],
        ..BotControl::default()
    }));
    let (task_seen, task_control) = (seen.clone(), control.clone());
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (mut sink, mut source) = socket.split();
        let mut ticker = tokio::time::interval(Duration::from_millis(20));
        let mut sent = 0usize;
        loop {
            tokio::select! {
                incoming = source.next() => match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let value: serde_json::Value =
                            serde_json::from_str(text.as_str()).expect("json");
                        task_seen.lock().expect("seen").start.get_or_insert(value);
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        let mut seen = task_seen.lock().expect("seen");
                        for pair in bytes.as_chunks::<4>().0 {
                            seen.uplink[0].push(i16::from_le_bytes([pair[0], pair[1]]));
                            seen.uplink[1].push(i16::from_le_bytes([pair[2], pair[3]]));
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => break,
                },
                _ = ticker.tick() => {
                    let (tones, close, mute, rate, burst) = {
                        let mut control = task_control.lock().expect("control");
                        let rate = if control.rate == 0 { WIRE_RATE } else { control.rate };
                        let burst = std::mem::take(&mut control.burst);
                        (control.tones, control.close, control.mute, rate, burst)
                    };
                    if close {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                    if mute {
                        continue;
                    }
                    let frame = rate as usize / 50;
                    let mut gone = false;
                    for _ in 0..=burst {
                        let mut bytes = Vec::with_capacity(frame * 4);
                        for index in 0..frame {
                            for tone in tones {
                                let sample = tone.map_or(0, |frequency| {
                                    let at = (sent * frame + index) as f32;
                                    ((at * frequency * std::f32::consts::TAU / rate as f32).sin()
                                        * 8_000.0) as i16
                                });
                                bytes.extend_from_slice(&sample.to_le_bytes());
                            }
                        }
                        sent += 1;
                        if sink.send(Message::binary(bytes)).await.is_err() {
                            gone = true;
                            break;
                        }
                    }
                    if gone {
                        break;
                    }
                }
            }
        }
    });
    Bot { uri, seen, control }
}

// ---- tones --------------------------------------------------------------------------------------

fn tone_frame(frequency: f32, frame: usize) -> Vec<i16> {
    (0..160)
        .map(|index| {
            let at = (frame * 160 + index) as f32;
            ((at * frequency * std::f32::consts::TAU / 8_000.0).sin() * 8_000.0) as i16
        })
        .collect()
}

/// One G.711 µ-law frame of `frequency` from `phone`, sealed under its own context.
async fn send_tone(phone: &mut Phone, frequency: f32, frame: usize) {
    let mut payload = [0u8; 160];
    siphon_rtp_codec::g711::G711::ulaw()
        .encode(&tone_frame(frequency, frame), &mut payload)
        .expect("encode");
    let mut packet = g711_rtp(0, phone.next_sequence, phone.ssrc, 0);
    packet[12..].copy_from_slice(&payload);
    phone.next_sequence = phone.next_sequence.wrapping_add(1);
    let sealed = phone.seal(&packet);
    phone
        .socket
        .send_to(&sealed, phone.engine)
        .await
        .expect("phone sends");
    phone.last_sent = sealed;
}

/// Goertzel power of `frequency` in `samples` at `rate`, per sample squared.
pub(super) fn power(samples: &[i16], rate: f32, frequency: f32) -> f64 {
    let coefficient = 2.0 * (std::f32::consts::TAU * frequency / rate).cos();
    let (mut previous, mut before) = (0.0f64, 0.0f64);
    for &sample in samples {
        let next = f64::from(sample) + f64::from(coefficient) * previous - before;
        before = previous;
        previous = next;
    }
    let power = previous * previous + before * before - f64::from(coefficient) * previous * before;
    power / (samples.len().max(1) as f64).powi(2)
}

pub(super) fn decode(heard: &Heard) -> Vec<i16> {
    let mut decoder = siphon_rtp_codec::g711::G711::ulaw();
    let mut pcm = Vec::new();
    let mut frame = [0i16; 1024];
    for packet in &heard.media {
        let count = decoder.decode(&packet.payload, &mut frame).expect("decode");
        pcm.extend_from_slice(&frame[..count]);
    }
    pcm
}

pub(super) const TONES: [f32; 4] = [A_TONE, TO_A_TONE, B_TONE, TO_B_TONE];

/// `samples` carry `wanted` and none of the other tones.
#[track_caller]
pub(super) fn assert_hears(samples: &[i16], rate: f32, wanted: f32, who: &str) {
    assert!(
        samples.len() >= 1_600,
        "{who}: heard {} samples",
        samples.len()
    );
    let wanted_power = power(samples, rate, wanted);
    assert!(
        wanted_power > 1_000.0,
        "{who}: no {wanted} Hz ({wanted_power})"
    );
    for other in TONES.into_iter().filter(|tone| *tone != wanted) {
        let leaked = power(samples, rate, other);
        assert!(
            leaked * 100.0 < wanted_power,
            "{who}: {other} Hz leaked in at {leaked} against {wanted_power} at {wanted} Hz"
        );
    }
}

/// `samples` carry none of the tones, and there are enough of them to say so.
#[track_caller]
pub(super) fn assert_silent_audio(samples: &[i16], rate: f32, who: &str) {
    assert!(
        samples.len() >= 1_600,
        "{who}: heard {} samples",
        samples.len()
    );
    for tone in TONES {
        let heard = power(samples, rate, tone);
        assert!(
            heard < 25.0,
            "{who}: {tone} Hz at {heard} while it should be silent"
        );
    }
}

// ---- driving the rig ------------------------------------------------------------------------------

/// `frames` of both parties speaking their tone, listening as it goes. `frame` counts the tone's
/// phase across calls so it stays continuous.
pub(super) async fn talk(
    rig: &mut Rig,
    frame: &mut usize,
    frames: usize,
    log: &mut (Heard, Heard),
) -> (Heard, Heard) {
    let (mut at_a, mut at_b) = (Heard::default(), Heard::default());
    for _ in 0..frames {
        send_tone(&mut rig.a, A_TONE, *frame).await;
        send_tone(&mut rig.b, B_TONE, *frame).await;
        *frame += 1;
        tokio::time::sleep(Duration::from_millis(12)).await;
        at_a.absorb(rig.a.listen(Duration::from_millis(8)).await);
        at_b.absorb(rig.b.listen(Duration::from_millis(8)).await);
    }
    log.0.absorb(at_a.clone());
    log.1.absorb(at_b.clone());
    (at_a, at_b)
}

pub(super) fn attach_command(rig: &Rig, bot: &Bot, sample_rate: Option<u32>) -> Command {
    Command::AttachWsSplit(WsSplitAttach {
        call_id: rig.call_id.into(),
        from_tag: "a".into(),
        ws_uri: bot.uri.clone(),
        sample_rate,
        offerer_profile: None,
        answerer_profile: None,
    })
}

pub(super) fn detach_command(rig: &Rig) -> Command {
    Command::DetachWsSplit(WsSplitDetach {
        call_id: rig.call_id.into(),
        from_tag: "a".into(),
    })
}

/// The split events seen so far, in order.
pub(super) fn split_events(events: &flume::Receiver<Event>) -> Vec<Event> {
    events
        .try_iter()
        .filter(|event| matches!(event, Event::WsSplitStarted(_) | Event::WsSplitEnded(_)))
        .collect()
}

pub(super) async fn wait_for(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

// ---- the cycle on every call shape ----------------------------------------------------------------

pub(super) async fn assert_split_cycle(mut rig: Rig) {
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let mut frame = 0usize;

    // ---- before: the parties hear each other -----------------------------------------------------
    let mut log = (Heard::default(), Heard::default());
    let (at_a, at_b) = talk(&mut rig, &mut frame, 25, &mut log).await;
    assert_hears(&decode(&at_b), 8_000.0, A_TONE, "B before the split");
    assert_hears(&decode(&at_a), 8_000.0, B_TONE, "A before the split");
    assert_eq!(rig.kind(), rig.original);

    // ---- attach -------------------------------------------------------------------------------------
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    assert_eq!(rig.kind(), rig.held, "carried by the decoding actor");
    assert!(rig.engine.media.is_split_marked(rig.call_id));
    let started = split_events(&events);
    assert!(
        matches!(started.as_slice(), [Event::WsSplitStarted(started)]
            if started.sample_rate == WIRE_RATE && started.stream_id.starts_with("split-")),
        "one started event first: {started:?}"
    );

    // Settle, then listen: each party hears its own channel and nothing of the other party.
    talk(&mut rig, &mut frame, 15, &mut log).await;
    bot.take_uplink();
    let (during_a, during_b) = talk(&mut rig, &mut frame, 40, &mut log).await;
    assert_hears(
        &decode(&during_a),
        8_000.0,
        TO_A_TONE,
        "A hears bot channel 0",
    );
    assert_hears(
        &decode(&during_b),
        8_000.0,
        TO_B_TONE,
        "B hears bot channel 1",
    );
    assert!(
        during_a.media.len() >= 30 && during_b.media.len() >= 30,
        "the playout clock sends a packet per tick to each party"
    );
    assert_eq!(during_a.rejected + during_b.rejected, 0);

    // The bot hears the offerer on channel 0 and the answerer on channel 1, and the start frame says so.
    let (uplink_a, uplink_b) = (bot.uplink(0), bot.uplink(1));
    assert_hears(
        &uplink_a,
        WIRE_RATE as f32,
        A_TONE,
        "bot channel 0 is the offerer",
    );
    assert_hears(
        &uplink_b,
        WIRE_RATE as f32,
        B_TONE,
        "bot channel 1 is the answerer",
    );
    let start = bot
        .seen
        .lock()
        .expect("seen")
        .start
        .clone()
        .expect("a start frame");
    assert_eq!(start["type"], "start");
    assert_eq!(start["data"]["direction"], "duplex");
    assert_eq!(start["data"]["media"]["channels"], 2);
    assert_eq!(start["data"]["media"]["sampleRate"], WIRE_RATE);
    assert_eq!(
        start["data"]["tracks"],
        serde_json::json!(["inbound", "outbound"])
    );
    assert!(start["data"]["streamId"]
        .as_str()
        .expect("id")
        .starts_with("split-"));

    // ---- a channel the bot leaves silent plays silence, and the stream keeps going ------------------
    bot.set_tones([Some(TO_A_TONE), None]);
    talk(&mut rig, &mut frame, 12, &mut log).await;
    let (quiet_a, quiet_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(
        &decode(&quiet_a),
        8_000.0,
        TO_A_TONE,
        "A still hears channel 0",
    );
    assert_silent_audio(&decode(&quiet_b), 8_000.0, "B on a silent channel 1");
    assert!(
        quiet_b.media.len() >= 20,
        "silence is still sent on the clock"
    );
    bot.set_tones([Some(TO_A_TONE), Some(TO_B_TONE)]);

    // ---- a stranger is still dropped -----------------------------------------------------------------
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind stranger");
    let mut intruder = [0u8; 160];
    siphon_rtp_codec::g711::G711::ulaw()
        .encode(&tone_frame(2_500.0, 0), &mut intruder)
        .expect("encode");
    bot.take_uplink();
    for round in 0..6u16 {
        for phone in [&mut rig.a, &mut rig.b] {
            let mut packet = g711_rtp(0, 50_000 + round, 0xBAD0_BAD0, 0);
            packet[12..].copy_from_slice(&intruder);
            let sealed = phone.seal(&packet);
            stranger
                .send_to(&sealed, phone.engine)
                .await
                .expect("stranger sends");
        }
        talk(&mut rig, &mut frame, 2, &mut log).await;
    }
    for channel in 0..2 {
        let uplink = bot.uplink(channel);
        assert!(
            power(&uplink, WIRE_RATE as f32, 2_500.0) < 25.0,
            "a source nobody signalled never reaches the bot (channel {channel})"
        );
    }

    // ---- the bot hangs up: one end event, the call stays isolated and silent -----------------------
    bot.control.lock().expect("control").close = true;
    wait_for("the end event", || {
        events.try_iter().any(|event| {
            matches!(&event, Event::WsSplitEnded(ended) if ended.reason == WsSplitEndReason::WsClosed)
        })
    })
    .await;
    talk(&mut rig, &mut frame, 8, &mut log).await;
    let (silent_a, silent_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_silent_audio(&decode(&silent_a), 8_000.0, "A after the bot left");
    assert_silent_audio(&decode(&silent_b), 8_000.0, "B after the bot left");
    assert!(
        silent_a.media.len() >= 20 && silent_b.media.len() >= 20,
        "still clocked"
    );
    assert!(
        rig.engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await
            .to_string_for_test()
            .contains("ws-split-already-bridged"),
        "the call is still the split's until it is detached"
    );

    // ---- detach: the direct path comes back, once, on the same streams --------------------------------
    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    assert_eq!(rig.kind(), rig.original, "back on its own kind");
    assert!(!rig.engine.media.is_split_marked(rig.call_id));
    assert_eq!(rig.engine.ws_split_count(), 0);
    assert!(
        split_events(&events).is_empty(),
        "the end was reported once, when the bot hung up"
    );
    talk(&mut rig, &mut frame, 12, &mut log).await;
    let (after_a, after_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(&decode(&after_b), 8_000.0, A_TONE, "B after the detach");
    assert_hears(&decode(&after_a), 8_000.0, B_TONE, "A after the detach");
    assert_eq!(after_a.rejected + after_b.rejected, 0);

    // A plain relay cannot renumber a stream, so its actor numbers its own (RFC 3550 §8.2); every
    // crypto bridge keeps one SSRC and one contiguous sequence through attach and detach.
    let (at_a, at_b) = log;
    if rig.original != PipelineKind::Passthrough {
        assert_stream_continuity(&at_b, rig.a.ssrc, "B hears A");
        assert_stream_continuity(&at_a, rig.b.ssrc, "A hears B");
    }
    assert_eq!(at_a.rejected + at_b.rejected, 0, "every datagram decrypts");
}

/// One SSRC, and a sequence number that rises by one on every packet it heard.
#[track_caller]
fn assert_stream_continuity(heard: &Heard, ssrc: u32, who: &str) {
    assert!(
        heard.media.len() > 100,
        "{who}: heard {} packets",
        heard.media.len()
    );
    for pair in heard.media.windows(2) {
        assert_eq!(pair[1].ssrc, ssrc, "{who}: one SSRC throughout");
        assert_eq!(
            pair[1].sequence,
            pair[0].sequence.wrapping_add(1),
            "{who}: the sequence never jumps: {pair:?}"
        );
    }
}

trait ResultText {
    fn to_string_for_test(&self) -> String;
}

impl ResultText for CmdResult {
    fn to_string_for_test(&self) -> String {
        format!("{self:?}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_call_is_split_and_restored() {
    assert_split_cycle(plain_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_to_plain_call_is_split_and_restored_under_its_own_keys() {
    assert_split_cycle(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_offerer_to_plain_call_is_split_and_restored_under_its_own_keys() {
    assert_split_cycle(srtp_offerer_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_to_sdes_call_is_split_and_restored_under_its_own_keys() {
    assert_split_cycle(srtp_transcrypt_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webrtc_answerer_to_plain_carrier_call_is_split_and_restored() {
    assert_split_cycle(dtls_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webrtc_answerer_behind_ice_is_split_and_restored() {
    assert_split_cycle(dtls_ice_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webrtc_offerer_to_plain_carrier_call_is_split_and_restored() {
    assert_split_cycle(dtls_offerer_rig().await).await;
}

// ---- refusals -----------------------------------------------------------------------------------

fn refusal(result: CmdResult) -> String {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A refusal leaves the call as it was: on its own kind, no split recorded, no mark, no actor it did
/// not have, and the bot was never dialled.
#[track_caller]
fn assert_untouched(rig: &Rig) {
    assert_eq!(rig.kind(), rig.original, "still on its own kind");
    assert_eq!(rig.engine.ws_split_count(), 0);
    assert!(!rig.engine.media.is_split_marked(rig.call_id));
    assert!(!rig
        .engine
        .calls
        .get(rig.call_id)
        .expect("call")
        .promotion_reasons
        .contains(&PromotionReason::WsSplit));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_that_cannot_be_split_is_refused_before_the_bot_is_dialled() {
    let rig = plain_rig().await;
    let bot = bot().await;

    // Not answered yet.
    let (_phone, addr) = phone().await;
    offer_from_a(
        &rig.engine,
        "unanswered",
        sdp_for(addr, true),
        Default::default(),
    )
    .await;
    let reason = refusal(
        rig.engine
            .handle(
                CLIENT,
                Command::AttachWsSplit(WsSplitAttach {
                    call_id: "unanswered".into(),
                    from_tag: "a".into(),
                    ws_uri: bot.uri.clone(),
                    sample_rate: None,
                    offerer_profile: None,
                    answerer_profile: None,
                }),
            )
            .await,
    );
    assert!(reason.contains("ws-split-not-answered"), "{reason}");

    // Answered by the engine itself.
    rig.engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, true),
                profile: Default::default(),
            },
        )
        .await;
    let reason = refusal(
        rig.engine
            .handle(
                CLIENT,
                Command::AttachWsSplit(WsSplitAttach {
                    call_id: "local".into(),
                    from_tag: "a".into(),
                    ws_uri: bot.uri.clone(),
                    sample_rate: None,
                    offerer_profile: None,
                    answerer_profile: None,
                }),
            )
            .await,
    );
    assert!(reason.contains("ws-split-answer-local"), "{reason}");

    // A wire rate that is not served, and a profile that asks for what a split does not run.
    let reason = refusal(
        rig.engine
            .handle(CLIENT, attach_command(&rig, &bot, Some(44_100)))
            .await,
    );
    assert!(reason.contains("ws-split-sample-rate"), "{reason}");
    let reason = refusal(
        rig.engine
            .handle(
                CLIENT,
                Command::AttachWsSplit(WsSplitAttach {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                    ws_uri: bot.uri.clone(),
                    sample_rate: None,
                    offerer_profile: Some(Box::new(ProfileFlags {
                        echo_cancellation: true,
                        ..Default::default()
                    })),
                    answerer_profile: None,
                }),
            )
            .await,
    );
    assert!(reason.contains("ws-split-profile"), "{reason}");
    assert_untouched(&rig);

    // A leg seated in a room.
    let seated = rig
        .engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: rig.call_id.into(),
                from_tag: "b".into(),
                conference_id: "room".into(),
                role: siphon_rtp_proto::ConferenceRole::Talker,
                dtmf: siphon_rtp_proto::ConferenceDtmf::Events,
            },
        )
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
    let reason = refusal(
        rig.engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await,
    );
    assert!(
        reason.contains("seated"),
        "a seated leg is refused: {reason}"
    );

    // The bot was never dialled by any of them: its listener still has nobody waiting.
    assert!(
        bot.seen.lock().expect("seen").start.is_none(),
        "no refusal dialled the bot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_with_a_split_or_a_takeover_already_on_it_is_refused() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let reason = refusal(
        rig.engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await,
    );
    assert!(reason.contains("ws-split-already-bridged"), "{reason}");
    rig.engine.handle(CLIENT, detach_command(&rig)).await;

    // A call a WebSocket takeover owns has no far party to split.
    rig.engine
        .calls
        .get_mut(rig.call_id)
        .expect("call")
        .pipeline = PipelineKind::Ws;
    let reason = refusal(
        rig.engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await,
    );
    assert!(reason.contains("ws-split-already-bridged"), "{reason}");
    rig.engine
        .calls
        .get_mut(rig.call_id)
        .expect("call")
        .pipeline = PipelineKind::Passthrough;
    rig.run(3, LOUD, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_source_of_a_multi_source_tee_is_refused_with_its_token() {
    let (engine, _events, streams) = super::multi_source_recording::siprec_streams(2).await;
    let (tee_uri, _frames, _downlink) = takeover_ws_server().await;
    let teed = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: streams[0].call_id.clone(),
                from_tag: super::multi_source_recording::SESSION_TAG.into(),
                ws_uri: tee_uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
                additional_sources: streams[1..].iter().map(|stream| stream.source()).collect(),
            },
        )
        .await;
    assert!(matches!(teed, CmdResult::Ok { .. }), "{teed:?}");
    let bot = bot().await;
    let reason = refusal(
        engine
            .handle(
                CLIENT,
                Command::AttachWsSplit(WsSplitAttach {
                    call_id: streams[1].call_id.clone(),
                    from_tag: super::multi_source_recording::SESSION_TAG.into(),
                    ws_uri: bot.uri.clone(),
                    sample_rate: None,
                    offerer_profile: None,
                    answerer_profile: None,
                }),
            )
            .await,
    );
    assert!(reason.contains("ws-split-secondary-source"), "{reason}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bot_that_cannot_be_dialled_leaves_the_call_exactly_as_it_was() {
    for rig in [plain_rig().await, srtp_rig().await, dtls_rig().await] {
        let mut rig = rig;
        rig.warm_up().await;
        // A port nobody listens on.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let uri = format!("ws://{}/gone", dead.local_addr().expect("addr"));
        drop(dead);
        let bot = Bot {
            uri,
            seen: Default::default(),
            control: Default::default(),
        };
        let reason = refusal(
            rig.engine
                .handle(CLIENT, attach_command(&rig, &bot, None))
                .await,
        );
        assert!(reason.contains("dial"), "{reason}");
        assert_untouched(&rig);
        assert!(
            !rig.engine.media.is_media_call(rig.call_id) || rig.original == PipelineKind::Media
        );
        // And it still relays directly.
        let (heard_a, heard_b) = rig.run(8, LOUD, None).await;
        assert!(!heard_a.media.is_empty() && !heard_b.media.is_empty());
    }
}

// ---- a re-offer while attached --------------------------------------------------------------------

/// The call is re-offered and answered while split: both parties still hear only the bot, nothing of
/// the other party gets through in between, the keys carry on, and the detach restores the bridge.
async fn assert_reoffer_while_split(mut rig: Rig) {
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    talk(&mut rig, &mut frame, 20, &mut log).await;

    rig.reoffer().await;
    assert_eq!(
        rig.kind(),
        rig.held,
        "the re-offer keeps the call on the actor's kind"
    );
    assert_eq!(rig.engine.ws_split_count(), 1);
    assert!(rig.engine.media.is_split_marked(rig.call_id));

    // Over the re-offer, and after it: the same isolation, the same two channels.
    talk(&mut rig, &mut frame, 15, &mut log).await;
    bot.take_uplink();
    let (after_a, after_b) = talk(&mut rig, &mut frame, 40, &mut log).await;
    assert_hears(
        &decode(&after_a),
        8_000.0,
        TO_A_TONE,
        "A after the re-offer",
    );
    assert_hears(
        &decode(&after_b),
        8_000.0,
        TO_B_TONE,
        "B after the re-offer",
    );
    assert_hears(
        &bot.uplink(0),
        WIRE_RATE as f32,
        A_TONE,
        "bot channel 0 after the re-offer",
    );
    assert_hears(
        &bot.uplink(1),
        WIRE_RATE as f32,
        B_TONE,
        "bot channel 1 after the re-offer",
    );
    // The whole span the party heard decrypted and carried no tone of the other party.
    assert_eq!(log.0.rejected + log.1.rejected, 0);
    for heard in [&log.0, &log.1] {
        let during = decode(heard);
        let (a_leaked, b_leaked) = (
            power(&during, 8_000.0, A_TONE),
            power(&during, 8_000.0, B_TONE),
        );
        // A hears B's tone only before the split; the split's whole span is a small share of it.
        assert!(a_leaked.min(b_leaked) < a_leaked.max(b_leaked) + 1.0);
    }
    assert!(
        split_events(&events)
            .iter()
            .all(|event| matches!(event, Event::WsSplitStarted(_))),
        "a re-offer is not the end of the split"
    );

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(rig.kind(), rig.original);
    let (back_a, back_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(&decode(&back_b), 8_000.0, A_TONE, "B after the detach");
    assert_hears(&decode(&back_a), 8_000.0, B_TONE, "A after the detach");
    assert_eq!(log.0.rejected + log.1.rejected, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_while_an_sdes_call_is_split_keeps_the_split_and_the_keys() {
    assert_reoffer_while_split(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_while_a_dtls_call_is_split_keeps_the_split_and_the_association() {
    assert_reoffer_while_split(dtls_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_while_a_plain_call_is_split_keeps_the_split() {
    let mut rig = plain_rig().await;
    let addr_a = rig.a.socket.local_addr().expect("a");
    let addr_b = rig.b.socket.local_addr().expect("b");
    rig.reoffer = Some(Reoffer {
        sdp: sdp_for(addr_a, true),
        profile: ProfileFlags::default(),
        answer: sdp_for(addr_b, true),
        far_addr: addr_b,
    });
    assert_reoffer_while_split(rig).await;
}

/// Packets in `heard` that carry the other party's tone, taken one at a time so a single leaked
/// frame shows. `own` is the tone the party is meant to hear, if any.
fn leaked_packets(heard: &Heard, other_tone: f32, own: f32) -> usize {
    heard
        .media
        .iter()
        .filter(|packet| {
            let one = Heard {
                media: vec![(*packet).clone()],
                ..Heard::default()
            };
            let pcm = decode(&one);
            power(&pcm, 8_000.0, other_tone) > 4.0 * power(&pcm, 8_000.0, own) + 1_000.0
        })
        .count()
}

/// Both phones send through `frames` ptimes at a high rate and listen as they go; nothing either
/// hears may carry the other's tone, and both must hear packets (the call is up, silent or not).
async fn assert_isolated_for(
    rig: &mut Rig,
    frame: &mut usize,
    frames: usize,
    own: [f32; 2],
    why: &str,
) {
    let mut heard = (Heard::default(), Heard::default());
    for _ in 0..frames {
        send_tone(&mut rig.a, A_TONE, *frame).await;
        send_tone(&mut rig.b, B_TONE, *frame).await;
        *frame += 1;
        tokio::time::sleep(Duration::from_millis(4)).await;
        heard.0.absorb(rig.a.listen(Duration::from_millis(2)).await);
        heard.1.absorb(rig.b.listen(Duration::from_millis(2)).await);
    }
    assert!(
        !heard.0.media.is_empty() && !heard.1.media.is_empty(),
        "{why}: the call is up"
    );
    assert_eq!(
        leaked_packets(&heard.0, B_TONE, own[0]),
        0,
        "{why}: A heard B"
    );
    assert_eq!(
        leaked_packets(&heard.1, A_TONE, own[1]),
        0,
        "{why}: B heard A"
    );
}

/// A DTLS re-handshake cannot be followed, and cannot be allowed to reconnect the parties either: the
/// answer is refused, the call keeps its association and its isolation, nothing is reported ended,
/// and the controller's detach is what gets direct audio back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_rehandshake_while_split_is_refused_and_the_call_stays_isolated() {
    let mut rig = dtls_rig().await;
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 10, &mut log).await;
    let _ = split_events(&events);

    let other = DtlsCertificate::generate().expect("second certificate");
    let (sdp, profile, far_addr) = {
        let reoffer = rig.reoffer.as_ref().expect("re-offer");
        (
            reoffer.sdp.clone(),
            reoffer.profile.clone(),
            reoffer.far_addr,
        )
    };
    let result = reoffer_from(&rig.engine, rig.call_id, "a", sdp, profile).await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    let answered = rig
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: dtls_answer_sdp(far_addr, 0, "PCMU", &other, sdp::Setup::Active),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let reason = refusal(answered);
    assert!(reason.contains("ws-split-renegotiation"), "{reason}");
    assert!(split_events(&events).is_empty(), "the split did not end");
    assert_eq!(rig.engine.ws_split_count(), 1);
    assert!(
        rig.engine.is_secure_held(rig.call_id),
        "still held on its association"
    );
    assert_isolated_for(
        &mut rig,
        &mut frame,
        60,
        [TO_A_TONE, TO_B_TONE],
        "after the refused re-handshake",
    )
    .await;

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(rig.kind(), PipelineKind::Dtls, "back on its DTLS bridge");
    let (back_a, back_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A after the detach",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B after the detach",
    );
}

/// An end the engine itself decides on (a re-offer the split cannot follow) reports once and leaves
/// the call isolated and silent on the actor; only the controller's detach gets direct audio back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_end_the_engine_decides_leaves_the_call_isolated_until_detach() {
    let mut rig = plain_rig().await;
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 10, &mut log).await;
    let _ = split_events(&events);

    rig.engine
        .end_ws_split_isolated(rig.call_id, WsSplitEndReason::Renegotiated)
        .await;
    rig.engine
        .end_ws_split_isolated(rig.call_id, WsSplitEndReason::Renegotiated)
        .await;
    let ended: Vec<_> = split_events(&events)
        .into_iter()
        .filter_map(|event| match event {
            Event::WsSplitEnded(ended) => Some(ended.reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![WsSplitEndReason::Renegotiated], "reported once");
    assert_eq!(
        rig.engine.ws_split_count(),
        1,
        "the split is still on the call"
    );
    assert!(rig.engine.media.is_split_marked(rig.call_id));
    assert_isolated_for(
        &mut rig,
        &mut frame,
        60,
        [0.0, 0.0],
        "after the engine ended the stream",
    )
    .await;

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert!(
        split_events(&events).is_empty(),
        "the end was already reported"
    );
    let (back_a, back_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A after the detach",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B after the detach",
    );
}

/// A checkpoint taken while the call is split carries the isolation: the restored call registers its
/// actor isolated and silent, reports `ws_split_ended` (`restored`) once, and only a detach gets
/// direct audio back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restored_split_call_stays_isolated_until_detach() {
    let mut rig = plain_rig().await;
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 10, &mut log).await;
    let CmdResult::Checkpoint { snapshot } = rig
        .engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
            },
        )
        .await
    else {
        panic!("a split call checkpoints");
    };
    assert!(snapshot.contains("\"split_isolated\":true"), "{snapshot}");
    // The engine that took the checkpoint is gone; a standby restores it on the same ports.
    rig.engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    let _ = split_events(&events);
    let restored = rig
        .engine
        .handle(CLIENT, Command::Restore { snapshot })
        .await;
    assert!(matches!(restored, CmdResult::Ok { .. }), "{restored:?}");
    let ended: Vec<_> = split_events(&events)
        .into_iter()
        .filter_map(|event| match event {
            Event::WsSplitEnded(ended) => Some(ended.reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![WsSplitEndReason::Restored]);
    assert!(rig.engine.media.is_split_marked(rig.call_id));
    assert_isolated_for(&mut rig, &mut frame, 80, [0.0, 0.0], "after the restore").await;

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert!(!rig.engine.media.is_split_marked(rig.call_id));
    let (back_a, back_b) = talk(&mut rig, &mut frame, 40, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A after the detach",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B after the detach",
    );
}

// ---- recording, delete -------------------------------------------------------------------------

/// A recording on the call keeps the parties' own voices, never the bot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recording_keeps_the_original_voices_and_never_the_bots() {
    for rig in [plain_rig().await, srtp_rig().await, dtls_rig().await] {
        let mut rig = rig;
        let events = rig.engine.register_client(CLIENT);
        rig.warm_up().await;
        let directory = std::env::temp_dir().join(format!("split-rec-{}", rig.call_id));
        std::fs::create_dir_all(&directory).expect("dir");
        let started = rig
            .engine
            .handle(
                CLIENT,
                Command::StartRecording {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                    recording_dir: Some(directory.to_string_lossy().into_owned()),
                    format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                    direction: Some(RecordingDirection::Both),
                    channels: Some(RecordingChannels::Stereo),
                    max_duration_ms: None,
                    silence_ms: None,
                    path: None,
                    bitrate_bps: None,
                    additional_sources: Vec::new(),
                },
            )
            .await;
        let CmdResult::Ok {
            recording_id: Some(recording_id),
            ..
        } = started
        else {
            panic!("the recording starts, got {started:?}");
        };
        let bot = bot().await;
        let mut frame = 0usize;
        let mut log = (Heard::default(), Heard::default());
        talk(&mut rig, &mut frame, 10, &mut log).await;
        let attached = rig
            .engine
            .handle(CLIENT, attach_command(&rig, &bot, None))
            .await;
        assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
        talk(&mut rig, &mut frame, 60, &mut log).await;
        rig.engine.handle(CLIENT, detach_command(&rig)).await;
        talk(&mut rig, &mut frame, 10, &mut log).await;
        let stopped = rig
            .engine
            .handle(
                CLIENT,
                Command::StopRecording {
                    call_id: rig.call_id.into(),
                    from_tag: "a".into(),
                    recording_id: Some(recording_id.clone()),
                },
            )
            .await;
        assert!(matches!(stopped, CmdResult::Ok { .. }), "{stopped:?}");
        let path = loop {
            match events.recv_async().await {
                Ok(Event::RecordingFinished { path, .. }) => break path.expect("a file"),
                Ok(_) => {}
                Err(_) => panic!("no recording_finished"),
            }
        };
        let bytes = std::fs::read(&path).expect("read");
        let wav = siphon_rtp_media::player::WavSource::parse(&bytes).expect("valid WAV");
        let samples = wav.samples();
        let rate = wav.sample_rate_hz() as f32;
        let (left, right): (Vec<i16>, Vec<i16>) = (
            samples.iter().step_by(2).copied().collect(),
            samples.iter().skip(1).step_by(2).copied().collect(),
        );
        // One channel per party, as the engine labels them, and none of the bot's tones anywhere.
        let (a_channel, b_channel) = if power(&left, rate, A_TONE) > power(&right, rate, A_TONE) {
            (&left, &right)
        } else {
            (&right, &left)
        };
        assert!(
            power(a_channel, rate, A_TONE) > 100.0,
            "{}: A's voice",
            rig.call_id
        );
        assert!(
            power(b_channel, rate, B_TONE) > 100.0,
            "{}: B's voice",
            rig.call_id
        );
        for (channel, own) in [(a_channel, A_TONE), (b_channel, B_TONE)] {
            for bot_tone in [TO_A_TONE, TO_B_TONE] {
                assert!(
                    power(channel, rate, bot_tone) * 1_000.0 < power(channel, rate, own),
                    "{}: the bot's {bot_tone} Hz is not in the recording",
                    rig.call_id
                );
            }
        }
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// Deleting a call while it is split closes the bot's socket, ends the split once, and leaves no
/// registry, mark, actor or task behind.
async fn assert_delete_while_split_drains(mut rig: Rig) {
    let events = rig.engine.register_client(CLIENT);
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut 0, 10, &mut log).await;
    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rig.engine.calls.get(rig.call_id).is_none());
    assert_eq!(rig.engine.ws_split_count(), 0);
    assert!(!rig.engine.media.is_split_marked(rig.call_id));
    assert!(
        !rig.engine.media.is_media_call(rig.call_id),
        "the actor is gone"
    );
    let ended: Vec<_> = split_events(&events)
        .into_iter()
        .filter_map(|event| match event {
            Event::WsSplitEnded(ended) => Some(ended.reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![WsSplitEndReason::CallDeleted]);
    // The socket is closed on the bot's side.
    wait_for("the bot's socket to close", || {
        Arc::strong_count(&bot.seen) == 1 || {
            let seen = bot.seen.lock().expect("seen");
            seen.start.is_some()
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_split_plain_call_drains_everything() {
    assert_delete_while_split_drains(plain_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_split_sdes_call_drains_everything() {
    assert_delete_while_split_drains(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_split_dtls_call_drains_everything() {
    assert_delete_while_split_drains(dtls_rig().await).await;
}

// ---- a WebRTC leg on Opus ------------------------------------------------------------------------

/// A plain G.711 A and a DTLS-SRTP B on Opus (`PipelineKind::DtlsMedia` from the start: the codecs
/// differ, so the call is already decoded and re-encoded and needs no promotion).
async fn opus_dtls_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");
    let offered = offer_from_a(
        &engine,
        "split-opus",
        sdp_for(addr_a, true),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        },
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine fingerprint");
    let peer_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    let answer = dtls_answer_sdp(addr_b, 111, "opus", &peer_cert, sdp::Setup::Active)
        .replace("opus/8000", "opus/48000/2");
    let answered = answer_from_b(&engine, "split-opus", answer, Default::default()).await;
    let leg = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        offered.remote_rtp,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;
    Rig {
        engine,
        call_id: "split-opus",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b: Phone::new(peer_b, offered.remote_rtp, Some(leg), 0x0B0B_0B0B),
        original: PipelineKind::DtlsMedia,
        held: PipelineKind::DtlsMedia,
        reoffer: None,
    }
}

fn opus_codec() -> siphon_rtp_codec::factory::CodecSpec {
    siphon_rtp_codec::factory::CodecSpec::new(111, "opus", 48_000, 1, 20)
}

/// One Opus frame of `frequency` from B, sealed under its own DTLS-SRTP context.
async fn send_opus_tone(
    phone: &mut Phone,
    encoder: &mut dyn Encoder,
    frequency: f32,
    frame: usize,
) {
    let pcm: Vec<i16> = (0..960)
        .map(|index| {
            let at = (frame * 960 + index) as f32;
            ((at * frequency * std::f32::consts::TAU / 48_000.0).sin() * 8_000.0) as i16
        })
        .collect();
    let mut payload = [0u8; 400];
    let length = encoder.encode(&pcm, &mut payload).expect("opus encode");
    let mut packet = vec![0x80, 111];
    packet.extend_from_slice(&phone.next_sequence.to_be_bytes());
    packet.extend_from_slice(&((frame * 960) as u32).to_be_bytes());
    packet.extend_from_slice(&phone.ssrc.to_be_bytes());
    packet.extend_from_slice(&payload[..length]);
    phone.next_sequence = phone.next_sequence.wrapping_add(1);
    let sealed = phone.seal(&packet);
    phone
        .socket
        .send_to(&sealed, phone.engine)
        .await
        .expect("phone sends");
}

fn decode_opus(heard: &Heard, decoder: &mut dyn Decoder) -> Vec<i16> {
    let mut pcm = Vec::new();
    let mut frame = vec![0i16; 5_760];
    for packet in &heard.media {
        let count = decoder
            .decode(&packet.payload, &mut frame)
            .expect("opus decode");
        pcm.extend_from_slice(&frame[..count]);
    }
    pcm
}

/// A WebRTC leg on Opus against a G.711 carrier: the call is a transcode before the split, the split
/// plays each party the bot in its own codec (Opus at 48 kHz toward B, µ-law at 8 kHz toward A), and
/// detaching leaves the transcode as it was.
async fn opus_cycle() {
    let mut rig = opus_dtls_rig().await;
    let mut encoder = siphon_rtp_codec::factory::encoder_for(&opus_codec()).expect("opus encoder");
    let mut decoder = siphon_rtp_codec::factory::decoder_for(&opus_codec()).expect("opus decoder");
    // Warm up: both ways until each side has heard the other.
    let mut frame = 0usize;
    for _ in 0..80 {
        send_tone(&mut rig.a, A_TONE, frame).await;
        send_opus_tone(&mut rig.b, encoder.as_mut(), B_TONE, frame).await;
        frame += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let heard_a = rig.a.listen(Duration::from_millis(5)).await;
        let heard_b = rig.b.listen(Duration::from_millis(5)).await;
        if !heard_a.media.is_empty() && !heard_b.media.is_empty() {
            break;
        }
    }
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    assert_eq!(rig.kind(), PipelineKind::DtlsMedia);

    let (mut at_a, mut at_b) = (Heard::default(), Heard::default());
    for round in 0..80 {
        send_tone(&mut rig.a, A_TONE, frame).await;
        send_opus_tone(&mut rig.b, encoder.as_mut(), B_TONE, frame).await;
        frame += 1;
        tokio::time::sleep(Duration::from_millis(12)).await;
        let (heard_a, heard_b) = (
            rig.a.listen(Duration::from_millis(8)).await,
            rig.b.listen(Duration::from_millis(8)).await,
        );
        if round >= 30 {
            at_a.absorb(heard_a);
            at_b.absorb(heard_b);
        }
    }
    assert_eq!(at_a.rejected + at_b.rejected, 0);
    assert_hears(
        &decode(&at_a),
        8_000.0,
        TO_A_TONE,
        "A hears bot channel 0 in G.711",
    );
    let heard_by_b = decode_opus(&at_b, decoder.as_mut());
    assert_hears(
        &heard_by_b,
        48_000.0,
        TO_B_TONE,
        "B hears bot channel 1 in Opus",
    );
    assert!(
        at_b.media.iter().all(|packet| !packet.payload.is_empty()),
        "every packet B was sent carries an Opus frame"
    );
    assert_hears(
        &bot.uplink(0),
        WIRE_RATE as f32,
        A_TONE,
        "the bot hears A on channel 0",
    );
    assert_hears(
        &bot.uplink(1),
        WIRE_RATE as f32,
        B_TONE,
        "the bot hears B (Opus) on channel 1",
    );

    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(
        rig.kind(),
        PipelineKind::DtlsMedia,
        "still the transcode it was"
    );
    let (mut back_a, mut back_b) = (Heard::default(), Heard::default());
    for round in 0..60 {
        send_tone(&mut rig.a, A_TONE, frame).await;
        send_opus_tone(&mut rig.b, encoder.as_mut(), B_TONE, frame).await;
        frame += 1;
        tokio::time::sleep(Duration::from_millis(12)).await;
        let (heard_a, heard_b) = (
            rig.a.listen(Duration::from_millis(8)).await,
            rig.b.listen(Duration::from_millis(8)).await,
        );
        if round >= 20 {
            back_a.absorb(heard_a);
            back_b.absorb(heard_b);
        }
    }
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B directly again",
    );
    let direct = decode_opus(&back_b, decoder.as_mut());
    assert_hears(&direct, 48_000.0, A_TONE, "B hears A directly again");
}

/// The Opus codecs are large values and a debug build runs them on stacks well past a test thread's
/// default, so this test brings its own runtime with threads sized for them.
#[test]
fn a_webrtc_opus_leg_to_a_g711_carrier_is_split_and_restored() {
    const STACK: usize = 64 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(STACK)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(opus_cycle());
        })
        .expect("spawn")
        .join()
        .expect("the Opus cycle passed");
}

/// A party's uplink profile is honoured: noise suppression runs on that party's uplink for as long as
/// the split is attached, the bot still receives audio, and the detach restores a plain direct call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_uplink_profile_with_noise_suppression_is_applied_and_then_removed() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    bot.control.lock().expect("control").rate = 24_000;
    let attached = rig
        .engine
        .handle(
            CLIENT,
            Command::AttachWsSplit(WsSplitAttach {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                ws_uri: bot.uri.clone(),
                sample_rate: Some(24_000),
                offerer_profile: Some(Box::new(ProfileFlags {
                    noise_suppression: true,
                    ..Default::default()
                })),
                answerer_profile: None,
            }),
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 40, &mut log).await;
    assert!(
        bot.uplink(0).len() > 24_000 / 2,
        "the bot receives the offerer's uplink at the 24 kHz it asked for"
    );
    let start = bot.seen.lock().expect("seen").start.clone().expect("start");
    assert_eq!(start["data"]["media"]["sampleRate"], 24_000);
    let (heard_a, _heard_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(
        &decode(&heard_a),
        8_000.0,
        TO_A_TONE,
        "A is played the bot at 24 kHz, converted",
    );
    rig.engine.handle(CLIENT, detach_command(&rig)).await;
    let (back_a, back_b) = talk(&mut rig, &mut frame, 40, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A directly after the detach",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B directly after the detach",
    );
}

// ---- no crossing while a re-offer re-installs the media path --------------------------------------

/// Both phones keep sending through a re-offer and its answer, at a rate high enough that a window of
/// a few milliseconds cannot fall between two packets. Not one packet either party hears may carry the
/// other party's tone.
async fn assert_no_crossing_through_reoffer(mut rig: Rig, ended_first: bool) {
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 15, &mut log).await;
    if ended_first {
        bot.control.lock().expect("control").close = true;
        wait_for("the bot to be gone", || rig.engine.ws_split_count() == 1).await;
        talk(&mut rig, &mut frame, 15, &mut log).await;
    }
    let (sdp, profile, answer) = {
        let reoffer = rig.reoffer.as_ref().expect("a re-offer");
        (
            reoffer.sdp.clone(),
            reoffer.profile.clone(),
            reoffer.answer.clone(),
        )
    };
    let Rig {
        engine,
        call_id,
        a,
        b,
        ..
    } = &mut rig;
    let signalling = async {
        let result = reoffer_from(engine, call_id, "a", sdp, profile).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
        answer_from_b(engine, call_id, answer, ProfileFlags::default()).await;
    };
    let mut heard = (Heard::default(), Heard::default());
    let traffic = async {
        for step in 0..400usize {
            send_tone(a, A_TONE, frame + step).await;
            send_tone(b, B_TONE, frame + step).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            heard.0.absorb(a.listen(Duration::from_millis(1)).await);
            heard.1.absorb(b.listen(Duration::from_millis(1)).await);
        }
    };
    tokio::join!(signalling, traffic);
    for (who, party, other_tone, own_bot_tone) in [
        ("A", &heard.0, B_TONE, TO_A_TONE),
        ("B", &heard.1, A_TONE, TO_B_TONE),
    ] {
        assert!(party.media.len() > 20, "{who} kept hearing the call");
        let leaked = party
            .media
            .iter()
            .filter(|packet| {
                let one = Heard {
                    media: vec![(*packet).clone()],
                    ..Heard::default()
                };
                let pcm = decode(&one);
                power(&pcm, 8_000.0, other_tone)
                    > 4.0 * power(&pcm, 8_000.0, own_bot_tone) + 1_000.0
            })
            .count();
        assert_eq!(
            leaked, 0,
            "{who} heard {leaked} packet(s) of the other party"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_call_never_crosses_while_a_reoffer_is_answered() {
    let mut rig = plain_rig().await;
    let addr_a = rig.a.socket.local_addr().expect("a");
    let addr_b = rig.b.socket.local_addr().expect("b");
    rig.reoffer = Some(Reoffer {
        sdp: sdp_for(addr_a, true),
        profile: ProfileFlags::default(),
        answer: sdp_for(addr_b, true),
        far_addr: addr_b,
    });
    assert_no_crossing_through_reoffer(rig, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ended_split_on_a_plain_call_never_crosses_while_a_reoffer_is_answered() {
    let mut rig = plain_rig().await;
    let addr_a = rig.a.socket.local_addr().expect("a");
    let addr_b = rig.b.socket.local_addr().expect("b");
    rig.reoffer = Some(Reoffer {
        sdp: sdp_for(addr_a, true),
        profile: ProfileFlags::default(),
        answer: sdp_for(addr_b, true),
        far_addr: addr_b,
    });
    assert_no_crossing_through_reoffer(rig, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_call_never_crosses_while_a_reoffer_is_answered() {
    assert_no_crossing_through_reoffer(srtp_rig().await, false).await;
}

/// While a split is on a plain call the datapath is never given a `Forward` rule for it, whatever
/// else happens to the call: those rules take the endpoints back from the actor and cross the parties
/// for as long as it takes the engine to put the actor back. Observed on the installs themselves, so
/// the window cannot hide between two packets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_forward_rule_is_installed_on_a_split_call() {
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    tokio::spawn(crate::srtp_bridge::run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let events = engine.register_client(CLIENT);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let call_id = "no-forward";
    let offer = |sdp| Command::Reoffer {
        call_id: call_id.into(),
        from_tag: "a".into(),
        sdp,
        profile: Default::default(),
    };
    let answer = |sdp| Command::Answer {
        call_id: call_id.into(),
        from_tag: "a".into(),
        to_tag: "b".into(),
        sdp,
        profile: Default::default(),
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine.handle(CLIENT, answer(sdp_for(addr_b, true))).await;
    let bot = bot().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsSplit(WsSplitAttach {
                call_id: call_id.into(),
                from_tag: "a".into(),
                ws_uri: bot.uri.clone(),
                sample_rate: None,
                offerer_profile: None,
                answerer_profile: None,
            }),
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    datapath.take_installs();

    let reoffer_cycle = || async {
        let result = engine.handle(CLIENT, offer(sdp_for(addr_a, true))).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
        let result = engine.handle(CLIENT, answer(sdp_for(addr_b, true))).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    };
    // A re-offer while the split is attached; another after the bot has gone; and what else can
    // release or re-install a hold on the call: a recording and a tee that come and go.
    reoffer_cycle().await;
    bot.control.lock().expect("control").close = true;
    wait_for("the bot to be gone", || {
        engine
            .ws_splits
            .get(call_id)
            .is_some_and(|split| split.ended.load(std::sync::atomic::Ordering::SeqCst))
    })
    .await;
    assert!(
        events.try_iter().any(|event| matches!(
            &event,
            Event::WsSplitEnded(ended) if ended.reason == WsSplitEndReason::WsClosed
        )),
        "the second re-offer is the one after an unasked end"
    );
    reoffer_cycle().await;
    let directory = std::env::temp_dir().join("split-no-forward");
    std::fs::create_dir_all(&directory).expect("dir");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: call_id.into(),
                from_tag: "a".into(),
                recording_dir: Some(directory.to_string_lossy().into_owned()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
                bitrate_bps: None,
                additional_sources: Vec::new(),
            },
        )
        .await;
    let CmdResult::Ok {
        recording_id: Some(recording_id),
        ..
    } = started
    else {
        panic!("the recording starts, got {started:?}");
    };
    reoffer_cycle().await;
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: call_id.into(),
                from_tag: "a".into(),
                recording_id: Some(recording_id),
            },
        )
        .await;
    let (tee_uri, _frames, _down) = takeover_ws_server().await;
    let teed = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: call_id.into(),
                from_tag: "a".into(),
                ws_uri: tee_uri,
                direction: WsTeeDirection::Both,
                channels: None,
                sample_rate: None,
                additional_sources: Vec::new(),
            },
        )
        .await;
    assert!(matches!(teed, CmdResult::Ok { .. }), "{teed:?}");
    engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: call_id.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    let blocked = engine
        .handle(
            CLIENT,
            Command::BlockMedia {
                call_id: call_id.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    assert!(matches!(blocked, CmdResult::Ok { .. }), "{blocked:?}");
    engine
        .handle(
            CLIENT,
            Command::UnblockMedia {
                call_id: call_id.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    engine.refresh_latched_destinations().await;

    let forwards: Vec<_> = datapath
        .take_installs()
        .into_iter()
        .filter(|(_, action)| matches!(action, FlowAction::Forward(_)))
        .collect();
    assert!(
        forwards.is_empty(),
        "a split call was handed a Forward rule: {forwards:?}"
    );
    let _ = std::fs::remove_dir_all(&directory);

    // The detach is what puts the relay back, on the rules the last answer computed.
    engine
        .handle(
            CLIENT,
            Command::DetachWsSplit(WsSplitDetach {
                call_id: call_id.into(),
                from_tag: "a".into(),
            }),
        )
        .await;
    assert!(
        datapath
            .take_installs()
            .iter()
            .any(|(_, action)| matches!(action, FlowAction::Forward(_))),
        "the detach reinstalls the in-kernel relay"
    );
}

// ---- controls that change who hears whom are delivered or the caller is told --------------------

/// A detach whose controls cannot reach the actor (its mailbox is full and stays so) fails and
/// changes nothing: the split stays registered, marked and on the actor, so the controller sends it
/// again. Once the actor reads again the same detach is confirmed. `try_send` would have dropped the
/// controls, removed the registry entry and answered ok, leaving the actor split for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_the_actor_does_not_confirm_is_an_error_a_retry_fixes() {
    // On a native transcode, whose actor outlives the split, so a lingering isolation shows.
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    offer_from_a(
        &engine,
        "wedged",
        sdp_single_codec(addr_a, 0, "PCMU"),
        Default::default(),
    )
    .await;
    answer_from_b(
        &engine,
        "wedged",
        sdp_single_codec(addr_b, 8, "PCMA"),
        Default::default(),
    )
    .await;
    assert_eq!(
        engine.calls.get("wedged").expect("call").pipeline,
        PipelineKind::Media
    );
    let bot = bot().await;
    let attach = |call_id: &str| {
        Command::AttachWsSplit(WsSplitAttach {
            call_id: call_id.into(),
            from_tag: "a".into(),
            ws_uri: bot.uri.clone(),
            sample_rate: None,
            offerer_profile: None,
            answerer_profile: None,
        })
    };
    let attached = engine.handle(CLIENT, attach("wedged")).await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");

    let (real, _unread) = engine.media.wedge_mailbox("wedged").expect("an actor");
    let detach = Command::DetachWsSplit(WsSplitDetach {
        call_id: "wedged".into(),
        from_tag: "a".into(),
    });
    let refused = refusal(engine.handle(CLIENT, detach.clone()).await);
    assert!(refused.contains("send detach_ws_split again"), "{refused}");
    assert_eq!(engine.ws_split_count(), 1, "the split is still registered");
    assert!(engine.media.is_split_marked("wedged"), "and still marked");
    assert!(engine.is_split_held("wedged"), "and still holds the call");

    engine.media.unwedge_mailbox("wedged", real);
    let detached = engine.handle(CLIENT, detach).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(engine.ws_split_count(), 0);
    assert!(!engine.media.is_split_marked("wedged"));
    assert!(!engine.is_split_held("wedged"));
}

/// An attach whose first control cannot reach an actor the call already has stops there, announces
/// nothing and leaves the call isolated and silent (the isolation may have landed), which a detach
/// undoes once the actor answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attach_the_actor_does_not_confirm_leaves_the_call_as_it_was() {
    let engine = engine_with_dispatcher();
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    offer_from_a(
        &engine,
        "wedged-attach",
        sdp_single_codec(addr_a, 0, "PCMU"),
        Default::default(),
    )
    .await;
    answer_from_b(
        &engine,
        "wedged-attach",
        sdp_single_codec(addr_b, 8, "PCMA"),
        Default::default(),
    )
    .await;
    let bot = bot().await;
    let (real, _unread) = engine
        .media
        .wedge_mailbox("wedged-attach")
        .expect("an actor");
    let refused = refusal(
        engine
            .handle(
                CLIENT,
                Command::AttachWsSplit(WsSplitAttach {
                    call_id: "wedged-attach".into(),
                    from_tag: "a".into(),
                    ws_uri: bot.uri.clone(),
                    sample_rate: None,
                    offerer_profile: None,
                    answerer_profile: None,
                }),
            )
            .await,
    );
    assert!(refused.contains("could not be isolated"), "{refused}");
    assert!(refused.contains("send detach_ws_split"), "{refused}");
    // Whether the isolation reached the actor is not known, so the call is left on the safe side:
    // held and marked, no split registered, and a detach cleans it up once the actor answers.
    assert_eq!(engine.ws_split_count(), 0);
    assert!(engine.media.is_split_marked("wedged-attach"));
    assert!(engine.is_split_held("wedged-attach"));
    engine.media.unwedge_mailbox("wedged-attach", real);
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsSplit(WsSplitDetach {
                call_id: "wedged-attach".into(),
                from_tag: "a".into(),
            }),
        )
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert!(!engine.media.is_split_marked("wedged-attach"));
    assert!(!engine.is_split_held("wedged-attach"));
}

// ---- a detach nobody confirmed never takes effect; a delete never lifts anything --------------------

/// The detach the engine gave up on is sitting in the actor's mailbox when the actor wakes up. It must
/// not reconnect the parties: the controller was told the split is still on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_applied_late_after_it_was_reported_failed_changes_nothing() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 10, &mut log).await;

    // The actor stalls: the detach's control gets into its mailbox, its barrier does not.
    let (real, unread) = rig
        .engine
        .media
        .wedge_mailbox(rig.call_id)
        .expect("an actor");
    let refused = refusal(rig.engine.handle(CLIENT, detach_command(&rig)).await);
    assert!(refused.contains("send detach_ws_split again"), "{refused}");
    // The actor wakes and applies what had queued, the stale detach included.
    for queued in unread.try_iter() {
        let _ = real.send(queued);
    }
    rig.engine.media.unwedge_mailbox(rig.call_id, real);
    rig.engine
        .media
        .control_confirmed(rig.call_id, Vec::new())
        .await
        .expect("the actor has caught up");
    assert_eq!(rig.engine.ws_split_count(), 1, "still registered");
    assert_isolated_for(
        &mut rig,
        &mut frame,
        60,
        [TO_A_TONE, TO_B_TONE],
        "after the stale detach was applied",
    )
    .await;

    // The retry is a new generation and succeeds.
    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    let (back_a, back_b) = talk(&mut rig, &mut frame, 30, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A after the retry",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B after the retry",
    );
}

/// A delete lifts nothing: it sends the actor no control that ends the isolation or takes a fork off,
/// so nothing crosses while recordings and interception finish. The mark goes with the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_delete_never_lifts_the_isolation() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let (_real, unread) = rig
        .engine
        .media
        .wedge_mailbox_unbounded(rig.call_id)
        .expect("an actor");
    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    let lifting: Vec<_> = unread
        .try_iter()
        .filter(|input| {
            matches!(
                input,
                crate::media_pipeline::MediaInput::Control(
                    MediaControl::SplitDetach { .. } | MediaControl::RemoveForkTagged { .. }
                )
            )
        })
        .collect();
    assert!(
        lifting.is_empty(),
        "the delete sent the actor {} controls that lift",
        lifting.len()
    );
    assert_eq!(rig.engine.ws_split_count(), 0);
    assert!(
        !rig.engine.media.is_split_marked(rig.call_id),
        "the mark went with the call"
    );
}

/// An isolation left by an attach that could not undo itself does not outlive the call: the same
/// call-id made again starts clean and carries audio.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_attach_does_not_isolate_a_call_made_later_under_the_same_id() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let bot = bot().await;
    let make = || async {
        let (phone_a, addr_a) = phone().await;
        let (phone_b, addr_b) = phone().await;
        let offered = offer_from_a(
            &engine,
            "reused",
            sdp_single_codec(addr_a, 0, "PCMU"),
            Default::default(),
        )
        .await;
        let answered = answer_from_b(
            &engine,
            "reused",
            sdp_single_codec(addr_b, 8, "PCMA"),
            Default::default(),
        )
        .await;
        (phone_a, answered.remote_rtp, phone_b, offered.remote_rtp)
    };
    let (_a, _near, _b, _far) = make().await;
    let (real, _unread) = engine.media.wedge_mailbox("reused").expect("an actor");
    let attach = Command::AttachWsSplit(WsSplitAttach {
        call_id: "reused".into(),
        from_tag: "a".into(),
        ws_uri: bot.uri.clone(),
        sample_rate: None,
        offerer_profile: None,
        answerer_profile: None,
    });
    let refused = refusal(engine.handle(CLIENT, attach).await);
    assert!(refused.contains("send detach_ws_split"), "{refused}");
    assert!(
        engine.media.is_split_marked("reused"),
        "left isolated, as designed"
    );
    engine.media.unwedge_mailbox("reused", real);
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "reused".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        !engine.media.is_split_marked("reused"),
        "the delete cleared the mark"
    );
    assert_eq!(engine.media.split_marked_count(), 0);

    // The same id again: media crosses.
    let (phone_a, near, phone_b, _far) = make().await;
    for sequence in 0..30u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x10), near)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (relayed, _) = recv(&phone_b).await;
    assert!(
        relayed.len() > 12,
        "B hears A on the call made under the reused id"
    );
    assert!(
        relayed[12..].iter().any(|byte| *byte != 0xD5),
        "and it is A's audio, not the silence an isolated actor sends"
    );
}

// ---- the detach that was applied and not heard; audio left in the queues; DTLS decoding calls ----------

/// The actor applies a detach and the answer is never heard: the engine reports the failure, the
/// parties are already connected, and the retry finds that out instead of assuming, finishes the
/// engine's side and reports success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_the_actor_applied_but_never_answered_is_reconciled_by_the_retry() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let mut frame = 0usize;
    let mut log = (Heard::default(), Heard::default());
    talk(&mut rig, &mut frame, 10, &mut log).await;

    let (real, unread) = rig
        .engine
        .media
        .wedge_mailbox(rig.call_id)
        .expect("an actor");
    let applier = {
        let real = real.clone();
        async move {
            // The actor applies the detach, and its answer is lost on the way back.
            let queued =
                loop {
                    if let Ok(crate::media_pipeline::MediaInput::Control(
                        MediaControl::SplitDetach { epoch, tag, reply },
                    )) = unread.try_recv()
                    {
                        break (epoch, tag, reply);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                };
            let (epoch, tag, reply) = queued;
            let _ = real.send(crate::media_pipeline::MediaInput::Control(
                MediaControl::SplitDetach {
                    epoch,
                    tag,
                    reply: None,
                },
            ));
            let (barrier, applied) = tokio::sync::oneshot::channel();
            let _ = real.send(crate::media_pipeline::MediaInput::Control(
                MediaControl::Barrier { reply: barrier },
            ));
            let _ = applied.await;
            drop(reply);
        }
    };
    let (outcome, ()) = tokio::join!(rig.engine.handle(CLIENT, detach_command(&rig)), applier);
    let refused = refusal(outcome);
    assert!(refused.contains("send detach_ws_split again"), "{refused}");
    assert_eq!(
        rig.engine.ws_split_count(),
        1,
        "the engine still has the split"
    );

    rig.engine.media.unwedge_mailbox(rig.call_id, real);
    let detached = rig.engine.handle(CLIENT, detach_command(&rig)).await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    assert_eq!(rig.engine.ws_split_count(), 0);
    assert!(!rig.engine.media.is_split_marked(rig.call_id));
    assert!(!rig.engine.is_split_held(rig.call_id));
    assert_eq!(rig.kind(), rig.original, "the relay is back");
    let (back_a, back_b) = talk(&mut rig, &mut frame, 40, &mut log).await;
    assert_hears(
        &decode(&back_b),
        8_000.0,
        A_TONE,
        "B hears A after the reconciling detach",
    );
    assert_hears(
        &decode(&back_a),
        8_000.0,
        B_TONE,
        "A hears B after the reconciling detach",
    );
}

/// What the bot had sent and the actor had not played does not play on after the stream was ended by
/// the engine or the call deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_the_bot_left_queued_does_not_play_on_after_the_engine_ends_the_stream() {
    let mut rig = plain_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    // A burst of audio faster than real time: most of it is queued behind the actor's clock.
    bot.control.lock().expect("control").burst = 40;
    wait_for("a backlog", || {
        rig.engine.ws_split_queued(rig.call_id) > Some(10)
    })
    .await;
    // What the parties had buffered from before the split is not what is being asked about.
    let _ = rig.a.listen(Duration::from_millis(60)).await;
    let _ = rig.b.listen(Duration::from_millis(60)).await;
    rig.engine
        .end_ws_split_isolated(rig.call_id, WsSplitEndReason::Renegotiated)
        .await;
    assert_eq!(
        rig.engine.ws_split_queued(rig.call_id),
        Some(0),
        "nothing of the bot is left to play once the stream is over"
    );
    let mut frame = 0usize;
    assert_isolated_for(&mut rig, &mut frame, 30, [0.0, 0.0], "after the end").await;
}

/// A DTLS re-handshake on a call that was a decoding DTLS call from the start (no bridge hold behind
/// it) is refused under a split like any other: the answer would install a new association under it.
async fn dtls_media_rehandshake_cycle() {
    let mut rig = opus_dtls_rig().await;
    rig.warm_up().await;
    let bot = bot().await;
    let attached = rig
        .engine
        .handle(CLIENT, attach_command(&rig, &bot, None))
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    assert_eq!(rig.kind(), PipelineKind::DtlsMedia);
    let addr_a = rig.a.socket.local_addr().expect("a");
    let addr_b = rig.b.socket.local_addr().expect("b");
    let result = reoffer_from(
        &rig.engine,
        rig.call_id,
        "a",
        sdp_for(addr_a, true),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    let other = siphon_rtp_dtls::DtlsCertificate::generate().expect("second certificate");
    let answer = dtls_answer_sdp(addr_b, 111, "opus", &other, sdp::Setup::Active)
        .replace("opus/8000", "opus/48000/2");
    let answered = rig
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let reason = refusal(answered);
    assert!(reason.contains("ws-split-renegotiation"), "{reason}");
    assert_eq!(rig.engine.ws_split_count(), 1, "the split is untouched");
    assert!(rig.engine.media.is_split_marked(rig.call_id));
}

/// The Opus codecs are large values; see the other Opus test.
#[test]
fn a_dtls_rehandshake_on_a_decoding_dtls_call_is_refused_while_split() {
    const STACK: usize = 64 * 1024 * 1024;
    std::thread::Builder::new()
        .stack_size(STACK)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .thread_stack_size(STACK)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(dtls_media_rehandshake_cycle());
        })
        .expect("spawn")
        .join()
        .expect("the re-handshake was refused");
}
