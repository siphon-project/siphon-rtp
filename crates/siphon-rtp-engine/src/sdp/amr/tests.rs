#![cfg(test)]
//! AMR offers and answers, table-driven from the SDP examples of 3GPP TS 26.114 Annex A and the
//! rules of RFC 4867 §8.3.1.

use super::*;
#[cfg(feature = "amr")]
use crate::sdp::force_answer_codec;
use crate::sdp::{apply_codec_policy, parse, CodecPolicy};

/// An audio-only SDP body around `media`, the `m=audio` line and its attributes.
fn sdp(media: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n{}\r\n",
        media.trim().replace('\n', "\r\n")
    )
}

/// 3GPP TS 26.114 Table A.3.1 (and A.1.2 without the channel count): a terminal offering AMR-WB
/// and AMR, each bandwidth-efficient first and octet-aligned second.
#[cfg(feature = "amr")]
const TERMINAL_OFFER: &str = "m=audio 49152 RTP/AVP 97 98 99 100
a=rtpmap:97 AMR-WB/16000
a=fmtp:97 mode-change-capability=2; max-red=220
a=rtpmap:98 AMR-WB/16000
a=fmtp:98 mode-change-capability=2; max-red=220; octet-align=1
a=rtpmap:99 AMR/8000
a=fmtp:99 mode-change-capability=2; max-red=220
a=rtpmap:100 AMR/8000
a=fmtp:100 mode-change-capability=2; max-red=220; octet-align=1
a=ptime:20
a=maxptime:240";

/// 3GPP TS 26.114 Table A.2.1: a gateway to a circuit-switched network offering AMR in one mode
/// set with restricted mode changes. The comma after `mode-change-period=2` is the table's own.
#[cfg(feature = "amr")]
const GATEWAY_OFFER: &str = "m=audio 49152 RTP/AVP 97
a=rtpmap:97 AMR/8000/1
a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2, mode-change-neighbor=1; mode-change-capability=2; max-red=0
a=ptime:20
a=maxptime:80";

/// 3GPP TS 26.114 Table A.2.4: the same gateway with wideband first.
#[cfg(feature = "amr")]
const WIDEBAND_GATEWAY_OFFER: &str = "m=audio 49152 RTP/AVP 98 97
a=rtpmap:97 AMR/8000/1
a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2, mode-change-neighbor=1; mode-change-capability=2; max-red=0
a=rtpmap:98 AMR-WB/16000/1
a=fmtp:98 mode-set=0,1,2; mode-change-period=2, mode-change-neighbor=1; mode-change-capability=2; max-red=0
a=ptime:20
a=maxptime:80";

fn fmtp(body: &str) -> AmrFmtp {
    parse_fmtp(&format!("fmtp:96 {body}"))
        .unwrap_or_else(|| panic!("{body} is an AMR fmtp"))
        .1
}

#[test]
fn every_rfc_4867_parameter_is_read_as_written() {
    let read = fmtp(
        "octet-align=1;mode-set=7,0,2;mode-change-period=2;mode-change-capability=2;\
         mode-change-neighbor=1;crc=0;robust-sorting=0;max-red=220",
    );
    assert_eq!(read.mode_set, [7, 0, 2], "in the order listed");
    assert_eq!(
        read.params,
        AmrParams {
            octet_align: Some(true),
            crc: Some(false),
            robust_sorting: Some(false),
            interleaving: None,
            mode_change_period: Some(2),
            mode_change_capability: Some(2),
            mode_change_neighbor: Some(true),
            max_red: Some(220),
            malformed: false,
            mode_request: None,
        }
    );
    // Absent stays absent: each parameter has its own default and its own way back in an answer.
    assert_eq!(fmtp("max-red=0").params.octet_align, None);
    assert_eq!(fmtp("octet-align=0").params.octet_align, Some(false));
    // Names are case-insensitive, spaces around the separators do not matter, and the annex's
    // comma between two parameters separates them without splitting a mode-set.
    let annex = fmtp("Mode-Set=0,2,4,7; mode-change-period=2, mode-change-neighbor=1 ; MAX-RED=0");
    assert_eq!(annex.mode_set, [0, 2, 4, 7]);
    assert_eq!(annex.params.mode_change_period, Some(2));
    assert_eq!(annex.params.mode_change_neighbor, Some(true));
    assert_eq!(annex.params.max_red, Some(0));
    assert!(!annex.params.malformed);
    // Interleaving is on by being present.
    assert_eq!(fmtp("interleaving=30").params.interleaving, Some(30));
    // The fmtp of another codec is not an AMR one.
    assert_eq!(parse_fmtp("fmtp:111 stereo=1;useinbandfec=1"), None);
    assert_eq!(parse_fmtp("fmtp:18 annexb=no"), None);
    assert_eq!(parse_fmtp("fmtp:101 0-15"), None);
    assert_eq!(parse_fmtp("fmtp:x octet-align=1"), None);
}

#[test]
fn a_value_the_rfc_does_not_permit_marks_the_payload_type_unusable() {
    for body in [
        "octet-align=2",
        "octet-align=",
        "crc=yes",
        "robust-sorting=-1",
        "mode-change-period=3",
        "mode-change-capability=0",
        "mode-change-neighbor=2",
        "max-red=70000",
        "mode-set=",
        "mode-set=0,x",
        "mode-set=0;mode-set=",
    ] {
        assert!(fmtp(body).params.malformed, "{body}");
    }
    assert!(!fmtp("mode-set=0, 1 ,2").params.malformed);
}

/// The payload type a local answer selects from `offer` (the first one the engine can encode, as
/// `answer_local` does it), and the SDP it answers with.
#[cfg(feature = "amr")]
fn answer(offer: &str) -> Option<(CodecSpec, String)> {
    let info = parse(&sdp(offer)).expect("parse");
    let chosen = info
        .audio_codecs()
        .into_iter()
        .find(|spec| siphon_rtp_codec::factory::encoder_for(spec).is_ok())?;
    let answered = force_answer_codec(&sdp(offer), &chosen, info.telephone_event_payload_type());
    Some((chosen, answered))
}

#[cfg(feature = "amr")]
fn answered_fmtp(offer: &str) -> String {
    let (chosen, answered) = answer(offer).expect("a codec is selected");
    answered
        .lines()
        .find(|line| line.starts_with(&format!("a=fmtp:{} ", chosen.payload_type)))
        .unwrap_or_else(|| panic!("no fmtp for {} in {answered}", chosen.payload_type))
        .to_owned()
}

/// RFC 4867 §8.3.1 on what an answer returns, one offered `a=fmtp` at a time.
#[cfg(feature = "amr")]
#[test]
fn the_answer_returns_the_offered_parameters() {
    for (codec, offered, answered) in [
        // Nothing offered: bandwidth-efficient, and the engine's own capability.
        ("AMR", None, "mode-change-capability=2"),
        ("AMR-WB", None, "mode-change-capability=2"),
        // octet-align, unmodified: absent, 0 and 1 are three different things to return.
        (
            "AMR",
            Some("octet-align=1"),
            "octet-align=1;mode-change-capability=2",
        ),
        (
            "AMR-WB",
            Some("octet-align=0"),
            "octet-align=0;mode-change-capability=2",
        ),
        // "the answerer SHALL return the mode-set unmodified", in the order it came.
        (
            "AMR",
            Some("mode-set=0,2,4,7"),
            "mode-set=0,2,4,7;mode-change-capability=2",
        ),
        (
            "AMR-WB",
            Some("mode-set=0,1,2;octet-align=1"),
            "octet-align=1;mode-set=0,1,2;mode-change-capability=2",
        ),
        (
            "AMR-WB",
            Some("mode-set=2,0"),
            "mode-set=2,0;mode-change-capability=2",
        ),
        // crc and robust-sorting spelled out as off are returned as they came.
        (
            "AMR",
            Some("crc=0;robust-sorting=0;octet-align=1"),
            "octet-align=1;mode-change-capability=2;crc=0;robust-sorting=0",
        ),
        // The peer's mode change requirements are its own declarations: obeyed, not repeated
        // (3GPP TS 26.114 Table 6.3). Its capability is replaced by the engine's.
        (
            "AMR",
            Some("mode-change-period=2;mode-change-neighbor=1;mode-change-capability=1"),
            "mode-change-capability=2",
        ),
        // max-red as offered; "Any unknown parameter in an offer SHALL be removed in the answer."
        (
            "AMR-WB",
            Some("max-red=220;ecn-capable-rtp=leap;future=1"),
            "mode-change-capability=2;max-red=220",
        ),
    ] {
        let rate = if codec == "AMR" { 8000 } else { 16000 };
        let attribute = offered.map_or_else(String::new, |body| format!("\na=fmtp:96 {body}"));
        let offer = format!("m=audio 49152 RTP/AVP 96\na=rtpmap:96 {codec}/{rate}{attribute}");
        assert_eq!(
            answered_fmtp(&offer),
            format!("a=fmtp:96 {answered}"),
            "{codec} {offered:?}"
        );
    }
}

#[cfg(feature = "amr")]
#[test]
fn a_terminal_offer_is_answered_bandwidth_efficient_wideband() {
    // 3GPP TS 26.114 Table A.3.1: the answer to this offer is payload type 97 with
    // `mode-change-capability=2; max-red=220`, `a=ptime:20` and `a=maxptime:240`.
    let (chosen, answered) = answer(TERMINAL_OFFER).expect("a codec is selected");
    assert_eq!(
        (chosen.payload_type, chosen.encoding_name.as_str()),
        (97, "AMR-WB")
    );
    assert!(!chosen.amr.unwrap_or_default().octet_aligned());
    assert!(
        answered.contains("m=audio 49152 RTP/AVP 97\r\n"),
        "{answered}"
    );
    assert!(
        answered.contains("a=rtpmap:97 AMR-WB/16000\r\n"),
        "{answered}"
    );
    assert!(
        answered.contains("a=fmtp:97 mode-change-capability=2;max-red=220\r\n"),
        "{answered}"
    );
    assert!(answered.contains("a=ptime:20\r\n"), "{answered}");
    assert!(answered.contains("a=maxptime:240\r\n"), "{answered}");
    assert_eq!(answered.matches("a=fmtp:").count(), 1, "{answered}");
    assert_eq!(answered.matches("a=maxptime:").count(), 1, "{answered}");
}

#[cfg(feature = "amr")]
#[test]
fn a_gateway_offer_is_answered_with_its_mode_set_and_obeyed() {
    // 3GPP TS 26.114 Table A.2.1.
    let (chosen, answered) = answer(GATEWAY_OFFER).expect("a codec is selected");
    assert_eq!(chosen.allowed_modes, [0, 2, 4, 7]);
    let params = chosen.amr.expect("params");
    assert_eq!(
        (params.mode_change_period, params.mode_change_neighbor),
        (Some(2), Some(true)),
        "what the gateway requires of the stream it receives"
    );
    assert!(
        answered.contains("a=fmtp:97 mode-set=0,2,4,7;mode-change-capability=2;max-red=0\r\n"),
        "{answered}"
    );
    // Table A.2.4: wideband first in the offer, so wideband is the answer.
    let (chosen, answered) = answer(WIDEBAND_GATEWAY_OFFER).expect("a codec is selected");
    assert_eq!(chosen.payload_type, 98);
    assert!(
        answered.contains("a=fmtp:98 mode-set=0,1,2;mode-change-capability=2;max-red=0\r\n"),
        "{answered}"
    );
}

/// RFC 4867 §8.3.1: a payload type whose configuration the answerer cannot return unmodified and
/// honour is removed, and RFC 3264 §6.1 has the answer select from what is left, in offer order.
#[cfg(feature = "amr")]
#[test]
fn a_configuration_the_engine_does_not_implement_falls_to_the_next_payload_type() {
    for refused in [
        "crc=1;octet-align=1",
        "robust-sorting=1;octet-align=1",
        "interleaving=30;octet-align=1",
        "octet-align=7",
        "mode-set=0,9",
    ] {
        let offer = format!(
            "m=audio 49152 RTP/AVP 96 97 8\na=rtpmap:96 AMR-WB/16000\na=fmtp:96 {refused}\n\
             a=rtpmap:97 AMR-WB/16000\na=fmtp:97 octet-align=1\na=rtpmap:8 PCMA/8000"
        );
        let (chosen, answered) = answer(&offer).expect("a codec is selected");
        assert_eq!(chosen.payload_type, 97, "{refused}");
        assert!(
            answered.contains("m=audio 49152 RTP/AVP 97\r\n"),
            "{refused}: {answered}"
        );
        assert!(!answered.contains("a=fmtp:96"), "{refused}: {answered}");
        // The stream's primary codec is the same one: a two-leg call transcodes with it too.
        let info = parse(&sdp(&offer)).expect("parse");
        assert_eq!(info.primary_codec().map(|spec| spec.payload_type), Some(97));
    }
    // Nothing usable in AMR: the next codec. Nothing usable at all: no answer (a 488 upstream).
    let mixed = "m=audio 49152 RTP/AVP 96 8\na=rtpmap:96 AMR/8000\na=fmtp:96 crc=1\n\
                 a=rtpmap:8 PCMA/8000";
    assert_eq!(
        answer(mixed).map(|(chosen, _)| chosen.payload_type),
        Some(8)
    );
    let only = "m=audio 49152 RTP/AVP 96\na=rtpmap:96 AMR/8000/2";
    assert_eq!(answer(only), None, "two-channel AMR");
    // AMR has no mode 8; AMR-WB has.
    let narrowband = "m=audio 49152 RTP/AVP 96\na=rtpmap:96 AMR/8000\na=fmtp:96 mode-set=0,8";
    assert_eq!(answer(narrowband), None);
    let wideband = "m=audio 49152 RTP/AVP 96\na=rtpmap:96 AMR-WB/16000\na=fmtp:96 mode-set=0,8";
    assert!(answer(wideband).is_some());
}

#[test]
fn an_unsupported_first_payload_type_is_still_the_primary_codec_when_it_is_the_only_one() {
    // A relay never runs the codec, so a stream offering only a configuration the engine does
    // not implement keeps it as its primary codec and relays.
    let offer = "m=audio 49152 RTP/AVP 96\na=rtpmap:96 AMR-WB/16000\na=fmtp:96 crc=1";
    let info = parse(&sdp(offer)).expect("parse");
    let primary = info.primary_codec().expect("primary");
    assert_eq!(primary.payload_type, 96);
    assert!(primary.amr_unsupported().is_some());
}

#[test]
fn the_engine_policy_sets_the_preferred_mode_and_the_mode_request() {
    let spec = CodecSpec::new(96, "AMR-WB", 16000, 1, 20);
    let offered = AmrParams {
        octet_align: Some(true),
        ..AmrParams::default()
    };
    // No policy: the highest mode of the set, no request, and the peer's parameters untouched.
    let plain = with_policy(
        spec.clone(),
        Some(offered),
        vec![0, 1, 2],
        AmrPolicy::default(),
    );
    assert_eq!((plain.encode_mode, plain.amr), (None, Some(offered)));
    assert_eq!(plain.allowed_modes, [0, 1, 2]);
    let policy = AmrPolicy {
        max_mode: Some(2),
        mode_request: Some(1),
    };
    let shaped = with_policy(spec.clone(), Some(offered), Vec::new(), policy);
    assert_eq!(shaped.encode_mode, Some(2));
    assert_eq!(
        shaped.amr,
        Some(AmrParams {
            mode_request: Some(1),
            ..offered
        })
    );
    // The request is the engine's own and never part of what it writes into SDP.
    assert_eq!(
        fmtp_line(&shaped).as_deref(),
        Some("a=fmtp:96 octet-align=1;mode-change-capability=2")
    );
    assert_eq!(
        with_policy(spec, None, Vec::new(), policy)
            .amr
            .map(|p| p.mode_request),
        Some(Some(1))
    );
}

/// GSMA IR.92 §3.2.5 and 3GPP TS 26.114 Table A.1.2: both formats, bandwidth-efficient first.
#[test]
fn the_engine_offers_both_payload_formats_bandwidth_efficient_first() {
    let [efficient, aligned] = offered([96, 97], "AMR-WB", 16000);
    assert_eq!(
        fmtp_line(&efficient).as_deref(),
        Some("a=fmtp:96 mode-change-capability=2;max-red=0")
    );
    assert_eq!(
        fmtp_line(&aligned).as_deref(),
        Some("a=fmtp:97 octet-align=1;mode-change-capability=2;max-red=0")
    );
    let policy = CodecPolicy {
        add: offered([96, 97], "AMR-WB", 16000)
            .into_iter()
            .chain(offered([98, 99], "AMR", 8000))
            .collect(),
        ..CodecPolicy::default()
    };
    let offer =
        sdp("m=audio 40000 RTP/AVP 8 101\na=rtpmap:8 PCMA/8000\na=rtpmap:101 telephone-event/8000");
    let out = apply_codec_policy(&offer, &policy);
    assert!(
        out.contains("m=audio 40000 RTP/AVP 8 101 96 97 98 99\r\n"),
        "{out}"
    );
    for line in [
        "a=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 mode-change-capability=2;max-red=0\r\n",
        "a=rtpmap:97 AMR-WB/16000\r\na=fmtp:97 octet-align=1;mode-change-capability=2;max-red=0\r\n",
        "a=rtpmap:98 AMR/8000\r\na=fmtp:98 mode-change-capability=2;max-red=0\r\n",
        "a=rtpmap:99 AMR/8000\r\na=fmtp:99 octet-align=1;mode-change-capability=2;max-red=0\r\n",
    ] {
        assert!(out.contains(line), "{line:?} in {out}");
    }
    // What comes back parses to the configuration that was offered.
    let reparsed = parse(&out).expect("reparse");
    let formats: Vec<(u8, bool)> = reparsed
        .audio_codecs()
        .iter()
        .filter(|spec| spec.is_amr())
        .map(|spec| {
            (
                spec.payload_type,
                spec.amr.unwrap_or_default().octet_aligned(),
            )
        })
        .collect();
    assert_eq!(formats, [(96, false), (97, true), (98, false), (99, true)]);
}

#[test]
fn an_added_codec_moves_off_a_payload_type_the_offer_uses_and_is_not_added_twice() {
    let add: Vec<CodecSpec> = offered([96, 97], "AMR-WB", 16000).into_iter().collect();
    let name = |name: &str| Some(name.to_owned());
    // 96 and 97 carry something else: the pair moves to the next free dynamic numbers, in order.
    let placed = place_added(
        &add,
        &[
            (8, name("PCMA")),
            (96, name("TELEPHONE-EVENT")),
            (97, name("OPUS")),
        ],
    );
    let numbers: Vec<(u8, bool)> = placed
        .iter()
        .map(|spec| {
            (
                spec.payload_type,
                spec.amr.unwrap_or_default().octet_aligned(),
            )
        })
        .collect();
    assert_eq!(numbers, [(98, false), (99, true)]);
    // The offer already carries the codec: nothing is added.
    assert_eq!(place_added(&add, &[(104, name("AMR-WB"))]), []);
    // A static payload type that is taken is the codec itself.
    let pcma = [CodecSpec::new(8, "PCMA", 8000, 1, 20)];
    assert_eq!(place_added(&pcma, &[(8, None)]), []);
    assert_eq!(place_added(&pcma, &[(0, name("PCMU"))]).len(), 1);
    // No dynamic number left: the codec is left out rather than colliding.
    let full: Vec<(u8, Option<String>)> = (96..=127).map(|number| (number, name("X"))).collect();
    assert_eq!(place_added(&add, &full), []);
}

use proptest::prelude::*;

proptest! {
    /// Any fmtp body is read or passed over, never a panic, and what is written from it parses back.
    #[test]
    fn arbitrary_fmtp_bodies_never_panic(body in "[ -~]{0,120}") {
        if let Some((payload_type, read)) = parse_fmtp(&format!("fmtp:96 {body}")) {
            prop_assert_eq!(payload_type, 96);
            let spec = CodecSpec::new(96, "AMR", 8000, 1, 20)
                .with_allowed_modes(read.mode_set.clone())
                .with_amr_params(Some(read.params));
            let line = fmtp_line(&spec).expect("line");
            let attribute = line.strip_prefix("a=").expect("attribute");
            let (_, again) = parse_fmtp(attribute).expect("reparse");
            prop_assert_eq!(again.mode_set, read.mode_set);
            prop_assert_eq!(again.params.octet_align, read.params.octet_align);
        }
    }
}
