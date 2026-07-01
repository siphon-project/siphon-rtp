//! The rtpengine NG command mapping: bencode dict ↔ the internal [`Command`]/[`CmdResult`].
//!
//! The wire envelope is `<cookie><SP><bencode-dict>` (split on the **first** space; the cookie is
//! opaque and echoed verbatim). This module turns a decoded request dict into a [`Command`] and a
//! [`CmdResult`] back into a response dict, faithful to what SIPhon's rtpengine client emits
//! (see the NG protocol spec). Codec transcoding flows through the `flags` list
//! (`codec-transcode-PCMA`, `codec-mask-AMR-WB`, …) and/or the structured `codec` dict — both are
//! normalized into [`ProfileFlags::flags`] for the engine.

use siphon_rtp_proto::{CmdResult, Command, PlayMediaSource, ProfileFlags};

use crate::bencode::{self, Value};

/// Errors mapping an NG request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NgError {
    /// No space separating the cookie from the bencode body.
    #[error("missing cookie separator")]
    NoCookie,
    /// The bencode body failed to parse.
    #[error("bencode: {0}")]
    Bencode(#[from] bencode::BencodeError),
    /// The top-level value was not a dict.
    #[error("request is not a dict")]
    NotADict,
    /// A required key was absent (or not the expected type).
    #[error("missing or invalid key: {0}")]
    MissingKey(&'static str),
    /// The `command` value is not one this engine implements.
    #[error("unsupported command: {0}")]
    UnknownCommand(String),
}

/// Split an NG datagram into the (opaque) cookie and the bencode body, on the first space.
pub fn split_cookie(datagram: &[u8]) -> Result<(&[u8], &[u8]), NgError> {
    let space = datagram
        .iter()
        .position(|&byte| byte == b' ')
        .ok_or(NgError::NoCookie)?;
    Ok((&datagram[..space], &datagram[space + 1..]))
}

/// Parse a decoded request dict into the internal [`Command`].
pub fn parse_command(request: &Value) -> Result<Command, NgError> {
    if request.as_dict().is_none() {
        return Err(NgError::NotADict);
    }
    let command = required_str(request, "command")?;
    match command.as_str() {
        "ping" => Ok(Command::Ping),
        // Read-only census verbs: no keys beyond `command` (rtpengine NG `list` / `statistics`).
        "list" => Ok(Command::List),
        "statistics" => Ok(Command::Statistics),
        // Cluster placement verbs (a siphon-rtp extension to the NG protocol): no keys beyond
        // `command`. `load` / `node info` are read-only; `drain` / `undrain` toggle admission of new
        // sessions for a zero-downtime rolling upgrade.
        "load" => Ok(Command::Load),
        "node info" => Ok(Command::NodeInfo),
        "drain" => Ok(Command::Drain),
        "undrain" => Ok(Command::Undrain),
        "offer" => Ok(Command::Offer {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            sdp: required_str(request, "sdp")?,
            profile: parse_profile(request),
        }),
        "answer" => Ok(Command::Answer {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            to_tag: required_str(request, "to-tag")?,
            sdp: required_str(request, "sdp")?,
            profile: parse_profile(request),
        }),
        "delete" => Ok(Command::Delete {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            to_tag: optional_str(request, "to-tag"),
        }),
        "query" => Ok(Command::Query {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            to_tag: optional_str(request, "to-tag"),
        }),
        "stop media" => Ok(Command::StopMedia {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
        }),
        "silence media" => Ok(Command::SilenceMedia {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
        }),
        "unsilence media" => Ok(Command::UnsilenceMedia {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
        }),
        "block media" => Ok(Command::BlockMedia {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
        }),
        "unblock media" => Ok(Command::UnblockMedia {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
        }),
        "play media" => parse_play_media(request),
        "play DTMF" => parse_play_dtmf(request),
        "subscribe request" => Ok(Command::SubscribeRequest {
            call_id: required_str(request, "call-id")?,
            from_tags: subscribe_from_tags(request)?,
            sdp: optional_str(request, "sdp"),
            profile: parse_profile(request),
        }),
        "subscribe answer" => Ok(Command::SubscribeAnswer {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            to_tag: required_str(request, "to-tag")?,
            sdp: required_str(request, "sdp")?,
            profile: parse_profile(request),
        }),
        "unsubscribe" => Ok(Command::Unsubscribe {
            call_id: required_str(request, "call-id")?,
            from_tag: required_str(request, "from-tag")?,
            to_tag: required_str(request, "to-tag")?,
        }),
        other => Err(NgError::UnknownCommand(other.to_string())),
    }
}

/// Serialize a [`CmdResult`] into an NG response dict.
#[must_use]
pub fn serialize_result(result: &CmdResult) -> Value {
    let mut dict = std::collections::BTreeMap::new();
    match result {
        CmdResult::Pong => {
            dict.insert(b"result".to_vec(), Value::string("pong"));
        }
        CmdResult::List { call_ids } => {
            // rtpengine `list` returns the call-ids under a `calls` list (each a bencode string).
            dict.insert(b"result".to_vec(), Value::string("ok"));
            dict.insert(
                b"calls".to_vec(),
                Value::List(
                    call_ids
                        .iter()
                        .map(|call_id| Value::string(call_id))
                        .collect(),
                ),
            );
        }
        CmdResult::Statistics { statistics } => {
            // rtpengine `statistics` returns the global counters under a `statistics` sub-dict. The
            // key names mirror the engine's own metric names (offers/answers/deletes/errors) plus the
            // live `sessions` gauge, so a passive collector reads one consistent vocabulary.
            dict.insert(b"result".to_vec(), Value::string("ok"));
            let mut statistics_dict = std::collections::BTreeMap::new();
            statistics_dict.insert(
                b"offers".to_vec(),
                Value::Integer(clamp_i64(statistics.offers_total)),
            );
            statistics_dict.insert(
                b"answers".to_vec(),
                Value::Integer(clamp_i64(statistics.answers_total)),
            );
            statistics_dict.insert(
                b"deletes".to_vec(),
                Value::Integer(clamp_i64(statistics.deletes_total)),
            );
            statistics_dict.insert(
                b"errors".to_vec(),
                Value::Integer(clamp_i64(statistics.control_errors_total)),
            );
            statistics_dict.insert(
                b"sessions".to_vec(),
                Value::Integer(clamp_i64(statistics.sessions)),
            );
            dict.insert(b"statistics".to_vec(), Value::Dict(statistics_dict));
        }
        CmdResult::Load { load } => {
            // The cluster `load` snapshot under a `load` sub-dict: integer per-mille figures + the
            // live gauges, so a dispatcher polling over NG reads the same vocabulary the JSON
            // front-end returns (hyphenated keys, the NG convention).
            dict.insert(b"result".to_vec(), Value::string("ok"));
            let mut load_dict = std::collections::BTreeMap::new();
            load_dict.insert(b"node-id".to_vec(), Value::string(&load.node_id));
            load_dict.insert(
                b"sessions".to_vec(),
                Value::Integer(clamp_i64(load.sessions)),
            );
            load_dict.insert(
                b"max-sessions".to_vec(),
                Value::Integer(clamp_i64(load.max_sessions)),
            );
            load_dict.insert(
                b"load-permille".to_vec(),
                Value::Integer(i64::from(load.load_permille)),
            );
            load_dict.insert(
                b"transcode-sessions".to_vec(),
                Value::Integer(clamp_i64(load.transcode_sessions)),
            );
            // Only present when a CPU sample has been taken (mirrors the JSON `skip_serializing_if`).
            if let Some(cpu) = load.cpu_permille {
                load_dict.insert(b"cpu-permille".to_vec(), Value::Integer(i64::from(cpu)));
            }
            load_dict.insert(
                b"allocated-bytes".to_vec(),
                Value::Integer(clamp_i64(load.jemalloc_allocated_bytes)),
            );
            // bencode has no boolean; draining is a 0/1 integer (the NG convention).
            load_dict.insert(
                b"draining".to_vec(),
                Value::Integer(i64::from(load.draining)),
            );
            dict.insert(b"load".to_vec(), Value::Dict(load_dict));
        }
        CmdResult::NodeInfo { node } => {
            // Static identity + capabilities under a `node` sub-dict.
            dict.insert(b"result".to_vec(), Value::string("ok"));
            let mut node_dict = std::collections::BTreeMap::new();
            node_dict.insert(b"node-id".to_vec(), Value::string(&node.node_id));
            node_dict.insert(b"version".to_vec(), Value::string(&node.version));
            node_dict.insert(
                b"media-addresses".to_vec(),
                encode_string_list(&node.media_addresses),
            );
            node_dict.insert(b"codecs".to_vec(), encode_string_list(&node.codecs));
            node_dict.insert(b"features".to_vec(), encode_string_list(&node.features));
            node_dict.insert(
                b"max-sessions".to_vec(),
                Value::Integer(clamp_i64(node.max_sessions)),
            );
            node_dict.insert(
                b"draining".to_vec(),
                Value::Integer(i64::from(node.draining)),
            );
            dict.insert(b"node".to_vec(), Value::Dict(node_dict));
        }
        CmdResult::Error { reason } => {
            dict.insert(b"result".to_vec(), Value::string("error"));
            dict.insert(b"error-reason".to_vec(), Value::string(reason));
        }
        CmdResult::Ok {
            sdp,
            duration_ms,
            to_tag,
            stats: _,
        } => {
            dict.insert(b"result".to_vec(), Value::string("ok"));
            if let Some(sdp) = sdp {
                dict.insert(b"sdp".to_vec(), Value::Bytes(sdp.clone().into_bytes()));
            }
            if let Some(duration) = duration_ms {
                dict.insert(b"duration".to_vec(), Value::Integer(*duration as i64));
            }
            if let Some(to_tag) = to_tag {
                dict.insert(b"to-tag".to_vec(), Value::string(to_tag));
            }
        }
    }
    Value::Dict(dict)
}

/// Build a complete NG response datagram: `<cookie><SP><bencode-dict>`.
#[must_use]
pub fn serialize_response(cookie: &[u8], result: &CmdResult) -> Vec<u8> {
    let body = bencode::encode(&serialize_result(result));
    let mut out = Vec::with_capacity(cookie.len() + 1 + body.len());
    out.extend_from_slice(cookie);
    out.push(b' ');
    out.extend_from_slice(&body);
    out
}

fn parse_play_media(request: &Value) -> Result<Command, NgError> {
    let source = if let Some(path) = optional_str(request, "file") {
        PlayMediaSource::File { path }
    } else if let Some(blob) = request.get("blob").and_then(Value::as_bytes) {
        PlayMediaSource::Blob {
            data: blob.to_vec(),
        }
    } else if let Some(id) = request.get("db-id").and_then(Value::as_integer) {
        PlayMediaSource::DbId {
            id: id.max(0) as u64,
        }
    } else {
        return Err(NgError::MissingKey("file|blob|db-id"));
    };
    Ok(Command::PlayMedia {
        call_id: required_str(request, "call-id")?,
        from_tag: required_str(request, "from-tag")?,
        source,
        repeat_times: optional_u64(request, "repeat-times"),
        start_pos_ms: optional_u64(request, "start-pos"),
        duration_ms: optional_u64(request, "duration"),
        to_tag: optional_str(request, "to-tag"),
    })
}

fn parse_play_dtmf(request: &Value) -> Result<Command, NgError> {
    Ok(Command::PlayDtmf {
        call_id: required_str(request, "call-id")?,
        from_tag: required_str(request, "from-tag")?,
        code: required_str(request, "code")?,
        duration_ms: optional_u64(request, "duration"),
        volume_dbm0: request.get("volume").and_then(Value::as_integer),
        pause_ms: optional_u64(request, "pause"),
        to_tag: optional_str(request, "to-tag"),
    })
}

fn subscribe_from_tags(request: &Value) -> Result<Vec<String>, NgError> {
    let listed = string_list(request, "from-tags");
    if !listed.is_empty() {
        return Ok(listed);
    }
    Ok(vec![required_str(request, "from-tag")?])
}

/// Parse the NgFlags surface into [`ProfileFlags`], normalizing codec directives into `flags`.
fn parse_profile(request: &Value) -> ProfileFlags {
    let mut flags = string_list(request, "flags");
    append_codec_flags(request, &mut flags);
    ProfileFlags {
        transport_protocol: optional_str(request, "transport-protocol"),
        ice: optional_str(request, "ICE"),
        dtls: optional_str(request, "DTLS"),
        replace: string_list(request, "replace"),
        // rtpengine spells it `address family`; accept the hyphenated form too.
        address_family: optional_str(request, "address family")
            .or_else(|| optional_str(request, "address-family")),
        flags,
        direction: string_list(request, "direction"),
        record_call: is_yes(request, "record call") || is_yes(request, "record-call"),
        record_path: optional_str(request, "recording-dir"),
        // The WS bridge is a native siphon-rtp (JSON control) extension; the NG/bencode front-end
        // never sets it.
        ws_uri: None,
    }
}

/// Normalize the structured `codec` dict (stock-client form) into `codec-<op>-<NAME>` flag strings,
/// plus a `ptime=<N>` flag — so the engine sees one codec representation regardless of wire form.
fn append_codec_flags(request: &Value, flags: &mut Vec<String>) {
    if let Some(codec) = request.get("codec").and_then(Value::as_dict) {
        for (operation, names) in codec {
            let Ok(operation) = std::str::from_utf8(operation) else {
                continue;
            };
            if let Some(names) = names.as_list() {
                for name in names.iter().filter_map(Value::as_str) {
                    flags.push(format!("codec-{operation}-{name}"));
                }
            }
        }
    }
    if let Some(ptime) = request.get("ptime").and_then(Value::as_integer) {
        flags.push(format!("ptime={ptime}"));
    }
}

fn required_str(dict: &Value, key: &'static str) -> Result<String, NgError> {
    optional_str(dict, key).ok_or(NgError::MissingKey(key))
}

fn optional_str(dict: &Value, key: &str) -> Option<String> {
    dict.get(key).and_then(Value::as_str).map(String::from)
}

fn optional_u64(dict: &Value, key: &str) -> Option<u64> {
    dict.get(key)
        .and_then(Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
}

fn string_list(dict: &Value, key: &str) -> Vec<String> {
    dict.get(key)
        .and_then(Value::as_list)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn is_yes(dict: &Value, key: &str) -> bool {
    optional_str(dict, key).as_deref() == Some("yes")
}

/// Clamp a `u64` counter into bencode's signed `i64` integer space (bencode has no unsigned form).
/// A real counter never approaches `i64::MAX`, so this only guards the theoretical overflow — it
/// saturates rather than wrapping a telemetry value negative.
fn clamp_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Encode a `&[String]` as a bencode list of strings (`node_info` codecs / features / addresses).
fn encode_string_list(items: &[String]) -> Value {
    Value::List(items.iter().map(|item| Value::string(item)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_proto::EngineStatistics;

    /// Build an NG request datagram from a logical command name + extra entries.
    fn datagram(cookie: &str, entries: &[(&str, Value)]) -> Vec<u8> {
        let mut dict = std::collections::BTreeMap::new();
        for (key, value) in entries {
            dict.insert(key.as_bytes().to_vec(), value.clone());
        }
        let mut out = cookie.as_bytes().to_vec();
        out.push(b' ');
        out.extend_from_slice(&bencode::encode(&Value::Dict(dict)));
        out
    }

    fn parse_datagram(bytes: &[u8]) -> (Vec<u8>, Command) {
        let (cookie, body) = split_cookie(bytes).expect("cookie");
        let request = bencode::decode(body).expect("decode");
        let command = parse_command(&request).expect("command");
        (cookie.to_vec(), command)
    }

    #[test]
    fn ping_needs_no_call_id() {
        let bytes = datagram("a3f91c0d", &[("command", Value::string("ping"))]);
        let (cookie, command) = parse_datagram(&bytes);
        assert_eq!(cookie, b"a3f91c0d");
        assert_eq!(command, Command::Ping);
    }

    #[test]
    fn scenario_1_offer_avp_to_savp_bridge() {
        // AMR-WB SRTP A-leg → ask engine for a plain-RTP (AVP) offer toward core. No codec flags.
        let bytes = datagram(
            "deadbeef",
            &[
                ("command", Value::string("offer")),
                ("call-id", Value::string("cid-1")),
                ("from-tag", Value::string("ftag")),
                (
                    "sdp",
                    Value::string(
                        "v=0\r\nm=audio 8000 RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n",
                    ),
                ),
                ("transport-protocol", Value::string("RTP/AVP")),
                ("ICE", Value::string("remove")),
                ("replace", Value::List(vec![Value::string("origin")])),
                (
                    "direction",
                    Value::List(vec![Value::string("external"), Value::string("internal")]),
                ),
            ],
        );
        let (_, command) = parse_datagram(&bytes);
        match command {
            Command::Offer {
                call_id,
                from_tag,
                profile,
                sdp,
            } => {
                assert_eq!(call_id, "cid-1");
                assert_eq!(from_tag, "ftag");
                assert_eq!(profile.transport_protocol.as_deref(), Some("RTP/AVP"));
                assert_eq!(profile.ice.as_deref(), Some("remove"));
                assert_eq!(profile.replace, vec!["origin"]);
                assert_eq!(profile.direction, vec!["external", "internal"]);
                assert!(
                    profile.flags.is_empty(),
                    "no codec flags in the bridge scenario"
                );
                assert!(sdp.contains("AMR-WB/16000"));
            }
            other => panic!("expected offer, got {other:?}"),
        }
    }

    #[test]
    fn scenario_2_offer_carries_codec_transcode_flags() {
        // AMR-WB SAVP → PCMA AVP transcode via the flags list.
        let bytes = datagram(
            "c0ffee01",
            &[
                ("command", Value::string("offer")),
                ("call-id", Value::string("cid-2")),
                ("from-tag", Value::string("ftag")),
                (
                    "sdp",
                    Value::string(
                        "v=0\r\nm=audio 8000 RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n",
                    ),
                ),
                ("transport-protocol", Value::string("RTP/AVP")),
                (
                    "flags",
                    Value::List(vec![
                        Value::string("codec-transcode-PCMA"),
                        Value::string("codec-mask-AMR-WB"),
                    ]),
                ),
            ],
        );
        let (_, command) = parse_datagram(&bytes);
        let Command::Offer { profile, .. } = command else {
            panic!("expected offer");
        };
        assert!(profile.flags.contains(&"codec-transcode-PCMA".to_string()));
        assert!(profile.flags.contains(&"codec-mask-AMR-WB".to_string()));
    }

    #[test]
    fn structured_codec_dict_normalizes_into_flags() {
        let mut codec = std::collections::BTreeMap::new();
        codec.insert(
            b"transcode".to_vec(),
            Value::List(vec![Value::string("PCMA")]),
        );
        codec.insert(b"mask".to_vec(), Value::List(vec![Value::string("AMR-WB")]));
        let bytes = datagram(
            "x",
            &[
                ("command", Value::string("offer")),
                ("call-id", Value::string("c")),
                ("from-tag", Value::string("f")),
                ("sdp", Value::string("v=0\r\n")),
                ("codec", Value::Dict(codec)),
                ("ptime", Value::Integer(20)),
            ],
        );
        let (_, Command::Offer { profile, .. }) = parse_datagram(&bytes) else {
            panic!("offer");
        };
        assert!(profile.flags.contains(&"codec-transcode-PCMA".to_string()));
        assert!(profile.flags.contains(&"codec-mask-AMR-WB".to_string()));
        assert!(profile.flags.contains(&"ptime=20".to_string()));
    }

    #[test]
    fn answer_requires_to_tag_and_sdp() {
        let bytes = datagram(
            "k",
            &[
                ("command", Value::string("answer")),
                ("call-id", Value::string("c")),
                ("from-tag", Value::string("f")),
                ("to-tag", Value::string("t")),
                ("sdp", Value::string("v=0\r\n")),
                ("transport-protocol", Value::string("RTP/SAVP")),
            ],
        );
        let (_, command) = parse_datagram(&bytes);
        match command {
            Command::Answer {
                to_tag, profile, ..
            } => {
                assert_eq!(to_tag, "t");
                assert_eq!(profile.transport_protocol.as_deref(), Some("RTP/SAVP"));
            }
            other => panic!("expected answer, got {other:?}"),
        }
        // Missing to-tag → error.
        let bad = datagram(
            "k",
            &[
                ("command", Value::string("answer")),
                ("call-id", Value::string("c")),
                ("from-tag", Value::string("f")),
                ("sdp", Value::string("v=0\r\n")),
            ],
        );
        let (_, body) = split_cookie(&bad).unwrap();
        let request = bencode::decode(body).unwrap();
        assert_eq!(parse_command(&request), Err(NgError::MissingKey("to-tag")));
    }

    #[test]
    fn record_call_accepts_spaced_and_dashed_key() {
        for key in ["record call", "record-call"] {
            let bytes = datagram(
                "k",
                &[
                    ("command", Value::string("offer")),
                    ("call-id", Value::string("c")),
                    ("from-tag", Value::string("f")),
                    ("sdp", Value::string("v=0\r\n")),
                    (key, Value::string("yes")),
                ],
            );
            let (_, Command::Offer { profile, .. }) = parse_datagram(&bytes) else {
                panic!("offer");
            };
            assert!(profile.record_call, "record_call via key {key:?}");
        }
    }

    #[test]
    fn list_and_statistics_need_no_call_id() {
        // Both census verbs carry only `command` — no call-id / from-tag required.
        let list = datagram("l1", &[("command", Value::string("list"))]);
        let (cookie, command) = parse_datagram(&list);
        assert_eq!(cookie, b"l1");
        assert_eq!(command, Command::List);

        let statistics = datagram("s1", &[("command", Value::string("statistics"))]);
        let (cookie, command) = parse_datagram(&statistics);
        assert_eq!(cookie, b"s1");
        assert_eq!(command, Command::Statistics);
    }

    #[test]
    fn list_result_encodes_calls_list() {
        // A populated list → result:ok + a `calls` list of the call-id strings.
        let populated = serialize_result(&CmdResult::List {
            call_ids: vec!["call-a".into(), "call-b".into()],
        });
        assert_eq!(populated.get("result").and_then(Value::as_str), Some("ok"));
        let calls = populated
            .get("calls")
            .and_then(Value::as_list)
            .expect("calls list");
        let names: Vec<&str> = calls.iter().filter_map(Value::as_str).collect();
        assert_eq!(names, vec!["call-a", "call-b"]);

        // An empty list still carries an (empty) `calls` list, not a missing key.
        let empty = serialize_result(&CmdResult::List {
            call_ids: Vec::new(),
        });
        assert_eq!(empty.get("result").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            empty.get("calls").and_then(Value::as_list).map(<[_]>::len),
            Some(0)
        );
    }

    #[test]
    fn statistics_result_encodes_counter_dict() {
        let result = serialize_result(&CmdResult::Statistics {
            statistics: EngineStatistics {
                offers_total: 12,
                answers_total: 11,
                deletes_total: 10,
                control_errors_total: 2,
                sessions: 3,
            },
        });
        assert_eq!(result.get("result").and_then(Value::as_str), Some("ok"));
        let statistics = result
            .get("statistics")
            .and_then(Value::as_dict)
            .expect("statistics dict");
        let counter = |key: &[u8]| statistics.get(key).and_then(Value::as_integer);
        assert_eq!(counter(b"offers"), Some(12));
        assert_eq!(counter(b"answers"), Some(11));
        assert_eq!(counter(b"deletes"), Some(10));
        assert_eq!(counter(b"errors"), Some(2));
        assert_eq!(counter(b"sessions"), Some(3));
    }

    #[test]
    fn statistics_result_clamps_oversize_counter() {
        // A counter beyond i64::MAX saturates rather than wrapping negative (bencode is signed).
        let result = serialize_result(&CmdResult::Statistics {
            statistics: EngineStatistics {
                offers_total: u64::MAX,
                ..Default::default()
            },
        });
        let statistics = result
            .get("statistics")
            .and_then(Value::as_dict)
            .expect("statistics dict");
        assert_eq!(
            statistics
                .get(b"offers".as_slice())
                .and_then(Value::as_integer),
            Some(i64::MAX)
        );
    }

    #[test]
    fn cluster_verbs_need_no_call_id() {
        // The cluster placement verbs carry only `command` (like list/statistics).
        for (verb, expected) in [
            ("load", Command::Load),
            ("node info", Command::NodeInfo),
            ("drain", Command::Drain),
            ("undrain", Command::Undrain),
        ] {
            let bytes = datagram("c1", &[("command", Value::string(verb))]);
            let (_, command) = parse_datagram(&bytes);
            assert_eq!(command, expected, "verb {verb:?}");
        }
    }

    #[test]
    fn load_result_encodes_load_dict() {
        let result = serialize_result(&CmdResult::Load {
            load: siphon_rtp_proto::NodeLoad {
                node_id: "rtp-ams-3".into(),
                sessions: 812,
                max_sessions: 4000,
                load_permille: 203,
                transcode_sessions: 140,
                cpu_permille: Some(247),
                jemalloc_allocated_bytes: 734_003_200,
                draining: false,
            },
        });
        assert_eq!(result.get("result").and_then(Value::as_str), Some("ok"));
        let load = result
            .get("load")
            .and_then(Value::as_dict)
            .expect("load dict");
        let int = |key: &[u8]| load.get(key).and_then(Value::as_integer);
        assert_eq!(
            load.get(b"node-id".as_slice()).and_then(Value::as_str),
            Some("rtp-ams-3")
        );
        assert_eq!(int(b"sessions"), Some(812));
        assert_eq!(int(b"max-sessions"), Some(4000));
        assert_eq!(int(b"load-permille"), Some(203));
        assert_eq!(int(b"transcode-sessions"), Some(140));
        assert_eq!(int(b"cpu-permille"), Some(247));
        assert_eq!(int(b"allocated-bytes"), Some(734_003_200));
        assert_eq!(int(b"draining"), Some(0));
    }

    #[test]
    fn load_result_omits_cpu_when_unsampled() {
        // No CPU sample → the `cpu-permille` key is absent (mirrors the JSON front-end).
        let result = serialize_result(&CmdResult::Load {
            load: siphon_rtp_proto::NodeLoad {
                cpu_permille: None,
                draining: true,
                ..Default::default()
            },
        });
        let load = result
            .get("load")
            .and_then(Value::as_dict)
            .expect("load dict");
        assert!(
            load.get(b"cpu-permille".as_slice()).is_none(),
            "cpu key omitted"
        );
        assert_eq!(
            load.get(b"draining".as_slice()).and_then(Value::as_integer),
            Some(1)
        );
    }

    #[test]
    fn node_info_result_encodes_capabilities() {
        let result = serialize_result(&CmdResult::NodeInfo {
            node: siphon_rtp_proto::NodeInfo {
                node_id: "rtp-ams-3".into(),
                version: "0.1.0".into(),
                media_addresses: vec!["203.0.113.10".into()],
                codecs: vec!["PCMU".into(), "AMR-WB".into()],
                features: vec!["relay".into(), "srtp".into()],
                max_sessions: 4000,
                draining: false,
            },
        });
        assert_eq!(result.get("result").and_then(Value::as_str), Some("ok"));
        let node = result
            .get("node")
            .and_then(Value::as_dict)
            .expect("node dict");
        assert_eq!(
            node.get(b"version".as_slice()).and_then(Value::as_str),
            Some("0.1.0")
        );
        let codecs: Vec<&str> = node
            .get(b"codecs".as_slice())
            .and_then(Value::as_list)
            .expect("codecs list")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(codecs, vec!["PCMU", "AMR-WB"]);
        assert_eq!(
            node.get(b"max-sessions".as_slice())
                .and_then(Value::as_integer),
            Some(4000)
        );
    }

    #[test]
    fn unknown_command_is_reported_not_panicked() {
        let bytes = datagram("k", &[("command", Value::string("frobnicate"))]);
        let (_, body) = split_cookie(&bytes).unwrap();
        let request = bencode::decode(body).unwrap();
        assert_eq!(
            parse_command(&request),
            Err(NgError::UnknownCommand("frobnicate".to_string()))
        );
    }

    #[test]
    fn serialize_results_match_contract() {
        // pong
        assert_eq!(
            serialize_result(&CmdResult::Pong)
                .get("result")
                .and_then(Value::as_str),
            Some("pong")
        );
        // error → result + error-reason
        let error = serialize_result(&CmdResult::Error {
            reason: "no such call".into(),
        });
        assert_eq!(error.get("result").and_then(Value::as_str), Some("error"));
        assert_eq!(
            error.get("error-reason").and_then(Value::as_str),
            Some("no such call")
        );
        // ok + sdp
        let ok = serialize_result(&CmdResult::Ok {
            sdp: Some("v=0\r\nm=audio 30000 RTP/SAVP 96\r\n".into()),
            duration_ms: None,
            to_tag: None,
            stats: None,
        });
        assert_eq!(ok.get("result").and_then(Value::as_str), Some("ok"));
        assert!(ok
            .get("sdp")
            .and_then(Value::as_str)
            .unwrap()
            .contains("RTP/SAVP"));
    }

    #[test]
    fn response_envelope_echoes_cookie() {
        let response = serialize_response(b"a3f91c0d", &CmdResult::Pong);
        // <cookie> <bencode>
        let (cookie, body) = split_cookie(&response).expect("split");
        assert_eq!(cookie, b"a3f91c0d");
        let decoded = bencode::decode(body).expect("decode response");
        assert_eq!(decoded.get("result").and_then(Value::as_str), Some("pong"));
    }

    #[test]
    fn no_space_is_missing_cookie() {
        assert_eq!(split_cookie(b"d7:command4:pinge"), Err(NgError::NoCookie));
    }
}
