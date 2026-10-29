//! A decoded recording on a call whose leg is seated in a conference room: its sinks tap the seat
//! in the room actor rather than a call's media actor.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{RecordingChannels, RecordingDirection};
use std::sync::Arc;

use crate::conference::ConferenceControl;

use super::super::Engine;
use super::{
    new_source_reason, open_recording_output, pcm_rate_of, AudioRecording, DecodedRecordingRequest,
    RecordingTaps, RecordingWriter, TapSource,
};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Stand a decoded recording up on a call whose leg is **seated** in a room: its sinks tap the
    /// seat in the room actor — what the party sends, and what the room sends it (its own prompts
    /// included). In the call's terms the seated party is the caller (its one, near, leg), so a
    /// stereo file puts its voice left and what it hears right, exactly as on a single-party call.
    pub(super) async fn begin_seat_recording(
        &self,
        call_id: &str,
        from_tag: &str,
        request: DecodedRecordingRequest,
    ) -> Result<String, String> {
        use siphon_rtp_media::bridge::protocol::{Encoding, Endianness, MediaFormat};
        use siphon_rtp_media::bridge::tee::{plan_ws_tee, TeeChannel, WsTeeSink};

        let (conference_id, tag) = self
            .seated_room(call_id)
            .ok_or_else(|| "the call's leg is not seated in a room".to_string())?;
        let (codec, to_tag, owner) = self
            .owned_call_internal(call_id, |call| {
                (call.near_codec.clone(), call.to_tag.clone(), call.owner)
            })
            .ok_or_else(|| "call no longer exists".to_string())?;
        let codec = codec.ok_or_else(|| "the seat has no negotiated codec".to_string())?;
        let rate = pcm_rate_of(&codec)?;
        let layout: Vec<(TapSource, TeeChannel)> = match request.direction {
            RecordingDirection::Ingress => {
                vec![(TapSource::Ingress { source_a: true }, TeeChannel::Caller)]
            }
            RecordingDirection::Egress => {
                vec![(TapSource::Egress { toward_a: true }, TeeChannel::Callee)]
            }
            RecordingDirection::Both => vec![
                (TapSource::Ingress { source_a: true }, TeeChannel::Caller),
                (TapSource::Egress { toward_a: true }, TeeChannel::Callee),
            ],
        };
        let two_sources = layout.len() == 2;
        let callee_only = !two_sources && layout[0].1 == TeeChannel::Callee;
        // The party and the room are the two sides of the conversation, so a stereo file of both is
        // honoured as on a two-party call.
        let channels: u8 = if two_sources && matches!(request.channels, RecordingChannels::Stereo) {
            2
        } else {
            1
        };
        let format = MediaFormat {
            encoding: Encoding::L16,
            sample_rate: rate,
            channels,
            bit_depth: 16,
            endianness: Endianness::Little,
            ptime: 20,
        };
        let encoding = request.format.encoding(rate, channels)?;
        let recording_id = self.next_recording_id();
        let (path, file) = open_recording_output(
            call_id,
            &recording_id,
            request.format.extension(),
            request.path,
            request.recording_dir,
        )
        .await?;
        let plan = plan_ws_tee(format, two_sources, callee_only);
        let mixer = Arc::downgrade(&plan.mixer);
        for (source, channel) in &layout {
            let sink = WsTeeSink::new(*channel, plan.mixer.clone(), recording_id.clone(), None);
            let egress = !source.is_voice_of(true);
            let attached = self
                .conference
                .ask(&conference_id, |reply| {
                    crate::conference::SeatControl::AddSeatTap {
                        tag: tag.clone(),
                        egress,
                        sink: Box::new(sink),
                        reply,
                    }
                })
                .await;
            if attached != Some(true) {
                self.conference.control(
                    &conference_id,
                    ConferenceControl::Seat(crate::conference::SeatControl::RemoveSeatTapsTagged {
                        tag: tag.clone(),
                        label: recording_id.clone(),
                    }),
                );
                // The file was created for nothing: remove it so a refusal leaves no trace.
                let _ = tokio::fs::remove_file(&path).await;
                return Err("the seat's room did not take the recording".to_string());
            }
        }
        let source_reason = new_source_reason();
        let writer = self.spawn_recording_writer(RecordingWriter {
            owner,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            to_tag,
            recording_id: recording_id.clone(),
            path: path.clone(),
            file,
            rate,
            channels,
            encoding,
            limits: request.limits,
            frames: plan.frames,
            recycle: plan.recycle,
            source_reason: source_reason.clone(),
            rename_to: None,
        });
        self.recordings.insert(
            recording_id.clone(),
            AudioRecording {
                recording_id: recording_id.clone(),
                call_id: call_id.to_string(),
                owner,
                path,
                ingress_legs: Vec::new(),
                egress_legs: Vec::new(),
                room: None,
                bridge_taps: Vec::new(),
                source_reason,
                writer,
                taps: Some(RecordingTaps {
                    mixer,
                    rate,
                    layout,
                }),
                seat: Some((conference_id, tag)),
                parked: std::sync::Mutex::new(Vec::new()),
            },
        );
        Ok(recording_id)
    }
}
