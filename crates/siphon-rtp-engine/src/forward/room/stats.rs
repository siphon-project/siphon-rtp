//! What a forwarding room counts about one seat.

/// What the room counted about one seat, for logs and stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ForwardSeatStats {
    /// RTP packets the seat sent while it was not the source: counted and dropped.
    pub not_source_dropped: u64,
    /// RTP packets from the seat with a payload type it did not negotiate: dropped.
    pub unknown_payload_type: u64,
    /// Packets the room forwarded to the seat.
    pub forwarded_packets: u32,
    /// Payload octets the room forwarded to the seat.
    pub forwarded_octets: u32,
    /// RTCP APP packets read from the seat (floor stream and audio RTCP), each raised as an event.
    pub app_events: u64,
    /// Datagrams with APP-bearing RTCP the room could not read to the end: counted, no event.
    pub malformed_app: u64,
    /// Audio SRTCP datagrams of a seat with media keys that did not authenticate under a held key
    /// (plaintext, unknown MKI, failed tag, replay), in a preserving room: dropped.
    pub media_srtcp_refused: u64,
    /// Resealed audio SRTCP the room did not send this seat, as a receiver of a keyed talker, because
    /// the seat holds no media keys (it is never sent plaintext).
    pub media_srtcp_unkeyed_receiver: u64,
    /// Floor datagrams a keyed seat's SRTCP refused (plaintext, unknown MKI, failed tag, replay).
    pub floor_refused: u64,
    /// Packets from the seat, while it was the source, that could not be transcoded for the
    /// cross-codec seats (a payload the decoder refused, or a frame of another length than the
    /// negotiated one). Same-codec seats were still sent them.
    pub transcode_dropped: u64,
    /// Audio RTCP datagrams the seat sent while it was not the source, in a preserving room: counted
    /// and dropped, never read (they are SRTCP end to end).
    pub receiver_rtcp_dropped: u64,
    /// Video RTP packets the seat sent while it was not the source: counted and dropped.
    pub video_not_source_dropped: u64,
    /// Video RTP packets the seat sent while it was the source but had offered receive-only video:
    /// counted and dropped.
    pub video_receive_only_dropped: u64,
    /// Video RTP packets with a payload type the seat did not negotiate: dropped.
    pub video_unknown_payload_type: u64,
    /// Video packets the room forwarded to the seat.
    pub video_forwarded_packets: u32,
    /// Video payload octets the room forwarded to the seat.
    pub video_forwarded_octets: u32,
    /// Keyframe requests (PLI, FIR) the room sent the seat as the video source.
    pub pli_sent: u64,
    pub fir_sent: u64,
    /// IDR pictures the seat sent as the video source.
    pub keyframes_seen: u64,
    /// Video packets not sent to the seat because it waited for a keyframe.
    pub video_dropped_awaiting_keyframe: u64,
    /// Packets sent again to the seat for its NACK, and packets it asked for that were gone.
    pub nack_answered: u64,
    pub nack_missed: u64,
    /// Source changes whose keyframe did not arrive in time (the room forwarded without one).
    pub keyframe_timeouts: u64,
    /// Audio and video packets not sent to the seat because its reception of that stream is off
    /// (`forward_set_reception`).
    pub reception_off_dropped_audio: u64,
    pub reception_off_dropped_video: u64,
}
