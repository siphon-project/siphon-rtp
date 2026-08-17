//! TURN (RFC 5766, updated by RFC 8656) message set, on top of the STUN codec.
//!
//! TURN is STUN with extra methods and attributes (RFC 5766 §2), so this module reuses the parent
//! module's [`parse`](super::parse), [`MessageBuilder`](super::MessageBuilder),
//! [`verify_message_integrity`](super::verify_message_integrity), and the XOR-address codec
//! verbatim — it adds only the TURN method/attribute registry, typed attribute accessors/encoders,
//! `ChannelData` framing (RFC 5766 §11), and the long-term-credential key derivation
//! (`MD5(username:realm:password)`, RFC 5389 §15.4 / RFC 5766 §4) with the `MD5` (RFC 1321) and
//! base64 (RFC 4648) primitives the built-in TURN server (`siphon-rtp-turn`, M-T*) needs. Pure Rust,
//! zero new dependencies — the credential key is hand-rolled `MD5`, the integrity HMAC is the
//! parent's hand-rolled HMAC-SHA1.
//!
//! Scope: the RFC 5766 long-term-credential mechanism (MESSAGE-INTEGRITY = HMAC-SHA1, key =
//! `MD5(username:realm:password)`). RFC 8656 MESSAGE-INTEGRITY-SHA256 is a deferred seam.
//! See `docs/security-and-nat.md` §11.

use std::net::SocketAddr;

use super::{decode_xor_mapped_address, encode_xor_mapped_address, StunMessage};

// --- Methods (RFC 5766 §13) -------------------------------------------------------------------

/// STUN Binding method (RFC 8489 §5). Not a TURN method, but a TURN server is required to answer it
/// (RFC 8656 §12: *"a TURN server MUST support Binding requests"*), which is also what lets one
/// server act as both the TURN and the STUN server for candidate gathering.
pub const METHOD_BINDING: u16 = 0x001;
/// TURN Allocate method.
pub const METHOD_ALLOCATE: u16 = 0x003;
/// TURN Refresh method.
pub const METHOD_REFRESH: u16 = 0x004;
/// TURN Send method (indication only, client → server).
pub const METHOD_SEND: u16 = 0x006;
/// TURN Data method (indication only, server → client).
pub const METHOD_DATA: u16 = 0x007;
/// TURN CreatePermission method.
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
/// TURN ChannelBind method.
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

// --- Classes (RFC 5389 §6) --------------------------------------------------------------------

/// Request class.
pub const CLASS_REQUEST: u16 = 0b00;
/// Indication class.
pub const CLASS_INDICATION: u16 = 0b01;
/// Success-response class.
pub const CLASS_SUCCESS: u16 = 0b10;
/// Error-response class.
pub const CLASS_ERROR: u16 = 0b11;

/// Encode a 16-bit STUN message type from a 12-bit `method` and 2-bit `class` (RFC 5389 §6: the
/// method bits are split around the two class bits at positions 4 and 8).
#[must_use]
pub fn message_type(method: u16, class: u16) -> u16 {
    ((method & 0x0F80) << 2)
        | ((method & 0x0070) << 1)
        | (method & 0x000F)
        | ((class & 0b10) << 7)
        | ((class & 0b01) << 4)
}

/// The 12-bit method of a message type (inverse of [`message_type`]).
#[must_use]
pub fn method_of(message_type: u16) -> u16 {
    (message_type & 0x000F) | ((message_type & 0x00E0) >> 1) | ((message_type & 0x3E00) >> 2)
}

/// The 2-bit class of a message type (inverse of [`message_type`]).
#[must_use]
pub fn class_of(message_type: u16) -> u16 {
    ((message_type & 0x0010) >> 4) | ((message_type & 0x0100) >> 7)
}

// --- Attribute registry (RFC 5389 §18.2, RFC 5766 §14) ----------------------------------------
//
// The values are the IANA-assigned attribute types; the parent module keeps its own private copies
// of the ones it needs (USERNAME, MESSAGE-INTEGRITY, …) — these `pub` consts are the registry the
// TURN server composes responses from.

/// MAPPED-ADDRESS — comprehension-required (RFC 5389).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
/// USERNAME (RFC 5389 §15.3).
pub const ATTR_USERNAME: u16 = 0x0006;
/// MESSAGE-INTEGRITY (RFC 5389 §15.4).
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
/// ERROR-CODE (RFC 5389 §15.6).
pub const ATTR_ERROR_CODE: u16 = 0x0009;
/// CHANNEL-NUMBER (RFC 5766 §14.1).
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
/// LIFETIME (RFC 5766 §14.2).
pub const ATTR_LIFETIME: u16 = 0x000D;
/// XOR-PEER-ADDRESS (RFC 5766 §14.3).
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
/// DATA (RFC 5766 §14.4).
pub const ATTR_DATA: u16 = 0x0013;
/// REALM (RFC 5389 §15.7).
pub const ATTR_REALM: u16 = 0x0014;
/// NONCE (RFC 5389 §15.8).
pub const ATTR_NONCE: u16 = 0x0015;
/// XOR-RELAYED-ADDRESS (RFC 5766 §14.5).
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
/// REQUESTED-ADDRESS-FAMILY (RFC 8656 §14).
pub const ATTR_REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
/// EVEN-PORT (RFC 5766 §14.6).
pub const ATTR_EVEN_PORT: u16 = 0x0018;
/// REQUESTED-TRANSPORT (RFC 5766 §14.7).
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
/// DONT-FRAGMENT (RFC 5766 §14.8).
pub const ATTR_DONT_FRAGMENT: u16 = 0x001A;
/// XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// RESERVATION-TOKEN (RFC 5766 §14.9).
pub const ATTR_RESERVATION_TOKEN: u16 = 0x0022;
/// SOFTWARE (RFC 5389 §15.10).
pub const ATTR_SOFTWARE: u16 = 0x8022;

/// The IANA transport number for UDP, carried by REQUESTED-TRANSPORT (RFC 5766 §14.7).
pub const TRANSPORT_UDP: u8 = 17;

// --- Error codes used by the server (RFC 5766 §15, RFC 5389 §15.6) ----------------------------

/// 400 Bad Request.
pub const ERROR_BAD_REQUEST: u16 = 400;
/// 401 Unauthorized — the long-term-credential challenge.
pub const ERROR_UNAUTHORIZED: u16 = 401;
/// 403 Forbidden — e.g. a denied peer address.
pub const ERROR_FORBIDDEN: u16 = 403;
/// 437 Allocation Mismatch.
pub const ERROR_ALLOCATION_MISMATCH: u16 = 437;
/// 438 Stale Nonce.
pub const ERROR_STALE_NONCE: u16 = 438;
/// 440 Address Family not Supported (RFC 8656).
pub const ERROR_ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;
/// 441 Wrong Credentials.
pub const ERROR_WRONG_CREDENTIALS: u16 = 441;
/// 442 Unsupported Transport Protocol.
pub const ERROR_UNSUPPORTED_TRANSPORT: u16 = 442;
/// 443 Peer Address Family Mismatch (RFC 8656).
pub const ERROR_PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;
/// 486 Allocation Quota Reached.
pub const ERROR_ALLOCATION_QUOTA_REACHED: u16 = 486;
/// 508 Insufficient Capacity.
pub const ERROR_INSUFFICIENT_CAPACITY: u16 = 508;

// --- Typed attribute encoders (for building responses/requests) -------------------------------

/// Encode an XOR-PEER / XOR-RELAYED / XOR-MAPPED address value (all share the RFC 5389 §15.2
/// encoding) for `addr`, XOR-keyed by `transaction_id`.
#[must_use]
pub fn xor_address_value(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    encode_xor_mapped_address(addr, transaction_id)
}

/// Encode a LIFETIME attribute value: `seconds` as a big-endian `u32` (RFC 5766 §14.2).
#[must_use]
pub fn lifetime_value(seconds: u32) -> [u8; 4] {
    seconds.to_be_bytes()
}

/// Encode a REQUESTED-TRANSPORT value for `protocol` (RFC 5766 §14.7: 1-byte protocol + 3 RFFU).
#[must_use]
pub fn requested_transport_value(protocol: u8) -> [u8; 4] {
    [protocol, 0, 0, 0]
}

/// Encode a CHANNEL-NUMBER value (RFC 5766 §14.1: 2-byte channel + 2 RFFU).
#[must_use]
pub fn channel_number_value(channel: u16) -> [u8; 4] {
    let c = channel.to_be_bytes();
    [c[0], c[1], 0, 0]
}

/// Encode an ERROR-CODE value (RFC 5389 §15.6): two reserved bytes, then the class (hundreds digit)
/// and number (`code % 100`), then the UTF-8 reason phrase.
#[must_use]
pub fn error_code_value(code: u16, reason: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(4 + reason.len());
    value.push(0);
    value.push(0);
    value.push((code / 100) as u8);
    value.push((code % 100) as u8);
    value.extend_from_slice(reason.as_bytes());
    value
}

// --- Typed attribute accessors ----------------------------------------------------------------

/// The REQUESTED-TRANSPORT protocol number, if present (RFC 5766 §14.7).
#[must_use]
pub fn requested_transport(message: &StunMessage) -> Option<u8> {
    message
        .attribute(ATTR_REQUESTED_TRANSPORT)?
        .first()
        .copied()
}

/// The LIFETIME in seconds, if present (RFC 5766 §14.2).
#[must_use]
pub fn lifetime(message: &StunMessage) -> Option<u32> {
    let value = message.attribute(ATTR_LIFETIME)?;
    let bytes: [u8; 4] = value.get(0..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// The CHANNEL-NUMBER, if present (RFC 5766 §14.1).
#[must_use]
pub fn channel_number(message: &StunMessage) -> Option<u16> {
    let value = message.attribute(ATTR_CHANNEL_NUMBER)?;
    let bytes: [u8; 2] = value.get(0..2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// The first XOR-PEER-ADDRESS, if present (RFC 5766 §14.3).
#[must_use]
pub fn xor_peer_address(message: &StunMessage) -> Option<SocketAddr> {
    decode_xor_mapped_address(
        message.attribute(ATTR_XOR_PEER_ADDRESS)?,
        &message.transaction_id,
    )
}

/// Every XOR-PEER-ADDRESS in the message (a CreatePermission may carry several, RFC 5766 §9.1).
#[must_use]
pub fn xor_peer_addresses(message: &StunMessage) -> Vec<SocketAddr> {
    message
        .attributes
        .iter()
        .filter(|(typ, _)| *typ == ATTR_XOR_PEER_ADDRESS)
        .filter_map(|(_, value)| decode_xor_mapped_address(value, &message.transaction_id))
        .collect()
}

/// The XOR-RELAYED-ADDRESS, if present (RFC 5766 §14.5).
#[must_use]
pub fn xor_relayed_address(message: &StunMessage) -> Option<SocketAddr> {
    decode_xor_mapped_address(
        message.attribute(ATTR_XOR_RELAYED_ADDRESS)?,
        &message.transaction_id,
    )
}

/// The DATA payload, if present (RFC 5766 §14.4).
#[must_use]
pub fn data(message: &StunMessage) -> Option<&[u8]> {
    message.attribute(ATTR_DATA)
}

/// The numeric error code from an ERROR-CODE attribute (RFC 5389 §15.6: `class * 100 + number`),
/// if present and well-formed.
#[must_use]
pub fn error_code(message: &StunMessage) -> Option<u16> {
    let value = message.attribute(ATTR_ERROR_CODE)?;
    let class = u16::from(*value.get(2)?);
    let number = u16::from(*value.get(3)?);
    Some(class * 100 + number)
}

/// The REALM as a string, if present and valid UTF-8 (RFC 5389 §15.7).
#[must_use]
pub fn realm(message: &StunMessage) -> Option<&str> {
    std::str::from_utf8(message.attribute(ATTR_REALM)?).ok()
}

/// The NONCE bytes, if present (RFC 5389 §15.8).
#[must_use]
pub fn nonce(message: &StunMessage) -> Option<&[u8]> {
    message.attribute(ATTR_NONCE)
}

/// Whether the request carries an EVEN-PORT attribute (RFC 5766 §14.6).
#[must_use]
pub fn has_even_port(message: &StunMessage) -> bool {
    message.attribute(ATTR_EVEN_PORT).is_some()
}

/// Whether the request carries a RESERVATION-TOKEN attribute (RFC 5766 §14.9).
#[must_use]
pub fn has_reservation_token(message: &StunMessage) -> bool {
    message.attribute(ATTR_RESERVATION_TOKEN).is_some()
}

// --- ChannelData framing (RFC 5766 §11) -------------------------------------------------------

/// The lowest valid channel number (RFC 5766 §11): `0x4000`.
pub const MIN_CHANNEL_NUMBER: u16 = 0x4000;
/// The highest valid channel number (RFC 5766 §11): `0x7FFF`.
pub const MAX_CHANNEL_NUMBER: u16 = 0x7FFF;

/// Whether a TURN-port datagram's first byte marks a ChannelData message (top two bits `01`) rather
/// than a STUN message (top two bits `00`) — the RFC 5766 §11 demux on the TURN listener socket.
#[must_use]
pub fn is_channel_data(first_byte: u8) -> bool {
    first_byte & 0xC0 == 0x40
}

/// Whether `channel` is a valid ChannelData channel number (RFC 5766 §11: `0x4000`–`0x7FFF`).
#[must_use]
pub fn valid_channel_number(channel: u16) -> bool {
    (MIN_CHANNEL_NUMBER..=MAX_CHANNEL_NUMBER).contains(&channel)
}

/// A parsed ChannelData message (RFC 5766 §11): a channel number and the application data it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelData<'a> {
    /// The 16-bit channel number (`0x4000`–`0x7FFF`).
    pub channel: u16,
    /// The application data (the declared length, padding excluded).
    pub data: &'a [u8],
}

/// Parse a ChannelData message (RFC 5766 §11): a 4-byte header (channel number + length) followed by
/// the application data. Returns `None` on a short buffer, an out-of-range channel number, or a
/// length that overruns the buffer — never panics. Trailing 4-byte-alignment padding (present on
/// TCP/TLS, §11.5) is ignored: the declared length is authoritative.
#[must_use]
pub fn parse_channel_data(buffer: &[u8]) -> Option<ChannelData<'_>> {
    if buffer.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([buffer[0], buffer[1]]);
    if !valid_channel_number(channel) {
        return None;
    }
    let length = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
    let data = buffer.get(4..4 + length)?;
    Some(ChannelData { channel, data })
}

/// The number of bytes a ChannelData message of `data_len` payload occupies on the wire, including
/// the 4-byte header and — when `pad_to_four` — the 4-byte-alignment padding TCP/TLS requires
/// (RFC 5766 §11.5). UDP carriers pass `pad_to_four = false`.
#[must_use]
pub fn channel_data_frame_len(data_len: usize, pad_to_four: bool) -> usize {
    let unpadded = 4 + data_len;
    if pad_to_four {
        unpadded.div_ceil(4) * 4
    } else {
        unpadded
    }
}

/// Encode a ChannelData message (RFC 5766 §11) wrapping `data` on `channel`. When `pad_to_four` is
/// set the message is zero-padded to a 4-byte boundary (required on TCP/TLS, §11.5; optional on UDP).
#[must_use]
pub fn encode_channel_data(channel: u16, data: &[u8], pad_to_four: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(channel_data_frame_len(data.len(), pad_to_four));
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    if pad_to_four {
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    out
}

// --- Long-term credential key + primitives ----------------------------------------------------

/// The long-term-credential key `MD5(username ":" realm ":" password)` (RFC 5389 §15.4, RFC 5766
/// §4) — the HMAC-SHA1 key for MESSAGE-INTEGRITY under the long-term mechanism.
#[must_use]
pub fn long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut input = Vec::with_capacity(username.len() + realm.len() + password.len() + 2);
    input.extend_from_slice(username.as_bytes());
    input.push(b':');
    input.extend_from_slice(realm.as_bytes());
    input.push(b':');
    input.extend_from_slice(password.as_bytes());
    md5(&input)
}

/// Per-round left-rotation amounts (RFC 1321 §3.4).
const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Per-round constants `K[i] = floor(2^32 · |sin(i + 1)|)` (RFC 1321 §3.4).
const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// `MD5` (RFC 1321) of `input`. Hand-rolled, pure Rust, zero dependencies — used only to derive the
/// long-term-credential key (never for integrity; the integrity HMAC is SHA-1).
#[must_use]
pub fn md5(input: &[u8]) -> [u8; 16] {
    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in message.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (word, bytes) in m.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(MD5_K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(MD5_SHIFTS[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 encode (RFC 4648 §4, with `=` padding).
#[must_use]
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(BASE64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(BASE64_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64 decode (RFC 4648 §4). Returns `None` on a non-multiple-of-4 length or an invalid
/// character — never panics.
#[must_use]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks_exact(4) {
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let value = if c == b'=' { 0 } else { sextet(c)? };
            n |= u32::from(value) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::{parse, verify_message_integrity, MessageBuilder, BINDING_REQUEST};
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn message_type_round_trips_turn_methods() {
        // RFC 5766 §13 worked examples of the RFC 5389 §6 method/class bit layout.
        assert_eq!(message_type(METHOD_ALLOCATE, CLASS_REQUEST), 0x0003);
        assert_eq!(message_type(METHOD_ALLOCATE, CLASS_SUCCESS), 0x0103);
        assert_eq!(message_type(METHOD_ALLOCATE, CLASS_ERROR), 0x0113);
        assert_eq!(message_type(METHOD_REFRESH, CLASS_REQUEST), 0x0004);
        assert_eq!(message_type(METHOD_SEND, CLASS_INDICATION), 0x0016);
        assert_eq!(message_type(METHOD_DATA, CLASS_INDICATION), 0x0017);
        assert_eq!(
            message_type(METHOD_CREATE_PERMISSION, CLASS_REQUEST),
            0x0008
        );
        assert_eq!(message_type(METHOD_CHANNEL_BIND, CLASS_REQUEST), 0x0009);

        for method in [
            METHOD_ALLOCATE,
            METHOD_REFRESH,
            METHOD_SEND,
            METHOD_DATA,
            METHOD_CREATE_PERMISSION,
            METHOD_CHANNEL_BIND,
        ] {
            for class in [CLASS_REQUEST, CLASS_INDICATION, CLASS_SUCCESS, CLASS_ERROR] {
                let mt = message_type(method, class);
                assert_eq!(method_of(mt), method, "method round-trip");
                assert_eq!(class_of(mt), class, "class round-trip");
            }
        }
    }

    #[test]
    fn md5_known_answers() {
        // RFC 1321 §A.5 test suite.
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&md5(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn base64_round_trips_rfc4648_vectors() {
        // RFC 4648 §10.
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain), encoded, "encode {plain:?}");
            assert_eq!(
                base64_decode(encoded).as_deref(),
                Some(plain),
                "decode {encoded}"
            );
        }
        assert_eq!(base64_decode("not*base64"), None);
        assert_eq!(base64_decode("abc"), None, "non-multiple-of-4 rejected");
    }

    #[test]
    fn long_term_key_matches_md5_of_credential_triplet() {
        // RFC 5389 §15.4 / RFC 5766 §4: key = MD5("username:realm:password").
        // Cross-checked against `echo -n 'user:realm:pass' | md5sum` (coturn computes the same).
        let key = long_term_key("user", "realm", "pass");
        assert_eq!(key, md5(b"user:realm:pass"));
        assert_eq!(hex(&key), hex(&md5(b"user:realm:pass")));
    }

    #[test]
    fn rest_credential_integrity_round_trips() {
        // The coturn REST profile: password = base64(HMAC-SHA1(secret, username)); the long-term key
        // is MD5(username:realm:password). Build a request signed with that key, verify it parses and
        // the integrity checks out — the exact path the server runs on every authenticated request.
        let secret = b"static-auth-secret";
        let username = "1730000000:webrtc-user";
        let realm = "siphon.example";
        // password = base64(HMAC-SHA1(secret, username)) — the coturn REST derivation, recomputed
        // server-side with the parent module's hand-rolled HMAC-SHA1.
        let password = base64_encode(&crate::hmac_sha1(secret, username.as_bytes()));
        let key = long_term_key(username, realm, &password);

        let request = MessageBuilder::new(message_type(METHOD_ALLOCATE, CLASS_REQUEST), &[7u8; 12])
            .attribute(ATTR_USERNAME, username.as_bytes())
            .attribute(ATTR_REALM, realm.as_bytes())
            .attribute(ATTR_NONCE, b"nonce-value")
            .attribute(
                ATTR_REQUESTED_TRANSPORT,
                &requested_transport_value(TRANSPORT_UDP),
            )
            .finish(Some(&key), false);

        let parsed = parse(&request).expect("parse allocate");
        assert_eq!(method_of(parsed.message_type), METHOD_ALLOCATE);
        assert_eq!(class_of(parsed.message_type), CLASS_REQUEST);
        assert_eq!(parsed.username(), Some(username));
        assert_eq!(realm_of(&parsed), Some(realm));
        assert_eq!(requested_transport(&parsed), Some(TRANSPORT_UDP));
        assert!(verify_message_integrity(&request, &key));
        assert!(!verify_message_integrity(&request, b"wrong-key"));
    }

    // Local helper so the test reads the REALM without colliding with the module's `realm` fn name.
    fn realm_of(message: &StunMessage) -> Option<&str> {
        realm(message)
    }

    #[test]
    fn builds_and_reads_allocate_success_attributes() {
        let txid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let relay: SocketAddr = "192.0.2.15:49152".parse().expect("relay addr");
        let mapped: SocketAddr = "203.0.113.7:51000".parse().expect("mapped addr");
        let key = long_term_key("user", "realm", "pass");

        let response = MessageBuilder::new(message_type(METHOD_ALLOCATE, CLASS_SUCCESS), &txid)
            .attribute(ATTR_XOR_RELAYED_ADDRESS, &xor_address_value(relay, &txid))
            .attribute(ATTR_LIFETIME, &lifetime_value(600))
            .attribute(ATTR_XOR_MAPPED_ADDRESS, &xor_address_value(mapped, &txid))
            .finish(Some(&key), false);

        let parsed = parse(&response).expect("parse success");
        assert_eq!(class_of(parsed.message_type), CLASS_SUCCESS);
        assert_eq!(xor_relayed_address(&parsed), Some(relay));
        assert_eq!(lifetime(&parsed), Some(600));
        assert!(verify_message_integrity(&response, &key));
    }

    #[test]
    fn create_permission_exposes_every_peer_address() {
        let txid = [9u8; 12];
        let peer_a: SocketAddr = "198.51.100.1:0".parse().expect("peer a");
        let peer_b: SocketAddr = "198.51.100.2:0".parse().expect("peer b");
        let request =
            MessageBuilder::new(message_type(METHOD_CREATE_PERMISSION, CLASS_REQUEST), &txid)
                .attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(peer_a, &txid))
                .attribute(ATTR_XOR_PEER_ADDRESS, &xor_address_value(peer_b, &txid))
                .finish(None, false);
        let parsed = parse(&request).expect("parse perm");
        assert_eq!(xor_peer_addresses(&parsed), vec![peer_a, peer_b]);
        assert_eq!(xor_peer_address(&parsed), Some(peer_a));
    }

    #[test]
    fn error_code_value_encodes_class_and_number() {
        // RFC 5389 §15.6: 401 → class 4, number 1.
        let value = error_code_value(ERROR_UNAUTHORIZED, "Unauthorized");
        assert_eq!(&value[0..2], &[0, 0], "reserved");
        assert_eq!(value[2], 4, "class");
        assert_eq!(value[3], 1, "number");
        assert_eq!(&value[4..], b"Unauthorized");
        assert_eq!(error_code_value(ERROR_STALE_NONCE, "x")[2..4], [4, 38]);
        assert_eq!(
            error_code_value(ERROR_INSUFFICIENT_CAPACITY, "x")[2..4],
            [5, 8]
        );

        // The accessor reconstructs the numeric code from a built error response.
        let response = MessageBuilder::new(message_type(METHOD_ALLOCATE, CLASS_ERROR), &[0u8; 12])
            .attribute(
                ATTR_ERROR_CODE,
                &error_code_value(ERROR_STALE_NONCE, "Stale Nonce"),
            )
            .finish(None, false);
        let parsed = parse(&response).expect("parse error");
        assert_eq!(error_code(&parsed), Some(ERROR_STALE_NONCE));
    }

    #[test]
    fn channel_data_round_trips_and_demuxes() {
        let payload = b"the quick brown rtp packet";
        let frame = encode_channel_data(0x4001, payload, false);
        assert!(is_channel_data(frame[0]));
        let parsed = parse_channel_data(&frame).expect("parse channel data");
        assert_eq!(parsed.channel, 0x4001);
        assert_eq!(parsed.data, payload);

        // TCP/TLS framing pads to a 4-byte boundary (RFC 5766 §11.5); the length stays authoritative.
        let padded = encode_channel_data(0x4002, b"odd", true);
        assert_eq!(padded.len() % 4, 0);
        assert_eq!(padded.len(), channel_data_frame_len(3, true));
        let parsed = parse_channel_data(&padded).expect("parse padded");
        assert_eq!(parsed.data, b"odd");
    }

    #[test]
    fn channel_data_rejects_out_of_range_and_truncated() {
        // A STUN message's first byte (top bits 00) is not ChannelData.
        assert!(!is_channel_data(0x00));
        assert!(!is_channel_data(0x01));
        // Channel number below 0x4000 is invalid.
        let mut frame = encode_channel_data(0x4000, b"x", false);
        frame[0] = 0x00;
        frame[1] = 0x01;
        assert!(parse_channel_data(&frame).is_none());
        // A length that overruns the buffer is rejected, not panicked on.
        assert!(parse_channel_data(&[0x40, 0x00, 0xFF, 0xFF, 0x01]).is_none());
        assert!(parse_channel_data(&[0x40, 0x00]).is_none());
    }

    #[test]
    fn valid_channel_number_bounds() {
        assert!(!valid_channel_number(0x3FFF));
        assert!(valid_channel_number(0x4000));
        assert!(valid_channel_number(0x7FFF));
        assert!(!valid_channel_number(0x8000));
    }

    use proptest::prelude::*;

    proptest! {
        /// A hostile datagram on the TURN listener must decode-or-error, never panic — both as a STUN
        /// message and as ChannelData.
        #[test]
        fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1500)) {
            let _ = parse(&bytes);
            let _ = parse_channel_data(&bytes);
            if let Ok(message) = parse(&bytes) {
                let _ = lifetime(&message);
                let _ = xor_peer_addresses(&message);
                let _ = requested_transport(&message);
                let _ = realm(&message);
            }
        }

        /// MD5 and base64 never panic and base64 round-trips for any input.
        #[test]
        fn md5_and_base64_total(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = md5(&bytes);
            let encoded = base64_encode(&bytes);
            let decoded = base64_decode(&encoded);
            prop_assert_eq!(decoded.as_deref(), Some(bytes.as_slice()));
        }
    }

    // A `BINDING_REQUEST` sanity check that the TURN module sees the same parser as the root.
    #[test]
    fn shares_root_binding_request_type() {
        assert_eq!(class_of(BINDING_REQUEST), CLASS_REQUEST);
    }
}
