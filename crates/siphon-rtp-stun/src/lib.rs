//! STUN (RFC 8489 / RFC 5389) message codec — the foundation for ICE connectivity checks
//! (RFC 8445) served on the media socket via the layer-1 demux.
//!
//! Pure Rust, zero C: SHA-1 (FIPS 180), HMAC (RFC 2104), and CRC-32 are hand-written here so
//! `MESSAGE-INTEGRITY` and `FINGERPRINT` need no external crypto dependency (the project's zero-C
//! hard rule; ring/rustls are reserved for DTLS-SRTP later, M-S4).
//!
//! Scope (M-S3 foundation): parse Binding requests/responses; build a Binding **success response**
//! with `XOR-MAPPED-ADDRESS`, short-term-credential `MESSAGE-INTEGRITY`, and `FINGERPRINT`; and
//! verify `MESSAGE-INTEGRITY`. The ICE state machine, the connectivity-check responder wired into
//! the datapath `recv_loop`, and consent (RFC 7675) build on this. See `docs/security-and-nat.md`
//! §4 layer 4.
//!
//! The [`turn`] submodule extends this with the TURN (RFC 5766) message set — Allocate / Refresh /
//! CreatePermission / ChannelBind / Send / Data, the TURN attributes, `ChannelData` framing, and the
//! long-term-credential key derivation (`MD5`/base64) — built on the same hand-rolled SHA-1 / HMAC /
//! CRC-32 primitives and the [`MessageBuilder`], so the built-in TURN server (`siphon-rtp-turn`,
//! M-T*) needs no new dependency. See `docs/security-and-nat.md` §11.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod client;
pub mod turn;

/// The STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed STUN header size (RFC 5389 §6).
const HEADER_LEN: usize = 20;

/// Binding request message type (class = request, method = Binding).
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding success-response message type.
pub const BINDING_SUCCESS: u16 = 0x0101;

const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// XOR applied to the CRC-32 for the `FINGERPRINT` attribute (RFC 5389 §15.5).
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// Errors from STUN parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// The buffer is shorter than a STUN header.
    #[error("STUN message too short")]
    TooShort,
    /// The magic cookie did not match — not a STUN message.
    #[error("not a STUN message (bad magic cookie)")]
    BadCookie,
    /// An attribute (or the declared message length) overran the buffer.
    #[error("STUN attribute length overruns the message")]
    BadLength,
}

/// A parsed STUN message: its type, transaction id, and raw attributes (type, value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// The 14-bit method + 2-bit class, as the on-the-wire 16-bit field.
    pub message_type: u16,
    /// The 96-bit transaction id.
    pub transaction_id: [u8; 12],
    /// Attributes in wire order, as `(type, value)` (padding stripped).
    pub attributes: Vec<(u16, Vec<u8>)>,
}

impl StunMessage {
    /// Whether this is a Binding request (an ICE connectivity check).
    #[must_use]
    pub fn is_binding_request(&self) -> bool {
        self.message_type == BINDING_REQUEST
    }

    /// The value of the first attribute of `attr_type`, if present.
    #[must_use]
    pub fn attribute(&self, attr_type: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(typ, _)| *typ == attr_type)
            .map(|(_, value)| value.as_slice())
    }

    /// The `USERNAME` attribute as a string slice, if present and valid UTF-8.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        std::str::from_utf8(self.attribute(ATTR_USERNAME)?).ok()
    }

    /// The reflexive transport address from `XOR-MAPPED-ADDRESS`, if present.
    #[must_use]
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        decode_xor_mapped_address(
            self.attribute(ATTR_XOR_MAPPED_ADDRESS)?,
            &self.transaction_id,
        )
    }
}

/// Parse a STUN message. Validates the cookie and that every attribute fits the declared length;
/// never panics on malformed input.
pub fn parse(data: &[u8]) -> Result<StunMessage, StunError> {
    if data.len() < HEADER_LEN {
        return Err(StunError::TooShort);
    }
    let message_type = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadCookie);
    }
    let end = HEADER_LEN + length;
    if end > data.len() {
        return Err(StunError::BadLength);
    }
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&data[8..20]);

    let mut attributes = Vec::new();
    let mut offset = HEADER_LEN;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > end {
            return Err(StunError::BadLength);
        }
        attributes.push((attr_type, data[value_start..value_end].to_vec()));
        offset = value_end + padding(attr_len);
    }
    Ok(StunMessage {
        message_type,
        transaction_id,
        attributes,
    })
}

/// Incrementally builds a STUN/TURN message: the 20-byte header (RFC 5389 §6), then attributes in
/// wire order, then — on [`finish`](MessageBuilder::finish) — optionally a `MESSAGE-INTEGRITY`
/// (HMAC-SHA1 over everything before it, RFC 5389 §15.4) and a `FINGERPRINT` (CRC-32 of the message
/// XOR `0x5354554e`, RFC 5389 §15.5), appended last in that order. Backs the Binding builders below
/// and every TURN response (RFC 5766).
pub struct MessageBuilder {
    message: Vec<u8>,
}

impl MessageBuilder {
    /// Start a message of `message_type` (14-bit method + 2-bit class, RFC 5389 §6) carrying
    /// `transaction_id`. The length field is a placeholder, fixed up as attributes are appended.
    #[must_use]
    pub fn new(message_type: u16, transaction_id: &[u8; 12]) -> Self {
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(&message_type.to_be_bytes());
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(transaction_id);
        Self { message }
    }

    /// Append one attribute (value zero-padded to a 4-byte boundary, RFC 5389 §15).
    #[must_use]
    pub fn attribute(mut self, attr_type: u16, value: &[u8]) -> Self {
        push_attribute(&mut self.message, attr_type, value);
        self
    }

    /// Finalize the message: append `MESSAGE-INTEGRITY` keyed by `integrity_key` (when `Some`), then
    /// — when `fingerprint` is set — `FINGERPRINT`. The integrity HMAC covers the message with the
    /// length field set through the 24-byte integrity attribute but the bytes taken *before* it
    /// (RFC 5389 §15.4); FINGERPRINT then covers everything through its own 8 bytes (§15.5).
    #[must_use]
    pub fn finish(mut self, integrity_key: Option<&[u8]>, fingerprint: bool) -> Vec<u8> {
        if let Some(key) = integrity_key {
            let length = self.message.len() - HEADER_LEN + 24;
            set_length(&mut self.message, length);
            let mac = hmac_sha1(key, &self.message);
            push_attribute(&mut self.message, ATTR_MESSAGE_INTEGRITY, &mac);
        }
        if fingerprint {
            let length = self.message.len() - HEADER_LEN + 8;
            set_length(&mut self.message, length);
            let value = (crc32(&self.message) ^ FINGERPRINT_XOR).to_be_bytes();
            push_attribute(&mut self.message, ATTR_FINGERPRINT, &value);
        }
        // Ensure the header length covers every attribute — for a message with neither
        // MESSAGE-INTEGRITY nor FINGERPRINT (e.g. a Send/Data indication) the branches above never
        // ran, so the placeholder would otherwise stay zero. Re-stating it is a no-op when they did,
        // since both compute over the length value that equals the final total.
        let length = self.message.len() - HEADER_LEN;
        set_length(&mut self.message, length);
        self.message
    }
}

/// Build a Binding success response reflecting `mapped` back to the peer, with `FINGERPRINT` and —
/// when `integrity_key` is `Some` (the short-term credential = the local ICE password) — a
/// `MESSAGE-INTEGRITY` attribute (RFC 5389 §15.4). Attribute order is XOR-MAPPED-ADDRESS,
/// MESSAGE-INTEGRITY, FINGERPRINT, as required.
#[must_use]
pub fn binding_success_response(
    transaction_id: &[u8; 12],
    mapped: SocketAddr,
    integrity_key: Option<&[u8]>,
) -> Vec<u8> {
    MessageBuilder::new(BINDING_SUCCESS, transaction_id)
        .attribute(
            ATTR_XOR_MAPPED_ADDRESS,
            &encode_xor_mapped_address(mapped, transaction_id),
        )
        .finish(integrity_key, true)
}

/// Build a Binding **request** carrying `username` and authenticated with `integrity_key` (the
/// short-term credential), plus `FINGERPRINT` — an ICE connectivity check (RFC 8445 §7.1.2).
#[must_use]
pub fn binding_request(transaction_id: &[u8; 12], username: &str, integrity_key: &[u8]) -> Vec<u8> {
    MessageBuilder::new(BINDING_REQUEST, transaction_id)
        .attribute(ATTR_USERNAME, username.as_bytes())
        .finish(Some(integrity_key), true)
}

/// Verify a message's `MESSAGE-INTEGRITY` against `key` (the short-term credential). Returns false
/// if the attribute is absent, malformed, or the HMAC does not match. Constant-time on the compare.
#[must_use]
pub fn verify_message_integrity(raw: &[u8], key: &[u8]) -> bool {
    if raw.len() < HEADER_LEN
        || u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) != MAGIC_COOKIE
    {
        return false;
    }
    let length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let end = match HEADER_LEN.checked_add(length) {
        Some(end) if end <= raw.len() => end,
        _ => return false,
    };
    let mut offset = HEADER_LEN;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        let attr_len = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
        if attr_type == ATTR_MESSAGE_INTEGRITY {
            if attr_len != 20 || offset + 4 + 20 > raw.len() {
                return false;
            }
            let provided = &raw[offset + 4..offset + 24];
            // Recompute over the bytes before the attribute, with the length field rewound to what
            // it was when the HMAC was taken (covering through MESSAGE-INTEGRITY).
            let mut prefix = raw[..offset].to_vec();
            set_length(&mut prefix, offset - HEADER_LEN + 24);
            return constant_time_eq(provided, &hmac_sha1(key, &prefix));
        }
        offset = offset + 4 + attr_len + padding(attr_len);
    }
    false
}

/// Bytes of zero padding that follow an attribute value of `len` bytes (4-byte alignment).
fn padding(len: usize) -> usize {
    (4 - (len % 4)) % 4
}

fn push_attribute(message: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    message.extend_from_slice(&attr_type.to_be_bytes());
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(value);
    for _ in 0..padding(value.len()) {
        message.push(0);
    }
}

fn set_length(message: &mut [u8], length: usize) {
    let bytes = (length as u16).to_be_bytes();
    message[2] = bytes[0];
    message[3] = bytes[1];
}

fn encode_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.push(0); // reserved
    let xport = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&xport.to_be_bytes());
            out.extend_from_slice(&(u32::from(ip) ^ MAGIC_COOKIE).to_be_bytes());
        }
        IpAddr::V6(ip) => {
            out.push(0x02);
            out.extend_from_slice(&xport.to_be_bytes());
            for (octet, key) in ip.octets().iter().zip(xor_key(transaction_id)) {
                out.push(octet ^ key);
            }
        }
    }
    out
}

fn decode_xor_mapped_address(value: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match value[1] {
        0x01 => {
            let bytes: [u8; 4] = value.get(4..8)?.try_into().ok()?;
            let addr = u32::from_be_bytes(bytes) ^ MAGIC_COOKIE;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port))
        }
        0x02 => {
            let xored: [u8; 16] = value.get(4..20)?.try_into().ok()?;
            let mut addr = [0u8; 16];
            for (slot, (byte, key)) in addr
                .iter_mut()
                .zip(xored.iter().zip(xor_key(transaction_id)))
            {
                *slot = byte ^ key;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port))
        }
        _ => None,
    }
}

/// The 128-bit XOR key for IPv6 XOR-MAPPED-ADDRESS: magic cookie ‖ transaction id.
fn xor_key(transaction_id: &[u8; 12]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    key[4..].copy_from_slice(transaction_id);
    key
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-1 (FIPS 180) of `data`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (word, bytes) in w.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (slot, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA1 (RFC 2104) of `message` under `key`. Exposed so the TURN server can derive the coturn
/// REST credential `password = base64(HMAC-SHA1(static_auth_secret, username))` (RFC 5766 §4) and
/// stamp stateless nonces with the same hand-rolled primitive — no new crypto dependency.
#[must_use]
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        block_key[..20].copy_from_slice(&sha1(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for ((inner, outer), key_byte) in ipad.iter_mut().zip(opad.iter_mut()).zip(block_key.iter()) {
        *inner ^= key_byte;
        *outer ^= key_byte;
    }

    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 20);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// CRC-32 (IEEE 802.3, reflected) of `data`.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha1_known_answer() {
        // FIPS 180 / RFC 3174 test vectors.
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn hmac_sha1_known_answer() {
        // RFC 2202 §3, test case 1: key = 0x0b×20, data = "Hi There".
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(&hmac_sha1(&key, b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        // RFC 2202 §3, test case 2: key = "Jefe", data = "what do ya want for nothing?".
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn crc32_known_answer() {
        // The canonical CRC-32 check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn binding_response_roundtrips_address_integrity_and_fingerprint() {
        let transaction_id = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let mapped: SocketAddr = "192.0.2.15:32853".parse().expect("addr");
        let key = b"VOkJxbRl1RmTxUk/WvJxBt";

        let response = binding_success_response(&transaction_id, mapped, Some(key));

        let parsed = parse(&response).expect("parse our own response");
        assert_eq!(parsed.message_type, BINDING_SUCCESS);
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.xor_mapped_address(), Some(mapped));

        // MESSAGE-INTEGRITY verifies with the right key and fails with the wrong one.
        assert!(verify_message_integrity(&response, key));
        assert!(!verify_message_integrity(&response, b"wrong-password"));

        // FINGERPRINT is the last attribute and matches the CRC-32 over the preceding bytes.
        let (fp_type, fp_value) = parsed.attributes.last().expect("fingerprint present");
        assert_eq!(*fp_type, ATTR_FINGERPRINT);
        let fingerprint_offset = response.len() - 4;
        let expected = crc32(&response[..fingerprint_offset - 4]) ^ FINGERPRINT_XOR;
        assert_eq!(fp_value.as_slice(), expected.to_be_bytes());
    }

    #[test]
    fn ipv6_xor_mapped_address_roundtrips() {
        let transaction_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mapped: SocketAddr = "[2001:db8::1]:5000".parse().expect("addr");
        let encoded = encode_xor_mapped_address(mapped, &transaction_id);
        assert_eq!(
            decode_xor_mapped_address(&encoded, &transaction_id),
            Some(mapped)
        );
    }

    #[test]
    fn response_without_key_omits_integrity_but_keeps_fingerprint() {
        let transaction_id = [0u8; 12];
        let mapped: SocketAddr = "198.51.100.7:4000".parse().expect("addr");
        let response = binding_success_response(&transaction_id, mapped, None);
        let parsed = parse(&response).expect("parse");
        assert!(parsed.attribute(ATTR_MESSAGE_INTEGRITY).is_none());
        assert!(parsed.attribute(ATTR_FINGERPRINT).is_some());
        assert_eq!(parsed.xor_mapped_address(), Some(mapped));
        assert!(!verify_message_integrity(&response, b"anything"));
    }

    #[test]
    fn parse_rejects_bad_cookie_and_truncation() {
        assert_eq!(parse(&[0u8; 8]), Err(StunError::TooShort));
        let mut msg = binding_success_response(&[0u8; 12], "192.0.2.1:1".parse().unwrap(), None);
        msg[4] ^= 0xFF; // corrupt the magic cookie
        assert_eq!(parse(&msg), Err(StunError::BadCookie));
    }

    #[test]
    fn parse_exposes_username() {
        // Hand-build a Binding request carrying a USERNAME ("evtj:h6vY").
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        msg.extend_from_slice(&[0, 0]);
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&[0u8; 12]);
        push_attribute(&mut msg, ATTR_USERNAME, b"evtj:h6vY");
        let length = msg.len() - HEADER_LEN;
        set_length(&mut msg, length);
        let parsed = parse(&msg).expect("parse request");
        assert!(parsed.is_binding_request());
        assert_eq!(parsed.username(), Some("evtj:h6vY"));
    }

    // --- RFC 5769 sample vectors -----------------------------------------------------------------
    // The reference short-term-credential test vectors (RFC 5769 §2.1-§2.3). Validating our
    // HMAC-SHA1 MESSAGE-INTEGRITY, CRC-32 FINGERPRINT, and XOR-MAPPED-ADDRESS codecs against these
    // exact bytes is the conformance anchor the round-trip tests above cannot provide (a shared
    // encode/decode bug passes a round-trip). §2.4 (long-term credential) needs SASLprep of a
    // Unicode password and is intentionally out of scope. The USERNAME/SOFTWARE padding in these
    // vectors is spaces (0x20), not our encoder's zero pad — so these are stored, not rebuilt.
    //
    // Common short-term credential (RFC 5769 §2.1): username "evtj:h6vY", password below.
    const RFC5769_PASSWORD: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

    /// Recompute the trailing FINGERPRINT (RFC 5389 §15.5) over a stored vector and confirm it
    /// matches the on-the-wire value — a CRC-32 known-answer over real RFC bytes.
    fn fingerprint_matches(message: &[u8]) -> bool {
        let value_offset = message.len() - 4;
        let expected = crc32(&message[..value_offset - 4]) ^ FINGERPRINT_XOR;
        message[value_offset..] == expected.to_be_bytes()
    }

    #[test]
    fn rfc5769_sample_request_vector() {
        // RFC 5769 §2.1 — Sample Request.
        let vector: [u8; 108] = [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e,
            0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24,
            0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1,
            0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68,
            0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c,
            0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5,
            0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
        ];
        let message = parse(&vector).expect("parse the RFC 5769 sample request");
        assert!(message.is_binding_request());
        assert_eq!(
            message.transaction_id,
            [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae]
        );
        assert_eq!(message.username(), Some("evtj:h6vY"));
        // The new ICE attribute codecs read the documented PRIORITY / ICE-CONTROLLED values.
        assert_eq!(client::priority(&message), Some(0x6e00_01ff));
        assert_eq!(
            client::ice_controlled(&message),
            Some(0x932f_f9b1_5126_3b36)
        );
        assert_eq!(client::ice_controlling(&message), None);
        // MESSAGE-INTEGRITY verifies with the reference password (our HMAC-SHA1 == the RFC's), and
        // a single-bit corruption fails it.
        assert!(verify_message_integrity(&vector, RFC5769_PASSWORD));
        let mut corrupted = vector;
        corrupted[24] ^= 0x01;
        assert!(!verify_message_integrity(&corrupted, RFC5769_PASSWORD));
        assert!(fingerprint_matches(&vector));
    }

    #[test]
    fn rfc5769_sample_ipv4_response_vector() {
        // RFC 5769 §2.2 — Sample IPv4 Response.
        let vector: [u8; 80] = [
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99,
            0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b,
            0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ];
        let message = parse(&vector).expect("parse the RFC 5769 sample IPv4 response");
        assert_eq!(message.message_type, BINDING_SUCCESS);
        assert_eq!(
            message.xor_mapped_address(),
            Some("192.0.2.1:32853".parse().expect("addr"))
        );
        assert!(verify_message_integrity(&vector, RFC5769_PASSWORD));
        assert!(fingerprint_matches(&vector));
    }

    #[test]
    fn rfc5769_sample_ipv6_response_vector() {
        // RFC 5769 §2.3 — Sample IPv6 Response.
        let vector: [u8; 92] = [
            0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x14, 0x00, 0x02,
            0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5,
            0xbe, 0xd2, 0xb9, 0xd9, 0x00, 0x08, 0x00, 0x14, 0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6,
            0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2, 0x75, 0xbf, 0xe3, 0xed, 0x41,
            0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
        ];
        let message = parse(&vector).expect("parse the RFC 5769 sample IPv6 response");
        assert_eq!(message.message_type, BINDING_SUCCESS);
        assert_eq!(
            message.xor_mapped_address(),
            Some(
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                    .parse()
                    .expect("addr")
            )
        );
        assert!(verify_message_integrity(&vector, RFC5769_PASSWORD));
        assert!(fingerprint_matches(&vector));
    }

    use proptest::prelude::*;

    proptest! {
        /// A hostile datagram on the media socket must decode-or-error, never panic.
        #[test]
        fn parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse(&bytes);
            let _ = verify_message_integrity(&bytes, b"key");
        }
    }
}
