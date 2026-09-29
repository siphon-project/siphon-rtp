//! Base64 (RFC 4648 §4, the standard alphabet with `=` padding) for binary fields carried in JSON.
//!
//! Hand-written rather than a dependency: this crate is the one published for controllers to link,
//! and the whole codec is a table and two loops. Strict on decode — padding is required (RFC 4648
//! §3.2) and anything outside the alphabet is refused (§3.3) — so a corrupted field fails loudly
//! instead of decoding into different audio.

use std::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a base64 string was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// The length is not a multiple of four (RFC 4648 §3.2 requires padding).
    Length(usize),
    /// A byte outside the alphabet, or padding anywhere but the end, at this offset.
    Symbol(usize),
}

impl fmt::Display for Base64Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(length) => write!(
                formatter,
                "base64 length {length} is not a multiple of 4 (padding is required)"
            ),
            Self::Symbol(offset) => write!(formatter, "invalid base64 symbol at offset {offset}"),
        }
    }
}

impl std::error::Error for Base64Error {}

/// The encoded length of `input_length` bytes: four symbols per three bytes, rounded up.
#[must_use]
pub const fn encoded_len(input_length: usize) -> usize {
    input_length.div_ceil(3) * 4
}

/// Encode `input`.
#[must_use]
pub fn encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(encoded_len(input.len()));
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let group = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                let symbol = (group >> (18 - 6 * index)) & 0x3f;
                output.push(char::from(ALPHABET[symbol as usize]));
            } else {
                output.push('=');
            }
        }
    }
    output
}

fn value(symbol: u8) -> Option<u32> {
    let value = match symbol {
        b'A'..=b'Z' => symbol - b'A',
        b'a'..=b'z' => symbol - b'a' + 26,
        b'0'..=b'9' => symbol - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decode `input`.
///
/// # Errors
/// [`Base64Error`] for a length that is not a multiple of four, a byte outside the alphabet, or
/// padding anywhere but the last one or two positions.
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    let input = input.as_bytes();
    if !input.len().is_multiple_of(4) {
        return Err(Base64Error::Length(input.len()));
    }
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let groups = input.len() / 4;
    for (group_index, group) in input.chunks(4).enumerate() {
        let last = group_index + 1 == groups;
        let padding = if last {
            group
                .iter()
                .rev()
                .take_while(|symbol| **symbol == b'=')
                .count()
        } else {
            0
        };
        if padding > 2 {
            return Err(Base64Error::Symbol(group_index * 4 + 4 - padding));
        }
        let mut bits = 0u32;
        for (offset, symbol) in group.iter().enumerate() {
            let symbol_value = if offset >= 4 - padding {
                0
            } else {
                value(*symbol).ok_or(Base64Error::Symbol(group_index * 4 + offset))?
            };
            bits = bits << 6 | symbol_value;
        }
        let bytes = bits.to_be_bytes();
        output.extend_from_slice(&bytes[1..4 - padding]);
    }
    Ok(output)
}

/// Serde for [`PlayMediaSource::Blob`]'s bytes: written as base64, read from base64, the legacy array
/// of byte values, or a native byte string from a binary format.
pub(crate) mod blob_data {
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(crate) fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode(data))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        struct BlobVisitor;

        impl<'de> Visitor<'de> for BlobVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64 string or an array of byte values")
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<Vec<u8>, E> {
                super::decode(value).map_err(E::custom)
            }

            fn visit_bytes<E: Error>(self, value: &[u8]) -> Result<Vec<u8>, E> {
                Ok(value.to_vec())
            }

            fn visit_byte_buf<E: Error>(self, value: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(value)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<u8>, A::Error> {
                let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(BlobVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 test vectors.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn encodes_the_rfc_4648_vectors() {
        for (plain, encoded) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), encoded, "{plain:?}");
            assert_eq!(encoded_len(plain.len()), encoded.len());
        }
    }

    #[test]
    fn decodes_the_rfc_4648_vectors() {
        for (plain, encoded) in VECTORS {
            assert_eq!(decode(encoded).expect(encoded), plain.as_bytes());
        }
    }

    #[test]
    fn uses_the_high_symbols_of_the_standard_alphabet() {
        // 0xfb 0xff 0xbf → 111110 111111 111110 111111 → `+/+/`: the two symbols that differ
        // between the standard and URL-safe alphabets (RFC 4648 §4 vs §5).
        assert_eq!(encode(&[0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(decode("+/+/").expect("decode"), [0xfb, 0xff, 0xbf]);
    }

    #[test]
    fn refuses_what_is_not_strict_base64() {
        assert_eq!(decode("Zg"), Err(Base64Error::Length(2)), "unpadded");
        assert_eq!(
            decode("Zm9-"),
            Err(Base64Error::Symbol(3)),
            "URL-safe alphabet"
        );
        assert_eq!(decode("Zm 9"), Err(Base64Error::Symbol(2)), "whitespace");
        assert_eq!(
            decode("Zg==Zm9v"),
            Err(Base64Error::Symbol(2)),
            "padding mid-stream"
        );
        assert_eq!(
            decode("Z==="),
            Err(Base64Error::Symbol(1)),
            "three padding symbols"
        );
    }

    #[test]
    fn every_byte_value_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        for length in 0..all.len() {
            let slice = &all[..length];
            assert_eq!(decode(&encode(slice)).expect("decode"), slice);
        }
    }
}
