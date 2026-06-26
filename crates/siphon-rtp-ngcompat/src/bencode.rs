//! Bencode (the rtpengine NG wire encoding).
//!
//! rtpengine's NG control protocol frames each message as `<cookie> <bencode-dict>` over UDP. This
//! module is the bencode half: a [`Value`] model plus [`decode`]/[`encode`]. Dicts use a
//! [`BTreeMap`] so keys serialize in the canonical sorted order rtpengine expects, and strings are
//! byte strings (SDP bodies and crypto keys are not guaranteed UTF-8).

use std::collections::BTreeMap;

/// A bencode value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `i<n>e` — a signed integer.
    Integer(i64),
    /// `<len>:<bytes>` — a byte string.
    Bytes(Vec<u8>),
    /// `l...e` — a list.
    List(Vec<Value>),
    /// `d...e` — a dictionary keyed by byte strings (canonical sorted order on encode).
    Dict(BTreeMap<Vec<u8>, Value>),
}

/// Errors from bencode parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BencodeError {
    /// Input ended before the value was complete.
    #[error("unexpected end of input")]
    UnexpectedEnd,
    /// A byte that does not start a valid value.
    #[error("unexpected byte {0:#04x} at offset {1}")]
    Unexpected(u8, usize),
    /// A malformed integer (`ie`, leading zero, lone `-`, overflow).
    #[error("malformed integer at offset {0}")]
    BadInteger(usize),
    /// A byte-string length that is malformed or runs past the input.
    #[error("malformed byte-string length at offset {0}")]
    BadLength(usize),
    /// Trailing bytes after a complete top-level value.
    #[error("{0} trailing bytes after value")]
    TrailingBytes(usize),
    /// A dict key that is not a byte string, or keys out of order.
    #[error("malformed dict at offset {0}")]
    BadDict(usize),
}

impl Value {
    /// Convenience: a UTF-8 byte-string value.
    #[must_use]
    pub fn string(text: &str) -> Self {
        Value::Bytes(text.as_bytes().to_vec())
    }

    /// Borrow as a dict.
    #[must_use]
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(dict) => Some(dict),
            _ => None,
        }
    }

    /// Borrow as a byte string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// Borrow as a UTF-8 string (None if not bytes or not valid UTF-8).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|bytes| std::str::from_utf8(bytes).ok())
    }

    /// As an integer.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Borrow as a list.
    #[must_use]
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(items) => Some(items),
            _ => None,
        }
    }

    /// Look up a key in a dict value.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict().and_then(|dict| dict.get(key.as_bytes()))
    }
}

/// Decode exactly one bencode value, rejecting trailing bytes.
pub fn decode(input: &[u8]) -> Result<Value, BencodeError> {
    let mut parser = Parser { input, pos: 0 };
    let value = parser.parse_value()?;
    if parser.pos != input.len() {
        return Err(BencodeError::TrailingBytes(input.len() - parser.pos));
    }
    Ok(value)
}

/// Decode one value from the front of `input`, returning it and the byte offset consumed (used by
/// the NG framing, which has a cookie before the dict).
pub fn decode_prefix(input: &[u8]) -> Result<(Value, usize), BencodeError> {
    let mut parser = Parser { input, pos: 0 };
    let value = parser.parse_value()?;
    Ok((value, parser.pos))
}

/// Encode a value to bencode bytes.
#[must_use]
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Integer(number) => {
            out.push(b'i');
            out.extend_from_slice(number.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(bytes) => {
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(bytes);
        }
        Value::List(items) => {
            out.push(b'l');
            for item in items {
                encode_into(item, out);
            }
            out.push(b'e');
        }
        Value::Dict(dict) => {
            out.push(b'd');
            for (key, item) in dict {
                encode_into(&Value::Bytes(key.clone()), out);
                encode_into(item, out);
            }
            out.push(b'e');
        }
    }
}

/// Whether `text` is a canonical bencode integer body (digits only, no leading zeros, no `-0`/`-`).
fn is_canonical_integer(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return false; // leading zero
    }
    !(digits == "0" && text.starts_with('-')) // reject "-0"
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Result<u8, BencodeError> {
        self.input.get(self.pos).copied().ok_or(BencodeError::UnexpectedEnd)
    }

    fn parse_value(&mut self) -> Result<Value, BencodeError> {
        match self.peek()? {
            b'i' => self.parse_integer(),
            b'l' => self.parse_list(),
            b'd' => self.parse_dict(),
            b'0'..=b'9' => self.parse_bytes(),
            other => Err(BencodeError::Unexpected(other, self.pos)),
        }
    }

    fn parse_integer(&mut self) -> Result<Value, BencodeError> {
        let start = self.pos;
        self.pos += 1; // 'i'
        let end = self.find(b'e').ok_or(BencodeError::UnexpectedEnd)?;
        let text = std::str::from_utf8(&self.input[self.pos..end])
            .map_err(|_| BencodeError::BadInteger(start))?;
        if !is_canonical_integer(text) {
            return Err(BencodeError::BadInteger(start));
        }
        let number = text.parse::<i64>().map_err(|_| BencodeError::BadInteger(start))?;
        self.pos = end + 1; // past 'e'
        Ok(Value::Integer(number))
    }

    fn parse_bytes(&mut self) -> Result<Value, BencodeError> {
        let start = self.pos;
        let colon = self.find(b':').ok_or(BencodeError::BadLength(start))?;
        let length_text =
            std::str::from_utf8(&self.input[self.pos..colon]).map_err(|_| BencodeError::BadLength(start))?;
        // No leading zeros in the length (canonical), and it must be all digits.
        if length_text.is_empty()
            || (length_text.starts_with('0') && length_text.len() > 1)
            || !length_text.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(BencodeError::BadLength(start));
        }
        let length: usize = length_text.parse().map_err(|_| BencodeError::BadLength(start))?;
        let data_start = colon + 1;
        let data_end = data_start.checked_add(length).ok_or(BencodeError::BadLength(start))?;
        if data_end > self.input.len() {
            return Err(BencodeError::UnexpectedEnd);
        }
        self.pos = data_end;
        Ok(Value::Bytes(self.input[data_start..data_end].to_vec()))
    }

    fn parse_list(&mut self) -> Result<Value, BencodeError> {
        self.pos += 1; // 'l'
        let mut items = Vec::new();
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(Value::List(items));
            }
            items.push(self.parse_value()?);
        }
    }

    fn parse_dict(&mut self) -> Result<Value, BencodeError> {
        let start = self.pos;
        self.pos += 1; // 'd'
        let mut dict = BTreeMap::new();
        let mut previous: Option<Vec<u8>> = None;
        loop {
            if self.peek()? == b'e' {
                self.pos += 1;
                return Ok(Value::Dict(dict));
            }
            let key = match self.parse_value()? {
                Value::Bytes(bytes) => bytes,
                _ => return Err(BencodeError::BadDict(start)),
            };
            // Keys must be strictly increasing (canonical bencode).
            if let Some(previous) = &previous {
                if &key <= previous {
                    return Err(BencodeError::BadDict(start));
                }
            }
            previous = Some(key.clone());
            let value = self.parse_value()?;
            dict.insert(key, value);
        }
    }

    fn find(&self, byte: u8) -> Option<usize> {
        self.input[self.pos..]
            .iter()
            .position(|&candidate| candidate == byte)
            .map(|offset| self.pos + offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(entries: &[(&str, Value)]) -> Value {
        let mut map = BTreeMap::new();
        for (key, value) in entries {
            map.insert(key.as_bytes().to_vec(), value.clone());
        }
        Value::Dict(map)
    }

    fn roundtrip(value: &Value) {
        let encoded = encode(value);
        let decoded = decode(&encoded).expect("decode");
        assert_eq!(&decoded, value, "roundtrip via {:?}", String::from_utf8_lossy(&encoded));
    }

    #[test]
    fn integers() {
        assert_eq!(decode(b"i42e").unwrap(), Value::Integer(42));
        assert_eq!(decode(b"i-7e").unwrap(), Value::Integer(-7));
        assert_eq!(decode(b"i0e").unwrap(), Value::Integer(0));
        assert_eq!(encode(&Value::Integer(-7)), b"i-7e");
        // Canonical rejections.
        assert!(matches!(decode(b"i03e"), Err(BencodeError::BadInteger(_))));
        assert!(matches!(decode(b"i-0e"), Err(BencodeError::BadInteger(_))));
        assert!(matches!(decode(b"ie"), Err(BencodeError::BadInteger(_))));
    }

    #[test]
    fn byte_strings() {
        assert_eq!(decode(b"4:spam").unwrap(), Value::Bytes(b"spam".to_vec()));
        assert_eq!(decode(b"0:").unwrap(), Value::Bytes(Vec::new()));
        assert_eq!(encode(&Value::string("spam")), b"4:spam");
        // Binary content survives.
        assert_eq!(decode(b"3:\x00\xff\x80").unwrap(), Value::Bytes(vec![0, 0xFF, 0x80]));
        assert!(matches!(decode(b"5:spam"), Err(BencodeError::UnexpectedEnd)));
        assert!(matches!(decode(b"01:a"), Err(BencodeError::BadLength(_))));
    }

    #[test]
    fn lists_and_dicts() {
        roundtrip(&Value::List(vec![Value::Integer(1), Value::string("a")]));
        roundtrip(&dict(&[
            ("command", Value::string("offer")),
            ("call-id", Value::string("abc@host")),
        ]));
        assert_eq!(decode(b"le").unwrap(), Value::List(Vec::new()));
        assert_eq!(decode(b"de").unwrap(), Value::Dict(BTreeMap::new()));
    }

    #[test]
    fn dict_encodes_keys_in_sorted_order() {
        // Insert out of order; encode must be canonical (sorted).
        let value = dict(&[
            ("z", Value::Integer(1)),
            ("a", Value::Integer(2)),
            ("m", Value::Integer(3)),
        ]);
        assert_eq!(encode(&value), b"d1:ai2e1:mi3e1:zi1ee");
    }

    #[test]
    fn dict_rejects_unsorted_or_duplicate_keys_on_decode() {
        assert!(matches!(decode(b"d1:zi1e1:ai2ee"), Err(BencodeError::BadDict(_))));
        assert!(matches!(decode(b"d1:ai1e1:ai2ee"), Err(BencodeError::BadDict(_))));
    }

    #[test]
    fn rejects_trailing_bytes_and_garbage() {
        assert!(matches!(decode(b"i1ei2e"), Err(BencodeError::TrailingBytes(3))));
        assert!(matches!(decode(b"x"), Err(BencodeError::Unexpected(b'x', 0))));
    }

    #[test]
    fn decode_prefix_returns_consumed_length() {
        // For NG framing: a dict followed by other bytes.
        let (value, consumed) = decode_prefix(b"d3:fooi1eeTRAILING").expect("prefix");
        assert_eq!(value.get("foo").and_then(Value::as_integer), Some(1));
        assert_eq!(consumed, "d3:fooi1ee".len());
    }

    #[test]
    fn realistic_ng_offer_dict_roundtrips() {
        let value = dict(&[
            ("command", Value::string("offer")),
            ("call-id", Value::string("1-2-3@1.2.3.4")),
            ("from-tag", Value::string("aBcD")),
            ("ICE", Value::string("remove")),
            ("transport-protocol", Value::string("RTP/AVP")),
            ("flags", Value::List(vec![Value::string("trust-address"), Value::string("symmetric")])),
            ("sdp", Value::string("v=0\r\nc=IN IP4 203.0.113.5\r\n")),
        ]);
        roundtrip(&value);
    }
}
