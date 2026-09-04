//! DiffServ code point (RFC 2474) for the media plane — the QoS marking every outbound media
//! datagram carries.
//!
//! A media relay's whole job is the real-time plane, so the packets it emits are marked **EF**
//! (Expedited Forwarding, DSCP 46 — RFC 3246) by default: RFC 4594 §4.1 assigns the *Telephony*
//! service class to EF, and that is what carrier and enterprise edges police voice on. This is the
//! same posture as Asterisk's `tos_audio=ef` (TOS byte 184) and rtpengine's `--tos`.
//!
//! The value here is the 6-bit DSCP; the wire field is the 8-bit IPv4 TOS byte / IPv6 Traffic Class
//! octet, which is `DSCP << 2` with the low two bits left to ECN (RFC 3168 — the relay never sets
//! them, so a marking never claims ECN capability the datapath does not implement).
//!
//! # Where this is applied
//! All three egress paths mark identically, so a call's marking does not depend on which datapath
//! happened to carry it:
//! - the userspace UDP relay, via `IP_TOS` / `IPV6_TCLASS` on each media socket;
//! - the AF_XDP TX frame builder, which writes the byte into the IPv4 header it constructs;
//! - the in-kernel XDP_TX fast path, which rewrites the byte and fixes the header checksum
//!   incrementally (RFC 1624).

use std::fmt;
use std::str::FromStr;

/// A 6-bit DiffServ code point (RFC 2474 §3), the marking applied to outbound media.
///
/// Construct from a well-known name ([`FromStr`]) or a raw value ([`Dscp::new`]). [`Dscp::BE`]
/// (0, best effort) means "do not mark" — the datapath then leaves the TOS byte alone rather than
/// explicitly writing zero, so an operator who marks upstream is not overwritten.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dscp(u8);

/// The DSCP field is 6 bits (RFC 2474 §3), so the largest legal code point.
const MAX_DSCP: u8 = 63;

impl Dscp {
    /// Best effort / CS0 (0) — the "no marking" value. See [`Dscp::is_marked`].
    pub const BE: Self = Self(0);
    /// Expedited Forwarding (46, RFC 3246); RFC 4594 §4.1 Telephony service class. The media default.
    pub const EF: Self = Self(46);
    /// Class Selector 3 (24) — the Cisco 12-class / Asterisk convention for call signalling.
    /// Media never uses this; it is here so an operator can express the same vocabulary everywhere.
    pub const CS3: Self = Self(24);
    /// VOICE-ADMIT (44, RFC 5865) — EF with an admission-controlled PHB, used by some IMS accesses.
    pub const VOICE_ADMIT: Self = Self(44);

    /// The DSCP applied to media when nothing is configured: [`EF`](Self::EF).
    pub const DEFAULT: Self = Self::EF;

    /// Wrap a raw 6-bit code point, or `None` if it does not fit the field (> 63).
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value > MAX_DSCP {
            None
        } else {
            Some(Self(value))
        }
    }

    /// The raw 6-bit code point.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// The 8-bit IPv4 TOS byte / IPv6 Traffic Class octet: `DSCP << 2` with ECN (RFC 3168) zero.
    ///
    /// This is the number an operator recognises from Asterisk's `tos_audio` — [`EF`](Self::EF)
    /// is `184`.
    #[must_use]
    pub const fn to_tos_byte(self) -> u8 {
        self.0 << 2
    }

    /// Whether this code point asks for a marking at all. [`BE`](Self::BE) does not: the datapath
    /// leaves the TOS byte untouched instead of writing an explicit zero.
    #[must_use]
    pub const fn is_marked(self) -> bool {
        self.0 != 0
    }
}

impl Default for Dscp {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why a string is not a DSCP.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum DscpParseError {
    /// Not a known name and not an integer.
    #[error("invalid DSCP value: {0} (expected a name such as EF, CS3, AF41, BE, or 0-63)")]
    Unknown(String),
    /// Parsed as an integer but wider than the 6-bit field.
    #[error("DSCP must be 0-63, got {0}")]
    OutOfRange(u16),
}

impl FromStr for Dscp {
    type Err = DscpParseError;

    /// Accepts the RFC 2474 / RFC 4594 pool-1 names (case-insensitive) or a raw `0`–`63`.
    ///
    /// The name table matches siphon-sip's `listen.dscp` so one vocabulary covers signalling and
    /// media; `VA` / `VOICE-ADMIT` (RFC 5865) is media-specific and additional.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let name = value.trim().to_ascii_uppercase();
        let code = match name.as_str() {
            "CS0" | "BE" => 0,
            "CS1" => 8,
            "AF11" => 10,
            "AF12" => 12,
            "AF13" => 14,
            "CS2" => 16,
            "AF21" => 18,
            "AF22" => 20,
            "AF23" => 22,
            "CS3" => 24,
            "AF31" => 26,
            "AF32" => 28,
            "AF33" => 30,
            "CS4" => 32,
            "AF41" => 34,
            "AF42" => 36,
            "AF43" => 38,
            "CS5" => 40,
            // RFC 5865 §4: VOICE-ADMIT, the capacity-admitted sibling of EF.
            "VA" | "VOICE-ADMIT" | "VOICE_ADMIT" => 44,
            "EF" => 46,
            "CS6" => 48,
            "CS7" => 56,
            _ => {
                // Parse wide, then range-check, so "200" reports OutOfRange rather than Unknown.
                let raw: u16 = name
                    .parse()
                    .map_err(|_| DscpParseError::Unknown(value.to_string()))?;
                if raw > u16::from(MAX_DSCP) {
                    return Err(DscpParseError::OutOfRange(raw));
                }
                raw as u8
            }
        };
        Ok(Self(code))
    }
}

impl fmt::Display for Dscp {
    /// The well-known name where one exists, else the raw code point.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0 => "BE",
            8 => "CS1",
            10 => "AF11",
            12 => "AF12",
            14 => "AF13",
            16 => "CS2",
            18 => "AF21",
            20 => "AF22",
            22 => "AF23",
            24 => "CS3",
            26 => "AF31",
            28 => "AF32",
            30 => "AF33",
            32 => "CS4",
            34 => "AF41",
            36 => "AF42",
            38 => "AF43",
            40 => "CS5",
            44 => "VOICE-ADMIT",
            46 => "EF",
            48 => "CS6",
            56 => "CS7",
            raw => return write!(formatter, "{raw}"),
        };
        formatter.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ef_is_the_media_default() {
        assert_eq!(Dscp::default(), Dscp::EF);
        assert_eq!(Dscp::EF.value(), 46);
    }

    #[test]
    fn ef_tos_byte_matches_the_asterisk_number() {
        // Asterisk `tos_audio=184` / `tos_audio=ef` — DSCP 46 << 2 (RFC 2474 §3, ECN bits zero).
        assert_eq!(Dscp::EF.to_tos_byte(), 184);
        assert_eq!(Dscp::CS3.to_tos_byte(), 96); // the siphon-sip signalling default
        assert_eq!(Dscp::VOICE_ADMIT.to_tos_byte(), 176);
        assert_eq!(Dscp::BE.to_tos_byte(), 0);
    }

    #[test]
    fn tos_byte_never_sets_the_ecn_bits() {
        for code in 0..=MAX_DSCP {
            let dscp = Dscp::new(code).expect("in range");
            assert_eq!(dscp.to_tos_byte() & 0b11, 0, "ECN bits set for DSCP {code}");
            assert_eq!(dscp.to_tos_byte() >> 2, code);
        }
    }

    #[test]
    fn new_rejects_values_wider_than_six_bits() {
        assert_eq!(Dscp::new(63).map(Dscp::value), Some(63));
        assert_eq!(Dscp::new(64), None);
        assert_eq!(Dscp::new(255), None);
    }

    #[test]
    fn only_be_is_unmarked() {
        assert!(!Dscp::BE.is_marked());
        assert!(Dscp::EF.is_marked());
        assert!(Dscp::new(1).expect("in range").is_marked());
    }

    #[test]
    fn parses_the_pool_one_names_case_insensitively() {
        let cases = [
            ("EF", 46),
            ("ef", 46),
            (" Ef ", 46),
            ("BE", 0),
            ("CS0", 0),
            ("CS1", 8),
            ("CS2", 16),
            ("CS3", 24),
            ("CS4", 32),
            ("CS5", 40),
            ("CS6", 48),
            ("CS7", 56),
            ("AF11", 10),
            ("AF12", 12),
            ("AF13", 14),
            ("AF21", 18),
            ("AF22", 20),
            ("AF23", 22),
            ("AF31", 26),
            ("AF32", 28),
            ("AF33", 30),
            ("AF41", 34),
            ("AF42", 36),
            ("AF43", 38),
            ("VA", 44),
            ("voice-admit", 44),
            ("VOICE_ADMIT", 44),
        ];
        for (text, expected) in cases {
            let parsed: Dscp = text.parse().unwrap_or_else(|_| panic!("{text} parses"));
            assert_eq!(parsed.value(), expected, "{text}");
        }
    }

    #[test]
    fn parses_raw_code_points() {
        assert_eq!("0".parse::<Dscp>().expect("zero"), Dscp::BE);
        assert_eq!("46".parse::<Dscp>().expect("ef"), Dscp::EF);
        assert_eq!("63".parse::<Dscp>().expect("max").value(), 63);
    }

    #[test]
    fn rejects_out_of_range_and_garbage() {
        assert_eq!(
            "64".parse::<Dscp>(),
            Err(DscpParseError::OutOfRange(64)),
            "64 is one past the 6-bit field"
        );
        assert_eq!("300".parse::<Dscp>(), Err(DscpParseError::OutOfRange(300)));
        assert_eq!(
            "EFF".parse::<Dscp>(),
            Err(DscpParseError::Unknown("EFF".to_string()))
        );
        assert_eq!(
            "".parse::<Dscp>(),
            Err(DscpParseError::Unknown(String::new()))
        );
        assert_eq!(
            "-1".parse::<Dscp>(),
            Err(DscpParseError::Unknown("-1".to_string()))
        );
    }

    #[test]
    fn display_round_trips_through_from_str() {
        for code in 0..=MAX_DSCP {
            let dscp = Dscp::new(code).expect("in range");
            let rendered = dscp.to_string();
            let reparsed: Dscp = rendered
                .parse()
                .unwrap_or_else(|_| panic!("{rendered} reparses"));
            assert_eq!(reparsed, dscp, "round trip failed for {code}");
        }
    }

    #[test]
    fn display_prefers_the_well_known_name() {
        assert_eq!(Dscp::EF.to_string(), "EF");
        assert_eq!(Dscp::BE.to_string(), "BE");
        assert_eq!(Dscp::CS3.to_string(), "CS3");
        assert_eq!(Dscp::VOICE_ADMIT.to_string(), "VOICE-ADMIT");
        assert_eq!(Dscp::new(45).expect("in range").to_string(), "45");
    }

    #[test]
    fn parse_errors_render_with_the_offending_value() {
        assert_eq!(
            DscpParseError::OutOfRange(99).to_string(),
            "DSCP must be 0-63, got 99"
        );
        assert!(DscpParseError::Unknown("nope".to_string())
            .to_string()
            .contains("nope"));
    }
}
