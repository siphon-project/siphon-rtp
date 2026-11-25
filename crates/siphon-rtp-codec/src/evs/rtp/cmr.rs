//! The codec mode request (CMR) of the EVS RTP payload format, 3GPP TS 26.445 Annex A.2.2.1.1.
//!
//! The header-full format starts with an optional CMR octet: `H(1) T(3) D(4)`, `H` = 1. `T` says
//! what `D` asks for: a bit rate at one audio bandwidth (T = 0 narrowband, 2 wideband, 3
//! super-wideband, 4 fullband), an AMR-WB interoperable mode (T = 1), the channel-aware mode of
//! 13.2 kbit/s at wideband or super-wideband (T = 5, 6), or no request (the octet `0xFF`). The
//! rest of the code space is reserved or unused.
//!
//! A decoder acts on none of this, since a request is addressed to the encoder of the stream sent
//! back to the peer. It is parsed so a consumer that has an encoder can follow it. The table was
//! read against Wireshark's dissector, which labels every one of the 128 values.

use crate::evs::frame::{AmrWbIoMode, PrimaryRate};
use crate::evs_fmtp::EvsBandwidth;

/// The bit rate a primary-mode request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedRate {
    /// 5.9 kbit/s, the source-controlled variable bit rate mode (`D` = 0).
    SourceControlledVbr,
    /// One of the fixed primary rates, 7.2 kbit/s (`D` = 1) up to 128 kbit/s (`D` = 11).
    Fixed(PrimaryRate),
}

/// A codec mode request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmr {
    /// Send the EVS primary mode at this bandwidth and rate (`T` = 0, 2, 3, 4).
    Primary {
        /// The audio bandwidth asked for.
        bandwidth: EvsBandwidth,
        /// The bit rate asked for.
        rate: RequestedRate,
    },
    /// Send the AMR-WB interoperable mode (`T` = 1).
    AmrWbIo(AmrWbIoMode),
    /// Send the channel-aware mode of 13.2 kbit/s (`T` = 5 wideband, 6 super-wideband): `D` bit 2
    /// is the criticality (high or low) and bits 1 to 0 the partial copy offset 2, 3, 5 or 7.
    ChannelAware {
        /// Wideband or super-wideband.
        bandwidth: EvsBandwidth,
        /// The "H" (high) criticality setting rather than "L" (low).
        high_criticality: bool,
        /// The partial copy offset in frames: 2, 3, 5 or 7.
        offset: u8,
    },
    /// No request (`0xFF`).
    NoRequest,
    /// The 3-bit CMR field of the compact AMR-WB interoperable format (A.2.1.2), as sent. The
    /// reference software's `amrwb_4bit_cmr` table and Wireshark's dissector disagree on what
    /// values 4 to 6 mean, and a decoder does not act on it, so it is not interpreted.
    AmrWbIoCompact(u8),
    /// An octet whose `T` / `D` the specification reserves or leaves unused. A receiver ignores it.
    Unassigned(u8),
}

impl Cmr {
    /// Read a header-full CMR octet. The `H` bit is the caller's business: this reads `T` and `D`
    /// of any octet and never fails, because a value the table does not use is [`Self::Unassigned`].
    #[must_use]
    pub fn from_octet(octet: u8) -> Self {
        let selector = (octet >> 4) & 0x07;
        let value = octet & 0x0F;
        let primary = |bandwidth, lowest: u8| {
            let rate = match value {
                0 if lowest == 0 => Some(RequestedRate::SourceControlledVbr),
                index @ 1..=11 if index >= lowest => PrimaryRate::ALL
                    .get(usize::from(index))
                    .copied()
                    .map(RequestedRate::Fixed),
                _ => None,
            };
            rate.map_or(Self::Unassigned(octet), |rate| Self::Primary {
                bandwidth,
                rate,
            })
        };
        let channel_aware = |bandwidth| match value {
            0..=7 => Self::ChannelAware {
                bandwidth,
                high_criticality: value & 0x04 != 0,
                offset: [2, 3, 5, 7][usize::from(value & 0x03)],
            },
            _ => Self::Unassigned(octet),
        };
        match selector {
            0 => match value {
                // narrowband stops at 24.4 kbit/s
                0..=6 => primary(EvsBandwidth::Narrowband, 0),
                _ => Self::Unassigned(octet),
            },
            1 => AmrWbIoMode::from_index(value).map_or(Self::Unassigned(octet), Self::AmrWbIo),
            2 => primary(EvsBandwidth::Wideband, 0),
            // super-wideband starts at 9.6 kbit/s, fullband at 16.4 kbit/s
            3 => primary(EvsBandwidth::SuperWideband, 3),
            4 => primary(EvsBandwidth::Fullband, 5),
            5 => channel_aware(EvsBandwidth::Wideband),
            6 => channel_aware(EvsBandwidth::SuperWideband),
            _ if octet == 0xFF => Self::NoRequest,
            _ => Self::Unassigned(octet),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labelled(octet: u8) -> String {
        match Cmr::from_octet(octet) {
            Cmr::Primary { bandwidth, rate } => {
                let rate = match rate {
                    RequestedRate::SourceControlledVbr => "5.9 (VBR)".to_string(),
                    RequestedRate::Fixed(rate) => format!("{}", rate.bits_per_second()),
                };
                format!("{} {rate}", bandwidth.token())
            }
            Cmr::AmrWbIo(mode) => format!("io {}", mode.index()),
            Cmr::ChannelAware {
                bandwidth,
                high_criticality,
                offset,
            } => format!(
                "{} ca {} {offset}",
                bandwidth.token(),
                if high_criticality { "H" } else { "L" }
            ),
            Cmr::NoRequest => "none".into(),
            Cmr::AmrWbIoCompact(raw) => format!("compact {raw}"),
            Cmr::Unassigned(_) => "unassigned".into(),
        }
    }

    /// Values read off Wireshark's labels for the same octets (`CMR NB 13.2 kbps`, `CMR WB 5.9
    /// kbps (VBR)`, `CMR SWB 9.6 kbps`, `CMR FB 16.4 kbps`, `CMR AMR-WB IO 23.85 kbps (mode-set
    /// 8)`, `CMR WB 13.2 kbps CA-H-O5`, `CMR NO_REQ`).
    #[test]
    fn requests_read_as_wireshark_labels_them() {
        for (octet, expected) in [
            (0x80, "nb 5.9 (VBR)"),
            (0x84, "nb 13200"),
            (0x86, "nb 24400"),
            (0x90, "io 0"),
            (0x98, "io 8"),
            (0xA0, "wb 5.9 (VBR)"),
            (0xA4, "wb 13200"),
            (0xAB, "wb 128000"),
            (0xB3, "swb 9600"),
            (0xBB, "swb 128000"),
            (0xC5, "fb 16400"),
            (0xCB, "fb 128000"),
            (0xD0, "wb ca L 2"),
            (0xD3, "wb ca L 7"),
            (0xD6, "wb ca H 5"),
            (0xD7, "wb ca H 7"),
            (0xE0, "swb ca L 2"),
            (0xE5, "swb ca H 3"),
            (0xFF, "none"),
        ] {
            assert_eq!(labelled(octet), expected, "{octet:#04x}");
        }
    }

    #[test]
    fn every_value_wireshark_calls_unused_or_reserved_is_unassigned() {
        let used = |octet: u8| {
            let (selector, value) = ((octet >> 4) & 7, octet & 15);
            match selector {
                0 => value <= 6,
                1 => value <= 8,
                2 => value <= 11,
                3 => (3..=11).contains(&value),
                4 => (5..=11).contains(&value),
                5 | 6 => value <= 7,
                _ => octet == 0xFF,
            }
        };
        for octet in 0x80..=0xFFu8 {
            let unassigned = matches!(Cmr::from_octet(octet), Cmr::Unassigned(_));
            assert_eq!(unassigned, !used(octet), "{octet:#04x}");
        }
    }

    #[test]
    fn a_primary_request_maps_to_the_rate_table_by_its_index() {
        assert_eq!(
            Cmr::from_octet(0xA7),
            Cmr::Primary {
                bandwidth: EvsBandwidth::Wideband,
                rate: RequestedRate::Fixed(PrimaryRate::Rate32000)
            }
        );
    }
}
