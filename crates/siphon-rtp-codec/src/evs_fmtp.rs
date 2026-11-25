//! The `a=fmtp` parameters of the EVS media type (3GPP TS 26.445 Annex A.3, registered with IANA as
//! `audio/EVS`), as one peer wrote them.
//!
//! Not behind the `evs` feature: a node that only relays EVS still reads these parameters off the
//! SDP, and the decoder is built from them when the feature is on. The syntax is a `;` separated
//! list of `name=value`.
//!
//! - A parameter the registration does not define is ignored (RFC 4566 §6: an `a=fmtp` is opaque
//!   to everything but the codec's own parser, and a newer peer may send more).
//! - A parameter it does define with a value it does not permit is **refused**, never defaulted:
//!   [`EvsParams::parse`] returns the parameter's name and what is wrong, so the payload type is
//!   not selected on a guess.
//! - A parameter written twice is refused too: which of the two the peer meant is not knowable.
//!
//! Every field is `None` when the peer did not write the parameter, because the registration gives
//! each its own default, and an answer returns the parameters as offered.
//!
//! Which direction a parameter belongs to follows the spec the parameters are attached to, the
//! **peer's** SDP: `bw-send` / `br-send` are what the peer will send us, `bw-recv` / `br-recv` and
//! `dtx-recv` / `ch-aw-recv` what it will accept, and a bare `bw` / `br` / `dtx` stands for both.

use std::fmt;

/// An audio bandwidth an EVS stream can carry, narrowest first (the order the registration's `bw`
/// ranges are written in).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvsBandwidth {
    /// Narrowband, 4 kHz audio.
    Narrowband,
    /// Wideband, 8 kHz.
    Wideband,
    /// Super-wideband, 16 kHz.
    SuperWideband,
    /// Fullband, 20 kHz.
    Fullband,
}

impl EvsBandwidth {
    /// The registration's spelling.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Narrowband => "nb",
            Self::Wideband => "wb",
            Self::SuperWideband => "swb",
            Self::Fullband => "fb",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        [
            Self::Narrowband,
            Self::Wideband,
            Self::SuperWideband,
            Self::Fullband,
        ]
        .into_iter()
        .find(|bandwidth| token.eq_ignore_ascii_case(bandwidth.token()))
    }

    /// The output sampling rate that carries this bandwidth, 8, 16, 32 or 48 kHz.
    #[must_use]
    pub const fn sample_rate_hz(self) -> u32 {
        match self {
            Self::Narrowband => 8_000,
            Self::Wideband => 16_000,
            Self::SuperWideband => 32_000,
            Self::Fullband => 48_000,
        }
    }
}

/// A `bw`, `bw-send` or `bw-recv` value: one bandwidth, or a range of them, narrowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthRange {
    /// The narrowest bandwidth permitted.
    pub low: EvsBandwidth,
    /// The widest bandwidth permitted.
    pub high: EvsBandwidth,
}

impl BandwidthRange {
    fn parse(value: &str) -> Option<Self> {
        let (low, high) = match value.split_once('-') {
            Some((low, high)) => (
                EvsBandwidth::from_token(low)?,
                EvsBandwidth::from_token(high)?,
            ),
            None => {
                let single = EvsBandwidth::from_token(value)?;
                (single, single)
            }
        };
        (low <= high).then_some(Self { low, high })
    }
}

impl fmt::Display for BandwidthRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low == self.high {
            formatter.write_str(self.low.token())
        } else {
            write!(formatter, "{}-{}", self.low.token(), self.high.token())
        }
    }
}

/// The EVS primary bit rates a `br` value can name, in bit/s. 5.9 kbit/s is the source-controlled
/// variable bit rate mode (an average, carried by the 2.8 kbit/s frames and the 2.4 kbit/s SID).
pub const BITRATES: [u32; 12] = [
    5_900, 7_200, 8_000, 9_600, 13_200, 16_400, 24_400, 32_000, 48_000, 64_000, 96_000, 128_000,
];

/// A `br`, `br-send` or `br-recv` value: one EVS bit rate, or a range of them, in bit/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitrateRange {
    /// The lowest bit rate permitted, one of [`BITRATES`].
    pub low: u32,
    /// The highest bit rate permitted, one of [`BITRATES`].
    pub high: u32,
}

/// `13.2` or `8` (kbit/s) as bit/s, with at most three decimals and nothing else.
fn parse_kilobits(token: &str) -> Option<u32> {
    let (whole, fraction) = token.split_once('.').unwrap_or((token, ""));
    let digits = |text: &str| text.bytes().all(|byte| byte.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) || fraction.len() > 3 {
        return None;
    }
    let whole: u32 = whole.parse().ok()?;
    let mut thousandths = 0u32;
    for position in 0..3 {
        let digit = fraction
            .as_bytes()
            .get(position)
            .map_or(0, |byte| u32::from(byte - b'0'));
        thousandths = thousandths * 10 + digit;
    }
    whole.checked_mul(1000)?.checked_add(thousandths)
}

impl BitrateRange {
    fn parse(value: &str) -> Option<Self> {
        let (low, high) = match value.split_once('-') {
            Some((low, high)) => (parse_kilobits(low)?, parse_kilobits(high)?),
            None => {
                let single = parse_kilobits(value)?;
                (single, single)
            }
        };
        let named = |rate: u32| BITRATES.contains(&rate);
        (named(low) && named(high) && low <= high).then_some(Self { low, high })
    }
}

/// Kilobits with the decimals the registration writes: `5.9`, `13.2`, `8`, `128`.
fn kilobits(rate: u32) -> String {
    match (rate / 1000, rate % 1000) {
        (whole, 0) => whole.to_string(),
        (whole, fraction) => format!("{whole}.{}", (fraction / 100)),
    }
}

impl fmt::Display for BitrateRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low == self.high {
            formatter.write_str(&kilobits(self.low))
        } else {
            write!(formatter, "{}-{}", kilobits(self.low), kilobits(self.high))
        }
    }
}

/// Why an EVS `a=fmtp` parameter was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvsFmtpError {
    /// A parameter the registration defines carries a value it does not permit for it.
    #[error("EVS fmtp parameter `{parameter}` has a value the registration does not permit")]
    BadValue {
        /// The parameter's name.
        parameter: &'static str,
    },
    /// A parameter the registration defines appears twice.
    #[error("EVS fmtp parameter `{parameter}` is written more than once")]
    Duplicate {
        /// The parameter's name.
        parameter: &'static str,
    },
}

impl EvsFmtpError {
    /// The refused parameter's name.
    #[must_use]
    pub const fn parameter(self) -> &'static str {
        match self {
            Self::BadValue { parameter } | Self::Duplicate { parameter } => parameter,
        }
    }
}

/// The `audio/EVS` parameters of one payload type, as the peer wrote them (3GPP TS 26.445 A.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvsParams {
    /// `hf-only`: "1" forbids the compact payload format, so every payload is header-full
    /// (TS 26.445 A.2.3.2); "0" or absent allows both (A.2.3.1).
    pub hf_only: Option<bool>,
    /// `evs-mode-switch`: the peer switches between the EVS primary and the AMR-WB interoperable
    /// modes. A decoder follows every switch regardless, so this only describes the peer.
    pub evs_mode_switch: Option<bool>,
    /// `dtx`: discontinuous transmission, for both directions.
    pub dtx: Option<bool>,
    /// `dtx-recv`: whether the peer wants DTX in what it receives.
    pub dtx_recv: Option<bool>,
    /// `br`: bit rates, for both directions.
    pub bitrate: Option<BitrateRange>,
    /// `br-send`: bit rates the peer sends.
    pub bitrate_send: Option<BitrateRange>,
    /// `br-recv`: bit rates the peer accepts.
    pub bitrate_recv: Option<BitrateRange>,
    /// `bw`: bandwidths, for both directions.
    pub bandwidth: Option<BandwidthRange>,
    /// `bw-send`: bandwidths the peer sends.
    pub bandwidth_send: Option<BandwidthRange>,
    /// `bw-recv`: bandwidths the peer accepts.
    pub bandwidth_recv: Option<BandwidthRange>,
    /// `cmr`: -1, 0 or 1, how the peer treats the codec mode request field of the header-full
    /// format.
    pub cmr: Option<i8>,
    /// `ch-aw-recv`: channel-aware mode in what the peer receives, -1 (off), 0 (default offset) or
    /// the partial copy offset 2, 3, 5 or 7.
    pub channel_aware_recv: Option<i8>,
    /// `mode-set`: the AMR-WB interoperable modes the peer uses, bit `n` for mode `n` (0 to 8).
    pub mode_set: Option<u16>,
    /// `max-red`: the largest redundancy the peer accepts, in milliseconds.
    pub max_red: Option<u16>,
    /// A parameter carried a value the registration does not permit; see [`Self::parse`]. The
    /// payload type is then not one the engine can promise to honour.
    pub malformed: bool,
}

/// The registration's parameter names, for the error and for [`EvsParams::to_fmtp`].
mod name {
    pub const HF_ONLY: &str = "hf-only";
    pub const EVS_MODE_SWITCH: &str = "evs-mode-switch";
    pub const DTX: &str = "dtx";
    pub const DTX_RECV: &str = "dtx-recv";
    pub const BR: &str = "br";
    pub const BR_SEND: &str = "br-send";
    pub const BR_RECV: &str = "br-recv";
    pub const BW: &str = "bw";
    pub const BW_SEND: &str = "bw-send";
    pub const BW_RECV: &str = "bw-recv";
    pub const CMR: &str = "cmr";
    pub const CH_AW_RECV: &str = "ch-aw-recv";
    pub const MODE_SET: &str = "mode-set";
    pub const MAX_RED: &str = "max-red";
}

fn parse_flag(value: &str) -> Option<bool> {
    match value {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn parse_mode_set(value: &str) -> Option<u16> {
    let mut mask = 0u16;
    for token in value.split(',') {
        let mode: u8 = token.trim().parse().ok()?;
        if mode > 8 {
            return None;
        }
        mask |= 1 << mode;
    }
    (mask != 0).then_some(mask)
}

/// Store `parsed` in `slot`, or say why not.
fn store<T>(
    slot: &mut Option<T>,
    parameter: &'static str,
    parsed: Option<T>,
) -> Result<(), EvsFmtpError> {
    let value = parsed.ok_or(EvsFmtpError::BadValue { parameter })?;
    if slot.replace(value).is_some() {
        return Err(EvsFmtpError::Duplicate { parameter });
    }
    Ok(())
}

impl EvsParams {
    /// Parse the parameters of an `a=fmtp:<pt> ...` line (the text after the payload type).
    ///
    /// # Errors
    /// [`EvsFmtpError`] naming the first parameter the registration defines whose value it does
    /// not permit, or that appears twice. Unknown parameters are skipped.
    pub fn parse(parameters: &str) -> Result<Self, EvsFmtpError> {
        let mut params = Self::default();
        for segment in parameters.split(';') {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            let (key, value) = match segment.split_once('=') {
                Some((key, value)) => (key.trim(), Some(value.trim())),
                None => (segment, None),
            };
            let key = key.to_ascii_lowercase();
            params.apply(&key, value)?;
        }
        Ok(params)
    }

    /// Take one `key[=value]` in.
    fn apply(&mut self, key: &str, value: Option<&str>) -> Result<(), EvsFmtpError> {
        // A known parameter without a value is as wrong as one with a bad value: the name picks
        // the parameter, so it is not skipped as unknown.
        let text = value.unwrap_or("");
        match key {
            name::HF_ONLY => store(&mut self.hf_only, name::HF_ONLY, parse_flag(text)),
            name::EVS_MODE_SWITCH => store(
                &mut self.evs_mode_switch,
                name::EVS_MODE_SWITCH,
                parse_flag(text),
            ),
            name::DTX => store(&mut self.dtx, name::DTX, parse_flag(text)),
            name::DTX_RECV => store(&mut self.dtx_recv, name::DTX_RECV, parse_flag(text)),
            name::BR => store(&mut self.bitrate, name::BR, BitrateRange::parse(text)),
            name::BR_SEND => store(
                &mut self.bitrate_send,
                name::BR_SEND,
                BitrateRange::parse(text),
            ),
            name::BR_RECV => store(
                &mut self.bitrate_recv,
                name::BR_RECV,
                BitrateRange::parse(text),
            ),
            name::BW => store(&mut self.bandwidth, name::BW, BandwidthRange::parse(text)),
            name::BW_SEND => store(
                &mut self.bandwidth_send,
                name::BW_SEND,
                BandwidthRange::parse(text),
            ),
            name::BW_RECV => store(
                &mut self.bandwidth_recv,
                name::BW_RECV,
                BandwidthRange::parse(text),
            ),
            name::CMR => store(
                &mut self.cmr,
                name::CMR,
                text.parse::<i8>().ok().filter(|cmr| (-1..=1).contains(cmr)),
            ),
            name::CH_AW_RECV => store(
                &mut self.channel_aware_recv,
                name::CH_AW_RECV,
                text.parse::<i8>()
                    .ok()
                    .filter(|offset| matches!(offset, -1 | 0 | 2 | 3 | 5 | 7)),
            ),
            name::MODE_SET => store(&mut self.mode_set, name::MODE_SET, parse_mode_set(text)),
            name::MAX_RED => store(&mut self.max_red, name::MAX_RED, text.parse::<u16>().ok()),
            _ => Ok(()),
        }
    }

    /// Whether every payload is header-full: `hf-only=1`.
    #[must_use]
    pub fn header_full_only(&self) -> bool {
        self.hf_only == Some(true)
    }

    /// The widest bandwidth the peer may send us: `bw-send`, else `bw`, else fullband (the
    /// registration's default is every bandwidth).
    #[must_use]
    pub fn send_bandwidth_ceiling(&self) -> EvsBandwidth {
        self.bandwidth_send
            .or(self.bandwidth)
            .map_or(EvsBandwidth::Fullband, |range| range.high)
    }

    /// Why the engine cannot carry this configuration, or `None` when it can.
    #[must_use]
    pub fn unsupported(&self) -> Option<&'static str> {
        self.malformed
            .then_some("an EVS fmtp parameter has a value the registration does not permit")
    }

    /// The parameters as an `a=fmtp` body, in a fixed order, so that [`Self::parse`] reads back
    /// what this wrote. The `malformed` mark has no spelling and is not written.
    #[must_use]
    pub fn to_fmtp(&self) -> String {
        let flag = |value: bool| if value { "1" } else { "0" };
        let mut parts: Vec<String> = Vec::new();
        let mut push = |parameter: &str, value: Option<String>| {
            if let Some(value) = value {
                parts.push(format!("{parameter}={value}"));
            }
        };
        push(name::HF_ONLY, self.hf_only.map(|value| flag(value).into()));
        push(
            name::EVS_MODE_SWITCH,
            self.evs_mode_switch.map(|value| flag(value).into()),
        );
        push(name::DTX, self.dtx.map(|value| flag(value).into()));
        push(
            name::DTX_RECV,
            self.dtx_recv.map(|value| flag(value).into()),
        );
        push(name::BR, self.bitrate.map(|value| value.to_string()));
        push(
            name::BR_SEND,
            self.bitrate_send.map(|value| value.to_string()),
        );
        push(
            name::BR_RECV,
            self.bitrate_recv.map(|value| value.to_string()),
        );
        push(name::BW, self.bandwidth.map(|value| value.to_string()));
        push(
            name::BW_SEND,
            self.bandwidth_send.map(|value| value.to_string()),
        );
        push(
            name::BW_RECV,
            self.bandwidth_recv.map(|value| value.to_string()),
        );
        push(name::CMR, self.cmr.map(|value| value.to_string()));
        push(
            name::CH_AW_RECV,
            self.channel_aware_recv.map(|value| value.to_string()),
        );
        push(
            name::MODE_SET,
            self.mode_set.map(|mask| {
                (0..=8u8)
                    .filter(|mode| mask & (1 << mode) != 0)
                    .map(|mode| mode.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            }),
        );
        push(name::MAX_RED, self.max_red.map(|value| value.to_string()));
        parts.join(";")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_parameters_of_a_volte_offer() {
        // 3GPP TS 26.114 Table A.3.1 style: the one the engine tests offer.
        let params = EvsParams::parse("br=5.9-24.4;bw=nb-swb;max-red=220").unwrap();
        assert_eq!(
            params.bitrate,
            Some(BitrateRange {
                low: 5_900,
                high: 24_400
            })
        );
        assert_eq!(
            params.bandwidth,
            Some(BandwidthRange {
                low: EvsBandwidth::Narrowband,
                high: EvsBandwidth::SuperWideband
            })
        );
        assert_eq!(params.max_red, Some(220));
        assert!(!params.header_full_only());
        assert!(!params.malformed);
    }

    #[test]
    fn parses_every_parameter_the_decoder_side_needs() {
        let params = EvsParams::parse(
            "hf-only=1; evs-mode-switch=1; dtx=0; dtx-recv=1; br-send=13.2; br-recv=7.2-32; \
             bw-send=wb; bw-recv=nb-fb; cmr=-1; ch-aw-recv=5; mode-set=0,2,8",
        )
        .unwrap();
        assert!(params.header_full_only());
        assert_eq!(params.evs_mode_switch, Some(true));
        assert_eq!(params.dtx, Some(false));
        assert_eq!(params.dtx_recv, Some(true));
        assert_eq!(
            params.bitrate_send,
            Some(BitrateRange {
                low: 13_200,
                high: 13_200
            })
        );
        assert_eq!(
            params.bitrate_recv,
            Some(BitrateRange {
                low: 7_200,
                high: 32_000
            })
        );
        assert_eq!(params.cmr, Some(-1));
        assert_eq!(params.channel_aware_recv, Some(5));
        assert_eq!(params.mode_set, Some(0b1_0000_0101));
        assert_eq!(params.send_bandwidth_ceiling(), EvsBandwidth::Wideband);
    }

    #[test]
    fn the_send_bandwidth_ceiling_falls_back_to_bw_and_then_fullband() {
        let both = EvsParams::parse("bw=nb-wb").unwrap();
        assert_eq!(both.send_bandwidth_ceiling(), EvsBandwidth::Wideband);
        let specific = EvsParams::parse("bw=nb-wb;bw-send=swb-fb;bw-recv=nb").unwrap();
        assert_eq!(specific.send_bandwidth_ceiling(), EvsBandwidth::Fullband);
        assert_eq!(
            EvsParams::default().send_bandwidth_ceiling(),
            EvsBandwidth::Fullband
        );
        assert_eq!(EvsBandwidth::Fullband.sample_rate_hz(), 48_000);
        assert_eq!(EvsBandwidth::Narrowband.sample_rate_hz(), 8_000);
    }

    #[test]
    fn unknown_parameters_are_ignored_and_names_are_case_insensitive() {
        let params = EvsParams::parse("Future-Thing=7;HF-ONLY=1;;flag-without-value").unwrap();
        assert!(params.header_full_only());
    }

    #[test]
    fn a_known_parameter_with_a_bad_value_is_refused_not_defaulted() {
        for (text, parameter) in [
            ("hf-only=2", "hf-only"),
            ("hf-only", "hf-only"),
            ("hf-only=", "hf-only"),
            ("evs-mode-switch=yes", "evs-mode-switch"),
            ("dtx=-1", "dtx"),
            ("dtx-recv=", "dtx-recv"),
            ("br=6.6", "br"),
            ("br=24.4-5.9", "br"),
            ("br-send=13.20x", "br-send"),
            ("br-recv=13.2000", "br-recv"),
            ("br=-", "br"),
            ("bw=ultra", "bw"),
            ("bw-send=fb-nb", "bw-send"),
            ("bw-recv=nb-", "bw-recv"),
            ("cmr=2", "cmr"),
            ("cmr=x", "cmr"),
            ("ch-aw-recv=4", "ch-aw-recv"),
            ("mode-set=9", "mode-set"),
            ("mode-set=", "mode-set"),
            ("mode-set=1,,2", "mode-set"),
            ("max-red=70000", "max-red"),
        ] {
            assert_eq!(
                EvsParams::parse(text),
                Err(EvsFmtpError::BadValue { parameter }),
                "{text}"
            );
        }
    }

    #[test]
    fn a_parameter_written_twice_is_refused() {
        let error = EvsParams::parse("bw=wb;bw=swb").unwrap_err();
        assert_eq!(error, EvsFmtpError::Duplicate { parameter: "bw" });
        assert_eq!(error.parameter(), "bw");
        assert!(error.to_string().contains("more than once"));
        assert!(EvsFmtpError::BadValue { parameter: "br" }
            .to_string()
            .contains("`br`"));
    }

    #[test]
    fn bit_rates_are_exact_not_floating_point() {
        assert_eq!(parse_kilobits("5.9"), Some(5_900));
        assert_eq!(parse_kilobits("13.2"), Some(13_200));
        assert_eq!(parse_kilobits("128"), Some(128_000));
        assert_eq!(parse_kilobits("24.400"), Some(24_400));
        assert_eq!(parse_kilobits(".5"), None);
        assert_eq!(parse_kilobits("1e3"), None);
        assert_eq!(parse_kilobits("4294968"), None, "overflow is refused");
    }

    #[test]
    fn the_malformed_mark_is_reported_as_unsupported() {
        assert!(EvsParams::default().unsupported().is_none());
        let params = EvsParams {
            malformed: true,
            ..EvsParams::default()
        };
        assert!(params.unsupported().is_some());
    }

    #[test]
    fn to_fmtp_is_read_back_by_parse() {
        for text in [
            "",
            "hf-only=1",
            "br=5.9-24.4;bw=nb-swb;max-red=220",
            "hf-only=0;evs-mode-switch=1;dtx=1;dtx-recv=0;br=13.2;br-send=8-32;br-recv=5.9;\
             bw=wb;bw-send=nb-fb;bw-recv=swb;cmr=0;ch-aw-recv=-1;mode-set=1,3,5;max-red=0",
        ] {
            let params = EvsParams::parse(text).unwrap();
            assert_eq!(
                EvsParams::parse(&params.to_fmtp()).unwrap(),
                params,
                "{text}"
            );
        }
    }

    proptest::proptest! {
        // Whatever the peer writes, the parser answers: Ok with canonical text that reads back
        // identically, or a typed refusal. It never panics.
        #[test]
        fn arbitrary_text_is_parsed_or_refused(text in "[ -~]{0,120}") {
            if let Ok(params) = EvsParams::parse(&text) {
                proptest::prop_assert_eq!(EvsParams::parse(&params.to_fmtp()), Ok(params));
            }
        }
    }
}
