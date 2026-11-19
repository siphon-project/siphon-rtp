//! The H.264 `profile-level-id` of RFC 6184 §8.1: three octets, `profile_idc`, `profile-iop` (the
//! constraint_set flags of H.264 §7.4.2.1.1) and `level_idc`.
//!
//! RFC 6184 §8.2.2 splits it in two for offer/answer. The profile part (the "default sub-profile",
//! `profile_idc` with most of `profile-iop`) MUST be used symmetrically: an answer keeps it or
//! removes the payload type. The level part is changeable. Matching a seat to a room therefore
//! compares sub-profiles ([`ProfileLevel::sub_profile`], which knows the Table 5 spellings that name
//! one sub-profile) and orders levels ([`ProfileLevel::level`], which knows the ad hoc Level 1b).

use std::fmt;

/// `profile_idc` of the three profiles whose Level 1b is `level_idc` 11 with constraint_set3
/// (RFC 6184 §8.1): Baseline, Main, Extended.
const BASELINE: u8 = 0x42;
const MAIN: u8 = 0x4d;
const EXTENDED: u8 = 0x58;

/// constraint_set3_flag, bit 4 of `profile-iop`: part of the level for the three profiles above.
const CONSTRAINT_SET3: u8 = 0x10;

/// `level_idc` of Level 1b in every profile other than Baseline, Main and Extended.
const LEVEL_1B_OTHER_PROFILES: u8 = 9;

/// `level_idc` that, with constraint_set3, is Level 1b in Baseline, Main and Extended.
const LEVEL_1_1: u8 = 11;

/// A parsed `profile-level-id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileLevel {
    pub profile_idc: u8,
    pub profile_iop: u8,
    pub level_idc: u8,
}

/// The default sub-profile of a `profile-level-id`: what two spellings must share to be one
/// configuration (RFC 6184 §8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubProfile {
    ConstrainedBaseline,
    Baseline,
    Main,
    Extended,
    /// Any combination outside Table 5, compared exactly (the Level 1b bit aside).
    Exact {
        profile_idc: u8,
        profile_iop: u8,
    },
}

/// An H.264 level, ordered. Level 1b sits between Level 1 and Level 1.1 (RFC 6184 §8.2.2 note).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Level(u16);

impl Level {
    /// Ten times the level number; Level 1b is 105.
    const ONE_B: u16 = 105;

    fn is_1b(self) -> bool {
        self.0 == Self::ONE_B
    }
}

impl fmt::Display for Level {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_1b() {
            return formatter.write_str("1b");
        }
        let (whole, tenth) = (self.0 / 100, self.0 / 10 % 10);
        if tenth == 0 {
            write!(formatter, "{whole}")
        } else {
            write!(formatter, "{whole}.{tenth}")
        }
    }
}

impl ProfileLevel {
    /// Parse the six hexadecimal digits of a `profile-level-id` (RFC 6184 §8.1, "base16").
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.len() != 6 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let octet = |at: usize| u8::from_str_radix(value.get(at..at + 2)?, 16).ok();
        Some(Self {
            profile_idc: octet(0)?,
            profile_iop: octet(2)?,
            level_idc: octet(4)?,
        })
    }

    /// Whether constraint_set3 is part of the level here (Baseline, Main, Extended).
    fn level_in_constraint_set3(self) -> bool {
        matches!(self.profile_idc, BASELINE | MAIN | EXTENDED)
    }

    /// The default sub-profile, Table 5 of RFC 6184 §8.1 folding the spellings of Constrained
    /// Baseline, Baseline, Main and Extended together.
    #[must_use]
    pub fn sub_profile(self) -> SubProfile {
        let iop = if self.level_in_constraint_set3() {
            self.profile_iop & !CONSTRAINT_SET3
        } else {
            self.profile_iop
        };
        // Every Table 5 row has the low four bits of profile-iop clear.
        if iop & 0x0f == 0 {
            let (set0, set1, set2) = (iop & 0x80 != 0, iop & 0x40 != 0, iop & 0x20 != 0);
            match self.profile_idc {
                BASELINE if set1 => return SubProfile::ConstrainedBaseline,
                BASELINE => return SubProfile::Baseline,
                MAIN if set0 => return SubProfile::ConstrainedBaseline,
                MAIN if !set2 => return SubProfile::Main,
                EXTENDED if set0 && set1 => return SubProfile::ConstrainedBaseline,
                EXTENDED if set0 => return SubProfile::Baseline,
                EXTENDED if !set1 => return SubProfile::Extended,
                _ => {}
            }
        }
        SubProfile::Exact {
            profile_idc: self.profile_idc,
            profile_iop: iop,
        }
    }

    /// The default level (RFC 6184 §8.1), Level 1b recognised in both its encodings.
    #[must_use]
    pub fn level(self) -> Level {
        let one_b = if self.level_in_constraint_set3() {
            self.level_idc == LEVEL_1_1 && self.profile_iop & CONSTRAINT_SET3 != 0
        } else {
            self.level_idc == LEVEL_1B_OTHER_PROFILES
        };
        if one_b {
            Level(Level::ONE_B)
        } else {
            Level(u16::from(self.level_idc) * 10)
        }
    }

    /// This `profile-level-id` with its level part replaced by `level`, as lower-case hex: the
    /// profile octets stay (RFC 6184 §8.2.2 keeps them symmetric), Level 1b written the way this
    /// profile writes it.
    #[must_use]
    pub fn with_level(self, level: Level) -> String {
        let mut iop = self.profile_iop;
        let level_idc = if level.is_1b() {
            if self.level_in_constraint_set3() {
                iop |= CONSTRAINT_SET3;
                LEVEL_1_1
            } else {
                LEVEL_1B_OTHER_PROFILES
            }
        } else {
            // Levels are at most 6.2 (level_idc 62), so the quotient fits an octet.
            let level_idc = u8::try_from(level.0 / 10).unwrap_or(u8::MAX);
            if level_idc == LEVEL_1_1 && self.level_in_constraint_set3() {
                iop &= !CONSTRAINT_SET3; // otherwise it would read as Level 1b
            }
            level_idc
        };
        format!("{:02x}{iop:02x}{level_idc:02x}", self.profile_idc)
    }
}

/// The level a `max-recv-level` value names (RFC 6184 §8.1): four hexadecimal digits, `profile-iop`
/// then `level_idc`. Level 1b is `level_idc` 11 with bit 4 of the octet before it set, or 9 with
/// it clear, whatever the profile.
#[must_use]
pub fn max_recv_level(value: &str) -> Option<Level> {
    let value = value.trim();
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let profile_iop = u8::from_str_radix(value.get(0..2)?, 16).ok()?;
    let level_idc = u8::from_str_radix(value.get(2..4)?, 16).ok()?;
    let set3 = profile_iop & CONSTRAINT_SET3 != 0;
    let one_b = (level_idc == LEVEL_1_1 && set3) || (level_idc == LEVEL_1B_OTHER_PROFILES && !set3);
    Some(if one_b {
        Level(Level::ONE_B)
    } else {
        Level(u16::from(level_idc) * 10)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(hex: &str) -> ProfileLevel {
        ProfileLevel::parse(hex).unwrap()
    }

    #[test]
    fn parses_the_three_octets_in_either_case() {
        let value = parsed("640C1F");
        assert_eq!(
            (value.profile_idc, value.profile_iop, value.level_idc),
            (0x64, 0x0c, 0x1f)
        );
        assert_eq!(parsed("640c1f"), value);
    }

    #[test]
    fn a_value_that_is_not_six_hex_digits_is_refused() {
        for bad in ["", "640c", "640c1f00", "64 c1f", "zz0c1f", "+40c1f"] {
            assert!(ProfileLevel::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn table_5_spellings_of_one_sub_profile_are_the_same_sub_profile() {
        // RFC 6184 §8.1 Table 5: Constrained Baseline is 42 x1xx0000, 4D 1xxx0000 and 58 11xx0000.
        let constrained_baseline = ["42e01f", "42c01f", "424015", "4d801f", "58c01f", "42f00b"];
        for spelling in constrained_baseline {
            assert_eq!(
                parsed(spelling).sub_profile(),
                parsed("42e01f").sub_profile(),
                "{spelling}"
            );
        }
        // Baseline is 42 x0xx0000 and 58 10xx0000.
        for spelling in ["42001f", "42801f", "42a01f", "58801f"] {
            assert_eq!(
                parsed(spelling).sub_profile(),
                parsed("42001f").sub_profile(),
                "{spelling}"
            );
        }
        // Main is 4D 0x0x0000; Extended is 58 00xx0000.
        assert_eq!(
            parsed("4d401f").sub_profile(),
            parsed("4d001f").sub_profile()
        );
        assert_eq!(
            parsed("58201f").sub_profile(),
            parsed("58001f").sub_profile()
        );
    }

    #[test]
    fn different_sub_profiles_differ() {
        let distinct = [
            "42e01f", "42001f", "4d001f", "58001f", "64001f", "640c1f", "6e001f",
        ];
        for (index, left) in distinct.iter().enumerate() {
            for right in &distinct[index + 1..] {
                assert_ne!(
                    parsed(left).sub_profile(),
                    parsed(right).sub_profile(),
                    "{left} vs {right}"
                );
            }
        }
    }

    #[test]
    fn a_combination_outside_table_5_compares_exactly() {
        // 4D with constraint_set2 and not set0 is not a Table 5 row.
        assert_ne!(
            parsed("4d201f").sub_profile(),
            parsed("4d001f").sub_profile()
        );
        assert_eq!(
            parsed("4d201f").sub_profile(),
            parsed("4d2028").sub_profile()
        );
    }

    #[test]
    fn the_level_is_level_idc_over_ten_with_level_1b_between_1_and_1_1() {
        assert!(parsed("640c1f").level() < parsed("640c28").level());
        assert_eq!(parsed("640c1f").level(), parsed("42e01f").level());
        // Level 1b: level_idc 11 with constraint_set3 for Baseline, Main and Extended...
        let one_b = parsed("42f00b").level();
        assert!(parsed("42e00a").level() < one_b && one_b < parsed("42e00b").level());
        // ...and level_idc 9 for the other profiles.
        assert_eq!(parsed("640009").level(), one_b);
        // constraint_set3 means Level 1b only at level_idc 11.
        assert_eq!(parsed("42f01f").level(), parsed("42e01f").level());
    }

    #[test]
    fn levels_are_named_as_h264_names_them() {
        assert_eq!(parsed("640c1f").level().to_string(), "3.1");
        assert_eq!(parsed("640c28").level().to_string(), "4");
        assert_eq!(parsed("42f00b").level().to_string(), "1b");
        assert_eq!(parsed("640009").level().to_string(), "1b");
    }

    #[test]
    fn writing_another_level_keeps_the_profile_octets() {
        assert_eq!(
            parsed("42c028").with_level(parsed("42e01f").level()),
            "42c01f"
        );
        assert_eq!(
            parsed("640c28").with_level(parsed("640c1f").level()),
            "640c1f"
        );
    }

    #[test]
    fn level_1b_is_written_in_the_encoding_of_the_profile() {
        let one_b = parsed("42f00b").level();
        assert_eq!(parsed("42e01f").with_level(one_b), "42f00b");
        assert_eq!(parsed("640c1f").with_level(one_b), "640c09");
        // Leaving 1b at level_idc 11 clears constraint_set3, or it would still read as 1b.
        assert_eq!(
            parsed("42f00b").with_level(parsed("42e00b").level()),
            "42e00b"
        );
    }

    #[test]
    fn max_recv_level_is_profile_iop_and_level_idc_with_its_own_level_1b_rule() {
        // RFC 6184 §8.1: Level 1b is level_idc 11 with bit 4 set, or level_idc 9 with it clear.
        assert_eq!(max_recv_level("0c28"), Some(parsed("640c28").level()));
        assert_eq!(max_recv_level("1F0B"), Some(parsed("42f00b").level()));
        assert_eq!(max_recv_level("0009"), Some(parsed("42f00b").level()));
        assert_eq!(max_recv_level("000b"), Some(parsed("42e00b").level()));
        for bad in ["28", "0c280", "0g28", ""] {
            assert_eq!(max_recv_level(bad), None, "{bad:?}");
        }
    }
}
