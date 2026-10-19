//! What a received EVS frame is, identified by its size.
//!
//! Every EVS frame is 20 ms, so a bit count and a bit rate are the same information (`bits · 50`).
//! The set of legal sizes is closed: the EVS primary rates, the EVS SID, the AMR-WB interoperable
//! (IO) modes with their SID, and the empty NO_DATA frame. The reference decoder refuses any other
//! size before it reads a bit (TS 26.442 `lib_com/bitstream_fx.c`, `rate2EVSmode` /
//! `rate2AMRWB_IOmode`); [`FrameKind::from_bits`] is that table.

/// One of the EVS primary bit rates, in bit/s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimaryRate {
    /// 2.8 kbit/s, the PPP/NELP source-controlled VBR rate.
    Rate2800,
    /// 7.2 kbit/s.
    Rate7200,
    /// 8.0 kbit/s.
    Rate8000,
    /// 9.6 kbit/s.
    Rate9600,
    /// 13.2 kbit/s, the usual VoLTE rate and the only one with a channel-aware mode.
    Rate13200,
    /// 16.4 kbit/s.
    Rate16400,
    /// 24.4 kbit/s.
    Rate24400,
    /// 32 kbit/s.
    Rate32000,
    /// 48 kbit/s.
    Rate48000,
    /// 64 kbit/s.
    Rate64000,
    /// 96 kbit/s.
    Rate96000,
    /// 128 kbit/s.
    Rate128000,
}

impl PrimaryRate {
    /// Every primary rate, lowest first.
    pub const ALL: [Self; 12] = [
        Self::Rate2800,
        Self::Rate7200,
        Self::Rate8000,
        Self::Rate9600,
        Self::Rate13200,
        Self::Rate16400,
        Self::Rate24400,
        Self::Rate32000,
        Self::Rate48000,
        Self::Rate64000,
        Self::Rate96000,
        Self::Rate128000,
    ];

    /// The bit rate in bit/s.
    #[must_use]
    pub const fn bits_per_second(self) -> u32 {
        match self {
            Self::Rate2800 => 2_800,
            Self::Rate7200 => 7_200,
            Self::Rate8000 => 8_000,
            Self::Rate9600 => 9_600,
            Self::Rate13200 => 13_200,
            Self::Rate16400 => 16_400,
            Self::Rate24400 => 24_400,
            Self::Rate32000 => 32_000,
            Self::Rate48000 => 48_000,
            Self::Rate64000 => 64_000,
            Self::Rate96000 => 96_000,
            Self::Rate128000 => 128_000,
        }
    }
}

/// One of the AMR-WB interoperable modes, numbered as AMR-WB numbers them (0 = 6.60 kbit/s
/// … 8 = 23.85 kbit/s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AmrWbIoMode(u8);

impl AmrWbIoMode {
    /// Speech bits per frame for modes 0..=8 (the AMR-WB frame sizes, TS 26.201).
    const BITS: [u16; 9] = [132, 177, 253, 285, 317, 365, 397, 461, 477];

    /// The mode number, 0..=8.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    /// Speech bits in one frame of this mode.
    #[must_use]
    pub const fn bits(self) -> u16 {
        Self::BITS[self.0 as usize]
    }
}

/// What a frame of a given size carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// An EVS primary-mode speech or audio frame.
    Primary(PrimaryRate),
    /// The EVS primary silence descriptor, 2.4 kbit/s.
    PrimarySid,
    /// An AMR-WB interoperable speech frame.
    AmrWbIo(AmrWbIoMode),
    /// The AMR-WB interoperable silence descriptor, 1.75 kbit/s.
    AmrWbIoSid,
    /// No frame was sent (DTX), or none arrived.
    NoData,
}

impl FrameKind {
    /// The largest legal frame, 128 kbit/s × 20 ms (the reference's `MAX_BITS_PER_FRAME`).
    pub const MAX_BITS: usize = 2560;

    /// Identify a frame by its size in bits, or `None` for a size no EVS frame has.
    #[must_use]
    pub fn from_bits(bits: usize) -> Option<Self> {
        let kind = match bits {
            0 => Self::NoData,
            35 => Self::AmrWbIoSid,
            48 => Self::PrimarySid,
            _ => {
                if let Some(rate) = PrimaryRate::ALL
                    .into_iter()
                    .find(|rate| rate.bits_per_second() as usize == bits * 50)
                {
                    Self::Primary(rate)
                } else {
                    let mode = AmrWbIoMode::BITS
                        .iter()
                        .position(|&size| size as usize == bits)?;
                    // `position` over a 9-entry table, so the index always fits a u8.
                    Self::AmrWbIo(AmrWbIoMode(mode as u8))
                }
            }
        };
        Some(kind)
    }

    /// Bits in a frame of this kind.
    #[must_use]
    pub const fn bits(self) -> usize {
        match self {
            Self::Primary(rate) => (rate.bits_per_second() / 50) as usize,
            Self::PrimarySid => 48,
            Self::AmrWbIo(mode) => mode.bits() as usize,
            Self::AmrWbIoSid => 35,
            Self::NoData => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_primary_rate_is_identified_by_its_frame_size() {
        let sizes = [56, 144, 160, 192, 264, 328, 488, 640, 960, 1280, 1920, 2560];
        for (rate, bits) in PrimaryRate::ALL.into_iter().zip(sizes) {
            assert_eq!(
                FrameKind::from_bits(bits),
                Some(FrameKind::Primary(rate)),
                "{bits}"
            );
            assert_eq!(FrameKind::Primary(rate).bits(), bits);
        }
    }

    #[test]
    fn every_amr_wb_io_mode_is_identified_by_its_frame_size() {
        for (index, &bits) in AmrWbIoMode::BITS.iter().enumerate() {
            let kind = FrameKind::from_bits(bits as usize);
            assert_eq!(kind, Some(FrameKind::AmrWbIo(AmrWbIoMode(index as u8))));
            assert_eq!(kind.map(FrameKind::bits), Some(bits as usize));
        }
    }

    #[test]
    fn silence_descriptors_and_no_data_have_their_own_sizes() {
        assert_eq!(FrameKind::from_bits(48), Some(FrameKind::PrimarySid));
        assert_eq!(FrameKind::from_bits(35), Some(FrameKind::AmrWbIoSid));
        assert_eq!(FrameKind::from_bits(0), Some(FrameKind::NoData));
    }

    #[test]
    fn a_size_no_frame_has_is_refused() {
        for bits in [1, 34, 36, 47, 49, 100, 263, 265, 2559, 2561, 5000] {
            assert_eq!(FrameKind::from_bits(bits), None, "{bits}");
        }
    }

    #[test]
    fn the_largest_frame_is_the_128_kbit_rate() {
        assert_eq!(
            FrameKind::Primary(PrimaryRate::Rate128000).bits(),
            FrameKind::MAX_BITS
        );
    }
}
