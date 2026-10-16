//! Ogg page writer (RFC 3533), std-only.
//!
//! Just enough of Ogg to carry one logical stream to a file: packets go in, framed pages come out.
//! No reader, no multiplexing, no packet that spans a page — a packet that does not fit on the
//! current page closes it first, which RFC 3533 permits and which keeps every page independently
//! decodable. That last property is what a recording relies on: a writer killed mid-stream leaves a
//! file playable up to its last complete page.

/// Length of the fixed part of a page header, before the segment table (RFC 3533 §6).
pub const PAGE_HEADER_LEN: usize = 27;

/// Most lacing values one page can carry (the segment count is one octet, RFC 3533 §6).
pub const MAX_SEGMENTS: usize = 255;

/// Header-type flag: this page begins the logical stream (RFC 3533 §6, `0x02`).
const FLAG_BEGINNING_OF_STREAM: u8 = 0x02;

/// Header-type flag: this page ends the logical stream (RFC 3533 §6, `0x04`).
const FLAG_END_OF_STREAM: u8 = 0x04;

/// Offset of the checksum field inside a page header (RFC 3533 §6).
const CRC_OFFSET: usize = 22;

/// The Ogg page checksum table: polynomial 0x04C11DB7, MSB-first (no reflection).
///
/// This is **not** the zlib CRC-32 (`siphon-rtp-stun`'s `crc32`): that one is reflected and
/// post-inverted, and a page checksummed with it is rejected by every Ogg decoder.
const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = (index as u32) << 24;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 0x8000_0000 != 0 {
                (value << 1) ^ 0x04C1_1DB7
            } else {
                value << 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

/// The Ogg page CRC of `bytes` (RFC 3533 §6): polynomial 0x04C11DB7, initial value 0, no
/// reflection, no final XOR. A page is checksummed with its own CRC field zeroed.
#[must_use]
pub fn ogg_crc(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |crc, &byte| {
        (crc << 8) ^ CRC_TABLE[usize::from(((crc >> 24) as u8) ^ byte)]
    })
}

/// A packet the writer cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OggError {
    /// The packet needs more lacing values than one page holds. Packets are never split across
    /// pages here, so anything at or above 255 × 255 octets is refused.
    #[error("packet of {0} bytes does not fit on one Ogg page")]
    PacketTooLarge(usize),
}

/// Lacing values a packet of `length` octets takes: one 255 per full segment, then a terminating
/// value below 255 — a zero when the length is an exact multiple (RFC 3533 §5).
const fn lacing_values(length: usize) -> usize {
    length / 255 + 1
}

/// Writes one logical Ogg stream as a sequence of pages.
///
/// The caller adds packets with the granule position each one completes at and decides when a page
/// closes ([`OggPageWriter::flush`]); a packet that would not fit closes the page on its own. The
/// first page written carries beginning-of-stream, and the caller marks the last.
#[derive(Debug)]
pub struct OggPageWriter {
    serial: u32,
    sequence: u32,
    lacing: Vec<u8>,
    body: Vec<u8>,
    packets: usize,
    granule: u64,
}

impl OggPageWriter {
    /// A writer for the logical stream `serial`, with room preallocated for a page of
    /// `body_capacity` octets so steady-state pages allocate nothing.
    #[must_use]
    pub fn new(serial: u32, body_capacity: usize) -> Self {
        Self {
            serial,
            sequence: 0,
            lacing: Vec::with_capacity(MAX_SEGMENTS),
            body: Vec::with_capacity(body_capacity),
            packets: 0,
            granule: 0,
        }
    }

    /// Packets completed on the page being built.
    #[must_use]
    pub fn packets_pending(&self) -> usize {
        self.packets
    }

    /// Pages written so far.
    #[must_use]
    pub fn pages_written(&self) -> u32 {
        self.sequence
    }

    /// Add a packet that completes at `granule`. If it does not fit on the open page, that page is
    /// written to `out` first (without end-of-stream).
    pub fn add_packet(
        &mut self,
        packet: &[u8],
        granule: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), OggError> {
        let needed = lacing_values(packet.len());
        if needed > MAX_SEGMENTS {
            return Err(OggError::PacketTooLarge(packet.len()));
        }
        if self.lacing.len() + needed > MAX_SEGMENTS {
            self.flush(false, out);
        }
        for _ in 0..packet.len() / 255 {
            self.lacing.push(255);
        }
        self.lacing.push((packet.len() % 255) as u8);
        self.body.extend_from_slice(packet);
        self.packets += 1;
        // RFC 3533 §6: the granule position of a page is that of the last packet completed on it.
        self.granule = granule;
        Ok(())
    }

    /// Write the open page to `out`, marking it end-of-stream if asked. Returns whether a page was
    /// written: an empty page is never emitted.
    pub fn flush(&mut self, end_of_stream: bool, out: &mut Vec<u8>) -> bool {
        if self.packets == 0 {
            return false;
        }
        let mut flags = 0;
        if self.sequence == 0 {
            flags |= FLAG_BEGINNING_OF_STREAM;
        }
        if end_of_stream {
            flags |= FLAG_END_OF_STREAM;
        }
        let start = out.len();
        out.extend_from_slice(b"OggS");
        out.push(0); // stream structure version (RFC 3533 §6)
        out.push(flags);
        out.extend_from_slice(&self.granule.to_le_bytes());
        out.extend_from_slice(&self.serial.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&[0; 4]); // CRC, filled in below over the zeroed field
        out.push(self.lacing.len() as u8);
        out.extend_from_slice(&self.lacing);
        out.extend_from_slice(&self.body);
        let crc = ogg_crc(&out[start..]);
        out[start + CRC_OFFSET..start + CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());

        self.sequence = self.sequence.wrapping_add(1);
        self.lacing.clear();
        self.body.clear();
        self.packets = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Ogg Opus file written by `opusenc` (opus-tools 0.2, libopusenc 0.3): a 2.5 s 440 Hz tone
    /// at 8 kHz, 16 kbit/s, serial 1234. A third party's pages, so a checksum bug of ours cannot
    /// also be in them.
    const OPUSENC_FIXTURE: &[u8] = include_bytes!("../tests/data/opusenc_440hz_8k_mono.opus");

    /// Split a file into pages by walking the headers.
    fn pages(file: &[u8]) -> Vec<&[u8]> {
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < file.len() {
            assert_eq!(&file[offset..offset + 4], b"OggS", "capture pattern");
            let segments = usize::from(file[offset + 26]);
            let body: usize = file[offset + PAGE_HEADER_LEN..offset + PAGE_HEADER_LEN + segments]
                .iter()
                .map(|&value| usize::from(value))
                .sum();
            let length = PAGE_HEADER_LEN + segments + body;
            pages.push(&file[offset..offset + length]);
            offset += length;
        }
        pages
    }

    fn checksum_of(page: &[u8]) -> u32 {
        let mut zeroed = page.to_vec();
        zeroed[CRC_OFFSET..CRC_OFFSET + 4].fill(0);
        ogg_crc(&zeroed)
    }

    #[test]
    fn the_crc_reproduces_every_page_checksum_a_third_party_wrote() {
        // The acceptance check for the checksum: an independent writer's pages, re-checksummed by
        // ours, give back every CRC field byte for byte. A round trip through our own reader could
        // not catch a wrong polynomial, because the reader would share it.
        let pages = pages(OPUSENC_FIXTURE);
        assert_eq!(pages.len(), 5, "OpusHead, OpusTags and three audio pages");
        for (index, page) in pages.iter().enumerate() {
            let stored = u32::from_le_bytes([
                page[CRC_OFFSET],
                page[CRC_OFFSET + 1],
                page[CRC_OFFSET + 2],
                page[CRC_OFFSET + 3],
            ]);
            assert_eq!(checksum_of(page), stored, "page {index}");
        }
    }

    #[test]
    fn the_crc_is_the_unreflected_ogg_crc_not_zlib() {
        // The standard check input. 0x89A1897F is the Ogg parameter set; zlib's reflected CRC-32
        // gives 0xCBF43926 for the same input and produces pages every decoder rejects.
        assert_eq!(ogg_crc(b"123456789"), 0x89A1_897F);
        assert_ne!(ogg_crc(b"123456789"), 0xCBF4_3926);
        assert_eq!(ogg_crc(b""), 0);
    }

    #[test]
    fn the_first_page_begins_the_stream_and_carries_the_header_fields() {
        let mut writer = OggPageWriter::new(0x0102_0304, 64);
        let mut out = Vec::new();
        writer.add_packet(b"hello", 0, &mut out).expect("fits");
        assert!(writer.flush(false, &mut out));
        assert_eq!(&out[..4], b"OggS");
        assert_eq!(out[4], 0, "version");
        assert_eq!(out[5], FLAG_BEGINNING_OF_STREAM);
        assert_eq!(&out[6..14], &0u64.to_le_bytes(), "granule");
        assert_eq!(&out[14..18], &0x0102_0304u32.to_le_bytes(), "serial");
        assert_eq!(&out[18..22], &0u32.to_le_bytes(), "sequence");
        assert_eq!(out[26], 1, "one segment");
        assert_eq!(out[27], 5, "lacing value = packet length");
        assert_eq!(&out[28..], b"hello");
        assert_eq!(
            u32::from_le_bytes([out[22], out[23], out[24], out[25]]),
            checksum_of(&out)
        );
    }

    #[test]
    fn later_pages_count_up_and_the_last_ends_the_stream() {
        let mut writer = OggPageWriter::new(7, 64);
        let mut out = Vec::new();
        writer.add_packet(b"a", 0, &mut out).expect("fits");
        writer.flush(false, &mut out);
        writer.add_packet(b"bb", 960, &mut out).expect("fits");
        writer.add_packet(b"ccc", 1920, &mut out).expect("fits");
        writer.flush(true, &mut out);
        let pages = pages(&out);
        assert_eq!(pages.len(), 2);
        let second = pages[1];
        assert_eq!(
            second[5], FLAG_END_OF_STREAM,
            "not beginning-of-stream again"
        );
        assert_eq!(
            &second[6..14],
            &1920u64.to_le_bytes(),
            "last completed packet"
        );
        assert_eq!(&second[18..22], &1u32.to_le_bytes(), "sequence 1");
        assert_eq!(&second[26..29], &[2, 2, 3], "two segments: 2 and 3 octets");
        assert_eq!(writer.pages_written(), 2);
    }

    #[test]
    fn lacing_encodes_a_multiple_of_255_with_a_terminating_zero() {
        // RFC 3533 §5: a packet whose length is an exact multiple of 255 ends with a zero lacing
        // value, or the reader would run it into the next packet.
        let mut writer = OggPageWriter::new(1, 1024);
        let mut out = Vec::new();
        writer.add_packet(&[0xAA; 510], 0, &mut out).expect("fits");
        writer.add_packet(&[0xBB; 256], 0, &mut out).expect("fits");
        writer.flush(false, &mut out);
        assert_eq!(out[26], 5);
        assert_eq!(&out[27..32], &[255, 255, 0, 255, 1]);
        assert_eq!(out.len(), PAGE_HEADER_LEN + 5 + 766);
    }

    #[test]
    fn a_packet_that_does_not_fit_closes_the_open_page_first() {
        // Packets never span pages, so every page holds only whole packets and decodes alone.
        let mut writer = OggPageWriter::new(1, 1024);
        let mut out = Vec::new();
        for granule in 0..254u64 {
            writer.add_packet(&[1], granule, &mut out).expect("fits");
        }
        assert!(out.is_empty(), "254 one-segment packets fit on one page");
        // Needs two lacing values; 254 + 2 > 255, so the open page is written first.
        writer.add_packet(&[2; 300], 999, &mut out).expect("fits");
        let first = pages(&out);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0][26], 254);
        assert_eq!(&first[0][6..14], &253u64.to_le_bytes());
        assert_eq!(writer.packets_pending(), 1);
    }

    #[test]
    fn a_packet_larger_than_a_page_is_refused_rather_than_split() {
        let mut writer = OggPageWriter::new(1, 0);
        let mut out = Vec::new();
        let packet = vec![0u8; 255 * 255];
        assert_eq!(
            writer.add_packet(&packet, 0, &mut out),
            Err(OggError::PacketTooLarge(255 * 255))
        );
        assert_eq!(writer.packets_pending(), 0, "nothing half-added");
        let largest = vec![0u8; 255 * 254 + 254];
        writer
            .add_packet(&largest, 0, &mut out)
            .expect("255 lacing values is the limit");
    }

    #[test]
    fn an_empty_page_is_never_written() {
        let mut writer = OggPageWriter::new(1, 0);
        let mut out = Vec::new();
        assert!(!writer.flush(true, &mut out));
        assert!(out.is_empty());
        assert_eq!(writer.pages_written(), 0);
    }

    #[test]
    fn display_names_the_refused_size() {
        assert_eq!(
            OggError::PacketTooLarge(70_000).to_string(),
            "packet of 70000 bytes does not fit on one Ogg page"
        );
    }
}
