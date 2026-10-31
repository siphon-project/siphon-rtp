//! SRTCP protection of the MCPTT floor stream: `AEAD_AES_128_GCM` (RFC 7714) keyed per seat or leg
//! with the floor keys the controller supplies (3GPP TS 33.180 §9.4.1: RTCP protection is required
//! between the UE and the server for floor control; §9.4.8: the profile).
//!
//! The key exchange (MIKEY-SAKKE in TS 33.180 §9.4.6) belongs to the controller; this module only
//! applies the resulting master keys. It is shared by the forwarding room's floor stream
//! ([`crate::forward`]) and a two-party call's ([`crate::call_floor`]), so both enforce the same
//! admission rule:
//!
//! * a keyed stream accepts nothing but a packet that authenticates under a held key (a plaintext
//!   packet, an unknown MKI, a failed tag and a replay are all dropped, counted and logged);
//! * the reply address latches only from an *authenticated* packet, so an unauthenticated datagram
//!   from the signalled host cannot pin the stream's destination (docs/security-and-nat.md §4,
//!   layer 5h);
//! * an unkeyed stream behaves exactly as before.
//!
//! The audio stream's RTCP is never protected with these keys: it is end to end under the media key.

use std::net::SocketAddr;

use siphon_rtp_datapath::RxPacket;
use siphon_rtp_proto::{FloorKey, FLOOR_SALT_LEN};
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};
use siphon_rtp_srtp::SrtpError;

use crate::ingress::{Refusal, RefusalContext, RefusalLog};
use crate::reply_latch::{OpaqueLatch, ReplyLatch};

/// Convert the controller's floor keys into master keys: a 12-octet salt is the 96-bit salt of
/// RFC 7714 §12 (zero-extended to the RFC 3711 §4.3.1 PRF input), a 14-octet one is used as is.
///
/// # Errors
/// The reason, for a key or salt of the wrong length or two keys sharing an MKI.
pub fn master_keys(keys: &[FloorKey]) -> Result<Vec<FloorMasterKey>, String> {
    let mut converted = Vec::with_capacity(keys.len());
    for key in keys {
        key.validate().map_err(|error| error.to_string())?;
        let master_key: [u8; 16] = key
            .key
            .as_slice()
            .try_into()
            .map_err(|_| "floor key is not 16 octets".to_string())?;
        let master = if key.salt.len() == FLOOR_SALT_LEN {
            let salt: [u8; FLOOR_SALT_LEN] = key
                .salt
                .as_slice()
                .try_into()
                .map_err(|_| "floor salt is not 12 octets".to_string())?;
            FloorMasterKey::from_salt_96(key.mki, master_key, &salt)
        } else {
            FloorMasterKey {
                mki: key.mki,
                master_key,
                master_salt: key
                    .salt
                    .as_slice()
                    .try_into()
                    .map_err(|_| "floor salt is not 14 octets".to_string())?,
            }
        };
        converted.push(master);
    }
    // Build the context once so a duplicate MKI is refused before anything is allocated.
    if !converted.is_empty() {
        SrtcpGcmContext::new(&converted).map_err(|error| format!("floor_keys: {error}"))?;
    }
    Ok(converted)
}

/// The SRTCP state of one keyed floor stream: the GCM context, the key set it was built from (for an
/// HA snapshot) and the scratch the plaintext is opened into.
pub(crate) struct FloorProtection {
    context: SrtcpGcmContext,
    /// The key set last applied, oldest first (at most the newest two).
    keys: Vec<FloorMasterKey>,
    /// Plaintext of the packet just opened; reused, so no allocation per packet once warm.
    plain: Vec<u8>,
}

impl FloorProtection {
    /// A context over `keys`, or `None` for an empty set (an unkeyed stream) or one the SRTP layer
    /// refuses (callers validate with [`master_keys`] first).
    pub(crate) fn new(keys: &[FloorMasterKey]) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }
        let context = SrtcpGcmContext::new(keys).ok()?;
        Some(Self {
            context,
            keys: kept(keys),
            plain: Vec::with_capacity(crate::app_events::MAX_APP_DATAGRAM),
        })
    }

    /// Replace the key set (keeps the send index and the replay state of an unchanged key).
    ///
    /// # Errors
    /// The SRTP layer's refusal; the held set is then untouched.
    pub(crate) fn replace_keys(&mut self, keys: &[FloorMasterKey]) -> Result<(), SrtpError> {
        self.context.replace_keys(keys)?;
        self.keys = kept(keys);
        Ok(())
    }

    /// The key set in force, oldest first; the last protects outgoing packets.
    #[must_use]
    pub(crate) fn keys(&self) -> &[FloorMasterKey] {
        &self.keys
    }

    /// The next outgoing SRTCP index, for an HA snapshot (RFC 7714 §9.4: never reuse an IV).
    #[must_use]
    pub(crate) fn send_index(&self) -> u32 {
        self.context.send_index()
    }

    /// Resume after an HA failover: the outgoing index starts at `index` (RFC 7714 §9.4: the
    /// caller has added the margin that keeps it past anything the primary sent), and the receive
    /// side refuses what the checkpoint had already seen (RFC 3711 §3.3.2).
    pub(crate) fn resume(&mut self, index: u32, received: &[(u32, u32)]) {
        self.context.set_send_index(index);
        for &(mki, highest) in received {
            self.context.resume_received(mki, highest);
        }
    }

    /// The highest index that authenticated under each held key, for an HA snapshot.
    #[must_use]
    pub(crate) fn received_indices(&self) -> Vec<(u32, u32)> {
        self.context.received_indices()
    }

    /// Verify and decrypt `wire` (RFC 7714 §9; TS 33.180 §9.4.1) into the scratch.
    pub(crate) fn open(&mut self, wire: &[u8]) -> Result<&[u8], SrtpError> {
        self.context.unprotect(wire, &mut self.plain)?;
        Ok(&self.plain)
    }

    /// Protect `rtcp` into `out`, encrypted (E=1, RFC 7714 §9.2) under the newest key.
    ///
    /// # Errors
    /// The SRTP layer's refusal, such as an exhausted index.
    pub(crate) fn seal(&mut self, rtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        self.context.protect(rtcp, true, out)
    }
}

fn kept(keys: &[FloorMasterKey]) -> Vec<FloorMasterKey> {
    keys[keys
        .len()
        .saturating_sub(siphon_rtp_srtp::srtcp_gcm::MAX_KEYS)..]
        .to_vec()
}

/// Why a floor datagram was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloorDrop {
    /// The reply latch holds another source (docs/security-and-nat.md §4 layer 5h).
    Latch,
    /// A keyed stream got a packet that did not authenticate under a held key.
    Unauthenticated,
}

/// Admit one floor datagram that already passed the layer-2 source gate: authenticate it when the
/// stream is keyed, then run the learn-once latch. Returns the datagram's APP-bearing RTCP (the
/// plaintext when keyed) and the destination the latch learned, if any.
///
/// The latch is consulted for an already-pinned *different* source before the packet is opened (so a
/// foreign datagram never spends an anti-replay slot, RFC 3711 §3.3.2) and committed only after the
/// packet authenticated.
pub(crate) fn admit<'a>(
    protection: &'a mut Option<FloorProtection>,
    latch: &mut OpaqueLatch,
    refusals: &RefusalLog,
    context: RefusalContext<'_>,
    packet: &'a RxPacket,
) -> Result<(&'a [u8], Option<SocketAddr>), FloorDrop> {
    let data: &[u8] = match protection {
        None => &packet.data,
        Some(protection) => {
            if latch
                .latched()
                .is_some_and(|latched| latched != packet.source)
            {
                refusals.log(Refusal::NewSource, context);
                return Err(FloorDrop::Latch);
            }
            // TS 33.180 §9.4.1: unprotected or unverifiable floor RTCP never reaches the controller.
            match protection.open(&packet.data) {
                Ok(plain) => plain,
                Err(error) => {
                    match Refusal::of_unprotect(&error) {
                        Some(refusal) => refusals.log(refusal, context),
                        // A replay is routine (a duplicated datagram): trace only.
                        None => tracing::debug!(
                            target: "siphon_rtp::media",
                            component = context.component,
                            call_id = context.call_id,
                            source = %context.source,
                            %error,
                            "floor SRTCP datagram dropped"
                        ),
                    }
                    return Err(FloorDrop::Unauthenticated);
                }
            }
        }
    };
    match latch.admit(packet.source) {
        ReplyLatch::Reject => {
            refusals.log(Refusal::NewSource, context);
            Err(FloorDrop::Latch)
        }
        ReplyLatch::Accept(destination) => Ok((data, destination)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn key(mki: u32, salt_length: usize) -> FloorKey {
        FloorKey {
            mki,
            key: vec![0x11; 16],
            salt: vec![0x22; salt_length],
        }
    }

    #[test]
    fn a_96_bit_salt_is_zero_extended_and_a_112_bit_salt_is_used_as_is() {
        let short = master_keys(&[key(1, 12)]).unwrap();
        assert_eq!(short[0].master_salt[..12], [0x22; 12]);
        assert_eq!(short[0].master_salt[12..], [0, 0]);
        let long = master_keys(&[key(1, 14)]).unwrap();
        assert_eq!(long[0].master_salt, [0x22; 14]);
        assert_eq!(long[0].mki, 1);
    }

    #[test]
    fn a_bad_length_or_a_shared_mki_is_refused() {
        assert!(master_keys(&[key(1, 13)]).is_err());
        let error = master_keys(&[key(5, 12), key(5, 12)]).unwrap_err();
        assert!(error.contains("duplicate MKI"), "{error}");
        assert!(master_keys(&[]).unwrap().is_empty());
    }

    #[test]
    fn protection_keeps_the_newest_two_keys_and_the_send_index_across_a_rekey() {
        let keys = master_keys(&[key(1, 12), key(2, 12), key(3, 12)]).unwrap();
        let mut protection = FloorProtection::new(&keys).unwrap();
        assert_eq!(protection.keys().len(), 2);
        assert_eq!(protection.keys()[1].mki, 3);
        let rtcp = [
            0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0, 0, 0, 0,
        ];
        let mut out = Vec::new();
        protection.seal(&rtcp, &mut out).unwrap();
        protection.seal(&rtcp, &mut out).unwrap();
        assert_eq!(protection.send_index(), 2);
        protection
            .replace_keys(&master_keys(&[key(3, 12), key(4, 12)]).unwrap())
            .unwrap();
        assert_eq!(protection.send_index(), 2, "the index only moves forward");
        assert!(FloorProtection::new(&[]).is_none());
    }
}
