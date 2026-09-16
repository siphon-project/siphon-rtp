//! Turn a completed DTLS handshake's exported keying material into a keyed [`SecureLeg`] — the same
//! secure leg the SDES path yields, so all downstream media handling (relay, HA, conference) is
//! shared.

use rtc_dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rtc_dtls::state::State;
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

use crate::identity::Fingerprint;
use crate::DtlsError;

/// The RFC 5764 §4.2 exporter label for DTLS-SRTP keying material.
const DTLS_SRTP_LABEL: &str = "EXTRACTOR-dtls_srtp";
/// `AES_CM_128_HMAC_SHA1_80` master key length (RFC 3711).
const SRTP_KEY_LEN: usize = 16;
/// `AES_CM_128_HMAC_SHA1_80` master salt length (RFC 3711).
const SRTP_SALT_LEN: usize = 14;
/// The keying block is a write key + write salt for *each* direction (RFC 5764 §4.2): 2·(16+14) = 60.
const KEYING_LEN: usize = 2 * (SRTP_KEY_LEN + SRTP_SALT_LEN);

/// Which side of the DTLS handshake this leg plays, chosen from the SDP `a=setup` (RFC 5763 §5). The
/// engine is [`DtlsRole::Server`] when it answered `a=setup:passive`, so the remote (a browser) is the
/// DTLS client and initiates the handshake into the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// This side initiates the handshake (`a=setup:active`).
    Client,
    /// This side waits for the handshake (`a=setup:passive`).
    Server,
}

/// A completed handshake's SRTP keying material, split for this leg's direction.
///
/// Held rather than turned straight into a [`SecureLeg`] so the caller decides when to build the leg,
/// and so the secret never needs a second copy.
pub struct SrtpKeying {
    local: SrtpKeyMaterial,
    remote: SrtpKeyMaterial,
}

impl SrtpKeying {
    /// Build the keyed secure leg: `local` protects egress, `remote` unprotects ingress.
    #[must_use]
    pub fn into_secure_leg(self) -> SecureLeg {
        SecureLeg::new(&self.local, &self.remote)
    }

    /// Build a keyed secure leg **without consuming the session that derived it**.
    ///
    /// The driver needs this: a session must stay alive after it keys so it can answer a peer that
    /// repeats its final flight (RFC 6347 §4.2.4), so the leg cannot be obtained by consuming it.
    /// Each call builds a fresh leg with its own SRTP contexts — callers hand exactly one to the
    /// owning actor, because two legs on one key would each start their own rollover counter
    /// (RFC 3711 §3.3.1).
    #[must_use]
    pub fn to_secure_leg(&self) -> SecureLeg {
        SecureLeg::new(&self.local, &self.remote)
    }
}

/// Authenticate the peer by matching its certificate to the fingerprint it signalled (RFC 5763 §5).
///
/// A mismatch means the media is not from the party we negotiated with, so the leg is rejected before
/// any key is derived from the association.
pub(crate) fn verify_peer(state: &State, expected: &Fingerprint) -> Result<(), DtlsError> {
    let peer_certificate = state
        .peer_certificates
        .first()
        .ok_or(DtlsError::MissingPeerCertificate)?;
    if expected.verify(peer_certificate) {
        Ok(())
    } else {
        Err(DtlsError::FingerprintMismatch)
    }
}

/// Export RFC 5764 §4.2 keying material from a completed handshake and split it for `role`.
pub(crate) fn derive_keying(state: &State, role: DtlsRole) -> Result<SrtpKeying, DtlsError> {
    // RFC 5764 §4.1.2: the negotiated profile must be one `SecureLeg` implements.
    if state.srtp_protection_profile() != SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 {
        return Err(DtlsError::UnsupportedProfile);
    }
    let keying = state
        .export_keying_material(DTLS_SRTP_LABEL, &[], KEYING_LEN)
        .map_err(|error| DtlsError::KeyExport(error.to_string()))?;
    let (local, remote) = split_keying(keying.as_ref(), role)?;
    Ok(SrtpKeying { local, remote })
}

/// Split the RFC 5764 §4.2 keying block into this leg's `(local, remote)` SRTP key material.
///
/// The block is laid out `client_write_key | server_write_key | client_write_salt | server_write_salt`
/// (RFC 5764 §4.2). `SecureLeg` encrypts outbound with `local` and decrypts inbound with `remote`, so
/// `local` is *our* write key and `remote` is the *peer's* write key — which of the two client/server
/// halves that is depends on our DTLS role.
fn split_keying(
    keying: &[u8],
    role: DtlsRole,
) -> Result<(SrtpKeyMaterial, SrtpKeyMaterial), DtlsError> {
    if keying.len() != KEYING_LEN {
        return Err(DtlsError::KeyExport(format!(
            "expected {KEYING_LEN} keying bytes, got {}",
            keying.len()
        )));
    }
    let client_key = &keying[0..SRTP_KEY_LEN];
    let server_key = &keying[SRTP_KEY_LEN..2 * SRTP_KEY_LEN];
    let salts = &keying[2 * SRTP_KEY_LEN..];
    let client_salt = &salts[0..SRTP_SALT_LEN];
    let server_salt = &salts[SRTP_SALT_LEN..2 * SRTP_SALT_LEN];

    let material = |key: &[u8], salt: &[u8]| -> Result<SrtpKeyMaterial, DtlsError> {
        let mut inline = [0u8; SRTP_KEY_LEN + SRTP_SALT_LEN];
        inline[..SRTP_KEY_LEN].copy_from_slice(key);
        inline[SRTP_KEY_LEN..].copy_from_slice(salt);
        SrtpKeyMaterial::from_inline_bytes(&inline)
            .map_err(|error| DtlsError::KeyExport(error.to_string()))
    };

    // local = our write key; remote = the peer's write key.
    match role {
        DtlsRole::Server => Ok((
            material(server_key, server_salt)?,
            material(client_key, client_salt)?,
        )),
        DtlsRole::Client => Ok((
            material(client_key, client_salt)?,
            material(server_key, server_salt)?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keying_maps_role_to_write_keys() {
        // A recognisable block: client key 0x11.., server key 0x22.., client salt 0x33.., server 0x44.
        let mut keying = Vec::with_capacity(KEYING_LEN);
        keying.extend(std::iter::repeat_n(0x11, SRTP_KEY_LEN));
        keying.extend(std::iter::repeat_n(0x22, SRTP_KEY_LEN));
        keying.extend(std::iter::repeat_n(0x33, SRTP_SALT_LEN));
        keying.extend(std::iter::repeat_n(0x44, SRTP_SALT_LEN));

        // As the server our write key is the *server* half; the peer writes with the client half.
        let (local, remote) = split_keying(&keying, DtlsRole::Server).expect("server split");
        assert_eq!(
            local.master_key[0], 0x22,
            "server writes with the server key"
        );
        assert_eq!(local.master_salt[0], 0x44, "and the server salt");
        assert_eq!(remote.master_key[0], 0x11, "and reads the client's");
        assert_eq!(remote.master_salt[0], 0x33, "with the client salt");

        // As the client the halves swap.
        let (local, remote) = split_keying(&keying, DtlsRole::Client).expect("client split");
        assert_eq!(
            local.master_key[0], 0x11,
            "client writes with the client key"
        );
        assert_eq!(remote.master_key[0], 0x22, "and reads the server's");
    }

    #[test]
    fn split_keying_rejects_a_short_block() {
        let short = vec![0u8; KEYING_LEN - 1];
        assert!(matches!(
            split_keying(&short, DtlsRole::Server),
            Err(DtlsError::KeyExport(_))
        ));
    }
}
