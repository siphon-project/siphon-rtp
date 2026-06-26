//! TLS material for the `turns:` (TURN-over-TLS) listener.
//!
//! Pure-Rust rustls on the ring backend (the project's sanctioned TLS stack). The PEM files are read
//! once at startup — blocking `std::fs` is fine here because it runs before the async runtime serves
//! traffic, never on the reactor.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::TurnError;

/// Install the ring crypto provider as the process default. Idempotent in effect: a second call
/// (after another component installed one) is ignored. Call once before building an acceptor.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a [`TlsAcceptor`] from a PEM certificate-chain file and a PEM private-key file. The crypto
/// provider must already be installed ([`install_crypto_provider`]).
pub fn acceptor_from_pem(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, TurnError> {
    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        return Err(TurnError::Tls(format!(
            "no certificates in {}",
            cert_path.display()
        )));
    }
    let key = load_key(key_path)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| TurnError::Tls(error.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TurnError> {
    let bytes = std::fs::read(path)
        .map_err(|error| TurnError::Tls(format!("read {}: {error}", path.display())))?;
    rustls_pemfile::certs(&mut bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TurnError::Tls(format!("{}: {error}", path.display())))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TurnError> {
    let bytes = std::fs::read(path)
        .map_err(|error| TurnError::Tls(format!("read {}: {error}", path.display())))?;
    rustls_pemfile::private_key(&mut bytes.as_slice())
        .map_err(|error| TurnError::Tls(format!("{}: {error}", path.display())))?
        .ok_or_else(|| TurnError::Tls(format!("no private key in {}", path.display())))
}
