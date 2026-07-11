//! TLS configuration support for WSS/HTTPS transport.
//!
//! Provides certificate and key validation for optional TLS on the JSON-RPC
//! server.  When both `tls_cert_path` and `tls_key_path` are set in
//! [`super::RpcConfig`], [`load_tls_config`] parses the PEM files and builds a
//! [`rustls::ServerConfig`] that can be used with a TLS acceptor.
//!
//! # Current status
//!
//! jsonrpsee's `ServerBuilder` does not natively accept a `rustls::ServerConfig`,
//! so full WSS transport requires either:
//!
//! 1. A TLS-terminating reverse proxy in front of the RPC server, **or**
//! 2. A custom `tokio-rustls` + `hyper` service that terminates TLS before
//!    handing the stream to jsonrpsee (planned for a future release).
//!
//! This module validates the TLS material at startup so misconfigured
//! certificates are caught early, even before the transport layer is wired.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

/// Errors that can occur during TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("tls_cert_path is set but tls_key_path is missing")]
    MissingKeyPath,
    #[error("tls_key_path is set but tls_cert_path is missing")]
    MissingCertPath,
    #[error("TLS certificate file not found: {0}")]
    CertFileNotFound(String),
    #[error("TLS key file not found: {0}")]
    KeyFileNotFound(String),
    #[error("failed to read TLS certificate file: {0}")]
    CertReadError(String),
    #[error("failed to read TLS key file: {0}")]
    KeyReadError(String),
    #[error("no valid certificates found in PEM file: {0}")]
    NoCertsFound(String),
    #[error("no valid private key found in PEM file: {0}")]
    NoKeyFound(String),
    #[error("failed to build TLS server configuration: {0}")]
    ServerConfigError(String),
}

/// Validated TLS configuration ready for use with a TLS acceptor.
#[derive(Debug)]
pub struct TlsConfig {
    /// Pre-built rustls [`ServerConfig`](rustls::ServerConfig).
    pub server_config: Arc<rustls::ServerConfig>,
}

/// Validate and load TLS configuration from PEM files.
///
/// * `(None, None)` → returns `Ok(None)` (TLS disabled).
/// * `(Some, Some)` → parses certs/key, returns `Ok(Some(TlsConfig))`.
/// * Mismatched → returns `Err`.
pub fn load_tls_config(
    cert_path: Option<&str>,
    key_path: Option<&str>,
) -> Result<Option<TlsConfig>, TlsConfigError> {
    match (cert_path, key_path) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(TlsConfigError::MissingKeyPath),
        (None, Some(_)) => Err(TlsConfigError::MissingCertPath),
        (Some(cert), Some(key)) => {
            let cert_p = Path::new(cert);
            let key_p = Path::new(key);

            if !cert_p.exists() {
                return Err(TlsConfigError::CertFileNotFound(cert.to_string()));
            }
            if !key_p.exists() {
                return Err(TlsConfigError::KeyFileNotFound(key.to_string()));
            }

            // Parse certificate chain.
            let cert_file =
                fs::File::open(cert_p).map_err(|e| TlsConfigError::CertReadError(e.to_string()))?;
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(cert_file)
                .collect::<Result<_, _>>()
                .map_err(|e| TlsConfigError::CertReadError(e.to_string()))?;
            if certs.is_empty() {
                return Err(TlsConfigError::NoCertsFound(cert.to_string()));
            }

            // Parse private key.
            let key_file =
                fs::File::open(key_p).map_err(|e| TlsConfigError::KeyReadError(e.to_string()))?;
            let private_key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(key_file)
                .map_err(|e| TlsConfigError::KeyReadError(e.to_string()))?;

            // Build and validate the ServerConfig.
            // Use an explicit ring provider (default-features = false means no
            // auto-detection; we must specify the provider explicitly).
            let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| TlsConfigError::ServerConfigError(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .map_err(|e| TlsConfigError::ServerConfigError(e.to_string()))?;

            Ok(Some(TlsConfig {
                server_config: Arc::new(server_config),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_disabled_by_default() {
        let result = load_tls_config(None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cert_without_key_is_error() {
        let err = load_tls_config(Some("cert.pem"), None).unwrap_err();
        assert!(
            matches!(err, TlsConfigError::MissingKeyPath),
            "expected MissingKeyPath, got: {err}",
        );
    }

    #[test]
    fn key_without_cert_is_error() {
        let err = load_tls_config(None, Some("key.pem")).unwrap_err();
        assert!(
            matches!(err, TlsConfigError::MissingCertPath),
            "expected MissingCertPath, got: {err}",
        );
    }

    #[test]
    fn missing_cert_file_is_error() {
        let err = load_tls_config(Some("/nonexistent/cert.pem"), Some("/nonexistent/key.pem"))
            .unwrap_err();
        assert!(
            matches!(err, TlsConfigError::CertFileNotFound(_)),
            "expected CertFileNotFound, got: {err}",
        );
    }

    #[test]
    fn empty_pem_has_no_certs() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        fs::write(&cert, "not a real PEM\n").unwrap();
        fs::write(&key, "not a real PEM\n").unwrap();

        let err =
            load_tls_config(Some(cert.to_str().unwrap()), Some(key.to_str().unwrap())).unwrap_err();
        assert!(
            matches!(err, TlsConfigError::NoCertsFound(_)),
            "expected NoCertsFound, got: {err}",
        );
    }

    #[test]
    fn valid_self_signed_cert_loads() {
        // Generate a self-signed cert+key via rcgen (test-only helper).
        let subject_alt_names = vec!["localhost".to_string()];
        let cert_params = rcgen::CertificateParams::new(subject_alt_names).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let tls_cfg = load_tls_config(
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
        )
        .unwrap();
        assert!(tls_cfg.is_some(), "expected Some(TlsConfig)");
    }

    #[test]
    fn rpc_config_defaults_have_no_tls() {
        let cfg = crate::RpcConfig::default();
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }
}
