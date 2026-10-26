//! The certificate served to DoT and DoH clients, reloaded from disk when the
//! files change so a renewed certificate is picked up without a restart.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{info, warn};

pub struct CertStore {
    cert_file: PathBuf,
    key_file: PathBuf,
    provider: Arc<CryptoProvider>,
    current: ArcSwap<CertifiedKey>,
    /// Modification times of the files the current certificate came from.
    loaded: Mutex<(SystemTime, SystemTime)>,
}

impl CertStore {
    /// Loads the certificate, failing if the files are missing or don't match.
    pub fn load(cert_file: &Path, key_file: &Path) -> Result<Arc<Self>> {
        let provider = ServerConfig::builder().crypto_provider().clone();
        let stamp = modified(cert_file, key_file)?;
        let key = read(cert_file, key_file, &provider)?;
        info!(cert = %cert_file.display(), "loaded TLS certificate");
        Ok(Arc::new(Self {
            cert_file: cert_file.to_owned(),
            key_file: key_file.to_owned(),
            provider,
            current: ArcSwap::from_pointee(key),
            loaded: Mutex::new(stamp),
        }))
    }

    /// Reloads the certificate if either file changed since the last load.
    /// A broken new certificate is logged and the current one kept, so a
    /// half-written renewal never takes the listeners down.
    pub fn reload_if_changed(&self) -> Result<bool> {
        let stamp = modified(&self.cert_file, &self.key_file)?;
        if *self.loaded.lock().unwrap() == stamp {
            return Ok(false);
        }
        let key = read(&self.cert_file, &self.key_file, &self.provider)?;
        self.current.store(Arc::new(key));
        *self.loaded.lock().unwrap() = stamp;
        info!(cert = %self.cert_file.display(), "reloaded TLS certificate");
        Ok(true)
    }

    pub fn spawn_reload(self: &Arc<Self>, every: Duration) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(every);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = store.reload_if_changed() {
                    warn!(error = %format!("{e:#}"), "keeping the current TLS certificate");
                }
            }
        });
    }

    /// A rustls server config that serves this store's certificate.
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let mut config = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("the default provider supports the default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(self) as Arc<dyn ResolvesServerCert>);
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertStore")
            .field("cert_file", &self.cert_file)
            .finish_non_exhaustive()
    }
}

fn modified(cert_file: &Path, key_file: &Path) -> Result<(SystemTime, SystemTime)> {
    let time = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .with_context(|| format!("reading {}", path.display()))
    };
    Ok((time(cert_file)?, time(key_file)?))
}

fn read(cert_file: &Path, key_file: &Path, provider: &CryptoProvider) -> Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert_file)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .with_context(|| format!("reading certificates from {}", cert_file.display()))?;
    anyhow::ensure!(
        !chain.is_empty(),
        "no certificates in {}",
        cert_file.display()
    );
    let key = PrivateKeyDer::from_pem_file(key_file)
        .with_context(|| format!("reading private key from {}", key_file.display()))?;
    CertifiedKey::from_der(chain, key, provider).with_context(|| {
        format!(
            "{} does not match {}",
            key_file.display(),
            cert_file.display()
        )
    })
}
