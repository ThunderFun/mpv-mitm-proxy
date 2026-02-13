use lru::LruCache;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Error, Debug)]
pub enum CertError {
    #[error("Certificate generation failed: {0}")]
    Generation(#[from] rcgen::Error),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Lock error")]
    Lock,
}

struct CaData {
    ca_cert: Certificate,
    ca_key: KeyPair,
}

pub struct CertificateAuthority {
    ca_data: Mutex<Option<CaData>>,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    fn generate_ca() -> Result<CaData, CertError> {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "MPV MITM Proxy CA");
        dn.push(DnType::OrganizationName, "MPV Proxy");
        ca_params.distinguished_name = dn;
        let now = OffsetDateTime::now_utc();
        ca_params.not_before = now;
        ca_params.not_after = now + Duration::from_secs(365 * 24 * 60 * 60 * 10);
        let ca_cert = ca_params.self_signed(&ca_key)?;
        Ok(CaData { ca_cert, ca_key })
    }

    pub fn new() -> Result<Self, CertError> {
        let ca_data = Self::generate_ca()?;
        Ok(Self {
            ca_data: Mutex::new(Some(ca_data)),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap())),
        })
    }

    fn ensure_initialized(&self) -> Result<(), CertError> {
        let mut ca_data_guard = self.ca_data.lock().map_err(|_| CertError::Lock)?;
        if ca_data_guard.is_some() {
            return Ok(());
        }
        let ca_data = Self::generate_ca()?;
        *ca_data_guard = Some(ca_data);
        Ok(())
    }

    pub fn get_server_config(&self, hostname: &str) -> Result<Arc<ServerConfig>, CertError> {
        // Fast path: check cache without generating
        {
            let mut cache = self.cache.lock().map_err(|_| CertError::Lock)?;
            if let Some(config) = cache.get(hostname) {
                return Ok(Arc::clone(config));
            }
        }

        self.ensure_initialized()?;

        // Slow path: generate config (this is expensive, done outside any lock)
        let config = self.generate_server_config(hostname)?;
        let config = Arc::new(config);

        // Insert into cache, but check again in case another thread already inserted
        {
            let mut cache = self.cache.lock().map_err(|_| CertError::Lock)?;
            // Use get_or_insert pattern to avoid redundant work
            if let Some(existing) = cache.get(hostname) {
                return Ok(Arc::clone(existing));
            }
            cache.put(hostname.to_string(), Arc::clone(&config));
        }

        Ok(config)
    }

    fn generate_server_config(&self, hostname: &str) -> Result<ServerConfig, CertError> {
        let ca_data_guard = self.ca_data.lock().map_err(|_| CertError::Lock)?;
        let ca_data = ca_data_guard
            .as_ref()
            .ok_or_else(|| CertError::Generation(rcgen::Error::CouldNotParseCertificate))?;

        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

        let mut server_params = CertificateParams::default();
        server_params.is_ca = IsCa::NoCa;
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        server_params.distinguished_name = dn;

        server_params.subject_alt_names = vec![SanType::DnsName(
            hostname
                .try_into()
                .map_err(|_| CertError::Generation(rcgen::Error::CouldNotParseCertificate))?,
        )];

        let now = OffsetDateTime::now_utc();
        server_params.not_before = now;
        server_params.not_after = now + Duration::from_secs(24 * 60 * 60 * 30);

        let server_cert =
            server_params.signed_by(&server_key, &ca_data.ca_cert, &ca_data.ca_key)?;

        let cert_der = CertificateDer::from(server_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)?;

        Ok(config)
    }
}
