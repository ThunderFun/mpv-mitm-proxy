use lru::LruCache;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use time::OffsetDateTime;
use dashmap::DashMap;
use tokio::sync::{watch, Mutex};

#[derive(Error, Debug, Clone)]
pub enum CertError {
    #[error("Certificate generation failed: {0}")]
    Generation(String),
    #[error("TLS configuration failed: {0}")]
    Tls(String),
    #[error("Lock error")]
    Lock,
}

impl From<rcgen::Error> for CertError {
    fn from(e: rcgen::Error) -> Self {
        CertError::Generation(e.to_string())
    }
}

impl From<rustls::Error> for CertError {
    fn from(e: rustls::Error) -> Self {
        CertError::Tls(e.to_string())
    }
}

struct CaData {
    ca_cert: Certificate,
    ca_key: KeyPair,
}

pub struct CertificateAuthority {
    ca_data: Mutex<Option<CaData>>,
    cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
    // Inflight map to prevent concurrent certificate generation for same hostname
    inflight: DashMap<String, watch::Receiver<Option<Result<Arc<ServerConfig>, CertError>>>>,
    // Separate flag for CA initialization to prevent duplicate CA generation
    ca_init_inflight: Mutex<Option<watch::Receiver<bool>>>,
}

impl CertificateAuthority {
    pub fn new() -> Result<Self, CertError> {

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

        Ok(Self {
            ca_data: Mutex::new(Some(CaData { ca_cert, ca_key })),
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap())),
            inflight: DashMap::new(),
            ca_init_inflight: Mutex::new(None),
        })
    }

    async fn ensure_initialized(&self) -> Result<(), CertError> {
        // Fast path: check if already initialized
        {
            let ca_data = self.ca_data.lock().await;
            if ca_data.is_some() {
                return Ok(());
            }
        }

        // Slow path: need to initialize - use ca_init_inflight to prevent duplicate work
        let mut ca_init_guard = self.ca_init_inflight.lock().await;
        
        if let Some(rx) = ca_init_guard.as_ref() {
            // Another task is initializing, wait for it
            let mut rx = rx.clone();
            drop(ca_init_guard);
            loop {
                if *rx.borrow() {
                    // Initialization complete (success or failure)
                    let ca_data = self.ca_data.lock().await;
                    return if ca_data.is_some() {
                        Ok(())
                    } else {
                        Err(CertError::Generation("CA initialization failed".to_string()))
                    };
                }
                if rx.changed().await.is_err() {
                    return Err(CertError::Lock);
                }
            }
        }

        // We are the one to initialize
        let (tx, rx) = watch::channel(false);
        *ca_init_guard = Some(rx);
        drop(ca_init_guard);

        // Double-check under the lock
        {
            let ca_data = self.ca_data.lock().await;
            if ca_data.is_some() {
                let _ = tx.send(true);
                *self.ca_init_inflight.lock().await = None;
                return Ok(());
            }
        }

        // Perform initialization
        let result = self.do_initialize().await;
        let _ = tx.send(true);
        *self.ca_init_inflight.lock().await = None;
        result
    }
    
    async fn do_initialize(&self) -> Result<(), CertError> {
        let mut ca_data = self.ca_data.lock().await;
        if ca_data.is_some() {
            return Ok(());
        }

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
        *ca_data = Some(CaData { ca_cert, ca_key });

        Ok(())
    }

    pub async fn get_server_config(self: &Arc<Self>, hostname: &str) -> Result<Arc<ServerConfig>, CertError> {
        // Check cache first
        {
            let mut cache = self.cache.lock().await;
            if let Some(config) = cache.get(hostname) {
                return Ok(Arc::clone(config));
            }
        }

        self.ensure_initialized().await?;

        // Use inflight mechanism to prevent concurrent generation for same hostname
        use dashmap::mapref::entry::Entry;
        
        let rx = match self.inflight.entry(hostname.to_string()) {
            Entry::Occupied(occ) => occ.get().clone(),
            Entry::Vacant(vac) => {
                let (tx, rx) = watch::channel(None);
                vac.insert(rx.clone());
                
                let hostname = hostname.to_string();
                let self_arc = Arc::clone(self);
                
                tokio::spawn(async move {
                    let result = self_arc.generate_server_config(&hostname).await;
                    match result {
                        Ok(config) => {
                            let config = Arc::new(config);
                            let _ = tx.send(Some(Ok(Arc::clone(&config))));
                            // Store in cache
                            let mut cache = self_arc.cache.lock().await;
                            cache.put(hostname.clone(), Arc::clone(&config));
                        }
                        Err(e) => {
                            let _ = tx.send(Some(Err(e)));
                        }
                    }
                    self_arc.inflight.remove(&hostname);
                });
                rx
            }
        };

        // Wait for the result
        let mut rx = rx;
        loop {
            if let Some(res) = rx.borrow().clone() {
                return res;
            }
            if rx.changed().await.is_err() {
                return Err(CertError::Lock);
            }
        }
    }

    async fn generate_server_config(&self, hostname: &str) -> Result<ServerConfig, CertError> {
        // Use lock().await since this is called from an async context
        let ca_data_guard = self.ca_data.lock().await;
        let ca_data = ca_data_guard
            .as_ref()
            .ok_or_else(|| CertError::Generation("Could not parse certificate".to_string()))?;

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
                .map_err(|_| CertError::Generation("Could not parse certificate".to_string()))?,
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
