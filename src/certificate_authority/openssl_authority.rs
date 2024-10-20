use crate::certificate_authority::{CertificateAuthority, CACHE_TTL, NOT_BEFORE_OFFSET, TTL_SECS};
use http::uri::Authority;
use moka::future::Cache;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rand,
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Builder, X509NameBuilder, X509,
    },
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_rustls::rustls::{
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use tracing::{debug, error};

pub struct OpensslAuthority {
    pkey: PKey<Private>,
    ca_cert: X509,
    hash: MessageDigest,
    cache: Cache<Authority, Arc<ServerConfig>>,
    provider: Arc<CryptoProvider>,
}

impl OpensslAuthority {
    pub fn new(
        pkey: PKey<Private>,
        ca_cert: X509,
        hash: MessageDigest,
        cache_size: u64,
        provider: CryptoProvider,
    ) -> Self {
        Self {
            pkey,
            ca_cert,
            hash,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(Duration::from_secs(CACHE_TTL))
                .build(),
            provider: Arc::new(provider),
        }
    }

    fn gen_cert(
        &self,
        authority: &Authority,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ErrorStack> {
        // Generate a new RSA key pair for the leaf certificate
        let rsa = Rsa::generate(2048)?;
        let keypair = PKey::from_rsa(rsa)?;

        // Build the subject name with the authority host
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", authority.host())?;
        let name = name_builder.build();

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_version(2)?;

        // Set the validity period
        let not_before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to determine current UNIX time")
            .as_secs() as i64
            - NOT_BEFORE_OFFSET;
        x509_builder.set_not_before(Asn1Time::from_unix(not_before)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::from_unix(not_before + TTL_SECS)?.as_ref())?;

        // Set the public key for the certificate (leaf's public key)
        x509_builder.set_pubkey(&keypair)?;
        x509_builder.set_issuer_name(self.ca_cert.subject_name())?;

        // Generate a random serial number
        let mut serial_number = [0; 16];
        rand::rand_bytes(&mut serial_number)?;
        let serial_number = BigNum::from_slice(&serial_number)?;
        let serial_number = Asn1Integer::from_bn(&serial_number)?;
        x509_builder.set_serial_number(&serial_number)?;

        // Add required extensions
        let basic_constraints = BasicConstraints::new().critical().build()?;
        x509_builder.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?;
        x509_builder.append_extension(key_usage)?;

        let ext_key_usage = ExtendedKeyUsage::new().server_auth().build()?;
        x509_builder.append_extension(ext_key_usage)?;

        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(subject_key_id)?;

        let authority_key_id = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(authority_key_id)?;

        let alternative_name = SubjectAlternativeName::new()
            .dns(authority.host())
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(alternative_name)?;

        // Sign the certificate with the CA's private key
        x509_builder.sign(&self.pkey, self.hash)?;
        let x509 = x509_builder.build();

        // Serialize the certificate and private key
        let cert_der = x509.to_der()?;

        // Get the private key in PKCS8 DER format
        let private_key_der = keypair.private_key_to_pkcs8()?;
        let private_key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key_der));

        Ok((
            CertificateDer::from(cert_der),
            PrivateKeyDer::from(private_key_der),
        ))
    }
}

impl CertificateAuthority for OpensslAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            debug!("Using cached server config");
            return server_cfg;
        }
        debug!("Generating server config");

        let (cert_der, private_key_der) = match self.gen_cert(authority) {
            Ok((cert, key)) => (cert, key),
            Err(e) => {
                error!("Failed to generate certificate for {}: {}", authority, e);
                panic!("Failed to generate certificate");
            }
        };

        let certs = vec![cert_der];

        let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("Failed to specify protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key_der)
            .expect("Failed to build ServerConfig");

        server_cfg.alpn_protocols = vec![
            #[cfg(feature = "http2")]
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        server_cfg
    }
}
