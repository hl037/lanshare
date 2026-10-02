//! TLS 1.3 with a self-signed cert derived from the device's ed25519 key.
//! Trust is NOT x509: the client pins the peer's raw public key (= its device id).
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig, SignatureScheme};
use std::sync::Arc;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

pub fn make_cert(seed: &[u8; 32]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    // PKCS#8 v1 wrapper around a raw ed25519 seed (RFC 8410).
    let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    pkcs8.extend_from_slice(seed);
    let kp = rcgen::KeyPair::try_from(pkcs8.as_slice())?;
    let params = rcgen::CertificateParams::new(vec!["lanshare".to_string()])?;
    let cert = params.self_signed(&kp)?;
    Ok((cert.der().to_vec(), pkcs8))
}

pub fn server_config(cert: &[u8], key: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec())),
        )?;
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct Pin {
    expected: [u8; 32],
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|_| Error::General("bad certificate".into()))?;
        if cert.public_key().subject_public_key.data.as_ref() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("peer key does not match pinned identity".into()))
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub fn client_config(peer_pub: [u8; 32]) -> anyhow::Result<Arc<ClientConfig>> {
    let p = provider();
    let algs = p.signature_verification_algorithms;
    let cfg = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pin { expected: peer_pub, algs }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}
