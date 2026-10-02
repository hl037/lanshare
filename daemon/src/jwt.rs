//! Minimal EdDSA JWT: header.claims.signature, base64url, no x509.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub iat: u64,
    pub jti: String,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Token issued by `iss` (us), to be presented back to us by `sub`.
pub fn issue(sk: &SigningKey, iss: &str, sub: &str) -> String {
    let head = B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = Claims {
        iss: iss.into(),
        sub: sub.into(),
        iat: now(),
        jti: hex::encode(rand::random::<[u8; 8]>()),
    };
    let body = B64.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{head}.{body}");
    let sig = sk.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", B64.encode(sig.to_bytes()))
}

pub fn verify(vk: &VerifyingKey, token: &str) -> Option<Claims> {
    let mut it = token.split('.');
    let (h, b, s) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let hdr: serde_json::Value = serde_json::from_slice(&B64.decode(h).ok()?).ok()?;
    if hdr.get("alg")?.as_str()? != "EdDSA" {
        return None;
    }
    let sig = Signature::from_slice(&B64.decode(s).ok()?).ok()?;
    vk.verify(format!("{h}.{b}").as_bytes(), &sig).ok()?;
    serde_json::from_slice(&B64.decode(b).ok()?).ok()
}
