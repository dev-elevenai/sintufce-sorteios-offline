use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("JSON inválido: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chave pública Ed25519 inválida")]
    InvalidPublicKey,
    #[error("assinatura Ed25519 inválida")]
    InvalidSignature,
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, CryptoError> {
    Ok(serde_json::to_vec(&canonical_value(value))?)
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            Value::Object(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical_value(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        _ => value.clone(),
    }
}

pub fn domain_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + payload.len() + 20);
    message.extend_from_slice(b"SINTUFCE\0");
    message.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    message.extend_from_slice(payload);
    message
}

pub fn sign_ed25519(secret: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(secret).sign(message).to_bytes()
}

pub fn verify_ed25519(
    public: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::InvalidPublicKey)?;
    key.verify(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
