use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const AUDIT_DOMAIN: &[u8] = b"SINTUFCE/AUDIT/V1\0";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub sequence: u64,
    pub kind: String,
    pub payload: String,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("sequência de auditoria inválida na posição {0}")]
    InvalidSequence(u64),
    #[error("encadeamento rompido na sequência {0}")]
    BrokenChain(u64),
    #[error("hash inválido na sequência {0}")]
    InvalidHash(u64),
}

pub fn audit_hash(previous_hash: &str, kind: &str, payload: &str) -> String {
    hex::encode(
        Sha256::new()
            .chain_update(AUDIT_DOMAIN)
            .chain_update(previous_hash.as_bytes())
            .chain_update(kind.as_bytes())
            .chain_update(payload.as_bytes())
            .finalize(),
    )
}

pub fn verify_audit_chain(entries: &[AuditEntry]) -> Result<(), AuditError> {
    let mut previous = "0".repeat(64);
    for (index, entry) in entries.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if entry.sequence != expected_sequence {
            return Err(AuditError::InvalidSequence(entry.sequence));
        }
        if entry.previous_hash != previous {
            return Err(AuditError::BrokenChain(entry.sequence));
        }
        if entry.hash != audit_hash(&entry.previous_hash, &entry.kind, &entry.payload) {
            return Err(AuditError::InvalidHash(entry.sequence));
        }
        previous = entry.hash.clone();
    }
    Ok(())
}
