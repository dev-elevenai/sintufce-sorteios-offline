use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

const COMMIT_DOMAIN: &[u8] = b"SINTUFCE/AUDITOR-COMMIT/V1\0";
const SEED_DOMAIN: &[u8] = b"SINTUFCE/FEDERAL-SHUFFLE/V2\0";
const NONCE_DOMAIN: &[u8] = b"SINTUFCE/NONCE/V2\0";
const ELIGIBLES_DOMAIN: &[u8] = b"SINTUFCE/ELIGIBLES/V1\0";
const PRIZES_DOMAIN: &[u8] = b"SINTUFCE/PRIZES/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleIdentity {
    pub uuid: Uuid,
    pub ticket: String,
    pub siape: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrizeIdentity {
    pub order: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct FederalResult {
    pub contest: u64,
    pub numbers: [u32; 5],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorReveal {
    pub auditor_id: String,
    pub secret: [u8; 32],
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawInput {
    pub federal: FederalResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawProof {
    pub algorithm_version: &'static str,
    pub seed_hash: [u8; 32],
    pub federal_key: String,
    pub permutation: Vec<usize>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DrawProtocolError {
    #[error("o protocolo exige exatamente três auditores independentes")]
    InsufficientAuditors,
    #[error("identificador de auditor repetido: {0}")]
    DuplicateAuditor(String),
    #[error("a revelação não corresponde ao compromisso do auditor {auditor_id}")]
    CommitmentMismatch { auditor_id: String },
    #[error("a lista de elegíveis está vazia")]
    EmptyEligibleList,
    #[error("resultado da Loteria Federal fora do formato permitido")]
    InvalidFederalResult,
}

pub fn auditor_commitment(event_id: Uuid, auditor_id: &str, secret: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COMMIT_DOMAIN);
    digest.update(event_id.as_bytes());
    digest.update((auditor_id.len() as u32).to_be_bytes());
    digest.update(auditor_id.as_bytes());
    digest.update(secret);
    digest.finalize().into()
}

pub fn canonical_eligible_hash(eligibles: &[EligibleIdentity]) -> [u8; 32] {
    let mut canonical = eligibles.to_vec();
    canonical.sort_by(|a, b| a.uuid.as_bytes().cmp(b.uuid.as_bytes()));

    let mut digest = Sha256::new();
    digest.update(ELIGIBLES_DOMAIN);
    digest.update((canonical.len() as u64).to_be_bytes());
    for eligible in canonical {
        digest.update(eligible.uuid.as_bytes());
        update_sized_text(&mut digest, eligible.ticket.trim());
        let siape: String = eligible.siape.trim().nfc().collect();
        update_sized_text(&mut digest, &siape);
    }
    digest.finalize().into()
}

pub fn canonical_prize_hash(prizes: &[PrizeIdentity]) -> [u8; 32] {
    let mut canonical = prizes.to_vec();
    canonical.sort_by_key(|prize| prize.order);

    let mut digest = Sha256::new();
    digest.update(PRIZES_DOMAIN);
    digest.update((canonical.len() as u64).to_be_bytes());
    for prize in canonical {
        digest.update(prize.order.to_be_bytes());
        let name: String = prize.name.trim().nfc().collect();
        update_sized_text(&mut digest, &name);
    }
    digest.finalize().into()
}

pub fn draw_permutation(
    input: &DrawInput,
    eligible_count: usize,
) -> Result<Vec<usize>, DrawProtocolError> {
    draw_proof(input, eligible_count).map(|proof| proof.permutation)
}

pub fn draw_proof(
    input: &DrawInput,
    eligible_count: usize,
) -> Result<DrawProof, DrawProtocolError> {
    if eligible_count == 0 {
        return Err(DrawProtocolError::EmptyEligibleList);
    }
    if input.federal.contest == 0 || input.federal.numbers.iter().any(|number| *number > 999_999) {
        return Err(DrawProtocolError::InvalidFederalResult);
    }
    let federal_key = federal_shuffle_key(&input.federal)?;
    let seed = derive_seed(&federal_key);
    let nonce_digest = Sha256::new().chain_update(NONCE_DOMAIN).finalize();
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&nonce_digest[..12]);

    let mut random = StableChaCha20::new(seed, nonce);
    let mut permutation: Vec<usize> = (0..eligible_count).collect();
    for last in (1..eligible_count).rev() {
        let selected = random.uniform_below((last + 1) as u64) as usize;
        permutation.swap(last, selected);
    }
    Ok(DrawProof {
        algorithm_version: "SINTUFCE-DRAW-V2",
        seed_hash: Sha256::digest(seed).into(),
        federal_key,
        permutation,
    })
}

fn derive_seed(federal_key: &str) -> [u8; 32] {
    Sha256::new()
        .chain_update(SEED_DOMAIN)
        .chain_update(federal_key.as_bytes())
        .finalize()
        .into()
}

pub fn federal_shuffle_key(result: &FederalResult) -> Result<String, DrawProtocolError> {
    if result.contest == 0 || result.numbers.iter().any(|number| *number > 999_999) {
        return Err(DrawProtocolError::InvalidFederalResult);
    }
    Ok(result
        .numbers
        .iter()
        .map(|number| format!("{:03}", number % 1_000))
        .collect::<String>())
}

fn update_sized_text(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u32).to_be_bytes());
    digest.update(value.as_bytes());
}

struct StableChaCha20(ChaCha20);

impl StableChaCha20 {
    fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self(ChaCha20::new((&key).into(), (&nonce).into()))
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.0.apply_keystream(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn uniform_below(&mut self, bound: u64) -> u64 {
        debug_assert!(bound > 0);
        let threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next_u64();
            if value >= threshold {
                return value % bound;
            }
        }
    }
}
