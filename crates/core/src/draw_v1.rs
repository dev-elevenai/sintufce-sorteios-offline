use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

const COMMIT_DOMAIN: &[u8] = b"SINTUFCE/AUDITOR-COMMIT/V1\0";
const SALT_DOMAIN: &[u8] = b"SINTUFCE/SALT/V1\0";
const NONCE_DOMAIN: &[u8] = b"SINTUFCE/NONCE/V1\0";
const HKDF_INFO: &[u8] = b"SINTUFCE/DRAW/V1";
const ELIGIBLES_DOMAIN: &[u8] = b"SINTUFCE/ELIGIBLES/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleIdentity {
    pub uuid: Uuid,
    pub ticket: String,
    pub siape: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub event_id: Uuid,
    pub list_hash: [u8; 32],
    pub prizes_hash: [u8; 32],
    pub federal: FederalResult,
    pub auditor_reveals: Vec<AuditorReveal>,
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

pub fn draw_permutation(
    input: &DrawInput,
    eligible_count: usize,
) -> Result<Vec<usize>, DrawProtocolError> {
    if eligible_count == 0 {
        return Err(DrawProtocolError::EmptyEligibleList);
    }
    if input.federal.contest == 0 || input.federal.numbers.iter().any(|number| *number > 999_999) {
        return Err(DrawProtocolError::InvalidFederalResult);
    }
    if input.auditor_reveals.len() != 3 {
        return Err(DrawProtocolError::InsufficientAuditors);
    }

    let mut reveals = input.auditor_reveals.clone();
    reveals.sort_by(|a, b| a.auditor_id.as_bytes().cmp(b.auditor_id.as_bytes()));
    let mut auditor_ids = HashSet::new();
    for reveal in &reveals {
        if !auditor_ids.insert(reveal.auditor_id.clone()) {
            return Err(DrawProtocolError::DuplicateAuditor(
                reveal.auditor_id.clone(),
            ));
        }
        let expected = auditor_commitment(input.event_id, &reveal.auditor_id, &reveal.secret);
        if expected != reveal.commitment {
            return Err(DrawProtocolError::CommitmentMismatch {
                auditor_id: reveal.auditor_id.clone(),
            });
        }
    }

    let seed = derive_seed(input, &reveals);
    let nonce_digest = Sha256::new()
        .chain_update(NONCE_DOMAIN)
        .chain_update(input.event_id.as_bytes())
        .finalize();
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&nonce_digest[..12]);

    let mut random = StableChaCha20::new(seed, nonce);
    let mut permutation: Vec<usize> = (0..eligible_count).collect();
    for last in (1..eligible_count).rev() {
        let selected = random.uniform_below((last + 1) as u64) as usize;
        permutation.swap(last, selected);
    }
    Ok(permutation)
}

fn derive_seed(input: &DrawInput, reveals: &[AuditorReveal]) -> [u8; 32] {
    let salt: [u8; 32] = Sha256::new()
        .chain_update(SALT_DOMAIN)
        .chain_update(input.event_id.as_bytes())
        .chain_update(input.list_hash)
        .chain_update(input.prizes_hash)
        .finalize()
        .into();

    let mut input_material = federal_canonical(&input.federal).into_bytes();
    for reveal in reveals {
        input_material.extend_from_slice(&(reveal.auditor_id.len() as u32).to_be_bytes());
        input_material.extend_from_slice(reveal.auditor_id.as_bytes());
        input_material.extend_from_slice(&reveal.secret);
    }

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &input_material);
    let mut seed = [0_u8; 32];
    hkdf.expand(HKDF_INFO, &mut seed)
        .expect("32 bytes sempre cabem na saída HKDF-SHA-256");
    seed
}

fn federal_canonical(result: &FederalResult) -> String {
    format!(
        "FEDERAL|{:010}|{:06}|{:06}|{:06}|{:06}|{:06}",
        result.contest,
        result.numbers[0],
        result.numbers[1],
        result.numbers[2],
        result.numbers[3],
        result.numbers[4]
    )
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
