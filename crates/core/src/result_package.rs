use crate::{
    audit::{AuditEntry, verify_audit_chain},
    crypto::{canonical_json, domain_message, sha256_hex, sign_ed25519, verify_ed25519},
    draw_v1::{DrawInput, FederalResult, draw_proof},
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read, Write},
};
use thiserror::Error;
use uuid::Uuid;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const FILES: [&str; 5] = [
    "result-manifest.json",
    "resultado.json",
    "auditoria.jsonl",
    "session-public-key.ed25519",
    "signature.ed25519",
];
const MAX_RESULT_SIZE: usize = 25 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultManifest {
    pub format_version: u16,
    pub protocol: String,
    pub event_id: Uuid,
    pub export_nonce: String,
    pub source_package_hash: String,
    pub eligible_hash: String,
    pub prizes_hash: String,
    pub session_public_key: Option<String>,
    pub audit_root: Option<String>,
    pub files: HashMap<String, String>,
}

impl ResultManifest {
    pub fn new(
        event_id: Uuid,
        export_nonce: String,
        source_package_hash: String,
        eligible_hash: String,
        prizes_hash: String,
    ) -> Self {
        Self {
            format_version: 1,
            protocol: "SINTUFCE-DRAW-V2".into(),
            event_id,
            export_nonce,
            source_package_hash,
            eligible_hash,
            prizes_hash,
            session_public_key: None,
            audit_root: None,
            files: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DrawRecord {
    pub sequence: u32,
    pub eligible_uuid: Uuid,
    pub prize_order: u32,
    pub status: String,
    pub called_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultPayload {
    pub participants: Vec<Uuid>,
    pub prize_orders: Vec<u32>,
    pub federal: FederalResult,
    pub seed_hash: String,
    pub draws: Vec<DrawRecord>,
}

#[derive(Debug)]
pub struct ValidatedResultPackage {
    pub manifest: ResultManifest,
    pub payload: ResultPayload,
    pub audit: Vec<AuditEntry>,
    pub final_hash: String,
}

#[derive(Debug, Error)]
pub enum ResultPackageError {
    #[error("pacote de resultado inválido: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("estrutura do resultado inválida: {0}")]
    Structure(String),
    #[error("JSON do resultado inválido: {0}")]
    Json(#[from] serde_json::Error),
    #[error("assinatura do resultado inválida")]
    Signature,
    #[error("hash divergente em {0}")]
    Hash(String),
    #[error("cadeia de auditoria inválida")]
    Audit,
    #[error("resultado não corresponde ao algoritmo: {0}")]
    Recompute(String),
    #[error("erro de E/S: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ResultPackageBuilder;

impl ResultPackageBuilder {
    pub fn build(
        mut manifest: ResultManifest,
        payload: ResultPayload,
        audit: Vec<AuditEntry>,
        secret: &[u8; 32],
    ) -> Result<Vec<u8>, ResultPackageError> {
        verify_audit_chain(&audit).map_err(|_| ResultPackageError::Audit)?;
        recompute_result(&payload)?;
        let payload_bytes = canonical_json(&serde_json::to_value(&payload)?)
            .map_err(|error| ResultPackageError::Structure(error.to_string()))?;
        let audit_bytes = audit
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n")
            .into_bytes();
        let public = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        manifest.session_public_key = Some(hex::encode(public));
        manifest.audit_root = audit.last().map(|entry| entry.hash.clone());
        manifest.files = HashMap::from([
            ("resultado.json".into(), sha256_hex(&payload_bytes)),
            ("auditoria.jsonl".into(), sha256_hex(&audit_bytes)),
            ("session-public-key.ed25519".into(), sha256_hex(&public)),
        ]);
        let manifest_bytes = canonical_json(&serde_json::to_value(&manifest)?)
            .map_err(|error| ResultPackageError::Structure(error.to_string()))?;
        let signature = sign_ed25519(
            secret,
            &domain_message("SINTUFCE/RESULT/V1", &manifest_bytes),
        );
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();
        for (name, bytes) in [
            ("result-manifest.json", manifest_bytes.as_slice()),
            ("resultado.json", payload_bytes.as_slice()),
            ("auditoria.jsonl", audit_bytes.as_slice()),
            ("session-public-key.ed25519", public.as_slice()),
            ("signature.ed25519", signature.as_slice()),
        ] {
            zip.start_file(name, options)?;
            zip.write_all(bytes)?;
        }
        Ok(zip.finish()?.into_inner())
    }
}

pub struct ResultPackageValidator;

impl ResultPackageValidator {
    pub fn validate(bytes: &[u8]) -> Result<ValidatedResultPackage, ResultPackageError> {
        if bytes.len() > MAX_RESULT_SIZE {
            return Err(ResultPackageError::Structure(
                "arquivo excede 25 MiB".into(),
            ));
        }
        let mut archive = ZipArchive::new(Cursor::new(bytes))?;
        if archive.len() != FILES.len() {
            return Err(ResultPackageError::Structure(
                "quantidade de arquivos".into(),
            ));
        }
        let mut files = HashMap::<String, Vec<u8>>::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            if !FILES.contains(&name.as_str())
                || files.contains_key(&name)
                || entry.enclosed_name().is_none()
                || entry.is_dir()
            {
                return Err(ResultPackageError::Structure(name));
            }
            let mut content = Vec::new();
            entry
                .by_ref()
                .take((MAX_RESULT_SIZE + 1) as u64)
                .read_to_end(&mut content)?;
            if content.len() > MAX_RESULT_SIZE {
                return Err(ResultPackageError::Structure(
                    "entrada excede limite".into(),
                ));
            }
            files.insert(name, content);
        }
        for name in FILES {
            if !files.contains_key(name) {
                return Err(ResultPackageError::Structure(name.into()));
            }
        }
        let manifest: ResultManifest = serde_json::from_slice(&files["result-manifest.json"])?;
        if manifest.format_version != 1 || manifest.protocol != "SINTUFCE-DRAW-V2" {
            return Err(ResultPackageError::Structure("versão".into()));
        }
        let public: [u8; 32] = files["session-public-key.ed25519"]
            .as_slice()
            .try_into()
            .map_err(|_| ResultPackageError::Signature)?;
        let signature: [u8; 64] = files["signature.ed25519"]
            .as_slice()
            .try_into()
            .map_err(|_| ResultPackageError::Signature)?;
        if manifest.session_public_key.as_deref() != Some(&hex::encode(public)) {
            return Err(ResultPackageError::Signature);
        }
        let canonical_manifest = canonical_json(&serde_json::to_value(&manifest)?)
            .map_err(|error| ResultPackageError::Structure(error.to_string()))?;
        verify_ed25519(
            &public,
            &domain_message("SINTUFCE/RESULT/V1", &canonical_manifest),
            &signature,
        )
        .map_err(|_| ResultPackageError::Signature)?;
        for name in [
            "resultado.json",
            "auditoria.jsonl",
            "session-public-key.ed25519",
        ] {
            if manifest.files.get(name).map(String::as_str) != Some(&sha256_hex(&files[name])) {
                return Err(ResultPackageError::Hash(name.into()));
            }
        }
        let payload: ResultPayload = serde_json::from_slice(&files["resultado.json"])?;
        let audit_text = std::str::from_utf8(&files["auditoria.jsonl"])
            .map_err(|_| ResultPackageError::Audit)?;
        let audit = if audit_text.is_empty() {
            Vec::new()
        } else {
            audit_text
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<Vec<AuditEntry>, _>>()?
        };
        verify_audit_chain(&audit).map_err(|_| ResultPackageError::Audit)?;
        if manifest.audit_root.as_deref() != audit.last().map(|entry| entry.hash.as_str()) {
            return Err(ResultPackageError::Audit);
        }
        recompute_result(&payload)?;
        let final_hash = sha256_hex(&canonical_manifest);
        Ok(ValidatedResultPackage {
            manifest,
            payload,
            audit,
            final_hash,
        })
    }
}

pub fn recompute_result(payload: &ResultPayload) -> Result<(), ResultPackageError> {
    if payload.participants.is_empty() || payload.prize_orders.is_empty() {
        return Err(ResultPackageError::Recompute("listas vazias".into()));
    }
    let mut participants = payload.participants.clone();
    participants.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    if participants.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ResultPackageError::Recompute(
            "participante repetido".into(),
        ));
    }
    let mut prizes = payload.prize_orders.clone();
    prizes.sort_unstable();
    if prizes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ResultPackageError::Recompute("prêmio repetido".into()));
    }
    let proof = draw_proof(
        &DrawInput {
            federal: payload.federal.clone(),
        },
        participants.len(),
    )
    .map_err(|error| ResultPackageError::Recompute(error.to_string()))?;
    if payload.seed_hash != hex::encode(proof.seed_hash) {
        return Err(ResultPackageError::Recompute("seedHash".into()));
    }
    let mut awarded = 0_usize;
    let mut used = HashSet::new();
    for (index, draw) in payload.draws.iter().enumerate() {
        if draw.sequence as usize != index + 1 {
            return Err(ResultPackageError::Recompute("sequência".into()));
        }
        let expected_uuid = participants[*proof
            .permutation
            .get(index)
            .ok_or_else(|| ResultPackageError::Recompute("participantes esgotados".into()))?];
        if draw.eligible_uuid != expected_uuid || !used.insert(draw.eligible_uuid) {
            return Err(ResultPackageError::Recompute("ganhador".into()));
        }
        let expected_prize = *prizes
            .get(awarded)
            .ok_or_else(|| ResultPackageError::Recompute("prêmios esgotados".into()))?;
        if draw.prize_order != expected_prize {
            return Err(ResultPackageError::Recompute("prêmio".into()));
        }
        match draw.status.as_str() {
            "VALID" => awarded += 1,
            "ABSENT" => {}
            _ => return Err(ResultPackageError::Recompute("status".into())),
        }
    }
    if awarded != prizes.len() {
        return Err(ResultPackageError::Recompute(
            "prêmios sem contemplado".into(),
        ));
    }
    Ok(())
}
