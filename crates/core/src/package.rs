use crate::crypto::{canonical_json, domain_message, sha256_hex, verify_ed25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read, Seek},
};
use thiserror::Error;
use uuid::{Uuid, Version};
use zip::ZipArchive;

const V1_REQUIRED: [&str; 3] = ["manifest.json", "elegiveis.csv", "premios.csv"];
const V2_REQUIRED: [&str; 5] = [
    "manifest.json",
    "elegiveis.csv",
    "premios.csv",
    "signature.ed25519",
    "key-id.txt",
];
const OPTIONAL_FILES: [&str; 1] = ["origem.pdf"];
const MAX_ENTRIES: usize = 8;
const MAX_ENTRY_SIZE: u64 = 10 * 1024 * 1024;
const MAX_TOTAL_SIZE: u64 = 25 * 1024 * 1024;
const MAX_ELIGIBLES: usize = 100_000;
const MAX_PRIZES: usize = 10_000;

pub type TrustedKeys = HashMap<String, [u8; 32]>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManifest {
    pub format_version: u16,
    pub event_id: Uuid,
    pub event_name: String,
    pub closed_at: String,
    pub eligible_count: usize,
    pub prize_count: usize,
    pub files: HashMap<String, String>,
    #[serde(default)]
    pub algorithm_version: Option<String>,
    #[serde(default)]
    pub export_nonce: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Eligible {
    pub ticket: u64,
    pub uuid: Uuid,
    #[serde(rename = "nome")]
    pub name: String,
    pub siape: String,
    pub situacao_vinculo: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Prize {
    #[serde(rename = "ordem")]
    pub order: u32,
    #[serde(rename = "premio")]
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedPackage {
    pub manifest: PackageManifest,
    pub eligibles: Vec<Eligible>,
    pub prizes: Vec<Prize>,
    pub package_hash: String,
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("pacote ZIP inválido: {0}")]
    InvalidZip(#[from] zip::result::ZipError),
    #[error("estrutura central do ZIP inválida")]
    InvalidArchiveStructure,
    #[error("arquivo obrigatório ausente: {0}")]
    MissingFile(String),
    #[error("arquivo não permitido no pacote: {0}")]
    UnexpectedFile(String),
    #[error("entrada insegura no pacote: {0}")]
    UnsafeArchiveEntry(String),
    #[error("entrada duplicada no pacote: {0}")]
    DuplicateArchiveEntry(String),
    #[error("pacote excede os limites permitidos")]
    PackageTooLarge,
    #[error("manifesto inválido: {0}")]
    InvalidManifest(#[from] serde_json::Error),
    #[error("CSV inválido em {file}: {message}")]
    InvalidCsv { file: String, message: String },
    #[error("hash divergente em {file}")]
    HashMismatch { file: String },
    #[error("formato de pacote não suportado: {0}")]
    UnsupportedVersion(u16),
    #[error("chave de assinatura desconhecida: {0}")]
    UnknownSigningKey(String),
    #[error("assinatura do pacote inválida")]
    InvalidSignature,
    #[error("metadado de segurança inválido: {0}")]
    InvalidSecurityMetadata(&'static str),
    #[error("contagem divergente em {file}: manifesto {expected}, arquivo {actual}")]
    CountMismatch {
        file: String,
        expected: usize,
        actual: usize,
    },
    #[error("identificador duplicado em {field}: {value}")]
    Duplicate { field: &'static str, value: String },
    #[error("UUID do ticket não é v4: {0}")]
    InvalidTicketUuid(Uuid),
    #[error("participante sem vínculo elegível: ticket {ticket}, situação {status}")]
    IneligibleMember { ticket: u64, status: String },
    #[error("erro de leitura: {0}")]
    Io(#[from] std::io::Error),
}

pub struct PackageValidator;

impl PackageValidator {
    pub fn validate_reader<R: Read + Seek>(reader: R) -> Result<ValidatedPackage, PackageError> {
        Self::validate(reader, None)
    }

    pub fn validate_reader_with_keys<R: Read + Seek>(
        reader: R,
        trusted: &TrustedKeys,
    ) -> Result<ValidatedPackage, PackageError> {
        Self::validate(reader, Some(trusted))
    }

    fn validate<R: Read + Seek>(
        mut reader: R,
        trusted: Option<&TrustedKeys>,
    ) -> Result<ValidatedPackage, PackageError> {
        let mut archive_bytes = Vec::new();
        reader
            .by_ref()
            .take(MAX_TOTAL_SIZE + 1)
            .read_to_end(&mut archive_bytes)?;
        if archive_bytes.len() as u64 > MAX_TOTAL_SIZE {
            return Err(PackageError::PackageTooLarge);
        }
        reject_duplicate_central_names(&archive_bytes)?;
        let mut archive = ZipArchive::new(Cursor::new(archive_bytes))?;
        if archive.len() > MAX_ENTRIES {
            return Err(PackageError::PackageTooLarge);
        }
        let mut files = HashMap::<String, Vec<u8>>::new();
        let mut total_size = 0_u64;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            let enclosed = entry
                .enclosed_name()
                .ok_or_else(|| PackageError::UnsafeArchiveEntry(name.clone()))?;
            if enclosed.to_string_lossy() != name
                || entry.is_dir()
                || entry
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err(PackageError::UnsafeArchiveEntry(name));
            }
            if files.contains_key(&name) {
                return Err(PackageError::DuplicateArchiveEntry(name));
            }
            if !V2_REQUIRED.contains(&name.as_str())
                && !V1_REQUIRED.contains(&name.as_str())
                && !OPTIONAL_FILES.contains(&name.as_str())
            {
                return Err(PackageError::UnexpectedFile(name));
            }
            total_size = total_size
                .checked_add(entry.size())
                .ok_or(PackageError::PackageTooLarge)?;
            if entry.size() > MAX_ENTRY_SIZE || total_size > MAX_TOTAL_SIZE {
                return Err(PackageError::PackageTooLarge);
            }
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry
                .by_ref()
                .take(MAX_ENTRY_SIZE + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_ENTRY_SIZE {
                return Err(PackageError::PackageTooLarge);
            }
            files.insert(name, bytes);
        }
        for required in V1_REQUIRED {
            require(&files, required)?;
        }
        let manifest: PackageManifest = serde_json::from_slice(&files["manifest.json"])?;
        match manifest.format_version {
            1 if trusted.is_none() => {}
            2 => {
                for required in V2_REQUIRED {
                    require(&files, required)?;
                }
                validate_v2_signature(
                    &manifest,
                    &files,
                    trusted.ok_or(PackageError::InvalidSignature)?,
                )?;
            }
            version => return Err(PackageError::UnsupportedVersion(version)),
        }
        if manifest.eligible_count == 0
            || manifest.eligible_count > MAX_ELIGIBLES
            || manifest.prize_count == 0
            || manifest.prize_count > MAX_PRIZES
        {
            return Err(PackageError::PackageTooLarge);
        }
        for file in ["elegiveis.csv", "premios.csv"] {
            let expected = manifest
                .files
                .get(file)
                .ok_or_else(|| PackageError::MissingFile(format!("hash de {file}")))?;
            if !expected.eq_ignore_ascii_case(&sha256_hex(&files[file])) {
                return Err(PackageError::HashMismatch {
                    file: file.to_owned(),
                });
            }
        }
        let eligibles: Vec<Eligible> = parse_csv("elegiveis.csv", &files["elegiveis.csv"])?;
        let prizes: Vec<Prize> = parse_csv("premios.csv", &files["premios.csv"])?;
        validate_count("elegiveis.csv", manifest.eligible_count, eligibles.len())?;
        validate_count("premios.csv", manifest.prize_count, prizes.len())?;
        validate_rows(&eligibles, &prizes)?;
        let package_hash = calculate_package_hash(&manifest, &files)?;
        Ok(ValidatedPackage {
            manifest,
            eligibles,
            prizes,
            package_hash,
        })
    }
}

fn reject_duplicate_central_names(bytes: &[u8]) -> Result<(), PackageError> {
    const EOCD: &[u8; 4] = b"PK\x05\x06";
    const CENTRAL: &[u8; 4] = b"PK\x01\x02";
    let eocd = bytes
        .windows(4)
        .rposition(|value| value == EOCD)
        .ok_or(PackageError::InvalidArchiveStructure)?;
    if eocd + 22 > bytes.len() {
        return Err(PackageError::InvalidArchiveStructure);
    }
    let entries = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
    let mut offset = u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    if entries > MAX_ENTRIES {
        return Err(PackageError::PackageTooLarge);
    }
    let mut names = HashSet::<Vec<u8>>::new();
    for _ in 0..entries {
        if offset + 46 > bytes.len() || &bytes[offset..offset + 4] != CENTRAL {
            return Err(PackageError::InvalidArchiveStructure);
        }
        let name_len = u16::from_le_bytes([bytes[offset + 28], bytes[offset + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[offset + 30], bytes[offset + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[offset + 32], bytes[offset + 33]]) as usize;
        let name_start = offset + 46;
        let next = name_start
            .checked_add(name_len)
            .and_then(|x| x.checked_add(extra_len))
            .and_then(|x| x.checked_add(comment_len))
            .ok_or(PackageError::InvalidArchiveStructure)?;
        if next > bytes.len() {
            return Err(PackageError::InvalidArchiveStructure);
        }
        let name = bytes[name_start..name_start + name_len].to_vec();
        if !names.insert(name.clone()) {
            return Err(PackageError::DuplicateArchiveEntry(
                String::from_utf8_lossy(&name).into_owned(),
            ));
        }
        offset = next;
    }
    Ok(())
}

fn require(files: &HashMap<String, Vec<u8>>, name: &str) -> Result<(), PackageError> {
    if files.contains_key(name) {
        Ok(())
    } else {
        Err(PackageError::MissingFile(name.to_owned()))
    }
}

fn validate_v2_signature(
    manifest: &PackageManifest,
    files: &HashMap<String, Vec<u8>>,
    trusted: &TrustedKeys,
) -> Result<(), PackageError> {
    if manifest.algorithm_version.as_deref() != Some("SINTUFCE/FEDERAL-SHUFFLE/V2")
        || manifest.state.as_deref() != Some("FECHADO_PARA_SORTEIO")
    {
        return Err(PackageError::InvalidSecurityMetadata("algoritmo ou estado"));
    }
    let nonce = manifest
        .export_nonce
        .as_deref()
        .ok_or(PackageError::InvalidSecurityMetadata("exportNonce"))?;
    if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PackageError::InvalidSecurityMetadata("exportNonce"));
    }
    let key_id = manifest
        .key_id
        .as_deref()
        .ok_or(PackageError::InvalidSecurityMetadata("keyId"))?;
    if files["key-id.txt"] != key_id.as_bytes() {
        return Err(PackageError::InvalidSecurityMetadata("key-id.txt"));
    }
    let public = trusted
        .get(key_id)
        .ok_or_else(|| PackageError::UnknownSigningKey(key_id.to_owned()))?;
    let signature: [u8; 64] = files["signature.ed25519"]
        .as_slice()
        .try_into()
        .map_err(|_| PackageError::InvalidSignature)?;
    let canonical = canonical_json(&serde_json::to_value(manifest)?)
        .map_err(|_| PackageError::InvalidSignature)?;
    verify_ed25519(
        public,
        &domain_message("SINTUFCE/PACKAGE/V2", &canonical),
        &signature,
    )
    .map_err(|_| PackageError::InvalidSignature)
}

fn calculate_package_hash(
    manifest: &PackageManifest,
    files: &HashMap<String, Vec<u8>>,
) -> Result<String, PackageError> {
    let mut digest = Sha256::new();
    digest.update(b"SINTUFCE/PACKAGE-HASH/V1\0");
    digest.update(
        canonical_json(&serde_json::to_value(manifest)?)
            .map_err(|_| PackageError::InvalidSignature)?,
    );
    for name in ["elegiveis.csv", "premios.csv"] {
        digest.update((name.len() as u32).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(Sha256::digest(&files[name]));
    }
    Ok(hex::encode(digest.finalize()))
}

fn parse_csv<T: for<'de> Deserialize<'de>>(
    file: &str,
    bytes: &[u8],
) -> Result<Vec<T>, PackageError> {
    std::str::from_utf8(bytes).map_err(|error| PackageError::InvalidCsv {
        file: file.to_owned(),
        message: error.to_string(),
    })?;
    csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(bytes)
        .deserialize()
        .collect::<Result<Vec<T>, _>>()
        .map_err(|error| PackageError::InvalidCsv {
            file: file.to_owned(),
            message: error.to_string(),
        })
}

fn validate_rows(eligibles: &[Eligible], prizes: &[Prize]) -> Result<(), PackageError> {
    let mut tickets = HashSet::new();
    let mut uuids = HashSet::new();
    let mut siapes = HashSet::new();
    for eligible in eligibles {
        if eligible.situacao_vinculo.trim().to_uppercase() != "FILIADO" {
            return Err(PackageError::IneligibleMember {
                ticket: eligible.ticket,
                status: eligible.situacao_vinculo.clone(),
            });
        }
        if eligible.uuid.get_version() != Some(Version::Random) {
            return Err(PackageError::InvalidTicketUuid(eligible.uuid));
        }
        unique(&mut tickets, eligible.ticket, "ticket")?;
        unique(&mut uuids, eligible.uuid, "uuid")?;
        unique(&mut siapes, eligible.siape.trim().to_owned(), "siape")?;
    }
    let mut orders = HashSet::new();
    for prize in prizes {
        unique(&mut orders, prize.order, "ordem do prêmio")?;
    }
    Ok(())
}

fn validate_count(file: &str, expected: usize, actual: usize) -> Result<(), PackageError> {
    if expected == actual {
        Ok(())
    } else {
        Err(PackageError::CountMismatch {
            file: file.to_owned(),
            expected,
            actual,
        })
    }
}

fn unique<T: Eq + std::hash::Hash + std::fmt::Display>(
    values: &mut HashSet<T>,
    value: T,
    field: &'static str,
) -> Result<(), PackageError> {
    let display = value.to_string();
    if values.insert(value) {
        Ok(())
    } else {
        Err(PackageError::Duplicate {
            field,
            value: display,
        })
    }
}
