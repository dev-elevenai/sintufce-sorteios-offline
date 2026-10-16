use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek},
};
use thiserror::Error;
use uuid::{Uuid, Version};
use zip::ZipArchive;

const REQUIRED_FILES: [&str; 3] = ["manifest.json", "elegiveis.csv", "premios.csv"];
const OPTIONAL_FILES: [&str; 2] = ["origem.pdf", "assinatura.ed25519"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageManifest {
    pub format_version: u16,
    pub event_id: Uuid,
    pub event_name: String,
    pub closed_at: String,
    pub eligible_count: usize,
    pub prize_count: usize,
    pub files: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct Eligible {
    pub ticket: u64,
    pub uuid: Uuid,
    #[serde(rename = "nome")]
    pub name: String,
    pub siape: String,
    pub situacao_vinculo: String,
}

#[derive(Debug, Deserialize)]
pub struct Prize {
    #[serde(rename = "ordem")]
    pub order: u32,
    #[serde(rename = "premio")]
    pub name: String,
}

#[derive(Debug)]
pub struct ValidatedPackage {
    pub manifest: PackageManifest,
    pub eligibles: Vec<Eligible>,
    pub prizes: Vec<Prize>,
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("pacote ZIP inválido: {0}")]
    InvalidZip(#[from] zip::result::ZipError),
    #[error("arquivo obrigatório ausente: {0}")]
    MissingFile(String),
    #[error("arquivo não permitido no pacote: {0}")]
    UnexpectedFile(String),
    #[error("manifesto inválido: {0}")]
    InvalidManifest(#[from] serde_json::Error),
    #[error("CSV inválido em {file}: {message}")]
    InvalidCsv { file: String, message: String },
    #[error("hash divergente em {file}")]
    HashMismatch { file: String },
    #[error("formato de pacote não suportado: {0}")]
    UnsupportedVersion(u16),
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
        let mut archive = ZipArchive::new(reader)?;
        let mut files = HashMap::<String, Vec<u8>>::new();

        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            let name = entry.name()?.into_owned();
            if !REQUIRED_FILES.contains(&name.as_str()) && !OPTIONAL_FILES.contains(&name.as_str())
            {
                return Err(PackageError::UnexpectedFile(name));
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            files.insert(name, bytes);
        }

        for required in REQUIRED_FILES {
            if !files.contains_key(required) {
                return Err(PackageError::MissingFile(required.to_owned()));
            }
        }

        let manifest: PackageManifest = serde_json::from_slice(&files["manifest.json"])?;
        if manifest.format_version != 1 {
            return Err(PackageError::UnsupportedVersion(manifest.format_version));
        }

        for file in ["elegiveis.csv", "premios.csv"] {
            let expected = manifest
                .files
                .get(file)
                .ok_or_else(|| PackageError::MissingFile(format!("hash de {file}")))?;
            let actual = hex::encode(Sha256::digest(&files[file]));
            if !expected.eq_ignore_ascii_case(&actual) {
                return Err(PackageError::HashMismatch {
                    file: file.to_owned(),
                });
            }
        }

        let eligibles: Vec<Eligible> = parse_csv("elegiveis.csv", &files["elegiveis.csv"])?;
        let prizes: Vec<Prize> = parse_csv("premios.csv", &files["premios.csv"])?;
        validate_count("elegiveis.csv", manifest.eligible_count, eligibles.len())?;
        validate_count("premios.csv", manifest.prize_count, prizes.len())?;

        let mut tickets = HashSet::new();
        let mut uuids = HashSet::new();
        let mut siapes = HashSet::new();
        for eligible in &eligibles {
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
        for prize in &prizes {
            unique(&mut orders, prize.order, "ordem do prêmio")?;
        }

        Ok(ValidatedPackage {
            manifest,
            eligibles,
            prizes,
        })
    }
}

fn parse_csv<T: for<'de> Deserialize<'de>>(
    file: &str,
    bytes: &[u8],
) -> Result<Vec<T>, PackageError> {
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

fn validate_count(file: &str, expected: usize, actual: usize) -> Result<(), PackageError> {
    if expected == actual {
        return Ok(());
    }
    Err(PackageError::CountMismatch {
        file: file.to_owned(),
        expected,
        actual,
    })
}

fn unique<T: Eq + std::hash::Hash + std::fmt::Display>(
    values: &mut HashSet<T>,
    value: T,
    field: &'static str,
) -> Result<(), PackageError> {
    let display = value.to_string();
    if values.insert(value) {
        return Ok(());
    }
    Err(PackageError::Duplicate {
        field,
        value: display,
    })
}
