use clap::Parser;
use sintufce_sorteio_core::{
    package::{PackageValidator, TrustedKeys},
    result_package::ResultPackageValidator,
};
use std::{
    fs,
    fs::File,
    path::{Path, PathBuf},
    process::ExitCode,
};

const KEY_ID: &str = "sintufce-prod-2026-01";
const PUBLIC_KEY: &str = "8f2ead5257bb7b9ae1e2345256fbdc461aac967db63499e3dab60e6750e9d4a6";

#[derive(Parser)]
#[command(
    name = "sintufce-verificador",
    version,
    about = "Verificador independente e somente leitura"
)]
struct Cli {
    arquivo: PathBuf,
}

fn trusted_keys() -> Result<TrustedKeys, String> {
    let key: [u8; 32] = hex::decode(PUBLIC_KEY)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "Chave pública inválida".to_string())?;
    Ok(TrustedKeys::from([(KEY_ID.to_owned(), key)]))
}

fn verify(path: &Path) -> Result<serde_json::Value, String> {
    if path.extension().and_then(|value| value.to_str()) == Some("sintufce-result") {
        let bytes = fs::read(path).map_err(|error| error.to_string())?;
        let result = ResultPackageValidator::validate(&bytes).map_err(|error| error.to_string())?;
        return Ok(serde_json::json!({
            "tipo": "resultado", "evento": result.manifest.event_id,
            "chamadas": result.payload.draws.len(), "auditoria": result.audit.len(),
            "hashFinal": result.final_hash,
        }));
    }
    let package = PackageValidator::validate_reader_with_keys(
        File::open(path).map_err(|error| error.to_string())?,
        &trusted_keys()?,
    )
    .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "tipo": "pacote", "evento": package.manifest.event_name,
        "elegiveis": package.eligibles.len(), "premios": package.prizes.len(),
        "hashPacote": package.package_hash,
    }))
}

fn main() -> ExitCode {
    match verify(&Cli::parse().arquivo) {
        Ok(details) => {
            println!(
                "{}",
                serde_json::json!({"resultado":"INTEGRO","detalhes":details})
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"resultado":"INVALIDO","erro":error})
            );
            ExitCode::FAILURE
        }
    }
}
