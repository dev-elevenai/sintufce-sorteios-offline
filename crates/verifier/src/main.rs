use clap::Parser;
use sintufce_sorteio_core::{
    audit::{verify_audit_chain, AuditEntry},
    package::PackageValidator,
};
use std::{
    collections::HashSet,
    fs::File,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "sintufce-verificador",
    version,
    about = "Verificador independente e somente leitura"
)]
struct Cli {
    arquivo: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match verify(&cli.arquivo) {
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

fn verify(path: &Path) -> Result<serde_json::Value, String> {
    if path.extension().and_then(|value| value.to_str()) == Some("json") {
        return verify_report(path);
    }
    let package = PackageValidator::validate_reader(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(
        serde_json::json!({"tipo":"pacote","evento":package.manifest.event_name,"elegiveis":package.eligibles.len(),"premios":package.prizes.len()}),
    )
}

fn verify_report(path: &Path) -> Result<serde_json::Value, String> {
    let report: serde_json::Value =
        serde_json::from_reader(File::open(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if report.get("protocol").and_then(|x| x.as_str()) != Some("SINTUFCE-DRAW-V2") {
        return Err("Versão de protocolo inválida.".into());
    }
    if report.pointer("/event/status").and_then(|x| x.as_str()) != Some("FINALIZADO") {
        return Err("Evento não está finalizado.".into());
    }
    let audit: Vec<AuditEntry> =
        serde_json::from_value(report.get("audit").cloned().ok_or("Diário ausente.")?)
            .map_err(|e| e.to_string())?;
    verify_audit_chain(&audit).map_err(|e| e.to_string())?;
    let draws = report
        .get("draws")
        .and_then(|x| x.as_array())
        .ok_or("Chamadas ausentes.")?;
    let mut winners = HashSet::new();
    let mut prizes = HashSet::new();
    for draw in draws
        .iter()
        .filter(|x| x.get("status").and_then(|v| v.as_str()) == Some("VALID"))
    {
        let uuid = draw
            .get("uuid")
            .and_then(|x| x.as_str())
            .ok_or("UUID ausente.")?;
        let prize = draw
            .get("prizeOrder")
            .and_then(|x| x.as_i64())
            .ok_or("Ordem do prêmio ausente.")?;
        if !winners.insert(uuid) {
            return Err(format!("Ganhador repetido: {uuid}"));
        }
        if !prizes.insert(prize) {
            return Err(format!("Prêmio repetido: {prize}"));
        }
    }
    Ok(serde_json::json!({"tipo":"relatorio","chamadas":draws.len(),"auditoria":audit.len()}))
}
