use clap::{Parser, Subcommand};
use sintufce_sorteio_core::package::{PackageValidator, TrustedKeys};
use std::{fs::File, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "sintufce-sorteio",
    version,
    about = "Motor auditável do sorteio offline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Confere integridade e conteúdo de um pacote sem importá-lo.
    PackageInspect { package: PathBuf },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERRO: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::PackageInspect { package } => {
            let key: [u8; 32] =
                hex::decode("8f2ead5257bb7b9ae1e2345256fbdc461aac967db63499e3dab60e6750e9d4a6")?
                    .try_into()
                    .map_err(|_| "chave pública inválida")?;
            let keys = TrustedKeys::from([("sintufce-prod-2026-01".to_owned(), key)]);
            let validated =
                PackageValidator::validate_reader_with_keys(File::open(package)?, &keys)?;
            println!(
                "{}",
                serde_json::json!({
                    "status": "INTEGRO",
                    "evento": validated.manifest.event_name,
                    "elegiveis": validated.eligibles.len(),
                    "premios": validated.prizes.len(),
                })
            );
        }
    }
    Ok(())
}
