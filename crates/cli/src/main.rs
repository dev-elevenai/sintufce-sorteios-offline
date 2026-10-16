use clap::{Parser, Subcommand};
use sintufce_sorteio_core::package::PackageValidator;
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
            let validated = PackageValidator::validate_reader(File::open(package)?)?;
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
