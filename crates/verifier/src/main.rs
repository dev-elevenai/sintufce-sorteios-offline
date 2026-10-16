use clap::Parser;
use sintufce_sorteio_core::package::PackageValidator;
use std::{fs::File, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "sintufce-verificador",
    version,
    about = "Verificador independente e somente leitura"
)]
struct Cli {
    package: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match File::open(cli.package)
        .map_err(|error| error.to_string())
        .and_then(|file| PackageValidator::validate_reader(file).map_err(|error| error.to_string()))
    {
        Ok(package) => {
            println!(
                "{}",
                serde_json::json!({
                    "resultado": "INTEGRO",
                    "evento": package.manifest.event_name,
                    "elegiveis": package.eligibles.len(),
                    "premios": package.prizes.len(),
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({ "resultado": "INVALIDO", "erro": error })
            );
            ExitCode::FAILURE
        }
    }
}
