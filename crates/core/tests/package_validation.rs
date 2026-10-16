use sha2::{Digest, Sha256};
use sintufce_sorteio_core::package::{PackageError, PackageValidator};
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, ZipWriter};

const ELEGIVEIS: &str = "ticket,uuid,nome,siape,situacao_vinculo\n1,550e8400-e29b-41d4-a716-446655440000,Ana Lima,12345,FILIADO\n";
const PREMIOS: &str = "ordem,premio\n1,Televisão\n";

fn sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn pacote(hash_elegiveis: &str) -> Cursor<Vec<u8>> {
    pacote_com_elegiveis_e_hash(ELEGIVEIS, hash_elegiveis)
}

fn pacote_com_elegiveis(elegiveis: &str) -> Cursor<Vec<u8>> {
    pacote_com_elegiveis_e_hash(elegiveis, &sha256(elegiveis))
}

fn pacote_com_elegiveis_e_hash(elegiveis: &str, hash_elegiveis: &str) -> Cursor<Vec<u8>> {
    let manifest = serde_json::json!({
        "formatVersion": 1,
        "eventId": "9b68b494-977e-4db0-8e65-f7a2bc8e2cb2",
        "eventName": "Sorteio de Final de Ano 2026",
        "closedAt": "2026-12-01T12:00:00-03:00",
        "eligibleCount": 1,
        "prizeCount": 1,
        "files": {
            "elegiveis.csv": hash_elegiveis,
            "premios.csv": sha256(PREMIOS)
        }
    });

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default();
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(manifest.to_string().as_bytes()).unwrap();
        zip.start_file("elegiveis.csv", options).unwrap();
        zip.write_all(elegiveis.as_bytes()).unwrap();
        zip.start_file("premios.csv", options).unwrap();
        zip.write_all(PREMIOS.as_bytes()).unwrap();
        zip.finish().unwrap();
    }
    cursor.set_position(0);
    cursor
}

#[test]
fn aceita_pacote_integro_e_sem_dados_excedentes() {
    let validado = PackageValidator::validate_reader(pacote(&sha256(ELEGIVEIS))).unwrap();

    assert_eq!(validado.manifest.eligible_count, 1);
    assert_eq!(validado.eligibles[0].ticket, 1);
    assert_eq!(validado.eligibles[0].name, "Ana Lima");
    assert_eq!(validado.prizes[0].order, 1);
}

#[test]
fn rejeita_arquivo_alterado_apos_fechamento() {
    let error = PackageValidator::validate_reader(pacote(&"0".repeat(64))).unwrap_err();

    assert!(matches!(error, PackageError::HashMismatch { ref file } if file == "elegiveis.csv"));
}

#[test]
fn rejeita_participante_sem_vinculo_ativo() {
    let desfiliado = ELEGIVEIS.replace(",FILIADO", ",DESFILIADO");
    let error = PackageValidator::validate_reader(pacote_com_elegiveis(&desfiliado)).unwrap_err();

    assert!(matches!(error, PackageError::IneligibleMember { .. }));
}
