use sintufce_sorteio_core::{
    crypto::{canonical_json, domain_message, sha256_hex, sign_ed25519},
    package::{PackageError, PackageValidator, TrustedKeys},
};
use std::{
    collections::HashMap,
    io::{Cursor, Write},
};
use zip::{ZipWriter, write::SimpleFileOptions};

const SECRET: [u8; 32] = [11; 32];
const KEY_ID: &str = "prod-2026-01";
const ELEGIVEIS: &[u8] = b"ticket,uuid,nome,siape,situacao_vinculo\n91827364,550e8400-e29b-41d4-a716-446655440000,Ana Lima,12345,FILIADO\n";
const PREMIOS: &[u8] = b"ordem,premio\n1,Televisao\n";

fn trusted() -> TrustedKeys {
    HashMap::from([(
        KEY_ID.to_owned(),
        *ed25519_dalek::SigningKey::from_bytes(&SECRET)
            .verifying_key()
            .as_bytes(),
    )])
}

fn signed_package(extra: Option<(&str, &[u8])>, eligible_bytes: &[u8]) -> Cursor<Vec<u8>> {
    let manifest = serde_json::json!({
        "algorithmVersion": "SINTUFCE/FEDERAL-SHUFFLE/V2",
        "closedAt": "2026-12-01T15:00:00.000Z",
        "eligibleCount": 1,
        "eventId": "9b68b494-977e-4db0-8e65-f7a2bc8e2cb2",
        "eventName": "Sorteio 2026",
        "exportNonce": "a4d76570d6172a983d4ab69606d33cb6fa17d0fe341749e49fbb8561f745d6c8",
        "files": {
            "elegiveis.csv": sha256_hex(ELEGIVEIS),
            "premios.csv": sha256_hex(PREMIOS)
        },
        "formatVersion": 2,
        "keyId": KEY_ID,
        "prizeCount": 1,
        "state": "FECHADO_PARA_SORTEIO"
    });
    let manifest_bytes = canonical_json(&manifest).unwrap();
    let signature = sign_ed25519(
        &SECRET,
        &domain_message("SINTUFCE/PACKAGE/V2", &manifest_bytes),
    );
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default();
        for (name, bytes) in [
            ("manifest.json", manifest_bytes.as_slice()),
            ("elegiveis.csv", eligible_bytes),
            ("premios.csv", PREMIOS),
            ("signature.ed25519", signature.as_slice()),
            ("key-id.txt", KEY_ID.as_bytes()),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        if let Some((name, bytes)) = extra {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    cursor.set_position(0);
    cursor
}

fn package_with_duplicate_name() -> Cursor<Vec<u8>> {
    let mut cursor = signed_package(Some(("dup-id.txt", KEY_ID.as_bytes())), ELEGIVEIS);
    let bytes = cursor.get_mut();
    let positions: Vec<_> = bytes
        .windows(10)
        .enumerate()
        .filter_map(|(index, value)| (value == b"dup-id.txt").then_some(index))
        .collect();
    for index in positions {
        bytes[index..index + 10].copy_from_slice(b"key-id.txt");
    }
    cursor.set_position(0);
    cursor
}

#[test]
fn aceita_pacote_v2_assinado_por_chave_confiavel() {
    let package =
        PackageValidator::validate_reader_with_keys(signed_package(None, ELEGIVEIS), &trusted())
            .unwrap();
    assert_eq!(package.manifest.format_version, 2);
    assert_eq!(package.manifest.key_id.as_deref(), Some(KEY_ID));
    assert_eq!(
        package.package_hash,
        "009c4135b7b4d2b0e05a28a07c1fc2d5d43470f63b76eeddda4b59907957d2d3"
    );
}

#[test]
fn rejeita_conteudo_alterado_apos_assinatura() {
    let mut changed = ELEGIVEIS.to_vec();
    changed.extend_from_slice(b" ");
    let error =
        PackageValidator::validate_reader_with_keys(signed_package(None, &changed), &trusted())
            .unwrap_err();
    assert!(matches!(error, PackageError::HashMismatch { .. }));
}

#[test]
fn rejeita_arquivo_duplicado_e_traversal() {
    let duplicate =
        PackageValidator::validate_reader_with_keys(package_with_duplicate_name(), &trusted())
            .unwrap_err();
    assert!(matches!(duplicate, PackageError::DuplicateArchiveEntry(_)));

    let traversal = PackageValidator::validate_reader_with_keys(
        signed_package(Some(("../malware.exe", b"x")), ELEGIVEIS),
        &trusted(),
    )
    .unwrap_err();
    assert!(matches!(traversal, PackageError::UnsafeArchiveEntry(_)));
}

#[test]
fn rejeita_chave_nao_confiavel() {
    let error = PackageValidator::validate_reader_with_keys(
        signed_package(None, ELEGIVEIS),
        &HashMap::new(),
    )
    .unwrap_err();
    assert!(matches!(error, PackageError::UnknownSigningKey(_)));
}
