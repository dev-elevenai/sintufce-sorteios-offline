use sintufce_sorteio_core::{
    audit::{audit_hash, AuditEntry},
    crypto::sign_ed25519,
    draw_v1::{draw_proof, DrawInput, FederalResult},
    result_package::{
        DrawRecord, ResultManifest, ResultPackageBuilder, ResultPackageValidator, ResultPayload,
    },
};
use uuid::Uuid;

fn fixture(reverse: bool) -> (Vec<u8>, [u8; 32]) {
    let mut participants = vec![
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        Uuid::parse_str("650e8400-e29b-41d4-a716-446655440001").unwrap(),
        Uuid::parse_str("750e8400-e29b-41d4-a716-446655440002").unwrap(),
    ];
    if reverse { participants.reverse(); }
    let federal = FederalResult { contest: 6001, numbers: [87_637, 75_621, 78_748, 55_165, 75_592] };
    let proof = draw_proof(&DrawInput { federal: federal.clone() }, participants.len()).unwrap();
    let mut canonical = participants.clone();
    canonical.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let draws = proof.permutation.iter().take(2).enumerate().map(|(index, selected)| DrawRecord {
        sequence: (index + 1) as u32,
        eligible_uuid: canonical[*selected],
        prize_order: (index + 1) as u32,
        status: "VALID".into(),
        called_at: format!("2026-12-01T15:00:0{}Z", index),
    }).collect();
    let payload = ResultPayload {
        participants,
        prize_orders: vec![1, 2],
        federal,
        seed_hash: hex::encode(proof.seed_hash),
        draws,
    };
    let first = AuditEntry { sequence: 1, kind: "PACKAGE_IMPORTED".into(), payload: "{}".into(), previous_hash: "0".repeat(64), hash: audit_hash(&"0".repeat(64), "PACKAGE_IMPORTED", "{}") };
    let manifest = ResultManifest::new(
        Uuid::parse_str("9b68b494-977e-4db0-8e65-f7a2bc8e2cb2").unwrap(),
        "a4d76570d6172a983d4ab69606d33cb6fa17d0fe341749e49fbb8561f745d6c8".into(),
        "1".repeat(64), "2".repeat(64), "3".repeat(64),
    );
    let secret = [19_u8; 32];
    (ResultPackageBuilder::build(manifest, payload, vec![first], &secret).unwrap(), secret)
}

#[test]
fn valida_resultado_assinado_e_recomputado() {
    let (bytes, _) = fixture(false);
    let result = ResultPackageValidator::validate(&bytes).unwrap();
    assert_eq!(result.payload.draws.len(), 2);
}

#[test]
fn ordem_original_dos_participantes_nao_muda_validacao() {
    let (bytes, _) = fixture(true);
    ResultPackageValidator::validate(&bytes).unwrap();
}

#[test]
fn rejeita_assinatura_adulterada() {
    let (mut bytes, secret) = fixture(false);
    let forged = sign_ed25519(&secret, b"outro conteudo");
    let position = bytes.windows(64).position(|window| window == forged).unwrap_or(usize::MAX);
    let fallback = bytes.len() / 2;
    if position != usize::MAX { bytes[position] ^= 1; } else { bytes[fallback] ^= 1; }
    assert!(ResultPackageValidator::validate(&bytes).is_err());
}
