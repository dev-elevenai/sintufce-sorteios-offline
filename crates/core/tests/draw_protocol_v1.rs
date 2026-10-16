use sintufce_sorteio_core::draw_v1::{
    AuditorReveal, DrawInput, DrawProtocolError, EligibleIdentity, FederalResult,
    auditor_commitment, canonical_eligible_hash, draw_permutation,
};
use std::collections::HashSet;
use uuid::Uuid;

fn input() -> DrawInput {
    let event_id = Uuid::parse_str("9b68b494-977e-4db0-8e65-f7a2bc8e2cb2").unwrap();
    let reveals = [1_u8, 2, 3].map(|value| {
        let auditor_id = format!("AUDITOR-{value}");
        let secret = [value; 32];
        AuditorReveal {
            commitment: auditor_commitment(event_id, &auditor_id, &secret),
            auditor_id,
            secret,
        }
    });

    DrawInput {
        event_id,
        list_hash: [0x11; 32],
        prizes_hash: [0x22; 32],
        federal: FederalResult {
            contest: 6109,
            numbers: [87_637, 75_621, 78_748, 55_165, 75_592],
        },
        auditor_reveals: reveals.to_vec(),
    }
}

#[test]
fn gera_permutacao_deterministica_com_todos_os_elegiveis() {
    let first = draw_permutation(&input(), 10).unwrap();
    let second = draw_permutation(&input(), 10).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.len(), 10);
    assert_eq!(first.iter().copied().collect::<HashSet<_>>().len(), 10);
    assert!(first.iter().all(|index| *index < 10));
}

#[test]
fn rejeita_revelacao_que_nao_corresponde_ao_compromisso() {
    let mut corrupted = input();
    corrupted.auditor_reveals[0].secret[0] ^= 0xff;

    assert!(matches!(
        draw_permutation(&corrupted, 10),
        Err(DrawProtocolError::CommitmentMismatch { .. })
    ));
}

#[test]
fn exige_tres_fontes_independentes_de_auditoria() {
    let mut insufficient = input();
    insufficient.auditor_reveals.pop();

    assert!(matches!(
        draw_permutation(&insufficient, 10),
        Err(DrawProtocolError::InsufficientAuditors)
    ));
}

#[test]
fn vetor_de_teste_publicado_v1_permanece_estavel() {
    assert_eq!(
        draw_permutation(&input(), 10).unwrap(),
        vec![9, 8, 4, 6, 1, 5, 3, 0, 7, 2]
    );
}

#[test]
fn hash_da_lista_independe_da_ordem_de_importacao() {
    let first = EligibleIdentity {
        uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        ticket: "83910427".into(),
        siape: "12345".into(),
    };
    let second = EligibleIdentity {
        uuid: Uuid::parse_str("6ba7b810-9dad-41d1-80b4-00c04fd430c8").unwrap(),
        ticket: "10592836".into(),
        siape: "67890".into(),
    };

    assert_eq!(
        canonical_eligible_hash(&[first.clone(), second.clone()]),
        canonical_eligible_hash(&[second, first]),
    );
}

#[test]
fn rejeita_numero_federal_fora_do_formato_oficial() {
    let mut invalid = input();
    invalid.federal.numbers[2] = 1_000_000;

    assert!(matches!(
        draw_permutation(&invalid, 10),
        Err(DrawProtocolError::InvalidFederalResult)
    ));
}
