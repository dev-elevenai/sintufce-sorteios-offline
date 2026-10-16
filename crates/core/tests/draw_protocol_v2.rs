use sintufce_sorteio_core::draw_v1::{
    canonical_eligible_hash, canonical_prize_hash, draw_proof, federal_shuffle_key, DrawInput,
    DrawProtocolError, EligibleIdentity, FederalResult, PrizeIdentity,
};
use std::collections::HashSet;
use uuid::Uuid;

fn federal() -> FederalResult {
    FederalResult {
        contest: 6109,
        numbers: [87_637, 75_621, 78_748, 55_165, 75_592],
    }
}

#[test]
fn extrai_ultimos_tres_digitos_na_ordem_oficial() {
    assert_eq!(federal_shuffle_key(&federal()).unwrap(), "637621748165592");
}

#[test]
fn mesma_chave_e_quantidade_produzem_a_mesma_permutacao() {
    let input = DrawInput { federal: federal() };
    let first = draw_proof(&input, 10).unwrap();
    let second = draw_proof(&input, 10).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.algorithm_version, "SINTUFCE-DRAW-V2");
    assert_eq!(
        first
            .permutation
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len(),
        10
    );
}

#[test]
fn vetor_publico_v2_permanece_estavel() {
    let proof = draw_proof(&DrawInput { federal: federal() }, 10).unwrap();
    assert_eq!(proof.federal_key, "637621748165592");
    assert_eq!(proof.permutation, vec![3, 4, 6, 1, 2, 8, 0, 9, 7, 5]);
    assert_eq!(
        hex::encode(proof.seed_hash),
        "74a1716db0c7769e6f8fe9202218358e4de6f1712a4dd0d909bbe69a280ea9c7"
    );
}

#[test]
fn ordem_da_importacao_nao_altera_hash_da_lista() {
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
fn ordem_da_importacao_nao_altera_os_ganhadores() {
    let participants = [
        Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
        Uuid::parse_str("6ba7b810-9dad-41d1-80b4-00c04fd430c8").unwrap(),
        Uuid::parse_str("7ba7b810-9dad-41d1-80b4-00c04fd430c8").unwrap(),
        Uuid::parse_str("8ba7b810-9dad-41d1-80b4-00c04fd430c8").unwrap(),
    ];
    let mut forward = participants.to_vec();
    let mut reverse = participants.into_iter().rev().collect::<Vec<_>>();
    forward.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    reverse.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let permutation = draw_proof(&DrawInput { federal: federal() }, forward.len())
        .unwrap()
        .permutation;

    let winners_forward = permutation
        .iter()
        .map(|index| forward[*index])
        .collect::<Vec<_>>();
    let winners_reverse = permutation
        .iter()
        .map(|index| reverse[*index])
        .collect::<Vec<_>>();
    assert_eq!(winners_forward, winners_reverse);
}

#[test]
fn ordem_de_importacao_dos_premios_nao_altera_hash() {
    let first = PrizeIdentity {
        order: 1,
        name: "Televisão".into(),
    };
    let second = PrizeIdentity {
        order: 2,
        name: "Cesta".into(),
    };
    assert_eq!(
        canonical_prize_hash(&[first.clone(), second.clone()]),
        canonical_prize_hash(&[second, first]),
    );
}

#[test]
fn rejeita_numero_federal_fora_do_formato() {
    let mut invalid = federal();
    invalid.numbers[2] = 1_000_000;
    assert!(matches!(
        draw_proof(&DrawInput { federal: invalid }, 10),
        Err(DrawProtocolError::InvalidFederalResult)
    ));
}
