use sintufce_sorteio_core::crypto::{
    canonical_json, domain_message, sha256_hex, sign_ed25519, verify_ed25519,
};

#[test]
fn canonicaliza_json_independente_da_ordem_das_chaves() {
    let a = serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}});
    let b = serde_json::json!({"a": {"b": 3, "y": 2}, "z": 1});
    assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
    assert_eq!(canonical_json(&a).unwrap(), br#"{"a":{"b":3,"y":2},"z":1}"#);
}

#[test]
fn assinatura_ed25519_e_vinculada_ao_dominio_e_conteudo() {
    let secret = [7_u8; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key();
    let message = domain_message("SINTUFCE/PACKAGE/V2", b"manifesto");
    let signature = sign_ed25519(&secret, &message);

    assert!(verify_ed25519(public.as_bytes(), &message, &signature).is_ok());
    assert!(
        verify_ed25519(
            public.as_bytes(),
            &domain_message("SINTUFCE/RESULT/V1", b"manifesto"),
            &signature
        )
        .is_err()
    );
    assert!(
        verify_ed25519(
            public.as_bytes(),
            &domain_message("SINTUFCE/PACKAGE/V2", b"alterado"),
            &signature
        )
        .is_err()
    );
}

#[test]
fn hash_sha256_tem_vetor_estavel() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
