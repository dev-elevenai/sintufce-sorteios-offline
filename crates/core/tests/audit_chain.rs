use sintufce_sorteio_core::audit::{audit_hash, verify_audit_chain, AuditEntry};

#[test]
fn valida_cadeia_integra_e_rejeita_payload_alterado() {
    let first_hash = audit_hash(&"0".repeat(64), "PACKAGE_IMPORTED", "{}");
    let second_hash = audit_hash(&first_hash, "EVENT_SEALED", "{\"ok\":true}");
    let mut entries = vec![
        AuditEntry {
            sequence: 1,
            kind: "PACKAGE_IMPORTED".into(),
            payload: "{}".into(),
            previous_hash: "0".repeat(64),
            hash: first_hash,
        },
        AuditEntry {
            sequence: 2,
            kind: "EVENT_SEALED".into(),
            payload: "{\"ok\":true}".into(),
            previous_hash: String::new(),
            hash: second_hash,
        },
    ];
    entries[1].previous_hash = entries[0].hash.clone();
    assert!(verify_audit_chain(&entries).is_ok());

    entries[0].payload = "adulterado".into();
    assert!(verify_audit_chain(&entries).is_err());
}
