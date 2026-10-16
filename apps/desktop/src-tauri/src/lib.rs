mod session_identity;

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sintufce_sorteio_core::{
    draw_v1::{
        canonical_eligible_hash, canonical_prize_hash, draw_proof, DrawInput, EligibleIdentity,
        FederalResult, PrizeIdentity,
    },
    package::{PackageValidator, TrustedKeys},
    result_package::{DrawRecord, ResultManifest, ResultPackageBuilder, ResultPayload},
};
use std::{collections::HashMap, fs::File, path::{Path, PathBuf}, sync::Mutex};
use tauri::{Manager, State};

struct Database(Mutex<Connection>, PathBuf);

const ONLINE_KEY_ID: &str = "sintufce-prod-2026-01";
const ONLINE_PUBLIC_KEY_HEX: &str = "8f2ead5257bb7b9ae1e2345256fbdc461aac967db63499e3dab60e6750e9d4a6";

fn trusted_online_keys() -> Result<TrustedKeys, String> {
    let bytes = hex::decode(ONLINE_PUBLIC_KEY_HEX).map_err(|_| "Chave pública online inválida".to_string())?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| "Chave pública online inválida".to_string())?;
    Ok(HashMap::from([(ONLINE_KEY_ID.to_owned(), key)]))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EventState {
    id: String,
    name: String,
    status: String,
    eligible_count: i64,
    prize_count: i64,
    draw_count: i64,
    list_hash: String,
    prizes_hash: String,
    seed_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealInput {
    contest: u64,
    numbers: [u32; 5],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DrawView {
    sequence: i64,
    ticket: String,
    participant_name: String,
    siape: String,
    prize: String,
    status: String,
}

fn initialize_database(path: &std::path::Path) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|e| e.to_string())?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS event(id TEXT PRIMARY KEY,name TEXT NOT NULL,status TEXT NOT NULL,list_hash TEXT NOT NULL,prizes_hash TEXT NOT NULL,seed_hash TEXT,permutation TEXT,next_index INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS eligible(uuid TEXT PRIMARY KEY,ticket TEXT NOT NULL UNIQUE,name TEXT NOT NULL,siape TEXT NOT NULL UNIQUE);
      CREATE TABLE IF NOT EXISTS prize(position INTEGER PRIMARY KEY,name TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS auditor_commit(auditor_id TEXT PRIMARY KEY,commitment TEXT NOT NULL UNIQUE);
      CREATE TABLE IF NOT EXISTS draw(sequence INTEGER PRIMARY KEY,eligible_uuid TEXT NOT NULL UNIQUE,prize_position INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'VALID',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
      CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,payload TEXT NOT NULL,previous_hash TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);")
        .map_err(|e| e.to_string())?;
    for (name, definition) in [
        ("source_package_hash", "TEXT"),
        ("export_nonce", "TEXT"),
        ("session_public_key", "TEXT"),
        ("protected_session_secret", "BLOB"),
        ("federal_contest", "INTEGER"),
        ("federal_numbers", "TEXT"),
    ] {
        add_event_column(&connection, name, definition)?;
    }
    Ok(connection)
}

fn add_event_column(connection: &Connection, name: &str, definition: &str) -> Result<(), String> {
    let mut statement = connection.prepare("PRAGMA table_info(event)").map_err(|error| error.to_string())?;
    let exists = statement.query_map([], |row| row.get::<_, String>(1)).map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?
        .iter().any(|column| column == name);
    if !exists {
        connection.execute_batch(&format!("ALTER TABLE event ADD COLUMN {name} {definition}")).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn import_package(path: String, database: State<'_, Database>) -> Result<EventState, String> {
    let package = PackageValidator::validate_reader_with_keys(
        File::open(path).map_err(|e| e.to_string())?,
        &trusted_online_keys()?,
    )
        .map_err(|e| e.to_string())?;
    let identities: Vec<_> = package
        .eligibles
        .iter()
        .map(|x| EligibleIdentity {
            uuid: x.uuid,
            ticket: x.ticket.to_string(),
            siape: x.siape.clone(),
        })
        .collect();
    let prize_ids: Vec<_> = package
        .prizes
        .iter()
        .map(|x| PrizeIdentity {
            order: x.order,
            name: x.name.clone(),
        })
        .collect();
    let list_hash = hex::encode(canonical_eligible_hash(&identities));
    let prizes_hash = hex::encode(canonical_prize_hash(&prize_ids));
    let export_nonce = package.manifest.export_nonce.clone().ok_or("Pacote sem nonce de exportação")?;
    let source_package_hash = package.package_hash.clone();
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let event_id = package.manifest.event_id.to_string();
    if let Some(existing_path) = find_event_path(&database.1, &event_id)? {
        let existing = initialize_database(&existing_path)?;
        let original_hash: Option<String> = existing.query_row(
            "SELECT source_package_hash FROM event WHERE id=?1", params![event_id], |row| row.get(0)
        ).map_err(|e| e.to_string())?;
        if original_hash.as_deref() != Some(source_package_hash.as_str()) {
            return Err("Este evento já existe com outro pacote. O histórico original foi preservado.".into());
        }
        *connection = existing;
        return read_state(&connection);
    }
    let events_dir = database.1.join("events");
    std::fs::create_dir_all(&events_dir).map_err(|e| e.to_string())?;
    let new_path = events_dir.join(format!("{event_id}.db"));
    let mut imported = initialize_database(&new_path)?;
    let secret = session_identity::generate_secret()?;
    let protected_secret = session_identity::protect(&secret)?;
    let session_public_key = hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes());
    let tx = imported.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO event(id,name,status,list_hash,prizes_hash,source_package_hash,export_nonce,session_public_key,protected_session_secret) VALUES(?1,?2,'CONFERIDO',?3,?4,?5,?6,?7,?8)",
        params![
            package.manifest.event_id.to_string(),
            package.manifest.event_name,
            list_hash,
            prizes_hash,
            source_package_hash,
            export_nonce,
            session_public_key,
            protected_secret,
        ],
    )
    .map_err(|e| e.to_string())?;
    for x in package.eligibles {
        tx.execute(
            "INSERT INTO eligible(uuid,ticket,name,siape) VALUES(?1,?2,?3,?4)",
            params![x.uuid.to_string(), x.ticket.to_string(), x.name, x.siape],
        )
        .map_err(|e| e.to_string())?;
    }
    for x in package.prizes {
        tx.execute(
            "INSERT INTO prize(position,name) VALUES(?1,?2)",
            params![x.order, x.name],
        )
        .map_err(|e| e.to_string())?;
    }
    append_audit(
        &tx,
        "PACKAGE_IMPORTED",
        &serde_json::json!({"listHash":list_hash,"prizesHash":prizes_hash,"packageHash":package.package_hash,"sessionPublicKey":session_public_key}).to_string(),
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    *connection = imported;
    read_state(&connection)
}

#[tauri::command]
fn get_event_state(database: State<'_, Database>) -> Result<Option<EventState>, String> {
    let connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    match read_state(&connection) {
        Ok(x) => Ok(Some(x)),
        Err(x) if x == "NO_EVENT" => Ok(None),
        Err(x) => Err(x),
    }
}

#[tauri::command]
fn seal_event(input: SealInput, database: State<'_, Database>) -> Result<EventState, String> {
    if input.contest == 0 || input.contest > 9_007_199_254_740_991 {
        return Err("Informe um número de concurso inteiro maior que zero e dentro do limite permitido.".into());
    }
    for (index, number) in input.numbers.iter().enumerate() {
        if *number > 999_999 {
            return Err(format!("O {}º número deve estar entre 0 e 999999.", index + 1));
        }
    }

    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status != "CONFERIDO" {
        return Err("O evento não está disponível para lacre.".into());
    }
    let proof = draw_proof(
        &DrawInput {
            federal: FederalResult {
                contest: input.contest,
                numbers: input.numbers,
            },
        },
        state.eligible_count as usize,
    )
    .map_err(|e| e.to_string())?;
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE event SET status='LACRADO',seed_hash=?1,permutation=?2,next_index=0,federal_contest=?4,federal_numbers=?5 WHERE id=?3",
        params![
            hex::encode(proof.seed_hash),
            serde_json::to_string(&proof.permutation).unwrap(),
            state.id,
            input.contest as i64,
            serde_json::to_string(&input.numbers).unwrap(),
        ],
    )
    .map_err(|e| e.to_string())?;
    append_audit(&tx, "EVENT_SEALED", &serde_json::json!({"algorithm":"SINTUFCE-DRAW-V2","contest":input.contest,"federalNumbers":input.numbers,"federalKey":proof.federal_key,"seedHash":hex::encode(proof.seed_hash)}).to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    read_state(&connection)
}

#[tauri::command]
fn draw_next(database: State<'_, Database>) -> Result<DrawView, String> {
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    let (event_id, status, permutation_json, next_index): (String, String, String, i64) = tx
        .query_row(
            "SELECT id,status,permutation,next_index FROM event LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|e| e.to_string())?;
    if status != "LACRADO" && status != "EM_SORTEIO" {
        return Err("O evento precisa estar lacrado.".into());
    }
    let permutation: Vec<usize> =
        serde_json::from_str(&permutation_json).map_err(|e| e.to_string())?;
    let sequence: i64 = tx
        .query_row("SELECT COALESCE(MAX(sequence),0)+1 FROM draw", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    let prize: (i64,String) = tx.query_row("SELECT position,name FROM prize WHERE position NOT IN (SELECT prize_position FROM draw WHERE status='VALID') ORDER BY position LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).map_err(|_| "Todos os prêmios já foram chamados.".to_string())?;
    let selected = *permutation
        .get(next_index as usize)
        .ok_or("Não há mais participantes elegíveis.")?;
    let participant: (String, String, String, String) = tx
        .query_row(
            "SELECT uuid,ticket,name,siape FROM eligible ORDER BY uuid LIMIT 1 OFFSET ?1",
            params![selected as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO draw(sequence,eligible_uuid,prize_position) VALUES(?1,?2,?3)",
        params![sequence, participant.0, prize.0],
    )
    .map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE event SET status='EM_SORTEIO',next_index=next_index+1 WHERE id=?1",
        params![event_id],
    )
    .map_err(|e| e.to_string())?;
    let view = DrawView {
        sequence,
        ticket: participant.1,
        participant_name: participant.2,
        siape: participant.3,
        prize: prize.1,
        status: "VALID".into(),
    };
    append_audit(
        &tx,
        "DRAW_CONFIRMED",
        &serde_json::to_string(&view).unwrap(),
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(view)
}

#[tauri::command]
fn list_draws(database: State<'_, Database>) -> Result<Vec<DrawView>, String> {
    let connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let mut statement = connection.prepare("SELECT d.sequence,e.ticket,e.name,e.siape,p.name,d.status FROM draw d JOIN eligible e ON e.uuid=d.eligible_uuid JOIN prize p ON p.position=d.prize_position ORDER BY d.sequence").map_err(|e| e.to_string())?;
    let mapped = statement
        .query_map([], |r| {
            Ok(DrawView {
                sequence: r.get(0)?,
                ticket: r.get(1)?,
                participant_name: r.get(2)?,
                siape: r.get(3)?,
                prize: r.get(4)?,
                status: r.get(5)?,
            })
        })
        .map_err(|e| e.to_string())?;
    mapped
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn mark_absent(sequence: i64, database: State<'_, Database>) -> Result<(), String> {
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status != "LACRADO" && state.status != "EM_SORTEIO" {
        return Err("O evento não permite registrar ausência nesta etapa.".into());
    }
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute(
            "UPDATE draw SET status='ABSENT' WHERE sequence=?1 AND status='VALID'",
            params![sequence],
        )
        .map_err(|e| e.to_string())?;
    if changed != 1 {
        return Err("A chamada não está disponível para marcar ausência.".into());
    }
    append_audit(
        &tx,
        "DRAW_ABSENT",
        &serde_json::json!({ "sequence": sequence }).to_string(),
    )?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn finish_event(database: State<'_, Database>) -> Result<EventState, String> {
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status == "FINALIZADO" { return Ok(state); }
    if state.status != "LACRADO" && state.status != "EM_SORTEIO" {
        return Err("O evento precisa estar lacrado para finalizar.".into());
    }
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    let remaining: i64 = tx.query_row("SELECT COUNT(*) FROM prize WHERE position NOT IN (SELECT prize_position FROM draw WHERE status='VALID')", [], |r| r.get(0)).map_err(|e| e.to_string())?;
    if remaining != 0 {
        return Err(format!(
            "Ainda existem {remaining} prêmios sem contemplado."
        ));
    }
    tx.execute("UPDATE event SET status='FINALIZADO'", [])
        .map_err(|e| e.to_string())?;
    append_audit(&tx, "EVENT_FINISHED", "{}")?;
    tx.commit().map_err(|e| e.to_string())?;
    read_state(&connection)
}

#[tauri::command]
fn export_report(path: String, database: State<'_, Database>) -> Result<(), String> {
    let connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status != "FINALIZADO" { return Err("Finalize o evento antes de exportar o resultado.".into()); }
    let (source_hash, export_nonce, protected_secret, contest, numbers_json): (String, String, Vec<u8>, i64, String) = connection.query_row(
        "SELECT source_package_hash,export_nonce,protected_session_secret,federal_contest,federal_numbers FROM event LIMIT 1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).map_err(|error| error.to_string())?;
    let secret = session_identity::unprotect(&protected_secret)?;
    let numbers: [u32; 5] = serde_json::from_str(&numbers_json).map_err(|error| error.to_string())?;
    let participants = connection.prepare("SELECT uuid FROM eligible ORDER BY uuid").map_err(|e| e.to_string())?
        .query_map([], |row| row.get::<_, String>(0)).map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?
        .into_iter().map(|uuid| uuid.parse::<uuid::Uuid>().map_err(|e| e.to_string())).collect::<Result<Vec<_>, _>>()?;
    let prize_orders = connection.prepare("SELECT position FROM prize ORDER BY position").map_err(|e| e.to_string())?
        .query_map([], |row| row.get::<_, u32>(0)).map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let mut draw_statement = connection.prepare("SELECT d.sequence,e.uuid,p.position,d.status,d.created_at FROM draw d JOIN eligible e ON e.uuid=d.eligible_uuid JOIN prize p ON p.position=d.prize_position ORDER BY d.sequence").map_err(|e| e.to_string())?;
    let draws = draw_statement.query_map([], |row| {
        let called_at: String = row.get(4)?;
        Ok(DrawRecord { sequence: row.get::<_, u32>(0)?, eligible_uuid: row.get::<_, String>(1)?.parse().unwrap(), prize_order: row.get(2)?, status: row.get(3)?, called_at: format!("{}Z", called_at.replace(' ', "T")) })
    }).map_err(|e| e.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let mut audit_statement = connection.prepare("SELECT sequence,kind,payload,previous_hash,hash FROM audit ORDER BY sequence").map_err(|e| e.to_string())?;
    let audit = audit_statement.query_map([], |row| Ok(sintufce_sorteio_core::audit::AuditEntry { sequence: row.get::<_, i64>(0)? as u64, kind: row.get(1)?, payload: row.get(2)?, previous_hash: row.get(3)?, hash: row.get(4)? }))
        .map_err(|e| e.to_string())?.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())?;
    let payload = ResultPayload { participants, prize_orders, federal: FederalResult { contest: contest as u64, numbers }, seed_hash: state.seed_hash.clone().ok_or("Evento sem semente")?, draws };
    let manifest = ResultManifest::new(state.id.parse().map_err(|e: uuid::Error| e.to_string())?, export_nonce, source_hash, state.list_hash, state.prizes_hash);
    let package = ResultPackageBuilder::build(manifest, payload, audit, &secret).map_err(|e| e.to_string())?;
    std::fs::write(path, package).map_err(|e| e.to_string())
}

fn read_state(connection: &Connection) -> Result<EventState, String> {
    let state = connection.query_row("SELECT e.id,e.name,e.status,(SELECT COUNT(*) FROM eligible),(SELECT COUNT(*) FROM prize),(SELECT COUNT(*) FROM draw WHERE status='VALID'),e.list_hash,e.prizes_hash,e.seed_hash FROM event e LIMIT 1", [], |r| Ok(EventState { id:r.get(0)?,name:r.get(1)?,status:r.get(2)?,eligible_count:r.get(3)?,prize_count:r.get(4)?,draw_count:r.get(5)?,list_hash:r.get(6)?,prizes_hash:r.get(7)?,seed_hash:r.get(8)? })).map_err(|e| if matches!(e,rusqlite::Error::QueryReturnedNoRows) {"NO_EVENT".into()} else {e.to_string()})?;
    Ok(state)
}

fn append_audit(connection: &Connection, kind: &str, payload: &str) -> Result<(), String> {
    let previous: String = connection
        .query_row(
            "SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "0".repeat(64));
    let hash = hex::encode(
        Sha256::new()
            .chain_update(b"SINTUFCE/AUDIT/V1\0")
            .chain_update(previous.as_bytes())
            .chain_update(kind.as_bytes())
            .chain_update(payload.as_bytes())
            .finalize(),
    );
    connection
        .execute(
            "INSERT INTO audit(kind,payload,previous_hash,hash) VALUES(?1,?2,?3,?4)",
            params![kind, payload, previous, hash],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            app.manage(Database(Mutex::new(
                initialize_database(&data_dir.join("sorteio.db")).map_err(std::io::Error::other)?,
            ), data_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            import_package,
            list_events,
            select_event,
            get_event_state,
            seal_event,
            draw_next,
            list_draws,
            mark_absent,
            finish_event,
            export_report
        ])
        .run(tauri::generate_context!())
        .expect("falha ao iniciar SINTUFCE Sorteios Offline");
}


fn event_paths(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    let legacy = directory.join("sorteio.db");
    if legacy.is_file() { paths.push(legacy); }
    let events = directory.join("events");
    if events.exists() {
        for entry in std::fs::read_dir(events).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.extension().and_then(|x| x.to_str()) == Some("db") { paths.push(path); }
        }
    }
    paths.sort();
    Ok(paths)
}

fn inspect_event(path: &Path) -> Result<Option<EventState>, String> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("Não foi possível abrir o histórico {}: {e}", path.display()))?;
    match read_state(&connection) {
        Ok(state) => Ok(Some(state)),
        Err(message) if message == "NO_EVENT" => Ok(None),
        Err(message) => Err(format!("Não foi possível ler o histórico {}: {message}", path.display())),
    }
}

fn find_event_path(directory: &Path, event_id: &str) -> Result<Option<PathBuf>, String> {
    for path in event_paths(directory)? {
        if inspect_event(&path)?.is_some_and(|state| state.id == event_id) { return Ok(Some(path)); }
    }
    Ok(None)
}

#[tauri::command]
fn list_events(database: State<'_, Database>) -> Result<Vec<EventState>, String> {
    let _guard = database.0.lock().map_err(|_| "Banco local indisponível".to_string())?;
    let mut events = Vec::new();
    for path in event_paths(&database.1)? {
        if let Some(state) = inspect_event(&path)? { events.push(state); }
    }
    events.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(events)
}

#[tauri::command]
fn select_event(event_id: String, database: State<'_, Database>) -> Result<EventState, String> {
    let mut connection = database.0.lock().map_err(|_| "Banco local indisponível".to_string())?;
    let path = find_event_path(&database.1, &event_id)?.ok_or("Evento não encontrado no computador.")?;
    let selected = initialize_database(&path)?;
    let state = read_state(&selected)?;
    *connection = selected;
    Ok(state)
}
