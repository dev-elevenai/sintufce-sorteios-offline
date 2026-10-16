use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sintufce_sorteio_core::{
    draw_v1::{
        AuditorReveal, DrawInput, EligibleIdentity, FederalResult, PrizeIdentity,
        auditor_commitment, canonical_eligible_hash, canonical_prize_hash, draw_proof,
    },
    package::PackageValidator,
};
use std::{fs::File, sync::Mutex};
use tauri::{Manager, State};
use uuid::Uuid;

struct Database(Mutex<Connection>);

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
    auditor_secrets: [String; 3],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitInput {
    auditor_secrets: [String; 3],
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
    Ok(connection)
}

#[tauri::command]
fn import_package(path: String, database: State<'_, Database>) -> Result<EventState, String> {
    let package = PackageValidator::validate_reader(File::open(path).map_err(|e| e.to_string())?)
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
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    tx.execute_batch("DELETE FROM draw;DELETE FROM audit;DELETE FROM auditor_commit;DELETE FROM eligible;DELETE FROM prize;DELETE FROM event;").map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO event(id,name,status,list_hash,prizes_hash) VALUES(?1,?2,'CONFERIDO',?3,?4)",
        params![
            package.manifest.event_id.to_string(),
            package.manifest.event_name,
            list_hash,
            prizes_hash
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
        &serde_json::json!({"listHash":list_hash,"prizesHash":prizes_hash}).to_string(),
    )?;
    tx.commit().map_err(|e| e.to_string())?;
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
fn commit_auditors(
    input: CommitInput,
    database: State<'_, Database>,
) -> Result<EventState, String> {
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status != "CONFERIDO" {
        return Err("Os compromissos já foram registrados.".into());
    }
    let event_id = Uuid::parse_str(&state.id).map_err(|e| e.to_string())?;
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    for (index, value) in input.auditor_secrets.iter().enumerate() {
        let secret = parse_secret(value, index)?;
        let auditor_id = format!("AUDITOR-{}", index + 1);
        let commitment = hex::encode(auditor_commitment(event_id, &auditor_id, &secret));
        tx.execute(
            "INSERT INTO auditor_commit(auditor_id,commitment) VALUES(?1,?2)",
            params![auditor_id, commitment],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute("UPDATE event SET status='COMPROMETIDO'", [])
        .map_err(|e| e.to_string())?;
    append_audit(&tx, "AUDITOR_COMMITMENTS_REGISTERED", "{}")?;
    tx.commit().map_err(|e| e.to_string())?;
    read_state(&connection)
}

#[tauri::command]
fn seal_event(input: SealInput, database: State<'_, Database>) -> Result<EventState, String> {
    let mut connection = database
        .0
        .lock()
        .map_err(|_| "Banco local indisponível".to_string())?;
    let state = read_state(&connection)?;
    if state.status != "COMPROMETIDO" {
        return Err("O evento não está disponível para lacre.".into());
    }
    let event_id = Uuid::parse_str(&state.id).map_err(|e| e.to_string())?;
    let mut reveals = Vec::new();
    for (index, value) in input.auditor_secrets.iter().enumerate() {
        let secret = parse_secret(value, index)?;
        let auditor_id = format!("AUDITOR-{}", index + 1);
        let commitment = auditor_commitment(event_id, &auditor_id, &secret);
        let expected: String = connection
            .query_row(
                "SELECT commitment FROM auditor_commit WHERE auditor_id=?1",
                params![auditor_id],
                |row| row.get(0),
            )
            .map_err(|_| format!("Compromisso do auditor {} ausente.", index + 1))?;
        if hex::encode(commitment) != expected {
            return Err(format!(
                "Segredo do auditor {} não corresponde ao compromisso.",
                index + 1
            ));
        }
        reveals.push(AuditorReveal {
            commitment,
            auditor_id,
            secret,
        });
    }
    let list_hash: [u8; 32] = hex::decode(&state.list_hash)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "Hash da lista inválido")?;
    let prizes_hash: [u8; 32] = hex::decode(&state.prizes_hash)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "Hash dos prêmios inválido")?;
    let proof = draw_proof(
        &DrawInput {
            event_id,
            list_hash,
            prizes_hash,
            federal: FederalResult {
                contest: input.contest,
                numbers: input.numbers,
            },
            auditor_reveals: reveals,
        },
        state.eligible_count as usize,
    )
    .map_err(|e| e.to_string())?;
    let tx = connection.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "UPDATE event SET status='LACRADO',seed_hash=?1,permutation=?2,next_index=0 WHERE id=?3",
        params![
            hex::encode(proof.seed_hash),
            serde_json::to_string(&proof.permutation).unwrap(),
            state.id
        ],
    )
    .map_err(|e| e.to_string())?;
    append_audit(&tx, "EVENT_SEALED", &serde_json::json!({"algorithm":"SINTUFCE-DRAW-V1","seedHash":hex::encode(proof.seed_hash)}).to_string())?;
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
        &serde_json::json!({"sequence":sequence}).to_string(),
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
    let mut statement = connection.prepare("SELECT d.sequence,d.status,e.ticket,e.uuid,e.name,e.siape,p.position,p.name,d.created_at FROM draw d JOIN eligible e ON e.uuid=d.eligible_uuid JOIN prize p ON p.position=d.prize_position ORDER BY d.sequence").map_err(|e| e.to_string())?;
    let rows = statement.query_map([], |r| Ok(serde_json::json!({"sequence":r.get::<_,i64>(0)?,"status":r.get::<_,String>(1)?,"ticket":r.get::<_,String>(2)?,"uuid":r.get::<_,String>(3)?,"name":r.get::<_,String>(4)?,"siape":r.get::<_,String>(5)?,"prizeOrder":r.get::<_,i64>(6)?,"prize":r.get::<_,String>(7)?,"createdAt":r.get::<_,String>(8)?}))).map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
    let mut audit_statement = connection.prepare("SELECT sequence,kind,payload,previous_hash,hash,created_at FROM audit ORDER BY sequence").map_err(|e| e.to_string())?;
    let audit = audit_statement.query_map([], |r| Ok(serde_json::json!({"sequence":r.get::<_,i64>(0)?,"kind":r.get::<_,String>(1)?,"payload":r.get::<_,String>(2)?,"previousHash":r.get::<_,String>(3)?,"hash":r.get::<_,String>(4)?,"createdAt":r.get::<_,String>(5)?}))).map_err(|e| e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e| e.to_string())?;
    let report = serde_json::to_vec_pretty(
        &serde_json::json!({"protocol":"SINTUFCE-DRAW-V1","event":state,"draws":rows,"audit":audit}),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(path, report).map_err(|e| e.to_string())
}

fn read_state(connection: &Connection) -> Result<EventState, String> {
    connection.query_row("SELECT e.id,e.name,e.status,(SELECT COUNT(*) FROM eligible),(SELECT COUNT(*) FROM prize),(SELECT COUNT(*) FROM draw WHERE status='VALID'),e.list_hash,e.prizes_hash,e.seed_hash FROM event e LIMIT 1", [], |r| Ok(EventState { id:r.get(0)?,name:r.get(1)?,status:r.get(2)?,eligible_count:r.get(3)?,prize_count:r.get(4)?,draw_count:r.get(5)?,list_hash:r.get(6)?,prizes_hash:r.get(7)?,seed_hash:r.get(8)? })).map_err(|e| if matches!(e,rusqlite::Error::QueryReturnedNoRows) {"NO_EVENT".into()} else {e.to_string()})
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

fn parse_secret(value: &str, index: usize) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(value.trim()).map_err(|_| format!("Segredo {} inválido.", index + 1))?;
    bytes
        .try_into()
        .map_err(|_| format!("Segredo {} deve ter 32 bytes.", index + 1))
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
            )));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            import_package,
            get_event_state,
            commit_auditors,
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
