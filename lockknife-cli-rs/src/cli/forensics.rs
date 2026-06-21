use std::fs;

use crate::app::{AppContext, Result};
use crate::case::CaseSession;
use crate::cli::ForensicsCommand;
use crate::modules::forensics::{
    build_timeline, carve_patterns, correlate_inputs, decode_protobuf_like, inventory_dir,
    recover_sqlite_sidecars, sqlite_inventory,
};
use crate::modules::{resolve_output_path, write_structured};

pub fn dispatch_forensics(ctx: &AppContext, command: ForensicsCommand) -> Result<()> {
    match command {
        ForensicsCommand::Snapshot {
            serial,
            full: _,
            paths,
            io,
            ..
        } => {
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output_dir = io
                .output
                .unwrap_or_else(|| session.output_path("derived", "snapshot"));
            fs::create_dir_all(&output_dir)?;
            let mut results = Vec::new();

            // Use provided paths, or fall back to default forensics paths if none given.
            let snapshot_paths = if paths.is_empty() {
                default_snapshot_paths()
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            } else {
                paths
            };

            for remote in snapshot_paths {
                let local = output_dir.join(
                    remote
                        .trim_start_matches('/')
                        .replace('/', "_")
                        .replace(':', "_"),
                );
                match ctx.services.adb.pull(&serial, &remote, &local) {
                    Ok(detail) => results.push(serde_json::json!({
                        "remote": remote,
                        "local": local,
                        "status": "ok",
                        "detail": detail,
                    })),
                    Err(err) => results.push(serde_json::json!({
                        "remote": remote,
                        "local": local,
                        "status": "error",
                        "detail": err.to_string(),
                    })),
                }
            }
            let report = serde_json::json!({
                "serial": serial,
                "output_dir": output_dir,
                "results": results,
            });
            let summary = resolve_output_path(&session, None, "derived", "snapshot_summary.json");
            write_structured(&mut session, &summary, &report, "forensics-snapshot", "forensics snapshot")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        ForensicsCommand::Sqlite { path, io } => {
            let payload = sqlite_inventory(&path)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(
                &session,
                io.output,
                "derived",
                &format!(
                    "{}_sqlite.json",
                    path.file_stem().and_then(|value| value.to_str()).unwrap_or("database")
                ),
            );
            write_structured(&mut session, &output, &payload, "forensics-sqlite", "forensics sqlite")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ForensicsCommand::Timeline { sources, io } => {
            let events = build_timeline(&sources)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "timeline.json");
            write_structured(&mut session, &output, &events, "forensics-timeline", "forensics timeline")?;
            println!("{}", serde_json::to_string_pretty(&events)?);
            Ok(())
        }
        ForensicsCommand::Parse { source_dir, io } => {
            let payload = inventory_dir(&source_dir)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "parse_inventory.json");
            write_structured(&mut session, &output, &payload, "forensics-parse", "forensics parse")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ForensicsCommand::DecodeProtobuf { path, io } => {
            let payload = decode_protobuf_like(&path)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(
                &session,
                io.output,
                "derived",
                &format!(
                    "{}_protobuf.json",
                    path.file_stem().and_then(|value| value.to_str()).unwrap_or("protobuf")
                ),
            );
            write_structured(
                &mut session,
                &output,
                &payload,
                "forensics-protobuf",
                "forensics decode-protobuf",
            )?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ForensicsCommand::Correlate { inputs, io } => {
            let payload = correlate_inputs(&inputs)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "correlation.json");
            write_structured(&mut session, &output, &payload, "forensics-correlation", "forensics correlate")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ForensicsCommand::Recover { db_path, io } => {
            let payload = recover_sqlite_sidecars(&db_path)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "recovery.json");
            write_structured(&mut session, &output, &payload, "forensics-recovery", "forensics recover")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ForensicsCommand::Carve {
            input_path,
            output_dir,
            source,
            io,
            max_matches,
        } => {
            fs::create_dir_all(&output_dir)?;
            let payload = carve_patterns(&input_path, &source, max_matches)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, Some(output_dir.clone()))?;
            let output = output_dir.join("carved_matches.json");
            write_structured(&mut session, &output, &payload, "forensics-carve", "forensics carve")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
    }
}

/// Default forensics paths to snapshot if --path is not specified.
/// These are common locations for forensics artifacts and artifacts recovery.
fn default_snapshot_paths() -> &'static [&'static str] {
    &[
        "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/data/com.android.providers.contacts/databases/calllog.db",
        "/data/data/com.android.chrome/app_chrome/Default/History",
        "/data/data/com.whatsapp/databases/msgstore.db",
        "/sdcard/DCIM",
        "/sdcard/Download",
    ]
}
