use std::time::Instant;

use crate::app::{best_effort_feature, AppContext, Result};
use crate::case::CaseSession;
use crate::cli::{CaseOutputArgs, CrackCommand, OutputFormat};
use crate::modules::credentials::{crack_pin_hash, dictionary_attack, dictionary_attack_rules, CrackMetadata};
use crate::modules::{
    default_structured_output_name, resolve_output_path, write_structured_with_format,
};

pub fn dispatch_crack(_ctx: &AppContext, command: CrackCommand) -> Result<()> {
    match command {
        CrackCommand::Pin {
            hash,
            algo,
            length,
            format,
            io,
        } => {
            let started = Instant::now();
            let metadata = crack_pin_hash(&hash, &algo, length)?;
            let payload = crack_payload(serde_json::json!({
                "mode": "pin",
                "algorithm": algo,
                "length": length,
                "target_hash_hex_length": hash.len(),
            }), metadata, started.elapsed().as_millis());
            emit_crack_payload(
                io,
                format,
                "crack_pin",
                "credential-pin",
                "crack pin",
                &payload,
            )?;
            Ok(())
        }
        CrackCommand::Password {
            hash,
            algo,
            wordlist,
            format,
            io,
        } => {
            let started = Instant::now();
            let metadata = dictionary_attack(&hash, &algo, &wordlist)?;
            let payload = crack_payload(serde_json::json!({
                "mode": "password",
                "algorithm": algo,
                "wordlist": wordlist,
                "target_hash_hex_length": hash.len(),
            }), metadata, started.elapsed().as_millis());
            emit_crack_payload(
                io,
                format,
                "crack_password",
                "credential-password",
                "crack password",
                &payload,
            )?;
            Ok(())
        }
        CrackCommand::PasswordRules {
            hash,
            algo,
            wordlist,
            max_suffix,
            format,
            io,
        } => {
            let started = Instant::now();
            let metadata = dictionary_attack_rules(&hash, &algo, &wordlist, max_suffix)?;
            let payload = crack_payload(serde_json::json!({
                "mode": "password-rules",
                "algorithm": algo,
                "wordlist": wordlist,
                "max_suffix": max_suffix,
                "target_hash_hex_length": hash.len(),
            }), metadata, started.elapsed().as_millis());
            emit_crack_payload(
                io,
                format,
                "crack_password_rules",
                "credential-password-rules",
                "crack password-rules",
                &payload,
            )?;
            Ok(())
        }
        CrackCommand::Gesture { .. } => Err(best_effort_feature("gesture cracking")),
        CrackCommand::Wifi { .. } => Err(best_effort_feature("WiFi credential cracking")),
        CrackCommand::Keystore { .. } => Err(best_effort_feature("keystore cracking")),
        CrackCommand::Passkeys { .. } => Err(best_effort_feature("passkey cracking")),
    }
}

fn emit_crack_payload(
    io: CaseOutputArgs,
    format: OutputFormat,
    default_stem: &str,
    category: &str,
    source_command: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
    let default_name = default_structured_output_name(default_stem, format)?;
    let output = resolve_output_path(&session, io.output, "derived", &default_name);
    let persisted = write_structured_with_format(
        &mut session,
        output.as_path(),
        format,
        payload,
        render_crack_text,
        category,
        source_command,
    )?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&persisted)?),
        OutputFormat::Text => println!("{}", render_crack_text(&persisted)),
        _ => {}
    }
    Ok(())
}

fn crack_payload(
    summary: serde_json::Value,
    metadata: CrackMetadata,
    elapsed_ms: u128,
) -> serde_json::Value {
    serde_json::json!({
        "summary": summary,
        "result": {
            "matched": metadata.matched,
            "recovered_secret": metadata.recovered_secret,
        },
        "metadata": {
            "strategy": metadata.strategy,
            "candidate_space": metadata.candidate_space,
            "input_size": metadata.input_size,
            "elapsed_ms": elapsed_ms,
        }
    })
}

fn render_crack_text(payload: &serde_json::Value) -> String {
    let summary = payload.get("summary").cloned().unwrap_or_default();
    let result = payload.get("result").cloned().unwrap_or_default();
    let metadata = payload.get("metadata").cloned().unwrap_or_default();

    format!(
        "Mode: {}\nAlgorithm: {}\nMatched: {}\nRecovered secret: {}\nCandidate space: {}\nInput size: {}\nElapsed ms: {}\nStrategy: {}\n",
        summary.get("mode").and_then(|value| value.as_str()).unwrap_or("n/a"),
        summary.get("algorithm").and_then(|value| value.as_str()).unwrap_or("n/a"),
        result.get("matched").and_then(|value| value.as_bool()).unwrap_or(false),
        result
            .get("recovered_secret")
            .and_then(|value| value.as_str())
            .unwrap_or("n/a"),
        metadata
            .get("candidate_space")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        metadata
            .get("input_size")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        metadata
            .get("elapsed_ms")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        metadata
            .get("strategy")
            .and_then(|value| value.as_str())
            .unwrap_or("n/a"),
    )
}
