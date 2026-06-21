use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;

use crate::app::{deferred_feature, LockKnifeError, Result};
use crate::case::{write_json, write_text, CaseSession};
use crate::cli::OutputFormat;
use crate::modules::write_structured_with_format;

#[derive(Debug, Clone, Serialize)]
pub struct ReportContext {
    pub generated_at_utc: String,
    pub template: String,
    pub case_id: Option<String>,
    pub artifacts: serde_json::Value,
}

pub fn load_report_context(
    case_dir: Option<PathBuf>,
    case_id: Option<String>,
    artifacts_path: Option<PathBuf>,
    template: &str,
) -> Result<(CaseSession, ReportContext)> {
    let session = CaseSession::from_case_or_output(case_dir.clone(), None)?;
    let resolved_case_id = case_id.or_else(|| session.manifest().map(|manifest| manifest.case_id.clone()));
    let artifacts = if let Some(path) = artifacts_path {
        serde_json::from_str(&fs::read_to_string(path)?)?
    } else if let Some(manifest) = session.manifest() {
        serde_json::to_value(manifest)?
    } else {
        serde_json::json!({
            "message": "no case manifest or artifacts file was provided"
        })
    };
    Ok((
        session,
        ReportContext {
            generated_at_utc: Utc::now().to_rfc3339(),
            template: template.to_string(),
            case_id: resolved_case_id,
            artifacts,
        },
    ))
}

pub fn write_report(
    session: &mut CaseSession,
    context: &ReportContext,
    format: OutputFormat,
    output: &Path,
) -> Result<()> {
    match format {
        OutputFormat::Html => {
            write_text(output, &render_html(context))?;
            register_report(session, output, "report-html", "report generate")
        }
        OutputFormat::Json => {
            write_json(output, &serde_json::to_value(context)?)?;
            register_report(session, output, "report-json", "report generate")
        }
        OutputFormat::Csv => {
            write_csv(output, &context.artifacts)?;
            register_report(session, output, "report-csv", "report generate")
        }
        OutputFormat::Pdf => Err(deferred_feature("pdf-report")),
        _ => Err(LockKnifeError::message("report format must be html, json, or csv")),
    }
}

pub fn write_chain_of_custody(
    session: &mut CaseSession,
    format: OutputFormat,
    case_id: String,
    examiner: String,
    notes: &str,
    evidence: &[PathBuf],
    output: &Path,
) -> Result<()> {
    let payload = serde_json::json!({
        "case_id": case_id,
        "examiner": examiner,
        "notes": notes,
        "evidence": evidence.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "generated_at_utc": Utc::now().to_rfc3339(),
        "custody_entries": session
            .manifest()
            .map(|manifest| manifest.custody_chain.clone())
            .unwrap_or_default(),
    });
    match format {
        OutputFormat::Html => write_text(output, &render_chain_html(&payload))?,
        OutputFormat::Text => write_text(output, &render_chain_text(&payload))?,
        _ => return Err(LockKnifeError::message("chain-of-custody supports text or html")),
    }
    register_report(session, output, "chain-of-custody", "report chain-of-custody")
}

pub fn write_integrity(
    session: &mut CaseSession,
    format: OutputFormat,
    output: &Path,
) -> Result<serde_json::Value> {
    let payload = session.verify_integrity()?;
    write_structured_with_format(
        session,
        output,
        format,
        &payload,
        render_integrity_text,
        "report-integrity",
        "report integrity",
    )
}

fn register_report(
    session: &mut CaseSession,
    output: &Path,
    category: &str,
    source_command: &str,
) -> Result<()> {
    if let Some(artifact) = session.register_path(
        output,
        category,
        source_command,
        serde_json::json!({ "area": "reports" }),
    )? {
        session.append_custody(&artifact, "write", source_command)?;
    }
    Ok(())
}

fn render_html(context: &ReportContext) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>LockKnife report</title>\
         <style>body{{font-family:system-ui,sans-serif;margin:2rem;}}pre{{white-space:pre-wrap;background:#f5f5f5;padding:1rem;border-radius:8px;}}</style></head>\
         <body><h1>LockKnife {}</h1><p>Generated at {}</p><p>Case: {}</p><pre>{}</pre></body></html>",
        context.template,
        context.generated_at_utc,
        context.case_id.clone().unwrap_or_else(|| "n/a".to_string()),
        serde_json::to_string_pretty(&context.artifacts).unwrap_or_else(|_| "{}".to_string())
    )
}

fn write_csv(output: &Path, artifacts: &serde_json::Value) -> Result<()> {
    let mut writer = csv::Writer::from_path(output)?;
    writer.write_record(["kind", "value"])?;
    match artifacts {
        serde_json::Value::Array(items) => {
            for item in items {
                writer.write_record(["artifact", &item.to_string()])?;
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                writer.write_record([key, &value.to_string()])?;
            }
        }
        _ => writer.write_record(["artifact", &artifacts.to_string()])?,
    }
    writer.flush()?;
    Ok(())
}

fn render_chain_text(payload: &serde_json::Value) -> String {
    format!(
        "Case: {}\nExaminer: {}\nGenerated: {}\nNotes: {}\nEvidence:\n{}\n",
        payload.get("case_id").and_then(|value| value.as_str()).unwrap_or("n/a"),
        payload.get("examiner").and_then(|value| value.as_str()).unwrap_or("n/a"),
        payload
            .get("generated_at_utc")
            .and_then(|value| value.as_str())
            .unwrap_or("n/a"),
        payload.get("notes").and_then(|value| value.as_str()).unwrap_or(""),
        payload
            .get("evidence")
            .and_then(|value| value.as_array())
            .map(|items| items.iter().filter_map(|item| item.as_str()).collect::<Vec<_>>().join("\n"))
            .unwrap_or_default()
    )
}

fn render_chain_html(payload: &serde_json::Value) -> String {
    format!(
        "<!doctype html><html><body><h1>Chain of Custody</h1><pre>{}</pre></body></html>",
        serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string())
    )
}

fn render_integrity_text(payload: &serde_json::Value) -> String {
    serde_json::to_string_pretty(payload).unwrap_or_else(|_| "{}".to_string())
}
