pub mod apk;
pub mod credentials;
pub mod extraction;
pub mod forensics;
pub mod reporting;
pub mod security;

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::app::{LockKnifeError, Result};
use crate::case::{write_json, write_text, CaseSession};
use crate::cli::OutputFormat;

pub fn resolve_output_path(
    session: &CaseSession,
    explicit: Option<PathBuf>,
    area: &str,
    default_name: &str,
) -> PathBuf {
    explicit.unwrap_or_else(|| session.output_path(area, default_name))
}

pub fn write_structured<T: Serialize>(
    session: &mut CaseSession,
    output: &Path,
    payload: &T,
    category: &str,
    source_command: &str,
) -> Result<()> {
    let json = serde_json::to_value(payload)?;
    write_json(output, &json)?;
    if let Some(artifact) = session.register_path(output, category, source_command, json)? {
        session.append_custody(&artifact, "write", source_command)?;
    }
    Ok(())
}

pub fn default_structured_output_name(default_stem: &str, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(format!("{default_stem}.json")),
        OutputFormat::Text => Ok(format!("{default_stem}.txt")),
        _ => Err(LockKnifeError::message(
            "structured output format must be json or text",
        )),
    }
}

pub fn write_structured_with_format<T, F>(
    session: &mut CaseSession,
    output: &Path,
    format: OutputFormat,
    payload: &T,
    render_text: F,
    category: &str,
    source_command: &str,
) -> Result<serde_json::Value>
where
    T: Serialize,
    F: FnOnce(&serde_json::Value) -> String,
{
    let json = serde_json::to_value(payload)?;
    match format {
        OutputFormat::Json => write_json(output, &json)?,
        OutputFormat::Text => write_text(output, &render_text(&json))?,
        _ => {
            return Err(LockKnifeError::message(
                "structured output format must be json or text",
            ))
        }
    }
    if let Some(artifact) = session.register_path(output, category, source_command, json.clone())? {
        session.append_custody(&artifact, "write", source_command)?;
    }
    Ok(json)
}
