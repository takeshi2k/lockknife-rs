use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use rusqlite::Connection;
use serde::Serialize;
use walkdir::WalkDir;

use crate::app::{LockKnifeError, Result};

#[derive(Debug, Serialize)]
pub struct TimelineEvent {
    pub timestamp: i64,
    pub source: String,
    pub payload: serde_json::Value,
}

pub fn sqlite_inventory(path: &Path) -> Result<serde_json::Value> {
    let connection = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = connection.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY 1",
    )?;
    let tables = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .map_while(|row| row.ok())
        .collect::<Vec<_>>();

    let mut inventory = Vec::new();
    for table in tables {
        let count = connection.query_row(
            &format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\"")),
            [],
            |row| row.get::<_, i64>(0),
        )?;
        inventory.push(serde_json::json!({
            "table": table,
            "row_count": count,
        }));
    }
    Ok(serde_json::json!({
        "db_path": path,
        "tables": inventory,
    }))
}

pub fn build_timeline(paths: &[PathBuf]) -> Result<Vec<TimelineEvent>> {
    let mut events = Vec::new();
    for path in paths {
        let raw = fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        collect_timeline_events(path, &value, &mut events);
    }
    events.sort_by_key(|event| event.timestamp);
    Ok(events)
}

pub fn inventory_dir(source_dir: &Path) -> Result<serde_json::Value> {
    let mut by_extension: BTreeMap<String, u64> = BTreeMap::new();
    let mut files = 0_u64;
    for entry in WalkDir::new(source_dir).into_iter().flatten().filter(|entry| entry.file_type().is_file()) {
        files += 1;
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("<none>")
            .to_ascii_lowercase();
        *by_extension.entry(extension).or_default() += 1;
    }
    Ok(serde_json::json!({
        "source_dir": source_dir,
        "file_count": files,
        "extensions": by_extension,
    }))
}

pub fn decode_protobuf_like(path: &Path) -> Result<serde_json::Value> {
    let bytes = fs::read(path)?;
    let mut varints = Vec::new();
    let mut current = 0_u64;
    let mut shift = 0_u32;
    for byte in bytes.iter().copied().take(512) {
        current |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            varints.push(current);
            current = 0;
            shift = 0;
        } else {
            shift += 7;
        }
        if varints.len() >= 64 {
            break;
        }
    }
    Ok(serde_json::json!({
        "path": path,
        "size": bytes.len(),
        "prefix_hex": hex::encode(bytes.iter().take(128).copied().collect::<Vec<_>>()),
        "decoded_varints": varints,
    }))
}

pub fn correlate_inputs(inputs: &[PathBuf]) -> Result<serde_json::Value> {
    let mut entity_set: BTreeSet<String> = BTreeSet::new();
    let mut edges: HashMap<(String, String), u64> = HashMap::new();
    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();

    for input in inputs {
        let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(input)?)?;
        let items = match value {
            serde_json::Value::Array(items) => items,
            _ => vec![value],
        };
        for item in items {
            let entities = extract_entities(&item);
            for entity in &entities {
                entity_set.insert(entity.clone());
            }
            for index in 0..entities.len() {
                for j in (index + 1)..entities.len() {
                    let (a, b) = ordered_pair(&entities[index], &entities[j]);
                    *edges.entry((a.clone(), b.clone())).or_default() += 1;
                    adjacency.entry(a.clone()).or_default().push(b.clone());
                    adjacency.entry(b).or_default().push(a);
                }
            }
        }
    }

    let mut clusters = Vec::new();
    let mut visited = HashSet::new();
    for entity in &entity_set {
        if !visited.insert(entity.clone()) {
            continue;
        }
        let mut stack = vec![entity.clone()];
        let mut cluster = Vec::new();
        while let Some(current) = stack.pop() {
            cluster.push(current.clone());
            if let Some(neighbors) = adjacency.get(&current) {
                for neighbor in neighbors {
                    if visited.insert(neighbor.clone()) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }
        cluster.sort();
        clusters.push(cluster);
    }

    Ok(serde_json::json!({
        "entities": entity_set,
        "edges": edges
            .into_iter()
            .map(|((source, target), count)| serde_json::json!({
                "source": source,
                "target": target,
                "count": count,
            }))
            .collect::<Vec<_>>(),
        "clusters": clusters,
    }))
}

pub fn recover_sqlite_sidecars(path: &Path) -> Result<serde_json::Value> {
    let related = ["-wal", "-shm", "-journal"]
        .iter()
        .map(|suffix| path.with_file_name(format!("{}{}", path.file_name().and_then(|v| v.to_str()).unwrap_or("database"), suffix)))
        .filter(|candidate| candidate.exists())
        .map(|candidate| serde_json::json!({
            "path": candidate,
            "size": candidate.metadata().ok().map(|meta| meta.len()),
        }))
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "db_path": path,
        "recoverable_sidecars": related,
    }))
}

pub fn carve_patterns(input_path: &Path, source: &str, max_matches: u32) -> Result<serde_json::Value> {
    let haystack = String::from_utf8_lossy(&fs::read(input_path)?).to_string();
    let regexes = [
        ("email", Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")?),
        ("url", Regex::new(r#"https?://[^\s"'<>]+"#)?),
        ("sha256", Regex::new(r"\b[a-fA-F0-9]{64}\b")?),
    ];
    let mut matches = Vec::new();
    for (kind, regex) in regexes {
        for capture in regex.find_iter(&haystack).take(max_matches as usize) {
            matches.push(serde_json::json!({
                "kind": kind,
                "value": capture.as_str(),
            }));
        }
    }
    Ok(serde_json::json!({
        "source": source,
        "input_path": input_path,
        "matches": matches,
    }))
}

fn collect_timeline_events(path: &Path, value: &serde_json::Value, events: &mut Vec<TimelineEvent>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_timeline_events(path, value, events);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["timestamp", "time", "date", "date_ms", "last_visit_time"] {
                if let Some(value) = map.get(key).and_then(as_i64) {
                    events.push(TimelineEvent {
                        timestamp: value,
                        source: path.display().to_string(),
                        payload: serde_json::Value::Object(map.clone()),
                    });
                    break;
                }
            }
        }
        _ => {}
    }
}

fn as_i64(value: &serde_json::Value) -> Option<i64> {
    match value {
        serde_json::Value::Number(number) => number.as_i64(),
        serde_json::Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    }
}

fn extract_entities(value: &serde_json::Value) -> Vec<String> {
    let keys = ["address", "number", "ssid", "package", "domain", "ip", "url", "sha256"];
    let mut out = Vec::new();
    if let serde_json::Value::Object(map) = value {
        for key in keys {
            if let Some(value) = map.get(key).and_then(|value| value.as_str()) {
                let value = value.trim();
                if !value.is_empty() {
                    out.push(value.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn ordered_pair(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_string(), right.to_string())
    } else {
        (right.to_string(), left.to_string())
    }
}

impl From<regex::Error> for LockKnifeError {
    fn from(value: regex::Error) -> Self {
        LockKnifeError::message(value.to_string())
    }
}
