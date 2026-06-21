use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::errors::{LockKnifeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub log_level: String,
    pub log_format: String,
    pub adb_path: String,
    pub case_root: Option<PathBuf>,
    pub signing_key_source: Option<String>,
    pub disable_frida: bool,
    pub disable_pdf_reports: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: "INFO".to_string(),
            log_format: "console".to_string(),
            adb_path: "adb".to_string(),
            case_root: None,
            signing_key_source: None,
            disable_frida: true,
            disable_pdf_reports: true,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ConfigEnvelope {
    Root(Config),
    Nested { lockknife: Config },
}

impl Config {
    pub fn load_with_legacy_compat(path: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = path {
            return Self::load_from_path(&path);
        }

        if let Ok(path) = env::var("LOCKKNIFE_CONFIG") {
            return Self::load_from_path(Path::new(&path));
        }

        for path in candidate_config_paths() {
            if path.exists() {
                return Self::load_from_path(&path);
            }
        }

        for path in candidate_legacy_paths() {
            if path.exists() {
                return Self::load_legacy(&path);
            }
        }

        Ok(Self::default())
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(LockKnifeError::MissingFile(path.to_path_buf()));
        }

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("toml") => {
                let raw = fs::read_to_string(path)?;
                let parsed: ConfigEnvelope = toml::from_str(&raw)?;
                let mut config = match parsed {
                    ConfigEnvelope::Root(config) => config,
                    ConfigEnvelope::Nested { lockknife } => lockknife,
                };
                config.enforce_migration_policy();
                Ok(config)
            }
            _ => Self::load_legacy(path),
        }
    }

    fn load_legacy(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let legacy = parse_legacy_kv(&raw);
        let mut config = Self::default();
        if let Some(value) = legacy.get("log_level").or_else(|| legacy.get("loglevel")) {
            config.log_level = value.clone();
        }
        if let Some(value) = legacy.get("log_format").or_else(|| legacy.get("logformat")) {
            config.log_format = value.clone();
        }
        if let Some(value) = legacy.get("adb_path").or_else(|| legacy.get("adb")) {
            config.adb_path = value.clone();
        }
        if let Some(value) = legacy.get("case_root") {
            config.case_root = Some(PathBuf::from(value));
        }
        if let Some(value) = legacy.get("signing_key_source") {
            config.signing_key_source = Some(value.clone());
        }
        config.enforce_migration_policy();
        Ok(config)
    }

    fn enforce_migration_policy(&mut self) {
        self.disable_frida = true;
        self.disable_pdf_reports = true;
        if self.adb_path.trim().is_empty() {
            self.adb_path = "adb".to_string();
        }
        if self.log_level.trim().is_empty() {
            self.log_level = "INFO".to_string();
        }
        if self.log_format.trim().is_empty() {
            self.log_format = "console".to_string();
        }
    }
}

fn parse_legacy_kv(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || !line.contains('=') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_ascii_lowercase(),
                value.trim().trim_matches('"').trim_matches('\'').to_string(),
            ))
        })
        .collect()
}

fn candidate_config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("lockknife.toml")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".config/lockknife/lockknife.toml"));
        paths.push(home.join(".lockknife.toml"));
    }
    paths.push(PathBuf::from("/etc/lockknife.toml"));
    paths
}

fn candidate_legacy_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("lockknife.conf")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".config/lockknife/lockknife.conf"));
        paths.push(home.join(".lockknife.conf"));
    }
    paths.push(PathBuf::from("/etc/lockknife.conf"));
    paths
}
