use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::app::{LockKnifeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseManifest {
    pub case_id: String,
    pub title: String,
    pub examiner: String,
    pub created_at_utc: String,
    pub artifacts: Vec<CaseArtifact>,
    pub custody_chain: Vec<ChainOfCustodyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseArtifact {
    pub artifact_id: String,
    pub category: String,
    pub path: String,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub created_at_utc: String,
    pub source_command: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainOfCustodyEntry {
    pub artifact_id: String,
    pub action: String,
    pub source: String,
    pub path: String,
    pub sha256: Option<String>,
    pub timestamp_utc: String,
}

#[derive(Debug, Clone)]
pub struct CaseSession {
    pub case_dir: Option<PathBuf>,
    pub output_root: PathBuf,
    manifest_path: Option<PathBuf>,
    manifest: Option<CaseManifest>,
}

impl CaseManifest {
    pub fn load_or_create(case_dir: &Path) -> Result<Self> {
        let manifest_path = case_dir.join("manifest.json");
        if manifest_path.exists() {
            let raw = fs::read_to_string(&manifest_path)?;
            return Ok(serde_json::from_str(&raw)?);
        }

        Ok(Self {
            case_id: format!("case-{}", Uuid::new_v4()),
            title: "LockKnife case".to_string(),
            examiner: whoami(),
            created_at_utc: Utc::now().to_rfc3339(),
            artifacts: Vec::new(),
            custody_chain: Vec::new(),
        })
    }
}

impl CaseSession {
    pub fn from_case_or_output(case_dir: Option<PathBuf>, output_hint: Option<PathBuf>) -> Result<Self> {
        let output_root = if let Some(case_root) = case_dir.as_ref() {
            fs::create_dir_all(case_root.join("derived"))?;
            fs::create_dir_all(case_root.join("reports"))?;
            fs::create_dir_all(case_root.join("logs"))?;
            case_root.clone()
        } else if let Some(path) = output_hint {
            let root = if path.extension().is_some() {
                path.parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
            } else {
                path
            };
            fs::create_dir_all(&root)?;
            root
        } else {
            PathBuf::from(".")
        };

        let (manifest_path, manifest) = if let Some(case_root) = case_dir.as_ref() {
            let manifest = CaseManifest::load_or_create(case_root)?;
            (Some(case_root.join("manifest.json")), Some(manifest))
        } else {
            (None, None)
        };

        Ok(Self {
            case_dir,
            output_root,
            manifest_path,
            manifest,
        })
    }

    pub fn output_path(&self, area: &str, filename: &str) -> PathBuf {
        if let Some(case_dir) = &self.case_dir {
            return case_dir.join(area).join(filename);
        }
        self.output_root.join(filename)
    }

    pub fn register_path(
        &mut self,
        path: &Path,
        category: impl Into<String>,
        source_command: impl Into<String>,
        metadata: serde_json::Value,
    ) -> Result<Option<CaseArtifact>> {
        if self.manifest.is_none() {
            return Ok(None);
        }

        let sha256 = if path.is_file() {
            Some(sha256_file(path)?)
        } else {
            None
        };
        let size = path.metadata().ok().map(|meta| meta.len());
        let artifact = CaseArtifact {
            artifact_id: Uuid::new_v4().to_string(),
            category: category.into(),
            path: path.display().to_string(),
            sha256,
            size,
            created_at_utc: Utc::now().to_rfc3339(),
            source_command: source_command.into(),
            metadata,
        };
        if let Some(manifest) = self.manifest.as_mut() {
            manifest.artifacts.push(artifact.clone());
        }
        self.save_manifest()?;
        Ok(Some(artifact))
    }

    pub fn append_custody(&mut self, artifact: &CaseArtifact, action: &str, source: &str) -> Result<()> {
        if self.manifest.is_none() {
            return Ok(());
        }
        if let Some(manifest) = self.manifest.as_mut() {
            manifest.custody_chain.push(ChainOfCustodyEntry {
                artifact_id: artifact.artifact_id.clone(),
                action: action.to_string(),
                source: source.to_string(),
                path: artifact.path.clone(),
                sha256: artifact.sha256.clone(),
                timestamp_utc: Utc::now().to_rfc3339(),
            });
        }
        self.save_manifest()
    }

    pub fn manifest(&self) -> Option<&CaseManifest> {
        self.manifest.as_ref()
    }

    pub fn verify_integrity(&self) -> Result<serde_json::Value> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| LockKnifeError::message("integrity verification requires --case-dir"))?;

        let mut verified = 0_u64;
        let mut modified = Vec::new();
        let mut missing = Vec::new();

        for artifact in &manifest.artifacts {
            let path = PathBuf::from(&artifact.path);
            if !path.exists() {
                missing.push(artifact.path.clone());
                continue;
            }
            if let Some(expected) = &artifact.sha256 {
                let actual = sha256_file(&path)?;
                if &actual == expected {
                    verified += 1;
                } else {
                    modified.push(serde_json::json!({
                        "path": artifact.path.clone(),
                        "expected": expected,
                        "actual": actual,
                    }));
                }
            }
        }

        Ok(serde_json::json!({
            "case_id": manifest.case_id,
            "examiner": manifest.examiner,
            "verified_at_utc": Utc::now().to_rfc3339(),
            "summary": {
                "artifact_count": manifest.artifacts.len(),
                "verified_count": verified,
                "modified_count": modified.len(),
                "missing_count": missing.len(),
            },
            "modified": modified,
            "missing": missing,
            "custody_chain": {
                "entry_count": manifest.custody_chain.len(),
                "status": if modified.is_empty() && missing.is_empty() { "ok" } else { "attention" },
            }
        }))
    }

    fn save_manifest(&self) -> Result<()> {
        if let (Some(path), Some(manifest)) = (&self.manifest_path, &self.manifest) {
            fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| LockKnifeError::message("invalid manifest path"))?,
            )?;
            fs::write(path, serde_json::to_vec_pretty(manifest)?)?;
        }
        Ok(())
    }
}

pub fn write_json(path: &Path, payload: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(payload)?)?;
    Ok(())
}

pub fn write_text(path: &Path, payload: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, payload)?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "examiner".to_string())
}
