use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::app::{LockKnifeError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct ApkAnalysis {
    pub apk_path: String,
    pub sha256: String,
    pub file_size: u64,
    pub manifest_present: bool,
    pub dex_files: Vec<String>,
    pub native_libs: Vec<String>,
    pub permissions: Vec<String>,
    pub high_risk_permissions: Vec<String>,
    pub findings: Vec<String>,
    pub owasp: Vec<String>,
}

pub fn decompile_archive(apk_path: &Path, output_dir: &Path) -> Result<serde_json::Value> {
    fs::create_dir_all(output_dir)?;
    let file = fs::File::open(apk_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut extracted = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let out_path = output_dir.join(entry.name());
        if entry.name().ends_with('/') {
            fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out_file = fs::File::create(&out_path)?;
        std::io::copy(&mut entry, &mut out_file)?;
        extracted.push(out_path.display().to_string());
    }
    Ok(serde_json::json!({
        "apk_path": apk_path,
        "output_dir": output_dir,
        "extracted_files": extracted.len(),
        "files": extracted,
    }))
}

pub fn analyze_apk(apk_path: &Path) -> Result<ApkAnalysis> {
    let bytes = fs::read(apk_path)?;
    let digest = Sha256::digest(&bytes);
    let file = fs::File::open(apk_path)?;
    let mut archive = ZipArchive::new(file)?;
    let mut dex_files = Vec::new();
    let mut native_libs = Vec::new();
    let mut manifest_present = false;
    let mut permission_strings = BTreeSet::new();
    let perm_re = Regex::new(r"android\.permission\.[A-Z0-9_\.]+")
        .map_err(|err| LockKnifeError::message(err.to_string()))?;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_string();
        if name == "AndroidManifest.xml" {
            manifest_present = true;
        }
        if name.ends_with(".dex") {
            dex_files.push(name.clone());
        }
        if name.starts_with("lib/") && name.ends_with(".so") {
            native_libs.push(name.clone());
        }
        let mut buf = Vec::new();
        if entry.size() <= 2_000_000 {
            entry.read_to_end(&mut buf)?;
            let haystack = String::from_utf8_lossy(&buf);
            for capture in perm_re.find_iter(&haystack) {
                permission_strings.insert(capture.as_str().to_string());
            }
        }
    }

    let permissions = permission_strings.into_iter().collect::<Vec<_>>();
    let high_risk_permissions = permissions
        .iter()
        .filter(|permission| {
            [
                "READ_SMS",
                "READ_CONTACTS",
                "ACCESS_FINE_LOCATION",
                "READ_CALL_LOG",
                "REQUEST_INSTALL_PACKAGES",
                "QUERY_ALL_PACKAGES",
                "SYSTEM_ALERT_WINDOW",
            ]
            .iter()
            .any(|needle| permission.contains(needle))
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut findings = Vec::new();
    if !manifest_present {
        findings.push("AndroidManifest.xml was not found in the archive".to_string());
    }
    if !native_libs.is_empty() {
        findings.push("Native shared libraries are present".to_string());
    }
    if !high_risk_permissions.is_empty() {
        findings.push("High-risk Android permissions were detected".to_string());
    }

    let mut owasp = Vec::new();
    if !high_risk_permissions.is_empty() {
        owasp.push("M2: Inadequate Supply Chain Security / privilege review".to_string());
        owasp.push("M3: Insecure Authentication / authorization exposure review".to_string());
    }
    if !native_libs.is_empty() {
        owasp.push("M7: Client Code Quality and binary attack surface".to_string());
    }

    Ok(ApkAnalysis {
        apk_path: apk_path.display().to_string(),
        sha256: hex::encode(digest),
        file_size: bytes.len() as u64,
        manifest_present,
        dex_files,
        native_libs,
        permissions,
        high_risk_permissions,
        findings,
        owasp,
    })
}

pub fn scan_file_for_patterns(path: &Path, patterns: &[String]) -> Result<serde_json::Value> {
    let bytes = fs::read(path)?;
    let haystack = String::from_utf8_lossy(&bytes);
    let matches = patterns
        .iter()
        .map(|pattern| {
            let count = haystack.matches(pattern).count();
            serde_json::json!({
                "pattern": pattern,
                "count": count,
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "target": path,
        "matches": matches,
    }))
}

pub fn default_decompile_output(apk_path: &Path) -> PathBuf {
    let stem = apk_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("apk");
    PathBuf::from(format!("{stem}_decompiled"))
}
