use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::adb::AdbClient;
use crate::app::Result;
use crate::modules::apk::analyze_apk;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityFinding {
    pub id: String,
    pub severity: String,
    pub message: String,
}

pub fn device_scan(adb: &AdbClient, serial: &str) -> Result<serde_json::Value> {
    let selinux = adb.shell(serial, &["getenforce".to_string()])?;
    let verified_boot = adb.shell(serial, &["getprop".to_string(), "ro.boot.verifiedbootstate".to_string()])?;
    let flash_locked = adb.shell(serial, &["getprop".to_string(), "ro.boot.flash.locked".to_string()])?;
    let debuggable = adb.shell(serial, &["getprop".to_string(), "ro.debuggable".to_string()])?;

    let mut findings = Vec::new();
    if selinux.trim() != "Enforcing" {
        findings.push(SecurityFinding {
            id: "selinux".to_string(),
            severity: "high".to_string(),
            message: format!("SELinux is not enforcing: {}", selinux.trim()),
        });
    }
    if verified_boot.trim() != "green" {
        findings.push(SecurityFinding {
            id: "verified-boot".to_string(),
            severity: "medium".to_string(),
            message: format!("Verified Boot state is {}", verified_boot.trim()),
        });
    }
    if flash_locked.trim() != "1" {
        findings.push(SecurityFinding {
            id: "bootloader".to_string(),
            severity: "medium".to_string(),
            message: "Bootloader appears unlocked".to_string(),
        });
    }
    if debuggable.trim() == "1" {
        findings.push(SecurityFinding {
            id: "debuggable".to_string(),
            severity: "medium".to_string(),
            message: "System image is debuggable".to_string(),
        });
    }

    Ok(serde_json::json!({
        "serial": serial,
        "selinux": selinux,
        "verified_boot": verified_boot,
        "flash_locked": flash_locked,
        "debuggable": debuggable,
        "findings": findings,
        "owasp": ["M1", "M2", "M9"],
    }))
}

pub fn malware_scan(target: &Path, patterns: &[String]) -> Result<serde_json::Value> {
    let haystack = String::from_utf8_lossy(&fs::read(target)?).to_string();
    let matches = patterns
        .iter()
        .map(|pattern| serde_json::json!({
            "pattern": pattern,
            "count": haystack.matches(pattern).count(),
        }))
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "target": target,
        "matches": matches,
    }))
}

pub fn network_scan(adb: &AdbClient, serial: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "serial": serial,
        "ip_addr": adb.shell(serial, &["ip".to_string(), "addr".to_string()])?,
        "ip_route": adb.shell(serial, &["ip".to_string(), "route".to_string()])?,
        "ss": adb.shell(serial, &["ss".to_string(), "-tunap".to_string()]).unwrap_or_default(),
    }))
}

pub fn bootloader_info(adb: &AdbClient, serial: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "serial": serial,
        "flash_locked": adb.shell(serial, &["getprop".to_string(), "ro.boot.flash.locked".to_string()])?,
        "verified_boot": adb.shell(serial, &["getprop".to_string(), "ro.boot.verifiedbootstate".to_string()])?,
        "vbmeta_state": adb.shell(serial, &["getprop".to_string(), "ro.boot.vbmeta.device_state".to_string()]).unwrap_or_default(),
    }))
}

pub fn hardware_info(adb: &AdbClient, serial: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "serial": serial,
        "fingerprint": adb.shell(serial, &["getprop".to_string(), "ro.build.fingerprint".to_string()])?,
        "hardware": adb.shell(serial, &["getprop".to_string(), "ro.hardware".to_string()])?,
        "soc_model": adb.shell(serial, &["getprop".to_string(), "ro.soc.model".to_string()]).unwrap_or_default(),
    }))
}

pub fn attack_surface_from_apk(path: &Path) -> Result<serde_json::Value> {
    let analysis = analyze_apk(path)?;
    Ok(serde_json::json!({
        "apk_path": analysis.apk_path,
        "high_risk_permissions": analysis.high_risk_permissions,
        "native_libs": analysis.native_libs,
        "findings": analysis.findings,
        "owasp": analysis.owasp,
    }))
}

pub fn map_owasp(artifacts_path: &Path) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(artifacts_path)?)?;
    let text = value.to_string();
    let mut categories = Vec::new();
    if text.contains("permission") {
        categories.push("M2");
    }
    if text.contains("debuggable") || text.contains("SELinux") {
        categories.push("M8");
    }
    if text.contains("http://") {
        categories.push("M5");
    }
    categories.sort();
    categories.dedup();
    Ok(serde_json::json!({
        "artifacts": artifacts_path,
        "owasp_categories": categories,
    }))
}
