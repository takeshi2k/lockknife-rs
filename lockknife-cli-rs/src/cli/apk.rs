use std::path::PathBuf;

use crate::app::{deferred_feature, AppContext, Result};
use crate::case::CaseSession;
use crate::cli::ApkCommand;
use crate::modules::apk::{
    analyze_apk, decompile_archive, default_decompile_output, scan_file_for_patterns,
};
use crate::modules::{resolve_output_path, write_structured};

pub fn dispatch_apk(ctx: &AppContext, command: ApkCommand) -> Result<()> {
    match command {
        ApkCommand::Decompile {
            apk_path,
            io,
            mode: _,
        } => {
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output_dir = io.output.unwrap_or_else(|| {
                session.output_root.join(default_decompile_output(&apk_path))
            });
            let payload = decompile_archive(&apk_path, &output_dir)?;
            let report = resolve_output_path(
                &session,
                None,
                "derived",
                &format!(
                    "{}_decompile.json",
                    apk_path.file_stem().and_then(|value| value.to_str()).unwrap_or("apk")
                ),
            );
            write_structured(&mut session, &report, &payload, "apk-decompile", "apk decompile")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ApkCommand::Permissions { apk_path, io } => {
            let analysis = analyze_apk(&apk_path)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(
                &session,
                io.output,
                "derived",
                &format!(
                    "{}_permissions.json",
                    apk_path.file_stem().and_then(|value| value.to_str()).unwrap_or("apk")
                ),
            );
            let payload = serde_json::json!({
                "apk_path": analysis.apk_path,
                "permissions": analysis.permissions,
                "high_risk_permissions": analysis.high_risk_permissions,
            });
            write_structured(&mut session, &output, &payload, "apk-permissions", "apk permissions")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        ApkCommand::Analyze { apk_path, io } | ApkCommand::Vulnerability { apk_path, io } => {
            let analysis = analyze_apk(&apk_path)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(
                &session,
                io.output,
                "derived",
                &format!(
                    "{}_analysis.json",
                    apk_path.file_stem().and_then(|value| value.to_str()).unwrap_or("apk")
                ),
            );
            write_structured(&mut session, &output, &analysis, "apk-analysis", "apk analyze")?;
            println!("{}", serde_json::to_string_pretty(&analysis)?);
            Ok(())
        }
        ApkCommand::Scan {
            yara,
            serial,
            target,
            apk,
            io,
        } => {
            if yara.is_some() {
                return Err(deferred_feature("yara-rule-scan"));
            }

            // Resolve the scan target:
            // 1. If --apk is provided, use it directly (local file).
            // 2. If --serial is provided, defer with explicit error (future enhancement).
            // 3. Otherwise, use --target (fallback positional argument).
            // 4. Error if none are provided.
            let scan_target = if let Some(apk_path) = apk {
                apk_path
            } else if serial.is_some() {
                return Err(crate::app::LockKnifeError::message(
                    "apk scan --serial is deferred; provide --apk with a local APK file instead"
                ));
            } else if let Some(target_path) = target {
                target_path
            } else {
                return Err(crate::app::LockKnifeError::message(
                    "provide --apk or --target"
                ));
            };

            let payload = if scan_target.extension().and_then(|value| value.to_str()) == Some("apk") {
                serde_json::to_value(analyze_apk(&scan_target))?
            } else {
                scan_file_for_patterns(
                    &scan_target,
                    &["http://".to_string(), "https://".to_string(), "token".to_string()],
                )?
            };
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(
                &session,
                io.output,
                "derived",
                &format!(
                    "{}_scan.json",
                    scan_target
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .unwrap_or("target")
                ),
            );
            write_structured(&mut session, &output, &payload, "apk-scan", "apk scan")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
    }
}
