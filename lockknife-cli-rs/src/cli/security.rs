use crate::app::{deferred_feature, AppContext, Result};
use crate::case::CaseSession;
use crate::cli::SecurityCommand;
use crate::modules::security::{
    attack_surface_from_apk, bootloader_info, device_scan, hardware_info, malware_scan, map_owasp,
    network_scan,
};
use crate::modules::{resolve_output_path, write_structured};

pub fn dispatch_security(ctx: &AppContext, command: SecurityCommand) -> Result<()> {
    match command {
        SecurityCommand::Scan { serial, io } => {
            let payload = device_scan(&ctx.services.adb, &serial)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "security_scan.json");
            write_structured(&mut session, &output, &payload, "security-scan", "security scan")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::Selinux { serial, io } => {
            let payload = serde_json::json!({
                "serial": serial,
                "getenforce": ctx.services.adb.shell(&serial, &["getenforce".to_string()])?,
            });
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "selinux.json");
            write_structured(&mut session, &output, &payload, "security-selinux", "security selinux")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::Malware {
            yara,
            patterns,
            target,
            io,
        } => {
            if yara.is_some() {
                return Err(deferred_feature("yara-rule-scan"));
            }
            let payload = malware_scan(&target, &patterns)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "malware_scan.json");
            write_structured(&mut session, &output, &payload, "security-malware", "security malware")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::NetworkScan { serial, io } => {
            let payload = network_scan(&ctx.services.adb, &serial)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "network_scan.json");
            write_structured(&mut session, &output, &payload, "security-network", "security network-scan")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::Bootloader { serial, io } => {
            let payload = bootloader_info(&ctx.services.adb, &serial)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "bootloader.json");
            write_structured(&mut session, &output, &payload, "security-bootloader", "security bootloader")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::Hardware { serial, io } => {
            let payload = hardware_info(&ctx.services.adb, &serial)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "hardware.json");
            write_structured(&mut session, &output, &payload, "security-hardware", "security hardware")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::AttackSurface { apk, io, .. } => {
            let apk =
                apk.ok_or_else(|| crate::app::LockKnifeError::message("provide --apk for attack-surface"))?;
            let payload = attack_surface_from_apk(&apk)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "attack_surface.json");
            write_structured(&mut session, &output, &payload, "security-attack-surface", "security attack-surface")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        SecurityCommand::Owasp { artifacts, io } => {
            let payload = map_owasp(&artifacts)?;
            let mut session = CaseSession::from_case_or_output(io.case_dir, io.output.clone())?;
            let output = resolve_output_path(&session, io.output, "derived", "owasp.json");
            write_structured(&mut session, &output, &payload, "security-owasp", "security owasp")?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
    }
}
