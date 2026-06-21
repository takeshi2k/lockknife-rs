use std::path::Path;
use std::process::Command;

use serde::Serialize;

use crate::app::{LockKnifeError, Result};

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub serial: String,
    pub state: String,
    pub model: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AdbClient {
    adb_path: String,
}

impl AdbClient {
    pub fn new(adb_path: String) -> Self {
        Self { adb_path }
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let output = self.run(["devices", "-l"])?;
        Ok(parse_devices(&output))
    }

    pub fn connect(&self, host: &str) -> Result<String> {
        self.run(["connect", host])
    }

    pub fn shell(&self, serial: &str, command: &[String]) -> Result<String> {
        let mut args = vec!["-s".to_string(), serial.to_string(), "shell".to_string()];
        args.extend(command.iter().cloned());
        self.run_owned(args)
    }

    pub fn getprop(&self, serial: &str) -> Result<String> {
        self.shell(serial, &["getprop".to_string()])
    }

    pub fn pull(&self, serial: &str, remote_path: &str, local_path: &Path) -> Result<String> {
        self.run_owned(vec![
            "-s".to_string(),
            serial.to_string(),
            "pull".to_string(),
            remote_path.to_string(),
            local_path.display().to_string(),
        ])
    }

    pub fn target_serial(&self, explicit: Option<&str>) -> Result<String> {
        if let Some(serial) = explicit {
            return Ok(serial.to_string());
        }
        let devices = self
            .list_devices()?
            .into_iter()
            .filter(|device| device.state == "device")
            .collect::<Vec<_>>();
        match devices.as_slice() {
            [only] => Ok(only.serial.clone()),
            [] => Err(LockKnifeError::DeviceSelection(
                "no authorized device is connected".to_string(),
            )),
            _ => Err(LockKnifeError::DeviceSelection(
                "multiple devices are connected; provide --serial".to_string(),
            )),
        }
    }

    /// Resolve the installed package path via `pm path <package>`.
    /// Returns the full path to the APK on the device (e.g., /data/app/.../base.apk).
    pub fn pm_path(&self, serial: &str, package: &str) -> Result<String> {
        let output = self.shell(serial, &["pm".to_string(), "path".to_string(), package.to_string()])?;
        // Output is typically "package:/data/app/..."
        output
            .strip_prefix("package:")
            .map(|s| s.trim().to_string())
            .ok_or_else(|| LockKnifeError::message(format!("pm path returned unexpected format: {}", output)))
    }

    /// List all installed packages on the device.
    /// Returns a vector of package names (e.g., ["com.android.chrome", "com.whatsapp", ...]).
    pub fn pm_list_packages(&self, serial: &str) -> Result<Vec<String>> {
        let output = self.shell(serial, &["pm".to_string(), "list".to_string(), "packages".to_string()])?;
        Ok(output
            .lines()
            .filter_map(|line| line.strip_prefix("package:").map(|s| s.to_string()))
            .collect())
    }

    /// Find and return the path to an installed package by name.
    /// Wrapper around pm_path for convenience; returns the device path to the APK.
    pub fn pm_get_package_by_name(&self, serial: &str, package: &str) -> Result<String> {
        self.pm_path(serial, package)
    }

    fn run<const N: usize>(&self, args: [&str; N]) -> Result<String> {
        self.run_owned(args.iter().map(|item| item.to_string()).collect())
    }

    fn run_owned(&self, args: Vec<String>) -> Result<String> {
        let output = Command::new(&self.adb_path).args(&args).output()?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        Err(LockKnifeError::CommandFailed {
            program: self.adb_path.clone(),
            args,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn parse_devices(output: &str) -> Vec<DeviceInfo> {
    output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let mut parts = line.split_whitespace();
            let serial = parts.next()?.to_string();
            let state = parts.next()?.to_string();
            let mut model = None;
            let mut device = None;
            let mut transport_id = None;
            for token in parts {
                if let Some(value) = token.strip_prefix("model:") {
                    model = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("device:") {
                    device = Some(value.to_string());
                } else if let Some(value) = token.strip_prefix("transport_id:") {
                    transport_id = Some(value.to_string());
                }
            }
            Some(DeviceInfo {
                serial,
                state,
                model,
                device,
                transport_id,
            })
        })
        .collect()
}
