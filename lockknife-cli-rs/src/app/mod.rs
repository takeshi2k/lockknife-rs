pub mod config;
pub mod errors;

use crate::adb::AdbClient;
pub use config::Config;
pub use errors::{LockKnifeError, Result};

#[derive(Debug, Clone, Copy)]
pub enum FeatureFlag {
    DisableFrida,
    DisablePdfReports,
    BestEffortCredentialExtras,
}

#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    pub adb: AdbClient,
}

#[derive(Debug, Clone)]
pub struct AppContext {
    pub config: Config,
    #[allow(dead_code)]
    pub feature_flags: Vec<FeatureFlag>,
    pub services: ServiceRegistry,
}

impl AppContext {
    pub fn boot(config: Config) -> Result<Self> {
        let adb = AdbClient::new(config.adb_path.clone());
        Ok(Self {
            config,
            feature_flags: vec![
                FeatureFlag::DisableFrida,
                FeatureFlag::DisablePdfReports,
                FeatureFlag::BestEffortCredentialExtras,
            ],
            services: ServiceRegistry { adb },
        })
    }
}

pub fn deferred_feature(name: &'static str) -> LockKnifeError {
    let reason = match name {
        "frida" => "Frida is intentionally disabled in the Rust-first migration phase",
        "pdf-report" => "PDF reports are intentionally disabled in the Rust-first migration phase; use HTML instead",
        "yara-rule-scan" => "YARA rule-based scanning lives in the parked lockknife-core crate (yara-x) and is not wired into the Rust-first CLI yet; rerun without --yara to use --pattern substring matching instead",
        _ => "This capability is intentionally deferred in the Rust-first migration phase",
    };
    LockKnifeError::deferred(name, reason)
}

pub fn delegated_sidecar(name: &'static str) -> LockKnifeError {
    LockKnifeError::message(format!(
        "{name} remains an external sidecar or later-phase migration target"
    ))
}

pub fn best_effort_feature(name: &'static str) -> LockKnifeError {
    LockKnifeError::message(format!(
        "{name} is intentionally left as a best-effort external capability in this phase"
    ))
}
