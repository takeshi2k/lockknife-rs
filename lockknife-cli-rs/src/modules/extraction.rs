use std::fs;
use std::path::PathBuf;

use serde::Serialize;

use crate::adb::AdbClient;
use crate::app::Result;
use crate::case::CaseSession;

#[derive(Debug, Clone, Serialize)]
pub struct PullResult {
    pub remote_path: String,
    pub local_path: String,
    pub status: String,
    pub detail: String,
}

pub fn run_extraction(
    adb: &AdbClient,
    serial: &str,
    kind: &str,
    case_dir: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<serde_json::Value> {
    let mut session = CaseSession::from_case_or_output(case_dir, output.clone())?;
    let root = output.unwrap_or_else(|| session.output_path("derived", &format!("extract-{kind}")));
    fs::create_dir_all(&root)?;

    let mut pulls = Vec::new();
    for remote in remote_paths(kind) {
        let safe = remote
            .trim_start_matches('/')
            .replace('/', "_")
            .replace(':', "_");
        let local = root.join(safe);
        let status = match adb.pull(serial, remote, &local) {
            Ok(detail) => {
                if let Some(artifact) = session.register_path(
                    &local,
                    format!("extract-{kind}"),
                    format!("extract {kind}"),
                    serde_json::json!({ "remote_path": remote }),
                )? {
                    session.append_custody(&artifact, "pull", serial)?;
                }
                PullResult {
                    remote_path: remote.to_string(),
                    local_path: local.display().to_string(),
                    status: "ok".to_string(),
                    detail,
                }
            }
            Err(err) => PullResult {
                remote_path: remote.to_string(),
                local_path: local.display().to_string(),
                status: "error".to_string(),
                detail: err.to_string(),
            },
        };
        pulls.push(status);
    }

    Ok(serde_json::json!({
        "module": "extraction",
        "kind": kind,
        "serial": serial,
        "output_root": root,
        "results": pulls,
    }))
}

fn remote_paths(kind: &str) -> &'static [&'static str] {
    match kind {
        "sms" => &[
            "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
            "/data/data/com.android.providers.telephony/databases/mmssms.db",
        ],
        "contacts" => &["/data/data/com.android.providers.contacts/databases/contacts2.db"],
        "call-logs" => &["/data/data/com.android.providers.contacts/databases/calllog.db"],
        "browser" => &[
            "/data/data/com.android.chrome/app_chrome/Default/History",
            "/data/data/org.mozilla.firefox/files/mozilla",
        ],
        "messaging" => &[
            "/data/data/com.whatsapp/databases/msgstore.db",
            "/data/data/org.thoughtcrime.securesms/databases",
        ],
        "media" => &["/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Movies", "/sdcard/Download"],
        "location" => &[
            "/data/data/com.google.android.gms/databases",
            "/data/system/location",
        ],
        "all" => &[
            "/data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
            "/data/data/com.android.providers.contacts/databases/contacts2.db",
            "/sdcard/DCIM",
            "/sdcard/Download",
        ],
        _ => &[],
    }
}
