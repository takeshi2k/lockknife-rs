pub mod apk;
pub mod crack;
pub mod device;
pub mod extract;
pub mod forensics;
pub mod report;
pub mod security;

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

use crate::app::{delegated_sidecar, deferred_feature, AppContext, Result};
use apk::dispatch_apk;
use crack::dispatch_crack;
use device::dispatch_device;
use extract::dispatch_extract;
use forensics::dispatch_forensics;
use report::dispatch_report;
use security::dispatch_security;

#[derive(Debug, Clone, Parser)]
#[command(name = "lockknife", version, about = "Rust-first LockKnife runtime")]
pub struct Cli {
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pub cli: bool,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub config_path: Option<PathBuf>,
    pub mode: Mode,
}

#[derive(Debug, Clone)]
pub enum Mode {
    Tui,
    Cli(Option<Command>),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Text,
    Html,
    Csv,
    Pdf,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    Crack {
        #[command(subcommand)]
        command: CrackCommand,
    },
    Extract {
        #[command(subcommand)]
        command: ExtractCommand,
    },
    Forensics {
        #[command(subcommand)]
        command: ForensicsCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
    Apk {
        #[command(subcommand)]
        command: ApkCommand,
    },
    Runtime,
    Ai,
    ThreatIntel,
    Network,
    CryptoWallet,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DeviceCommand {
    List {
        #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
        format: OutputFormat,
    },
    Connect {
        host: String,
    },
    Info {
        #[arg(long)]
        serial: Option<String>,
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
    },
    Shell {
        #[arg(long)]
        serial: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Clone, Args)]
pub struct CaseOutputArgs {
    #[arg(long)]
    pub case_dir: Option<PathBuf>,
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ExtractionArgs {
    #[arg(long)]
    pub serial: Option<String>,
    #[command(flatten)]
    pub io: CaseOutputArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CrackCommand {
    Pin {
        hash: String,
        #[arg(long, default_value = "sha256")]
        algo: String,
        #[arg(long, default_value_t = 4)]
        length: u32,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Password {
        hash: String,
        #[arg(long, default_value = "sha256")]
        algo: String,
        #[arg(long)]
        wordlist: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    PasswordRules {
        hash: String,
        #[arg(long, default_value = "sha256")]
        algo: String,
        #[arg(long)]
        wordlist: PathBuf,
        #[arg(long, default_value_t = 100)]
        max_suffix: u32,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Gesture {
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Wifi {
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Keystore {
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Passkeys {
        #[command(flatten)]
        io: CaseOutputArgs,
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ExtractCommand {
    Sms(ExtractionArgs),
    Contacts(ExtractionArgs),
    #[command(name = "call-logs")]
    CallLogs(ExtractionArgs),
    Browser(ExtractionArgs),
    Messaging(ExtractionArgs),
    Media(ExtractionArgs),
    Location(ExtractionArgs),
    All(ExtractionArgs),
}

#[derive(Debug, Clone, Subcommand)]
pub enum ForensicsCommand {
    Snapshot {
        serial: String,
        #[arg(long, default_value_t = false)]
        full: bool,
        #[arg(long = "path")]
        paths: Vec<String>,
        #[arg(long, default_value_t = false)]
        encrypt: bool,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Sqlite {
        path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Timeline {
        sources: Vec<PathBuf>,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Parse {
        source_dir: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    #[command(name = "decode-protobuf")]
    DecodeProtobuf {
        path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Correlate {
        inputs: Vec<PathBuf>,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Recover {
        db_path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Carve {
        input_path: PathBuf,
        output_dir: PathBuf,
        #[arg(long, default_value = "generic")]
        source: String,
        #[arg(long, default_value_t = 500)]
        max_matches: u32,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ReportCommand {
    Generate {
        #[arg(long)]
        case_id: Option<String>,
        #[arg(long)]
        artifacts: Option<PathBuf>,
        #[arg(long, default_value = "technical")]
        template: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Html)]
        format: OutputFormat,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    #[command(name = "chain-of-custody")]
    ChainOfCustody {
        #[arg(long)]
        case_id: Option<String>,
        #[arg(long)]
        examiner: Option<String>,
        #[arg(long = "evidence")]
        evidence: Vec<PathBuf>,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        #[arg(long, default_value_t = false)]
        sign: bool,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Integrity {
        #[arg(long)]
        case_dir: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        format: OutputFormat,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SecurityCommand {
    Scan {
        serial: String,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Selinux {
        serial: String,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Malware {
        #[arg(long)]
        yara: Option<PathBuf>,
        #[arg(long = "pattern")]
        patterns: Vec<String>,
        target: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    #[command(name = "network-scan")]
    NetworkScan {
        serial: String,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Bootloader {
        serial: String,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Hardware {
        serial: String,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    #[command(name = "attack-surface")]
    AttackSurface {
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        apk: Option<PathBuf>,
        #[arg(long)]
        artifacts: Option<PathBuf>,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Owasp {
        artifacts: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ApkCommand {
    Decompile {
        apk_path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
        #[arg(long, default_value = "archive")]
        mode: String,
    },
    Permissions {
        apk_path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Analyze {
        apk_path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Vulnerability {
        apk_path: PathBuf,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
    Scan {
        #[arg(long)]
        yara: Option<PathBuf>,
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        apk: Option<PathBuf>,
        #[command(flatten)]
        io: CaseOutputArgs,
    },
}

pub fn parse_args() -> ParsedArgs {
    let cli = Cli::parse();
    let mode = if cli.command.is_none() && !cli.cli {
        Mode::Tui
    } else {
        Mode::Cli(cli.command)
    };
    ParsedArgs {
        config_path: cli.config,
        mode,
    }
}

pub fn dispatch_cli(ctx: &AppContext, command: Option<Command>) -> Result<()> {
    match command {
        Some(Command::Device { command }) => dispatch_device(ctx, command),
        Some(Command::Crack { command }) => dispatch_crack(ctx, command),
        Some(Command::Extract { command }) => dispatch_extract(ctx, command),
        Some(Command::Forensics { command }) => dispatch_forensics(ctx, command),
        Some(Command::Report { command }) => dispatch_report(ctx, command),
        Some(Command::Security { command }) => dispatch_security(ctx, command),
        Some(Command::Apk { command }) => dispatch_apk(ctx, command),
        Some(Command::Runtime) => Err(deferred_feature("frida")),
        Some(Command::Ai) => Err(delegated_sidecar("ml/ai workflows")),
        Some(Command::ThreatIntel) => Err(delegated_sidecar("threat-intel")),
        Some(Command::Network) => Err(delegated_sidecar("network/pcap")),
        Some(Command::CryptoWallet) => Err(delegated_sidecar("crypto-wallet")),
        None => {
            Cli::command().print_help().ok();
            println!();
            Ok(())
        }
    }
}
