mod adb;
mod app;
mod case;
mod cli;
mod modules;
mod tui;

use app::{AppContext, Config, Result};
use cli::{dispatch_cli, parse_args, Mode};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = parse_args();
    let config = Config::load_with_legacy_compat(args.config_path)?;
    let ctx = AppContext::boot(config)?;

    match args.mode {
        Mode::Tui => tui::run_tui(&ctx),
        Mode::Cli(command) => dispatch_cli(&ctx, command),
    }
}
