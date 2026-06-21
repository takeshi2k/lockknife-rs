use crate::app::{AppContext, Result};
use crate::cli::ExtractCommand;
use crate::modules::extraction::{run_extraction, run_extraction_by_package};

pub fn dispatch_extract(ctx: &AppContext, command: ExtractCommand) -> Result<()> {
    let (kind, args) = match command {
        ExtractCommand::Sms(args) => ("sms", args),
        ExtractCommand::Contacts(args) => ("contacts", args),
        ExtractCommand::CallLogs(args) => ("call-logs", args),
        ExtractCommand::Browser(args) => ("browser", args),
        ExtractCommand::Messaging(args) => ("messaging", args),
        ExtractCommand::Media(args) => ("media", args),
        ExtractCommand::Location(args) => ("location", args),
        ExtractCommand::All(args) => ("all", args),
    };
    let serial = ctx.services.adb.target_serial(args.serial.as_deref())?;
    let payload = run_extraction(
        &ctx.services.adb,
        &serial,
        kind,
        args.io.case_dir,
        args.io.output,
    )?;
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
