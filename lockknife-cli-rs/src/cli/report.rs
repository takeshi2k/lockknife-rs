use crate::app::{AppContext, Result};
use crate::case::CaseSession;
use crate::cli::{OutputFormat, ReportCommand};
use crate::modules::default_structured_output_name;
use crate::modules::reporting::{
    load_report_context, write_chain_of_custody, write_integrity, write_report,
};

pub fn dispatch_report(_ctx: &AppContext, command: ReportCommand) -> Result<()> {
    match command {
        ReportCommand::Generate {
            case_id,
            artifacts,
            template,
            format,
            io,
        } => {
            let (mut session, context) =
                load_report_context(io.case_dir.clone(), case_id, artifacts, &template)?;
            let extension = match format {
                OutputFormat::Html => "html",
                OutputFormat::Json => "json",
                OutputFormat::Csv => "csv",
                OutputFormat::Pdf => "pdf",
                _ => "txt",
            };
            let output = io.output.unwrap_or_else(|| {
                session.output_path(
                    "reports",
                    &format!(
                        "{}_report.{}",
                        context.case_id.clone().unwrap_or_else(|| "lockknife".to_string()),
                        extension
                    ),
                )
            });
            write_report(&mut session, &context, format, &output)?;
            println!("{}", output.display());
            Ok(())
        }
        ReportCommand::ChainOfCustody {
            case_id,
            examiner,
            evidence,
            notes,
            format,
            sign: _,
            io,
        } => {
            let mut session = CaseSession::from_case_or_output(io.case_dir.clone(), io.output.clone())?;
            let case_id = case_id
                .or_else(|| session.manifest().map(|manifest| manifest.case_id.clone()))
                .unwrap_or_else(|| "case-unknown".to_string());
            let examiner = examiner
                .or_else(|| session.manifest().map(|manifest| manifest.examiner.clone()))
                .unwrap_or_else(|| "examiner".to_string());
            let extension = match format {
                OutputFormat::Html => "html",
                _ => "txt",
            };
            let output = io.output.unwrap_or_else(|| {
                session.output_path("reports", &format!("chain_of_custody_{case_id}.{extension}"))
            });
            write_chain_of_custody(&mut session, format, case_id, examiner, &notes, &evidence, &output)?;
            println!("{}", output.display());
            Ok(())
        }
        ReportCommand::Integrity {
            case_dir,
            format,
            output,
        } => {
            let mut session = CaseSession::from_case_or_output(Some(case_dir), output.clone())?;
            let default_name = default_structured_output_name("integrity", format)?;
            let output = output.unwrap_or_else(|| session.output_path("reports", &default_name));
            write_integrity(&mut session, format, &output)?;
            println!("{}", output.display());
            Ok(())
        }
    }
}
