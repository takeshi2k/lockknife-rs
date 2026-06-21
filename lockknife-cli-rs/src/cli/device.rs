use crate::app::{AppContext, Result};
use crate::cli::{DeviceCommand, OutputFormat};

pub fn dispatch_device(ctx: &AppContext, command: DeviceCommand) -> Result<()> {
    match command {
        DeviceCommand::List { format } => {
            let devices = ctx.services.adb.list_devices()?;
            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&devices)?),
                _ => {
                    if devices.is_empty() {
                        println!("No devices found");
                    } else {
                        for device in devices {
                            println!(
                                "{}\t{}\t{}\t{}",
                                device.serial,
                                device.state,
                                device.model.unwrap_or_else(|| "-".to_string()),
                                device.device.unwrap_or_else(|| "-".to_string())
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        DeviceCommand::Connect { host } => {
            println!("{}", ctx.services.adb.connect(&host)?);
            Ok(())
        }
        DeviceCommand::Info {
            serial,
            all,
            format,
        } => {
            if all {
                let devices = ctx.services.adb.list_devices()?;
                let mut payload = Vec::new();
                for device in devices.into_iter().filter(|device| device.state == "device") {
                    let props = ctx.services.adb.getprop(&device.serial)?;
                    payload.push(serde_json::json!({
                        "device": device,
                        "getprop": props,
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&payload)?);
                return Ok(());
            }

            let serial = ctx.services.adb.target_serial(serial.as_deref())?;
            let props = ctx.services.adb.getprop(&serial)?;
            match format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "serial": serial,
                        "getprop": props,
                    }))?
                ),
                _ => println!("{props}"),
            }
            Ok(())
        }
        DeviceCommand::Shell { serial, command } => {
            let serial = ctx.services.adb.target_serial(serial.as_deref())?;
            println!("{}", ctx.services.adb.shell(&serial, &command)?);
            Ok(())
        }
    }
}
