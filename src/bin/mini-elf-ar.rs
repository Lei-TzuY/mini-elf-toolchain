use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use std::env;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-ar t <archive>";

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(mut args: I) -> Result<String, String>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let operation = args.next().ok_or_else(|| USAGE.to_owned())?;
    if operation == "--help" || operation == "-h" {
        if args.next().is_some() {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }
    if operation != "t" {
        return Err(format!(
            "unsupported archive operation '{}'; only 't' is supported\n{USAGE}",
            operation.to_string_lossy()
        ));
    }

    let input = args.next().ok_or_else(|| USAGE.to_owned())?;
    if args.next().is_some() {
        return Err(USAGE.to_owned());
    }

    let display = input.to_string_lossy();
    let file = fs::read(&input).map_err(|error| format!("cannot read '{display}': {error}"))?;
    let archive = Archive::parse(&file).map_err(|error| format!("{display}: {error}"))?;

    let mut output = String::new();
    for member in archive.members {
        if member.kind != ArchiveMemberKind::Ordinary {
            continue;
        }
        let name = std::str::from_utf8(&member.name)
            .map_err(|_| format!("{display}: archive member name is not UTF-8"))?;
        output.push_str(name);
        output.push('\n');
    }
    Ok(output)
}
