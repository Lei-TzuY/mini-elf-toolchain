use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use mini_elf_toolchain::archive_extract::plan_archive_extraction;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-ar <t|x> [--] <archive> [member...]";

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
    if operation != "t" && operation != "x" {
        return Err(format!(
            "unsupported archive operation '{}'; only 't' and 'x' are supported\n{USAGE}",
            operation.to_string_lossy()
        ));
    }

    let mut input = args.next().ok_or_else(|| USAGE.to_owned())?;
    if input == "--" {
        input = args.next().ok_or_else(|| USAGE.to_owned())?;
    }
    let selectors = args
        .map(|selector| {
            selector
                .into_string()
                .map_err(|_| "archive member selector is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let display = input.to_string_lossy();
    let file = fs::read(&input).map_err(|error| format!("cannot read '{display}': {error}"))?;
    let archive = Archive::parse(&file).map_err(|error| format!("{display}: {error}"))?;

    if operation == "t" {
        list_members(&archive, &selectors, &display)
    } else {
        extract_members(&archive, &selectors, &display)
    }
}

fn list_members(
    archive: &Archive<'_>,
    selectors: &[String],
    display: &str,
) -> Result<String, String> {
    let mut output = String::new();
    for member in &archive.members {
        if member.kind != ArchiveMemberKind::Ordinary {
            continue;
        }
        let name = std::str::from_utf8(&member.name)
            .map_err(|_| format!("{display}: archive member name is not UTF-8"))?;
        if !selectors.is_empty() && !selectors.iter().any(|selector| selector == name) {
            continue;
        }
        output.push_str(name);
        output.push('\n');
    }
    Ok(output)
}

fn extract_members(
    archive: &Archive<'_>,
    selectors: &[String],
    display: &str,
) -> Result<String, String> {
    let planned =
        plan_archive_extraction(archive, selectors).map_err(|error| format!("{display}: {error}"))?;

    for member in &planned {
        match fs::symlink_metadata(&member.name) {
            Ok(_) => {
                return Err(format!(
                    "refusing to overwrite existing extraction target '{}'",
                    member.name
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect extraction target '{}': {error}",
                    member.name
                ));
            }
        }
    }

    for member in planned {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&member.name)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "refusing to overwrite existing extraction target '{}'",
                        member.name
                    )
                } else {
                    format!("cannot create extraction target '{}': {error}", member.name)
                }
            })?;

        if let Err(error) = output.write_all(member.data) {
            drop(output);
            let _ = fs::remove_file(&member.name);
            return Err(format!(
                "cannot write extraction target '{}': {error}",
                member.name
            ));
        }
    }

    Ok(String::new())
}
