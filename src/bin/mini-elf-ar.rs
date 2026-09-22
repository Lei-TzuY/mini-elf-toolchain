use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use mini_elf_toolchain::archive_extract::plan_archive_extraction;
use mini_elf_toolchain::archive_writer::{write_indexed_archive, ArchiveWriterMember};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-ar <t|x|rcs|crs> [--] <archive> [member...]";

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

    let is_create = operation == "rcs" || operation == "crs";
    if operation != "t" && operation != "x" && !is_create {
        return Err(format!(
            "unsupported archive operation '{}'; supported operations are 't', 'x', and creation-only 'rcs'/'crs'\n{USAGE}",
            operation.to_string_lossy()
        ));
    }

    let mut archive_path = args.next().ok_or_else(|| USAGE.to_owned())?;
    if archive_path == "--" {
        archive_path = args.next().ok_or_else(|| USAGE.to_owned())?;
    }

    if is_create {
        let members = args.collect::<Vec<_>>();
        return create_archive(&archive_path, &members);
    }

    let selectors = args
        .map(|selector| {
            selector
                .into_string()
                .map_err(|_| "archive member selector is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let display = archive_path.to_string_lossy();
    let file =
        fs::read(&archive_path).map_err(|error| format!("cannot read '{display}': {error}"))?;
    let archive = Archive::parse(&file).map_err(|error| format!("{display}: {error}"))?;

    if operation == "t" {
        list_members(&archive, &selectors, &display)
    } else {
        extract_members(&archive, &selectors, &display)
    }
}

fn create_archive(
    archive_path: &std::ffi::OsStr,
    member_paths: &[std::ffi::OsString],
) -> Result<String, String> {
    let display = archive_path.to_string_lossy();
    match fs::symlink_metadata(archive_path) {
        Ok(_) => {
            return Err(format!(
                "refusing to overwrite existing archive '{display}' in creation-only mode"
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect archive target '{display}': {error}"
            ))
        }
    }

    let mut loaded = Vec::with_capacity(member_paths.len());
    for path in member_paths {
        let path_ref = Path::new(path);
        let member_name = path_ref
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "archive member path '{}' has no UTF-8 file name",
                    path_ref.display()
                )
            })?
            .to_owned();
        let data = fs::read(path_ref).map_err(|error| {
            format!(
                "cannot read archive member '{}': {error}",
                path_ref.display()
            )
        })?;
        loaded.push((member_name, data));
    }

    let members = loaded
        .iter()
        .map(|(name, data)| ArchiveWriterMember {
            name: name.as_bytes(),
            data,
        })
        .collect::<Vec<_>>();
    let bytes = write_indexed_archive(&members)
        .map_err(|error| format!("cannot create '{display}': {error}"))?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(archive_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite existing archive '{display}' in creation-only mode")
            } else {
                format!("cannot create archive '{display}': {error}")
            }
        })?;
    if let Err(error) = output.write_all(&bytes) {
        drop(output);
        let _ = fs::remove_file(archive_path);
        return Err(format!("cannot write archive '{display}': {error}"));
    }

    Ok(String::new())
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
    let planned = plan_archive_extraction(archive, selectors)
        .map_err(|error| format!("{display}: {error}"))?;

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
