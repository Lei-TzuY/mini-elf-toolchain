use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::archive_index::parse_archive_symbol_index;
use std::env;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-armap <archive>";

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
    let input = args.next().ok_or_else(|| USAGE.to_owned())?;
    if input == "--help" || input == "-h" {
        if args.next().is_some() {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }
    if args.next().is_some() {
        return Err(USAGE.to_owned());
    }

    let display = input.to_string_lossy();
    let file = fs::read(&input).map_err(|error| format!("cannot read '{display}': {error}"))?;
    let archive = Archive::parse(&file).map_err(|error| format!("{display}: {error}"))?;
    let index = parse_archive_symbol_index(&archive)
        .map_err(|error| format!("{display}: {error}"))?
        .ok_or_else(|| format!("{display}: archive has no symbol index"))?;

    let mut output = String::from("Archive index:\n");
    for entry in index.entries {
        let symbol = String::from_utf8_lossy(entry.name);
        let member = String::from_utf8_lossy(&archive.members[entry.member_index].name);
        output.push_str(&format!("{symbol} in {member}\n"));
    }
    Ok(output)
}
