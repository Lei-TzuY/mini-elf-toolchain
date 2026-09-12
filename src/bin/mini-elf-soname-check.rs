use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::process::ExitCode;

#[allow(dead_code)]
mod checked {
    include!("mini-elf-needed-check.rs");

    const DT_SONAME_TAG: i64 = 14;

    pub fn soname(input: &OsStr) -> Result<Option<String>, String> {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let headers = program_headers(header, &file).map_err(|error| format!("{display}: {error}"))?;
        let entries = dynamic_entries(&headers, &file).map_err(|error| format!("{display}: {error}"))?;
        let soname_offset = unique_tag_value(&entries, DT_SONAME_TAG, "DT_SONAME")
            .map_err(|error| format!("{display}: {error}"))?;
        let Some(soname_offset) = soname_offset else {
            return Ok(None);
        };
        let (strtab_offset, strsz) = dynamic_string_table(&entries, &headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        let soname = dynamic_string(
            &file,
            strtab_offset,
            strsz,
            soname_offset,
            "DT_SONAME name",
        )
        .map_err(|error| format!("{display}: {error}"))?;
        Ok(Some(soname))
    }
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-soname-check <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-soname-check <input>...".to_owned())
        };
    }

    let multiple = args.len() > 1;
    let mut reports = Vec::with_capacity(args.len());
    for input in args {
        let display = input.to_string_lossy().into_owned();
        let soname = checked::soname(&input)?;
        reports.push((display, soname));
    }

    let mut output = String::new();
    for (index, (display, soname)) in reports.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {display}\n"));
        }
        match soname {
            Some(soname) => output.push_str(&format!("DT_SONAME: {soname}\n")),
            None => output.push_str("DT_SONAME: <none>\n"),
        }
    }
    Ok(output)
}
