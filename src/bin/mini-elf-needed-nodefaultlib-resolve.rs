use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn resolve(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args.into_iter())
    }
}

#[allow(dead_code)]
mod dynflags {
    include!("mini-elf-dynflags.rs");

    pub fn nodefaultlib(input: &std::ffi::OsStr) -> Result<bool, String> {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_flags(header, &file).map_err(|error| format!("{display}: {error}"))?;
        Ok(rendered.split_ascii_whitespace().any(|token| token == "NODEFLIB"))
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

fn run<I: Iterator<Item = OsString>>(args: I) -> Result<String, String> {
    let mut args = args.collect::<Vec<_>>();
    let (root_index, fallback_index) = positional_indices(&args)?;
    let root = args[root_index].clone();
    let fallback = PathBuf::from(&args[fallback_index]);

    let metadata = fs::metadata(&fallback).map_err(|error| {
        format!(
            "cannot inspect fallback library directory '{}': {error}",
            fallback.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "fallback library search path '{}' is not a directory",
            fallback.display()
        ));
    }

    if !dynflags::nodefaultlib(&root)? {
        return base::resolve(args);
    }

    let empty_fallback = create_empty_fallback()?;
    args[fallback_index] = empty_fallback.as_os_str().to_owned();
    let result = base::resolve(args).map_err(|error| {
        format!(
            "{error}; DF_1_NODEFLIB suppressed fallback directory '{}'",
            fallback.display()
        )
    });
    let _ = fs::remove_dir(&empty_fallback);
    result.map(|output| {
        format!(
            "DF_1_NODEFLIB: fallback directory '{}' suppressed\n{output}",
            fallback.display()
        )
    })
}

fn positional_indices(args: &[OsString]) -> Result<(usize, usize), String> {
    match args {
        [_, _, _] => Ok((1, 2)),
        [flag, _, _, _, _] if flag == "--ld-library-path" => Ok((3, 4)),
        _ => Err(usage()),
    }
}

fn create_empty_fallback() -> Result<PathBuf, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before UNIX_EPOCH: {error}"))?
        .as_nanos();
    let path = env::temp_dir().join(format!(
        "mini-elf-nodefaultlib-{}-{stamp}",
        std::process::id()
    ));
    fs::create_dir(&path).map_err(|error| {
        format!(
            "cannot create temporary empty fallback directory '{}': {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn usage() -> String {
    "usage: mini-elf-needed-nodefaultlib-resolve [--ld-library-path <dir[:dir...]>] <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
