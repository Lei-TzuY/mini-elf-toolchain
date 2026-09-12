use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

#[allow(dead_code)]
mod token_base {
    include!("mini-elf-needed-loader-token-resolve.rs");

    pub fn run_with_args(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args)
    }
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
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

fn run(args: Vec<OsString>) -> Result<String, String> {
    let [flag, loader_path, symbol, root, fallback] = args.as_slice() else {
        return Err(usage());
    };
    if flag != "--ld-library-path" {
        return Err(usage());
    }

    let normalized = normalize_loader_path(loader_path)?;
    token_base::run_with_args(vec![
        flag.clone(),
        normalized,
        symbol.clone(),
        root.clone(),
        fallback.clone(),
    ])
}

fn normalize_loader_path(value: &OsString) -> Result<OsString, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "--ld-library-path value is not UTF-8".to_owned())?;
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot determine current working directory: {error}"))?;
    let cwd = cwd
        .to_str()
        .ok_or_else(|| {
            "current working directory is not UTF-8 and cannot be used as an empty loader-path component"
                .to_owned()
        })?;
    if cwd.contains(':') {
        return Err(format!(
            "current working directory '{}' contains ':' and cannot be represented in the bounded loader-path list",
            Path::new(cwd).display()
        ));
    }

    let normalized = value
        .split(':')
        .map(|entry| if entry.is_empty() { cwd } else { entry })
        .collect::<Vec<_>>()
        .join(":");
    Ok(OsString::from(normalized))
}

fn usage() -> String {
    "usage: mini-elf-needed-loader-cwd-resolve --ld-library-path <dir[:dir...]> <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
