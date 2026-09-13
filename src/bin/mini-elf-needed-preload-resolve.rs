use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[allow(dead_code)]
mod env_resolve {
    include!("mini-elf-needed-env-resolve.rs");

    pub fn resolve(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args)
    }
}

#[allow(dead_code)]
mod dynamic_resolve {
    include!("mini-elf-dynamic-hash-resolve.rs");

    pub fn resolve(symbol: &str, inputs: &[std::ffi::OsString]) -> Result<String, String> {
        let args = std::iter::once(std::ffi::OsString::from(symbol)).chain(inputs.iter().cloned());
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

fn run(mut args: Vec<OsString>) -> Result<String, String> {
    let secure = matches!(args.first().and_then(|arg| arg.to_str()), Some("--secure"));
    if secure {
        args.remove(0);
    }

    let [symbol, root, _fallback] = args.as_slice() else {
        return Err(usage());
    };
    let symbol = symbol
        .to_str()
        .ok_or_else(|| "symbol name is not UTF-8".to_owned())?;
    if symbol.is_empty() {
        return Err("symbol name must not be empty".to_owned());
    }

    if secure {
        return env_resolve::resolve(
            std::iter::once(OsString::from("--secure"))
                .chain(args)
                .collect(),
        );
    }

    let Some(preload_value) = env::var_os("LD_PRELOAD") else {
        return env_resolve::resolve(args);
    };
    let preload_paths = parse_preload_paths(&preload_value)?;
    if preload_paths.is_empty() {
        return env_resolve::resolve(args);
    }

    let root_output = dynamic_resolve::resolve(symbol, std::slice::from_ref(root))?;
    let root_found = found(&root_output);

    let mut first_preload_match = None;
    for preload in &preload_paths {
        let input = preload.as_os_str().to_os_string();
        let output = dynamic_resolve::resolve(symbol, std::slice::from_ref(&input))?;
        if first_preload_match.is_none() && found(&output) {
            first_preload_match = Some(output);
        }
    }

    if root_found {
        return Ok(format!(
            "LD_PRELOAD scope: root-first preloads={}\n{root_output}",
            preload_paths.len()
        ));
    }
    if let Some(output) = first_preload_match {
        return Ok(format!(
            "LD_PRELOAD scope: root-first preloads={}\n{output}",
            preload_paths.len()
        ));
    }

    let output = env_resolve::resolve(args)?;
    Ok(format!(
        "LD_PRELOAD scope: root-first preloads={}\n{output}",
        preload_paths.len()
    ))
}

fn found(output: &str) -> bool {
    !output.contains(" not-found\n")
}

fn parse_preload_paths(value: &OsStr) -> Result<Vec<PathBuf>, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "LD_PRELOAD value is not UTF-8".to_owned())?;
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot determine current working directory: {error}"))?;
    value
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(|entry| normalize_preload_path(entry, &cwd))
        .collect()
}

fn normalize_preload_path(entry: &str, cwd: &Path) -> Result<PathBuf, String> {
    if !entry.contains('/') {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' is a bare library name; this bounded slice requires an explicit pathname"
        ));
    }
    if entry.contains('$') {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' contains an unsupported dynamic token"
        ));
    }

    let path = Path::new(entry);
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => saw_normal = true,
            _ => {
                return Err(format!(
                    "LD_PRELOAD entry '{entry}' is not a normalized pathname"
                ));
            }
        }
    }
    if !saw_normal {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' must name a shared-object pathname"
        ));
    }

    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(path),
        Ok(_) => Err(format!(
            "LD_PRELOAD entry '{}' resolved to non-file '{}'",
            entry,
            path.display()
        )),
        Err(error) => Err(format!(
            "cannot inspect LD_PRELOAD entry '{}' as '{}': {error}",
            entry,
            path.display()
        )),
    }
}

fn usage() -> String {
    "usage: mini-elf-needed-preload-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
