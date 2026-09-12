use std::env;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn run_with_args(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args.into_iter())
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

    let expanded = expand_loader_path(loader_path, Path::new(root))?;
    base::run_with_args(vec![
        flag.clone(),
        expanded,
        symbol.clone(),
        root.clone(),
        fallback.clone(),
    ])
}

fn expand_loader_path(value: &OsString, root: &Path) -> Result<OsString, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "--ld-library-path value is not UTF-8".to_owned())?;
    if value.is_empty() {
        return Err("--ld-library-path must not be empty".to_owned());
    }

    let origin = root.parent().unwrap_or_else(|| Path::new("."));
    let mut expanded = Vec::new();
    for entry in value.split(':') {
        if entry.is_empty() {
            return Err(
                "--ld-library-path contains an empty directory entry; implicit current-directory lookup is unsupported"
                    .to_owned(),
            );
        }
        let path = if entry.contains('$') {
            expand_token_entry(root, origin, entry)?
        } else {
            PathBuf::from(entry)
        };
        expanded.push(path);
    }

    let mut joined = OsString::new();
    for (index, path) in expanded.iter().enumerate() {
        if index != 0 {
            joined.push(":");
        }
        joined.push(path.as_os_str());
    }
    Ok(joined)
}

fn expand_token_entry(root: &Path, origin: &Path, entry: &str) -> Result<PathBuf, String> {
    let suffix = if entry == "$ORIGIN" || entry == "${ORIGIN}" {
        ""
    } else if let Some(suffix) = entry.strip_prefix("$ORIGIN/") {
        suffix
    } else if let Some(suffix) = entry.strip_prefix("${ORIGIN}/") {
        suffix
    } else {
        return Err(format!(
            "{}: unsupported --ld-library-path dynamic token entry '{entry}'; tokenized entries must be $ORIGIN-anchored",
            root.display()
        ));
    };

    if suffix.is_empty() {
        return Ok(origin.to_path_buf());
    }

    let mut relative = PathBuf::new();
    for component in suffix.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "{}: --ld-library-path entry '{entry}' escapes or is not a safe relative path",
                root.display()
            ));
        }
        match component {
            "$LIB" | "${LIB}" => relative.push("lib64"),
            "$PLATFORM" | "${PLATFORM}" => relative.push("x86_64"),
            normal if normal.contains('$') => {
                return Err(format!(
                    "{}: unsupported --ld-library-path dynamic token placement in entry '{entry}'",
                    root.display()
                ));
            }
            normal => relative.push(normal),
        }
    }

    if !safe_relative_path(&relative) {
        return Err(format!(
            "{}: --ld-library-path entry '{entry}' escapes or is not a safe relative path",
            root.display()
        ));
    }
    Ok(origin.join(relative))
}

fn safe_relative_path(path: &Path) -> bool {
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => saw_component = true,
            _ => return false,
        }
    }
    saw_component
}

fn usage() -> String {
    "usage: mini-elf-needed-loader-token-resolve --ld-library-path <dir[:dir...]> <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
