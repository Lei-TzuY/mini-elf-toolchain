use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
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

#[allow(dead_code)]
mod loader_path_model {
    include!("mini-elf-needed-loader-token-resolve.rs");

    pub fn directories(value: &OsString, root: &Path) -> Result<Vec<PathBuf>, String> {
        let value = value
            .to_str()
            .ok_or_else(|| "LD_LIBRARY_PATH value is not UTF-8".to_owned())?;
        let cwd = env::current_dir()
            .map_err(|error| format!("cannot determine current working directory: {error}"))?;
        let cwd = cwd.to_str().ok_or_else(|| {
            "current working directory is not UTF-8 and cannot be used as an empty LD_LIBRARY_PATH component"
                .to_owned()
        })?;
        if cwd.contains(':') {
            return Err(format!(
                "current working directory '{}' contains ':' and cannot be represented in LD_LIBRARY_PATH",
                Path::new(cwd).display()
            ));
        }

        let with_cwd = value
            .split(':')
            .map(|entry| if entry.is_empty() { cwd } else { entry })
            .collect::<Vec<_>>()
            .join(":");
        let expanded = expand_loader_path(&OsString::from(with_cwd), root)?;
        let expanded = expanded
            .to_str()
            .ok_or_else(|| "expanded LD_LIBRARY_PATH value is not UTF-8".to_owned())?;

        let mut directories = Vec::new();
        for entry in expanded.split(':') {
            let path = PathBuf::from(entry);
            let metadata = std::fs::metadata(&path).map_err(|error| {
                format!(
                    "cannot inspect LD_LIBRARY_PATH directory '{}': {error}",
                    path.display()
                )
            })?;
            if !metadata.is_dir() {
                return Err(format!(
                    "LD_LIBRARY_PATH entry '{}' is not a directory",
                    path.display()
                ));
            }
            if !directories.contains(&path) {
                directories.push(path);
            }
        }
        Ok(directories)
    }
}

#[allow(dead_code)]
mod preload_search {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn resolve_bare(
        root: &OsStr,
        name: &str,
        loader_dirs: &[PathBuf],
        fallback: &Path,
    ) -> Result<PathBuf, String> {
        validate_dependency_name(name)
            .map_err(|_| format!("LD_PRELOAD entry '{name}' is not a plain library basename"))?;

        let fallback_metadata = fs::metadata(fallback).map_err(|error| {
            format!(
                "cannot inspect fallback library directory '{}': {error}",
                fallback.display()
            )
        })?;
        if !fallback_metadata.is_dir() {
            return Err(format!(
                "fallback library search path '{}' is not a directory",
                fallback.display()
            ));
        }

        let metadata = needed::metadata(root)?;
        let root_path = Path::new(root);
        let (before_loader_dirs, after_loader_dirs) =
            if let Some(runpath) = metadata.runpath.as_deref() {
                (
                    Vec::new(),
                    preload_dynamic_path_directories(root_path, "DT_RUNPATH", runpath)?,
                )
            } else if let Some(rpath) = metadata.rpath.as_deref() {
                (
                    preload_dynamic_path_directories(root_path, "DT_RPATH", rpath)?,
                    Vec::new(),
                )
            } else {
                (Vec::new(), Vec::new())
            };

        resolve_dependency(
            name,
            &before_loader_dirs,
            loader_dirs,
            &after_loader_dirs,
            fallback,
        )
        .map_err(|error| error.replace("DT_NEEDED dependency", "LD_PRELOAD entry"))
    }

    fn preload_dynamic_path_directories(
        parent: &Path,
        tag: &str,
        path_value: &str,
    ) -> Result<Vec<PathBuf>, String> {
        let origin = parent.parent().unwrap_or_else(|| Path::new("."));
        let cwd = env::current_dir()
            .map_err(|error| format!("cannot determine process current directory: {error}"))?;
        path_value
            .split(':')
            .map(|entry| {
                if entry.is_empty() {
                    return Ok(cwd.clone());
                }
                let path = Path::new(entry);
                if !path.is_absolute() {
                    if entry.contains('$') {
                        return expand_dynamic_path_entry(parent, origin, tag, entry);
                    }
                    let invalid_relative = entry.split('/').any(|component| {
                        component.is_empty() || component == "." || component == ".."
                    }) || !safe_relative_path(path);
                    if invalid_relative {
                        return Err(format!(
                            "{}: relative {tag} entry '{entry}' is not a normalized relative path",
                            parent.display()
                        ));
                    }
                    return Ok(cwd.join(path));
                }
                if entry.contains('$') {
                    return Err(format!(
                        "{}: absolute {tag} entry '{entry}' contains an unsupported dynamic token",
                        parent.display()
                    ));
                }
                let mut saw_component = false;
                for component in path.components() {
                    match component {
                        Component::RootDir => {}
                        Component::Normal(_) => saw_component = true,
                        _ => {
                            return Err(format!(
                                "{}: absolute {tag} entry '{entry}' is not a normalized absolute path",
                                parent.display()
                            ));
                        }
                    }
                }
                if !saw_component {
                    return Err(format!(
                        "{}: absolute {tag} entry '{entry}' must name a directory path",
                        parent.display()
                    ));
                }
                Ok(path.to_path_buf())
            })
            .collect()
    }
}

#[derive(Debug)]
enum PreloadEntry {
    Path(PathBuf),
    Bare(String),
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

    let [symbol, root, fallback] = args.as_slice() else {
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
    let preload_entries = parse_preload_entries(&preload_value)?;
    if preload_entries.is_empty() {
        return env_resolve::resolve(args);
    }

    let loader_dirs = match env::var_os("LD_LIBRARY_PATH") {
        Some(value) => loader_path_model::directories(&value, Path::new(root))?,
        None => Vec::new(),
    };
    let fallback_path = Path::new(fallback);
    let preload_paths = preload_entries
        .iter()
        .map(|entry| match entry {
            PreloadEntry::Path(path) => Ok(path.clone()),
            PreloadEntry::Bare(name) => {
                preload_search::resolve_bare(root, name, &loader_dirs, fallback_path)
            }
        })
        .collect::<Result<Vec<_>, String>>()?;

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

fn parse_preload_entries(value: &OsStr) -> Result<Vec<PreloadEntry>, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "LD_PRELOAD value is not UTF-8".to_owned())?;
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot determine current working directory: {error}"))?;
    value
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if entry.contains('/') {
                normalize_preload_path(entry, &cwd).map(PreloadEntry::Path)
            } else {
                normalize_preload_basename(entry).map(PreloadEntry::Bare)
            }
        })
        .collect()
}

fn normalize_preload_basename(entry: &str) -> Result<String, String> {
    if entry.contains('$') {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' contains an unsupported dynamic token"
        ));
    }
    let path = Path::new(entry);
    if entry.is_empty()
        || path.file_name() != Some(OsStr::new(entry))
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.components().count() != 1
    {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' is not a plain library basename"
        ));
    }
    Ok(entry.to_owned())
}

fn normalize_preload_path(entry: &str, cwd: &Path) -> Result<PathBuf, String> {
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
        Err(error) if error.kind() == ErrorKind::NotFound => Err(format!(
            "cannot resolve LD_PRELOAD entry '{}' as '{}'",
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
