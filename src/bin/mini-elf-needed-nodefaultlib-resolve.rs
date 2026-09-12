use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
mod dynflags {
    include!("mini-elf-dynflags.rs");

    pub fn nodefaultlib(input: &std::ffi::OsStr) -> Result<bool, String> {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_flags(header, &file).map_err(|error| format!("{display}: {error}"))?;
        Ok(rendered
            .split_ascii_whitespace()
            .any(|token| token == "NODEFLIB"))
    }
}

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn resolve_nodefaultlib(
        args: Vec<std::ffi::OsString>,
        empty_fallback: &std::path::Path,
    ) -> Result<String, String> {
        let (loader_dirs, positional) = parse_args(&args)?;
        let symbol = positional[0]
            .to_str()
            .ok_or_else(|| "symbol name is not UTF-8".to_owned())?;
        if symbol.is_empty() {
            return Err("symbol name must not be empty".to_owned());
        }

        let root = positional[1];
        let fallback_dir = PathBuf::from(positional[2]);
        let fallback_metadata = fs::metadata(&fallback_dir).map_err(|error| {
            format!(
                "cannot inspect fallback library directory '{}': {error}",
                fallback_dir.display()
            )
        })?;
        if !fallback_metadata.is_dir() {
            return Err(format!(
                "fallback library search path '{}' is not a directory",
                fallback_dir.display()
            ));
        }

        let mut scope = vec![ScopeEntry {
            path: root.clone(),
            inherited_rpath: Vec::new(),
        }];
        let mut seen = BTreeSet::new();
        let mut loaded_sonames = BTreeSet::new();
        let mut cursor = 0usize;
        let mut runpath_directories_used = 0usize;
        let mut rpath_directories_used = 0usize;
        let mut nodefaultlib_objects = 0usize;
        while cursor < scope.len() {
            let parent = scope[cursor].clone();
            let metadata = needed::metadata(&parent.path)?;
            let parent_nodefaultlib = super::dynflags::nodefaultlib(&parent.path)?;
            if parent_nodefaultlib {
                nodefaultlib_objects = nodefaultlib_objects
                    .checked_add(1)
                    .ok_or_else(|| "DF_1_NODEFLIB object count overflows usize".to_owned())?;
            }
            if let Some(soname) = metadata.soname.as_ref() {
                loaded_sonames.insert(soname.clone());
            }
            let (before_loader_dirs, after_loader_dirs, child_inherited_rpath) =
                if let Some(runpath) = metadata.runpath.as_deref() {
                    let runpath_dirs = dynamic_path_directories(
                        Path::new(&parent.path),
                        "DT_RUNPATH",
                        runpath,
                    )?;
                    runpath_directories_used = runpath_directories_used
                        .checked_add(runpath_dirs.len())
                        .ok_or_else(|| "RUNPATH directory count overflows usize".to_owned())?;
                    (
                        parent.inherited_rpath.clone(),
                        runpath_dirs,
                        parent.inherited_rpath.clone(),
                    )
                } else if let Some(rpath) = metadata.rpath.as_deref() {
                    let rpath_dirs =
                        dynamic_path_directories(Path::new(&parent.path), "DT_RPATH", rpath)?;
                    rpath_directories_used = rpath_directories_used
                        .checked_add(rpath_dirs.len())
                        .ok_or_else(|| "RPATH directory count overflows usize".to_owned())?;
                    let mut inherited = rpath_dirs;
                    append_unique_paths(&mut inherited, parent.inherited_rpath.clone());
                    (inherited.clone(), Vec::new(), inherited)
                } else {
                    (
                        parent.inherited_rpath.clone(),
                        Vec::new(),
                        parent.inherited_rpath.clone(),
                    )
                };

            for dependency in metadata.names {
                if seen.contains(&dependency) || loaded_sonames.contains(&dependency) {
                    continue;
                }
                let effective_fallback = if parent_nodefaultlib {
                    empty_fallback
                } else {
                    &fallback_dir
                };
                let path = resolve_needed_dependency(
                    Path::new(&parent.path),
                    &dependency,
                    &before_loader_dirs,
                    &loader_dirs,
                    &after_loader_dirs,
                    effective_fallback,
                )
                .map_err(|error| {
                    if parent_nodefaultlib {
                        format!(
                            "{error}; DF_1_NODEFLIB suppressed fallback directory '{}' for loader '{}'",
                            fallback_dir.display(),
                            Path::new(&parent.path).display()
                        )
                    } else {
                        error
                    }
                })?;
                let child_metadata = needed::metadata(path.as_os_str())?;
                if let Some(soname) = child_metadata.soname.as_ref() {
                    if loaded_sonames.contains(soname) {
                        seen.insert(dependency);
                        continue;
                    }
                    loaded_sonames.insert(soname.clone());
                }
                seen.insert(dependency);
                scope.push(ScopeEntry {
                    path: path.into_os_string(),
                    inherited_rpath: child_inherited_rpath.clone(),
                });
            }
            cursor += 1;
        }

        let inputs = scope
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        let resolved = dynamic_resolve::resolve(symbol, &inputs)?;
        Ok(format!(
            "NODEFLIB-aware DT_NEEDED scope: root={} dependencies={} nodefaultlib-objects={} loader-path-directories={} runpath-directories={} rpath-directories={}\n{resolved}",
            root.to_string_lossy(),
            scope.len() - 1,
            nodefaultlib_objects,
            loader_dirs.len(),
            runpath_directories_used,
            rpath_directories_used
        ))
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
    let args = args.collect::<Vec<_>>();
    let empty_fallback = create_empty_fallback()?;
    let result = base::resolve_nodefaultlib(args, &empty_fallback);
    let _ = fs::remove_dir(&empty_fallback);
    result
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
