use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[allow(dead_code)]
mod needed {
    include!("mini-elf-needed-check.rs");

    const DT_RUNPATH_TAG: i64 = 29;

    pub struct Metadata {
        pub names: Vec<String>,
        pub runpath: Option<String>,
    }

    pub fn metadata(input: &std::ffi::OsStr) -> Result<Metadata, String> {
        let display = input.to_string_lossy().into_owned();
        let file =
            std::fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let headers =
            program_headers(header, &file).map_err(|error| format!("{display}: {error}"))?;
        let entries =
            dynamic_entries(&headers, &file).map_err(|error| format!("{display}: {error}"))?;
        let needed_offsets = entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED)
            .map(|entry| entry.value)
            .collect::<Vec<_>>();
        let runpath_offset = unique_tag_value(&entries, DT_RUNPATH_TAG, "DT_RUNPATH")
            .map_err(|error| format!("{display}: {error}"))?;

        if needed_offsets.is_empty() && runpath_offset.is_none() {
            return Ok(Metadata {
                names: Vec::new(),
                runpath: None,
            });
        }

        let (strtab_offset, strsz) = dynamic_string_table(&entries, &headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        let names = needed_offsets
            .into_iter()
            .map(|offset| {
                dynamic_string(&file, strtab_offset, strsz, offset, "DT_NEEDED name")
                    .map_err(|error| format!("{display}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let runpath = runpath_offset
            .map(|offset| {
                dynamic_string(&file, strtab_offset, strsz, offset, "DT_RUNPATH value")
                    .map_err(|error| format!("{display}: {error}"))
            })
            .transpose()?;

        Ok(Metadata { names, runpath })
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
    if args.len() != 3 {
        return Err(usage());
    }
    let symbol = args[0]
        .to_str()
        .ok_or_else(|| "symbol name is not UTF-8".to_owned())?;
    if symbol.is_empty() {
        return Err("symbol name must not be empty".to_owned());
    }

    let root = &args[1];
    let fallback_dir = PathBuf::from(&args[2]);
    let metadata = fs::metadata(&fallback_dir).map_err(|error| {
        format!(
            "cannot inspect fallback library directory '{}': {error}",
            fallback_dir.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "fallback library search path '{}' is not a directory",
            fallback_dir.display()
        ));
    }

    let mut scope = vec![root.clone()];
    let mut seen = BTreeSet::new();
    let mut cursor = 0usize;
    let mut runpath_directories_used = 0usize;
    while cursor < scope.len() {
        let parent = scope[cursor].clone();
        let metadata = needed::metadata(&parent)?;
        let runpath_dirs = runpath_directories(Path::new(&parent), metadata.runpath.as_deref())?;
        runpath_directories_used = runpath_directories_used
            .checked_add(runpath_dirs.len())
            .ok_or_else(|| "RUNPATH directory count overflows usize".to_owned())?;

        for dependency in metadata.names {
            if !seen.insert(dependency.clone()) {
                continue;
            }
            let path = resolve_dependency(&dependency, &runpath_dirs, &fallback_dir)?;
            scope.push(path.into_os_string());
        }
        cursor += 1;
    }

    let resolved = dynamic_resolve::resolve(symbol, &scope)?;
    Ok(format!(
        "RUNPATH DT_NEEDED scope: root={} dependencies={} runpath-directories={}\n{resolved}",
        root.to_string_lossy(),
        scope.len() - 1,
        runpath_directories_used
    ))
}

fn runpath_directories(parent: &Path, runpath: Option<&str>) -> Result<Vec<PathBuf>, String> {
    let Some(runpath) = runpath else {
        return Ok(Vec::new());
    };
    if runpath.is_empty() {
        return Err(format!(
            "{}: DT_RUNPATH must not be empty in this bounded resolver",
            parent.display()
        ));
    }

    let origin = parent.parent().unwrap_or_else(|| Path::new("."));
    runpath
        .split(':')
        .map(|entry| expand_runpath_entry(parent, origin, entry))
        .collect()
}

fn expand_runpath_entry(parent: &Path, origin: &Path, entry: &str) -> Result<PathBuf, String> {
    let suffix = if entry == "$ORIGIN" || entry == "${ORIGIN}" {
        ""
    } else if let Some(suffix) = entry.strip_prefix("$ORIGIN/") {
        suffix
    } else if let Some(suffix) = entry.strip_prefix("${ORIGIN}/") {
        suffix
    } else {
        return Err(format!(
            "{}: unsupported DT_RUNPATH entry '{entry}'; expected $ORIGIN or $ORIGIN/<relative-path>",
            parent.display()
        ));
    };

    if suffix.is_empty() {
        return Ok(origin.to_path_buf());
    }
    let relative = Path::new(suffix);
    if !safe_relative_path(relative) {
        return Err(format!(
            "{}: DT_RUNPATH entry '{entry}' escapes or is not a safe relative path",
            parent.display()
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

fn resolve_dependency(
    dependency: &str,
    runpath_dirs: &[PathBuf],
    fallback_dir: &Path,
) -> Result<PathBuf, String> {
    validate_dependency_name(dependency)?;
    let mut directories = runpath_dirs.to_vec();
    directories.push(fallback_dir.to_path_buf());
    let mut checked = BTreeSet::new();

    for directory in directories {
        let candidate = directory.join(dependency);
        if !checked.insert(candidate.clone()) {
            continue;
        }
        match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => return Ok(candidate),
            Ok(_) => {
                return Err(format!(
                    "DT_NEEDED dependency '{dependency}' resolved to non-file '{}'",
                    candidate.display()
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect DT_NEEDED candidate '{}': {error}",
                    candidate.display()
                ));
            }
        }
    }

    Err(format!(
        "cannot resolve DT_NEEDED dependency '{dependency}' through DT_RUNPATH or fallback directory '{}'",
        fallback_dir.display()
    ))
}

fn validate_dependency_name(name: &str) -> Result<(), String> {
    let path = Path::new(name);
    let mut components = path.components();
    let valid =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !valid || name.is_empty() || path.file_name() != Some(OsStr::new(name)) {
        return Err(format!(
            "DT_NEEDED dependency '{name}' is not a plain library basename"
        ));
    }
    Ok(())
}

fn usage() -> String {
    "usage: mini-elf-needed-runpath-resolve <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
