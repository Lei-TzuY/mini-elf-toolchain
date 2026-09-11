use std::collections::BTreeSet;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[allow(dead_code)]
mod needed {
    include!("mini-elf-needed-check.rs");

    pub fn names(input: &std::ffi::OsStr) -> Result<Vec<String>, String> {
        let display = input.to_string_lossy().into_owned();
        let file =
            std::fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let headers =
            program_headers(header, &file).map_err(|error| format!("{display}: {error}"))?;
        let entries =
            dynamic_entries(&headers, &file).map_err(|error| format!("{display}: {error}"))?;
        let offsets = entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED)
            .map(|entry| entry.value)
            .collect::<Vec<_>>();
        if offsets.is_empty() {
            return Ok(Vec::new());
        }
        let (strtab_offset, strsz) = dynamic_string_table(&entries, &headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        offsets
            .into_iter()
            .map(|offset| {
                dynamic_string(&file, strtab_offset, strsz, offset, "DT_NEEDED name")
                    .map_err(|error| format!("{display}: {error}"))
            })
            .collect()
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
    let library_dir = PathBuf::from(&args[2]);
    let metadata = fs::metadata(&library_dir).map_err(|error| {
        format!(
            "cannot inspect library directory '{}': {error}",
            library_dir.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "library search path '{}' is not a directory",
            library_dir.display()
        ));
    }

    let mut scope = vec![root.clone()];
    let mut seen = BTreeSet::new();
    let mut cursor = 0usize;
    while cursor < scope.len() {
        let parent = scope[cursor].clone();
        for dependency in needed::names(&parent)? {
            if !seen.insert(dependency.clone()) {
                continue;
            }
            let path = dependency_path(&library_dir, &dependency)?;
            let metadata = fs::metadata(&path).map_err(|error| {
                format!(
                    "cannot resolve DT_NEEDED dependency '{dependency}' as '{}': {error}",
                    path.display()
                )
            })?;
            if !metadata.is_file() {
                return Err(format!(
                    "DT_NEEDED dependency '{dependency}' resolved to non-file '{}'",
                    path.display()
                ));
            }
            scope.push(path.into_os_string());
        }
        cursor += 1;
    }

    let resolved = dynamic_resolve::resolve(symbol, &scope)?;
    Ok(format!(
        "Transitive DT_NEEDED scope: root={} dependencies={}\n{resolved}",
        root.to_string_lossy(),
        scope.len() - 1
    ))
}

fn dependency_path(directory: &Path, name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    let mut components = path.components();
    let valid =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if !valid || name.is_empty() || path.file_name() != Some(OsStr::new(name)) {
        return Err(format!(
            "DT_NEEDED dependency '{name}' is not a plain library basename"
        ));
    }
    Ok(directory.join(path))
}

fn usage() -> String {
    "usage: mini-elf-needed-closure-resolve <symbol> <root-et-dyn> <library-dir>".to_owned()
}
