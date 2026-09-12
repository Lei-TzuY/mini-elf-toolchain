use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn run_with_absolute_dynamic_paths(
        args: Vec<std::ffi::OsString>,
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

        let mut scope = vec![ScopeEntry {
            path: root.clone(),
            inherited_rpath: Vec::new(),
        }];
        let mut seen = BTreeSet::new();
        let mut loaded_sonames = BTreeSet::new();
        let mut cursor = 0usize;
        let mut runpath_directories_used = 0usize;
        let mut rpath_directories_used = 0usize;
        while cursor < scope.len() {
            let parent = scope[cursor].clone();
            let metadata = needed::metadata(&parent.path)?;
            if let Some(soname) = metadata.soname.as_ref() {
                loaded_sonames.insert(soname.clone());
            }
            let (before_loader_dirs, after_loader_dirs, child_inherited_rpath) =
                if let Some(runpath) = metadata.runpath.as_deref() {
                    let runpath_dirs = absolute_dynamic_path_directories(
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
                    let rpath_dirs = absolute_dynamic_path_directories(
                        Path::new(&parent.path),
                        "DT_RPATH",
                        rpath,
                    )?;
                    rpath_directories_used =
                        rpath_directories_used
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
                let path = resolve_needed_dependency_with_cwd_relative(
                    Path::new(&parent.path),
                    &dependency,
                    &before_loader_dirs,
                    &loader_dirs,
                    &after_loader_dirs,
                    &fallback_dir,
                )?;
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
            "absolute/relative RUNPATH/RPATH DT_NEEDED scope: root={} dependencies={} loader-path-directories={} runpath-directories={} rpath-directories={}\n{resolved}",
            root.to_string_lossy(),
            scope.len() - 1,
            loader_dirs.len(),
            runpath_directories_used,
            rpath_directories_used
        ))
    }

    fn absolute_dynamic_path_directories(
        parent: &Path,
        tag: &str,
        path_value: &str,
    ) -> Result<Vec<PathBuf>, String> {
        let origin = parent.parent().unwrap_or_else(|| Path::new("."));
        let cwd = std::env::current_dir()
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
                    if entry.split('/').any(|component| {
                        component.is_empty() || component == "." || component == ".."
                    }) {
                        return Err(format!(
                            "{}: relative {tag} entry '{entry}' is not a normalized relative path",
                            parent.display()
                        ));
                    }
                    if !safe_relative_path(path) {
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

    fn resolve_needed_dependency_with_cwd_relative(
        parent: &Path,
        dependency: &str,
        before_loader_dirs: &[PathBuf],
        loader_dirs: &[PathBuf],
        after_loader_dirs: &[PathBuf],
        fallback_dir: &Path,
    ) -> Result<PathBuf, String> {
        if !dependency.contains('/') {
            return resolve_dependency(
                dependency,
                before_loader_dirs,
                loader_dirs,
                after_loader_dirs,
                fallback_dir,
            );
        }

        let dependency_path = Path::new(dependency);
        let candidate = if dependency_path.is_absolute() {
            validate_absolute_direct_dependency(dependency_path, dependency)?;
            dependency_path.to_path_buf()
        } else if dependency == "$ORIGIN"
            || dependency == "${ORIGIN}"
            || dependency.starts_with("$ORIGIN/")
            || dependency.starts_with("${ORIGIN}/")
        {
            let origin = parent.parent().unwrap_or_else(|| Path::new("."));
            expand_dynamic_path_entry(parent, origin, "DT_NEEDED", dependency)?
        } else {
            validate_cwd_relative_direct_dependency(dependency_path, dependency)?;
            let cwd = std::env::current_dir()
                .map_err(|error| format!("cannot determine process current directory: {error}"))?;
            cwd.join(dependency_path)
        };

        match fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => Ok(candidate),
            Ok(_) => Err(format!(
                "direct DT_NEEDED dependency '{dependency}' resolved to non-file '{}'",
                candidate.display()
            )),
            Err(error) if error.kind() == ErrorKind::NotFound => Err(format!(
                "cannot resolve direct DT_NEEDED dependency '{dependency}' as '{}'",
                candidate.display()
            )),
            Err(error) => Err(format!(
                "cannot inspect direct DT_NEEDED candidate '{}': {error}",
                candidate.display()
            )),
        }
    }

    fn validate_cwd_relative_direct_dependency(
        path: &Path,
        dependency: &str,
    ) -> Result<(), String> {
        if dependency.contains('$') {
            return Err(format!(
                "cwd-relative direct DT_NEEDED dependency '{dependency}' contains an unsupported dynamic token"
            ));
        }
        if dependency
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
            || !safe_relative_path(path)
        {
            return Err(format!(
                "cwd-relative direct DT_NEEDED dependency '{dependency}' is not a normalized relative path"
            ));
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    match base::run_with_absolute_dynamic_paths(env::args_os().skip(1).collect::<Vec<OsString>>()) {
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
