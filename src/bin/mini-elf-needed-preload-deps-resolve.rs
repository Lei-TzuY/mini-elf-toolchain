use std::env;
use std::process::ExitCode;

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-preload-resolve.rs");

    pub fn resolve_with_preload_dependencies(args: Vec<OsString>) -> Result<String, String> {
        let secure = matches!(args.first().and_then(|arg| arg.to_str()), Some("--secure"));
        if secure {
            return run(args);
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

        let Some(preload_value) = env::var_os("LD_PRELOAD") else {
            return run(args);
        };
        let preload_entries = parse_preload_entries(&preload_value)?;
        if preload_entries.is_empty() {
            return run(args);
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

        let mut first_preload_scope_match = None;
        for preload in &preload_paths {
            let output = env_resolve::resolve(vec![
                OsString::from(symbol),
                preload.as_os_str().to_os_string(),
                fallback.clone(),
            ])?;
            if first_preload_scope_match.is_none() && found(&output) {
                first_preload_scope_match = Some(output);
            }
        }

        if root_found {
            return Ok(format!(
                "LD_PRELOAD dependency scope: root-first preloads={}\n{root_output}",
                preload_paths.len()
            ));
        }
        if let Some(output) = first_preload_match {
            return Ok(format!(
                "LD_PRELOAD dependency scope: root-first preloads={}\n{output}",
                preload_paths.len()
            ));
        }
        if let Some(output) = first_preload_scope_match {
            return Ok(format!(
                "LD_PRELOAD dependency scope: root-first preloads={}\n{output}",
                preload_paths.len()
            ));
        }

        let output = env_resolve::resolve(args)?;
        Ok(format!(
            "LD_PRELOAD dependency scope: root-first preloads={}\n{output}",
            preload_paths.len()
        ))
    }
}

fn main() -> ExitCode {
    match base::resolve_with_preload_dependencies(env::args_os().skip(1).collect()) {
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
