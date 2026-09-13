use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

#[allow(dead_code)]
mod loader_path {
    include!("mini-elf-needed-loader-token-resolve.rs");

    pub fn normalize(
        value: &std::ffi::OsString,
        root: &std::path::Path,
    ) -> Result<std::ffi::OsString, String> {
        let value = value
            .to_str()
            .ok_or_else(|| "LD_LIBRARY_PATH value is not UTF-8".to_owned())?;
        let cwd = std::env::current_dir()
            .map_err(|error| format!("cannot determine current working directory: {error}"))?;
        let cwd = cwd.to_str().ok_or_else(|| {
            "current working directory is not UTF-8 and cannot be used as an empty LD_LIBRARY_PATH component"
                .to_owned()
        })?;
        if cwd.contains(':') {
            return Err(format!(
                "current working directory '{}' contains ':' and cannot be represented in LD_LIBRARY_PATH",
                std::path::Path::new(cwd).display()
            ));
        }

        let with_cwd = value
            .split(':')
            .map(|entry| if entry.is_empty() { cwd } else { entry })
            .collect::<Vec<_>>()
            .join(":");
        expand_loader_path(&std::ffi::OsString::from(with_cwd), root)
    }
}

#[allow(dead_code)]
mod latest {
    include!("mini-elf-needed-absolute-runpath-resolve.rs");

    pub fn run_with_args(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        base::run_with_absolute_dynamic_paths(args)
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

    let [symbol, root, fallback] = args.as_slice() else {
        return Err(usage());
    };

    if secure {
        return latest::run_with_args(args);
    }

    match env::var_os("LD_LIBRARY_PATH") {
        Some(loader_path) => {
            let normalized = loader_path::normalize(&loader_path, Path::new(root))?;
            latest::run_with_args(vec![
                OsString::from("--ld-library-path"),
                normalized,
                symbol.clone(),
                root.clone(),
                fallback.clone(),
            ])
        }
        None => latest::run_with_args(args),
    }
}

fn usage() -> String {
    "usage: mini-elf-needed-env-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
