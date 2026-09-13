use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-preload-resolve.rs");

    pub fn resolve(args: Vec<OsString>) -> Result<String, String> {
        run(args)
    }
}

#[allow(dead_code)]
mod token_model {
    include!("mini-elf-needed-loader-token-resolve.rs");

    pub fn expand_preload(entry: &str, root: &Path) -> Result<PathBuf, String> {
        let origin = root.parent().unwrap_or_else(|| Path::new("."));
        expand_token_entry(root, origin, entry)
            .map_err(|error| error.replace("--ld-library-path", "LD_PRELOAD"))
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
    if matches!(args.first().and_then(|arg| arg.to_str()), Some("--secure")) {
        return base::resolve(args);
    }

    let [_, root, _] = args.as_slice() else {
        return base::resolve(args);
    };
    let Some(value) = env::var_os("LD_PRELOAD") else {
        return base::resolve(args);
    };
    let value = value
        .to_str()
        .ok_or_else(|| "LD_PRELOAD value is not UTF-8".to_owned())?;

    let mut entries = Vec::new();
    for entry in value
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
    {
        if !entry.contains('$') {
            entries.push(entry.to_owned());
            continue;
        }
        if !entry.contains('/') {
            return Err(format!(
                "tokenized LD_PRELOAD entry '{entry}' must be a $ORIGIN-anchored pathname"
            ));
        }
        let expanded = token_model::expand_preload(entry, Path::new(root))?;
        entries.push(
            expanded
                .to_str()
                .ok_or_else(|| "expanded LD_PRELOAD pathname is not UTF-8".to_owned())?
                .to_owned(),
        );
    }

    let expanded = entries.join(":");
    let previous = env::var_os("LD_PRELOAD");
    env::set_var("LD_PRELOAD", &expanded);
    let result = base::resolve(args);
    match previous {
        Some(value) => env::set_var("LD_PRELOAD", value),
        None => env::remove_var("LD_PRELOAD"),
    }
    result
}
