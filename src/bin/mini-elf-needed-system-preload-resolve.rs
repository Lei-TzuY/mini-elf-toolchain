use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

#[allow(dead_code)]
mod preload_deps {
    include!("mini-elf-needed-preload-deps-resolve.rs");

    pub fn resolve(args: Vec<OsString>) -> Result<String, String> {
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

fn run(args: Vec<OsString>) -> Result<String, String> {
    let (secure, preload_file, symbol, root, fallback) = match args.as_slice() {
        [flag, preload_file, symbol, root, fallback] if flag == "--secure" => {
            (true, preload_file, symbol, root, fallback)
        }
        [preload_file, symbol, root, fallback] => (false, preload_file, symbol, root, fallback),
        _ => return Err(usage()),
    };

    let preload_file = Path::new(preload_file);
    let bytes = fs::read(preload_file).map_err(|error| {
        format!(
            "cannot read system preload file '{}': {error}",
            preload_file.display()
        )
    })?;
    let contents = String::from_utf8(bytes).map_err(|_| {
        format!(
            "system preload file '{}' is not UTF-8",
            preload_file.display()
        )
    })?;

    let entries = contents.split_ascii_whitespace().collect::<Vec<_>>();
    for entry in &entries {
        if entry.contains(':') {
            return Err(format!(
                "system preload entry '{entry}' contains ':'; this bounded file model accepts whitespace-separated entries only"
            ));
        }
    }

    let previous_preload = env::var_os("LD_PRELOAD");
    let previous_library_path = secure.then(|| env::var_os("LD_LIBRARY_PATH"));
    let system_value = entries.join(" ");
    let combined = if secure {
        system_value
    } else {
        match previous_preload.as_ref().and_then(|value| value.to_str()) {
            Some(value) if !value.is_empty() && !system_value.is_empty() => {
                format!("{value} {system_value}")
            }
            Some(value) if !value.is_empty() => value.to_owned(),
            _ => system_value,
        }
    };

    if combined.is_empty() {
        env::remove_var("LD_PRELOAD");
    } else {
        env::set_var("LD_PRELOAD", &combined);
    }
    if secure {
        env::remove_var("LD_LIBRARY_PATH");
    }

    let result = preload_deps::resolve(vec![symbol.clone(), root.clone(), fallback.clone()]);

    match previous_preload {
        Some(value) => env::set_var("LD_PRELOAD", value),
        None => env::remove_var("LD_PRELOAD"),
    }
    if let Some(previous_library_path) = previous_library_path {
        match previous_library_path {
            Some(value) => env::set_var("LD_LIBRARY_PATH", value),
            None => env::remove_var("LD_LIBRARY_PATH"),
        }
    }

    let output = result?;
    Ok(format!(
        "system preload file: entries={} secure={secure}\n{output}",
        entries.len()
    ))
}

fn usage() -> String {
    "usage: mini-elf-needed-system-preload-resolve [--secure] <system-preload-file> <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
