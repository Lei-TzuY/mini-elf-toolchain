use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

use mini_elf_toolchain::system_preload::SystemPreloadRequest;

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
    let request = SystemPreloadRequest::parse(&args)?.ok_or_else(usage)?;
    let result = request.resolve(preload_deps::resolve)?;
    Ok(format!(
        "system preload file: entries={} secure={}\n{}",
        result.entry_count, result.secure, result.output
    ))
}

fn usage() -> String {
    "usage: mini-elf-needed-system-preload-resolve [--secure] <system-preload-file> <symbol> <root-et-dyn> <fallback-library-dir>"
        .to_owned()
}
