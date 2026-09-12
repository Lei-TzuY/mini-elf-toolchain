use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

#[allow(dead_code)]
mod explicit_loader_path {
    include!("mini-elf-needed-loader-cwd-resolve.rs");

    pub fn run_with_args(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args)
    }
}

#[allow(dead_code)]
mod base {
    include!("mini-elf-needed-runpath-resolve.rs");

    pub fn run_with_args(args: Vec<std::ffi::OsString>) -> Result<String, String> {
        run(args.into_iter())
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
    let [symbol, root, fallback] = args.as_slice() else {
        return Err(usage());
    };

    match env::var_os("LD_LIBRARY_PATH") {
        Some(loader_path) => explicit_loader_path::run_with_args(vec![
            OsString::from("--ld-library-path"),
            loader_path,
            symbol.clone(),
            root.clone(),
            fallback.clone(),
        ]),
        None => base::run_with_args(args),
    }
}

fn usage() -> String {
    "usage: mini-elf-needed-env-resolve <symbol> <root-et-dyn> <fallback-library-dir>".to_owned()
}
