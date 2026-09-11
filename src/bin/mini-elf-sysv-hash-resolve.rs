use std::env;
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

#[allow(dead_code)]
mod checked_external_lookup {
    include!("mini-elf-sysv-hash-external-lookup.rs");

    pub fn lookup(symbol: &str, input: &std::ffi::OsStr) -> Result<Option<u32>, String> {
        let output = run([std::ffi::OsString::from(symbol), input.to_os_string()].into_iter())?;
        if output.contains(" not-found\n") {
            return Ok(None);
        }
        let marker = " index=";
        let start = output.find(marker).ok_or_else(|| {
            "checked SysV external lookup returned an unrecognized result".to_owned()
        })? + marker.len();
        let end = output[start..]
            .find(' ')
            .map(|offset| start + offset)
            .ok_or_else(|| {
                "checked SysV external lookup omitted the symbol index terminator".to_owned()
            })?;
        output[start..end]
            .parse::<u32>()
            .map(Some)
            .map_err(|_| "checked SysV external lookup returned an invalid symbol index".to_owned())
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
    if args.len() < 2 {
        return Err(usage());
    }
    let symbol = args[0]
        .to_str()
        .ok_or_else(|| "symbol name is not UTF-8".to_owned())?;
    if symbol.is_empty() {
        return Err("symbol name must not be empty".to_owned());
    }

    for input in &args[1..] {
        if let Some(index) = checked_external_lookup::lookup(symbol, input)? {
            return Ok(render_found(symbol, input, index));
        }
    }

    Ok(format!(
        "SysV external resolve: symbol={symbol} not-found\n"
    ))
}

fn render_found(symbol: &str, input: &OsStr, index: u32) -> String {
    format!(
        "SysV external resolve: symbol={symbol} file={} index={index}\n",
        input.to_string_lossy()
    )
}

fn usage() -> String {
    "usage: mini-elf-sysv-hash-resolve <symbol> <input>...".to_owned()
}
