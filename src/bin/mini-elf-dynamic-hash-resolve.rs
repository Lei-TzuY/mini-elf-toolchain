use std::env;
use std::ffi::{OsStr, OsString};
use std::process::ExitCode;

const MISSING_GNU_HASH: &str = "PT_DYNAMIC is missing required DT_GNU_HASH";

#[allow(dead_code)]
mod gnu_external_lookup {
    include!("mini-elf-gnu-hash-external-lookup.rs");

    pub fn lookup(symbol: &str, input: &std::ffi::OsStr) -> Result<String, String> {
        run([std::ffi::OsString::from(symbol), input.to_os_string()].into_iter())
    }
}

#[allow(dead_code)]
mod sysv_external_lookup {
    include!("mini-elf-sysv-hash-external-lookup.rs");

    pub fn lookup(symbol: &str, input: &std::ffi::OsStr) -> Result<String, String> {
        run([std::ffi::OsString::from(symbol), input.to_os_string()].into_iter())
    }
}

#[derive(Clone, Copy)]
enum HashStyle {
    Gnu,
    Sysv,
}

impl HashStyle {
    fn name(self) -> &'static str {
        match self {
            Self::Gnu => "gnu",
            Self::Sysv => "sysv",
        }
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
        if let Some((style, index)) = lookup_one(symbol, input)? {
            return Ok(render_found(symbol, input, style, index));
        }
    }

    Ok(format!(
        "Dynamic external resolve: symbol={symbol} not-found\n"
    ))
}

fn lookup_one(symbol: &str, input: &OsStr) -> Result<Option<(HashStyle, u32)>, String> {
    match gnu_external_lookup::lookup(symbol, input) {
        Ok(output) => parse_lookup_index(&output, "GNU").map(|index| index.map(|index| (HashStyle::Gnu, index))),
        Err(error) if error == MISSING_GNU_HASH => {
            let output = sysv_external_lookup::lookup(symbol, input)?;
            parse_lookup_index(&output, "SysV")
                .map(|index| index.map(|index| (HashStyle::Sysv, index)))
        }
        Err(error) => Err(error),
    }
}

fn parse_lookup_index(output: &str, style: &str) -> Result<Option<u32>, String> {
    if output.contains(" not-found\n") {
        return Ok(None);
    }
    let marker = " index=";
    let start = output
        .find(marker)
        .ok_or_else(|| format!("checked {style} external lookup returned an unrecognized result"))?
        + marker.len();
    let end = output[start..]
        .find(' ')
        .map(|offset| start + offset)
        .ok_or_else(|| format!("checked {style} external lookup omitted the symbol index terminator"))?;
    output[start..end]
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("checked {style} external lookup returned an invalid symbol index"))
}

fn render_found(symbol: &str, input: &OsStr, style: HashStyle, index: u32) -> String {
    format!(
        "Dynamic external resolve: symbol={symbol} file={} hash={} index={index}\n",
        input.to_string_lossy(),
        style.name()
    )
}

fn usage() -> String {
    "usage: mini-elf-dynamic-hash-resolve <symbol> <input>...".to_owned()
}
