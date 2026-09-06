use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::symbol_names::symbol_name;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-nm <input>";

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(mut args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let input = args.next().ok_or_else(|| USAGE.to_owned())?;
    if input == "--help" || input == "-h" {
        if args.next().is_some() {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }
    if args.next().is_some() {
        return Err(USAGE.to_owned());
    }

    let file = fs::read(&input)
        .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
    let header = Elf64Header::parse(&file)
        .map_err(|error| format!("{}: {error}", input.to_string_lossy()))?;
    let sections = header
        .section_headers(&file)
        .map_err(|error| format!("{}: {error}", input.to_string_lossy()))?;
    let tables = header
        .symbol_tables(&file, &sections)
        .map_err(|error| format!("{}: {error}", input.to_string_lossy()))?;

    let mut output = String::from("VALUE             SIZE BIND   TYPE    SHNDX NAME\n");
    for table in &tables {
        for (symbol_index, symbol) in table.symbols.iter().enumerate() {
            let name = symbol_name(&file, &sections, table, symbol_index)
                .map_err(|error| format!("{}: {error}", input.to_string_lossy()))?;
            if name.is_empty() {
                continue;
            }
            let binding = binding_name(symbol.info >> 4);
            let symbol_type = type_name(symbol.info & 0x0f);
            let section = section_name(symbol.section_index);
            let name = String::from_utf8_lossy(name);
            output.push_str(&format!(
                "{:<016x} {:>4} {:<6} {:<7} {:>5} {}\n",
                symbol.value, symbol.size, binding, symbol_type, section, name
            ));
        }
    }

    Ok(output)
}

fn binding_name(binding: u8) -> String {
    match binding {
        0 => "LOCAL".to_owned(),
        1 => "GLOBAL".to_owned(),
        2 => "WEAK".to_owned(),
        value => format!("BIND{value}"),
    }
}

fn type_name(symbol_type: u8) -> String {
    match symbol_type {
        0 => "NOTYPE".to_owned(),
        1 => "OBJECT".to_owned(),
        2 => "FUNC".to_owned(),
        3 => "SECTION".to_owned(),
        4 => "FILE".to_owned(),
        5 => "COMMON".to_owned(),
        6 => "TLS".to_owned(),
        value => format!("TYPE{value}"),
    }
}

fn section_name(section_index: u16) -> String {
    match section_index {
        0 => "UND".to_owned(),
        0xfff1 => "ABS".to_owned(),
        0xfff2 => "COM".to_owned(),
        value => value.to_string(),
    }
}
