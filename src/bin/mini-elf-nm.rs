use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::symbol_names::symbol_name;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";
const USAGE: &str = "usage: mini-elf-nm [-u|--undefined-only] [-g|--extern-only] [-n|--numeric-sort] [-r|--reverse-sort] <input>...";
const TABLE_HEADER: &str = "VALUE             SIZE BIND   TYPE    SHNDX NAME\n";

#[derive(Clone, Copy, Default)]
struct Filters {
    undefined_only: bool,
    extern_only: bool,
    numeric_sort: bool,
    reverse_sort: bool,
}

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

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let mut inputs: Vec<_> = args.collect();
    if inputs.is_empty() {
        return Err(USAGE.to_owned());
    }
    if inputs[0] == "--help" || inputs[0] == "-h" {
        if inputs.len() != 1 {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }

    let mut filters = Filters::default();
    while let Some(first) = inputs.first().and_then(|value| value.to_str()) {
        match first {
            "-u" | "--undefined-only" => filters.undefined_only = true,
            "-g" | "--extern-only" => filters.extern_only = true,
            "-n" | "--numeric-sort" => filters.numeric_sort = true,
            "-r" | "--reverse-sort" => filters.reverse_sort = true,
            _ => break,
        }
        inputs.remove(0);
    }
    if inputs.is_empty() {
        return Err(USAGE.to_owned());
    }

    let multiple_inputs = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy();
        let symbols = if file.starts_with(ARCHIVE_MAGIC) {
            inspect_archive(&file, &display, filters)?
        } else {
            inspect_elf(&file, &display, filters)?
        };
        inspected.push((display.into_owned(), symbols));
    }

    let mut output = String::new();
    for (index, (display, symbols)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("{display}:\n"));
        }
        output.push_str(&symbols);
    }
    Ok(output)
}

fn inspect_archive(file: &[u8], display: &str, filters: Filters) -> Result<String, String> {
    let archive = Archive::parse(file).map_err(|error| format!("{display}: {error}"))?;
    let mut members = Vec::new();
    for member in archive.ordinary_members() {
        let member_name = String::from_utf8_lossy(&member.name);
        let provenance = format!("{display}({member_name})");
        let symbols = inspect_elf(member.data, &provenance, filters)?;
        members.push((member_name.into_owned(), symbols));
    }

    let mut output = String::new();
    for (index, (member_name, symbols)) in members.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        output.push_str(&format!("{member_name}:\n"));
        output.push_str(&symbols);
    }
    Ok(output)
}

fn inspect_elf(file: &[u8], display: &str, filters: Filters) -> Result<String, String> {
    let header = Elf64Header::parse(file).map_err(|error| format!("{display}: {error}"))?;
    let sections = header
        .section_headers(file)
        .map_err(|error| format!("{display}: {error}"))?;
    let tables = header
        .symbol_tables(file, &sections)
        .map_err(|error| format!("{display}: {error}"))?;

    let mut rows = Vec::new();
    for table in &tables {
        for (symbol_index, symbol) in table.symbols.iter().enumerate() {
            let name = symbol_name(file, &sections, table, symbol_index)
                .map_err(|error| format!("{display}: {error}"))?;
            let binding = symbol.info >> 4;
            if name.is_empty()
                || (filters.undefined_only && symbol.section_index != 0)
                || (filters.extern_only && binding == 0)
            {
                continue;
            }
            let binding = binding_name(binding);
            let symbol_type = type_name(symbol.info & 0x0f);
            let section = section_name(symbol.section_index);
            let name = String::from_utf8_lossy(name);
            rows.push((
                symbol.value,
                format!(
                    "{:<016x} {:>4} {:<6} {:<7} {:>5} {}\n",
                    symbol.value, symbol.size, binding, symbol_type, section, name
                ),
            ));
        }
    }

    if filters.numeric_sort {
        rows.sort_by_key(|(value, _)| *value);
    }
    if filters.reverse_sort {
        rows.reverse();
    }

    let mut output = String::from(TABLE_HEADER);
    for (_, row) in rows {
        output.push_str(&row);
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
