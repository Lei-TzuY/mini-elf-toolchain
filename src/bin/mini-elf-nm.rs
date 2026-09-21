use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::elf64::{Elf64Header, SHT_DYNSYM};
use mini_elf_toolchain::symbol_names::symbol_name;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ARCHIVE_MAGIC: &[u8; 8] = b"!<arch>\n";
const USAGE: &str = "usage: mini-elf-nm [-u|--undefined-only] [--defined-only] [-g|--extern-only] [-W|--no-weak] [-D|--dynamic] [-n|--numeric-sort] [--size-sort] [-p|--no-sort] [-r|--reverse-sort] [-A|--print-file-name] [-j|--just-symbols] [-t d|o|x|--radix=d|o|x] <input>...";
const TABLE_HEADER: &str = "VALUE             SIZE BIND   TYPE    SHNDX NAME\n";

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum SortMode {
    #[default]
    Name,
    Numeric,
    Size,
    None,
}

#[derive(Clone, Copy, Default)]
enum Radix {
    Decimal,
    Octal,
    #[default]
    Hexadecimal,
}

#[derive(Clone, Copy, Default)]
struct Filters {
    undefined_only: bool,
    defined_only: bool,
    extern_only: bool,
    no_weak: bool,
    dynamic_only: bool,
    sort_mode: SortMode,
    reverse_sort: bool,
    print_file_name: bool,
    just_symbols: bool,
    radix: Radix,
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

fn parse_radix(value: &str) -> Result<Radix, String> {
    match value {
        "d" | "10" => Ok(Radix::Decimal),
        "o" | "8" => Ok(Radix::Octal),
        "x" | "16" => Ok(Radix::Hexadecimal),
        _ => Err(format!("invalid radix '{value}'; expected d, o, or x")),
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
        if first == "-t" || first == "--radix" {
            if inputs.len() < 2 {
                return Err(format!("{first} requires a radix argument"));
            }
            let value = inputs[1]
                .to_str()
                .ok_or_else(|| "radix argument must be valid UTF-8".to_owned())?;
            filters.radix = parse_radix(value)?;
            inputs.remove(0);
            inputs.remove(0);
            continue;
        }
        if let Some(value) = first.strip_prefix("--radix=") {
            filters.radix = parse_radix(value)?;
            inputs.remove(0);
            continue;
        }
        if let Some(value) = first.strip_prefix("-t").filter(|value| !value.is_empty()) {
            filters.radix = parse_radix(value)?;
            inputs.remove(0);
            continue;
        }
        match first {
            "-u" | "--undefined-only" => filters.undefined_only = true,
            "--defined-only" => filters.defined_only = true,
            "-g" | "--extern-only" => filters.extern_only = true,
            "-W" | "--no-weak" => filters.no_weak = true,
            "-D" | "--dynamic" => filters.dynamic_only = true,
            "-n" | "--numeric-sort" => filters.sort_mode = SortMode::Numeric,
            "--size-sort" => filters.sort_mode = SortMode::Size,
            "-p" | "--no-sort" => filters.sort_mode = SortMode::None,
            "-r" | "--reverse-sort" => filters.reverse_sort = true,
            "-A" | "--print-file-name" => filters.print_file_name = true,
            "-j" | "--just-symbols" => filters.just_symbols = true,
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
        if index != 0 && !filters.just_symbols {
            output.push('\n');
        }
        if multiple_inputs && !filters.print_file_name && !filters.just_symbols {
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
        if index != 0 && !filters.just_symbols {
            output.push('\n');
        }
        if !filters.print_file_name && !filters.just_symbols {
            output.push_str(&format!("{member_name}:\n"));
        }
        output.push_str(&symbols);
    }
    Ok(output)
}

fn format_value(value: u64, radix: Radix) -> String {
    match radix {
        Radix::Decimal => format!("{value:016}"),
        Radix::Octal => format!("{value:016o}"),
        Radix::Hexadecimal => format!("{value:016x}"),
    }
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
        if filters.dynamic_only
            && sections[usize::from(table.section_index)].section_type != SHT_DYNSYM
        {
            continue;
        }
        for (symbol_index, symbol) in table.symbols.iter().enumerate() {
            let name = symbol_name(file, &sections, table, symbol_index)
                .map_err(|error| format!("{display}: {error}"))?;
            let binding = symbol.info >> 4;
            if name.is_empty()
                || (filters.undefined_only && symbol.section_index != 0)
                || (filters.defined_only && symbol.section_index == 0)
                || (filters.extern_only && binding == 0)
                || (filters.no_weak && binding == 2)
            {
                continue;
            }
            let binding = binding_name(binding);
            let symbol_type = type_name(symbol.info & 0x0f);
            let section = section_name(symbol.section_index);
            let name = String::from_utf8_lossy(name).into_owned();
            let prefix = if filters.print_file_name && !filters.just_symbols {
                format!("{display}:")
            } else {
                String::new()
            };
            let row = if filters.just_symbols {
                format!("{name}\n")
            } else {
                format!(
                    "{}{:<16} {:>4} {:<6} {:<7} {:>5} {}\n",
                    prefix,
                    format_value(symbol.value, filters.radix),
                    symbol.size,
                    binding,
                    symbol_type,
                    section,
                    name,
                )
            };
            rows.push((symbol.value, symbol.size, name, row));
        }
    }

    match filters.sort_mode {
        SortMode::Name => rows.sort_by(|(_, _, left, _), (_, _, right, _)| left.cmp(right)),
        SortMode::Numeric => rows.sort_by_key(|(value, _, _, _)| *value),
        SortMode::Size => rows.sort_by(
            |(_, left_size, left_name, _), (_, right_size, right_name, _)| {
                left_size.cmp(right_size).then(left_name.cmp(right_name))
            },
        ),
        SortMode::None => {}
    }
    if filters.reverse_sort && filters.sort_mode != SortMode::None {
        rows.reverse();
    }

    let mut output = if filters.just_symbols {
        String::new()
    } else {
        String::from(TABLE_HEADER)
    };
    for (_, _, _, row) in rows {
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
