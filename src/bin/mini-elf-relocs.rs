use mini_elf_toolchain::elf64::{Elf64Header, Elf64SectionHeader};
use mini_elf_toolchain::symbol_names::symbol_name;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const ELF64_RELA_SIZE: u64 = 24;
const ELF64_REL_SIZE: u64 = 16;

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
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-relocs <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-relocs <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_relocations(header, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        inspected.push((display, rendered));
    }

    let mut output = String::new();
    for (index, (display, rendered)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&rendered);
    }
    Ok(output)
}

fn format_relocations(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let sections = header
        .section_headers(file)
        .map_err(|error| error.to_string())?;
    let symbol_tables = header
        .symbol_tables(file, &sections)
        .map_err(|error| error.to_string())?;

    let mut output = String::new();
    let mut rendered_tables = 0usize;
    for (section_index, section) in sections.iter().enumerate() {
        if section.section_type != SHT_RELA && section.section_type != SHT_REL {
            continue;
        }
        let expected_entry_size = if section.section_type == SHT_RELA {
            ELF64_RELA_SIZE
        } else {
            ELF64_REL_SIZE
        };
        if section.entry_size != expected_entry_size {
            return Err(format!(
                "relocation section {section_index} has entry size {}, expected {expected_entry_size}",
                section.entry_size
            ));
        }
        if section.size % section.entry_size != 0 {
            return Err(format!(
                "relocation section {section_index} has size {}, which is not a multiple of entry size {}",
                section.size, section.entry_size
            ));
        }
        if section.link >= sections.len() as u32 {
            return Err(format!(
                "relocation section {section_index} links to symbol-table section {}, outside section-header count {}",
                section.link,
                sections.len()
            ));
        }
        if section.info >= sections.len() as u32 {
            return Err(format!(
                "relocation section {section_index} targets section {}, outside section-header count {}",
                section.info,
                sections.len()
            ));
        }

        let symbol_table = symbol_tables
            .iter()
            .find(|table| u32::from(table.section_index) == section.link)
            .ok_or_else(|| {
                format!(
                    "relocation section {section_index} links to section {}, which is not a parsed symbol table",
                    section.link
                )
            })?;

        if rendered_tables != 0 {
            output.push('\n');
        }
        rendered_tables += 1;
        let relocation_count = section.size / section.entry_size;
        output.push_str(&format!(
            "Relocation section {section_index} contains {relocation_count} entries:\n"
        ));
        output.push_str("  Offset             Info               Type                 Symbol               Addend\n");

        for relocation_index in 0..relocation_count {
            let relative = relocation_index
                .checked_mul(section.entry_size)
                .ok_or_else(|| format!("relocation section {section_index} entry offset overflows u64"))?;
            let entry_offset = section
                .offset
                .checked_add(relative)
                .ok_or_else(|| format!("relocation section {section_index} entry offset overflows u64"))?;
            let entry_end = entry_offset
                .checked_add(section.entry_size)
                .ok_or_else(|| format!("relocation section {section_index} entry range overflows u64"))?;
            if entry_end > file.len() as u64 {
                return Err(format!(
                    "relocation section {section_index} entry {relocation_index} ends at file offset {entry_end}, beyond file length {}",
                    file.len()
                ));
            }
            let entry_offset = usize::try_from(entry_offset)
                .map_err(|_| format!("relocation section {section_index} entry offset does not fit usize"))?;
            let offset = read_u64(file, entry_offset);
            let info = read_u64(file, entry_offset + 8);
            let symbol_index = (info >> 32) as usize;
            let relocation_type = info as u32;
            let addend = if section.section_type == SHT_RELA {
                read_i64(file, entry_offset + 16)
            } else {
                0
            };
            if symbol_index >= symbol_table.symbols.len() {
                return Err(format!(
                    "relocation {relocation_index} in section {section_index} refers to symbol {symbol_index}, outside symbol-table size {}",
                    symbol_table.symbols.len()
                ));
            }
            let name = symbol_name(file, &sections, symbol_table, symbol_index)
                .map_err(|error| error.to_string())?;
            output.push_str(&format!(
                "  {offset:016x} {info:016x} {:<20} {:<20} {addend}\n",
                relocation_type_name(relocation_type),
                String::from_utf8_lossy(name),
            ));
        }
    }

    Ok(output)
}

fn relocation_type_name(relocation_type: u32) -> String {
    match relocation_type {
        0 => "R_X86_64_NONE".to_owned(),
        1 => "R_X86_64_64".to_owned(),
        2 => "R_X86_64_PC32".to_owned(),
        3 => "R_X86_64_GOT32".to_owned(),
        4 => "R_X86_64_PLT32".to_owned(),
        9 => "R_X86_64_GOTPCREL".to_owned(),
        10 => "R_X86_64_32".to_owned(),
        11 => "R_X86_64_32S".to_owned(),
        22 => "R_X86_64_GOTTPOFF".to_owned(),
        23 => "R_X86_64_TPOFF32".to_owned(),
        24 => "R_X86_64_PC64".to_owned(),
        25 => "R_X86_64_GOTOFF64".to_owned(),
        26 => "R_X86_64_GOTPC32".to_owned(),
        27 => "R_X86_64_GOT64".to_owned(),
        28 => "R_X86_64_GOTPCREL64".to_owned(),
        29 => "R_X86_64_GOTPC64".to_owned(),
        30 => "R_X86_64_GOTPLT64".to_owned(),
        31 => "R_X86_64_PLTOFF64".to_owned(),
        32 => "R_X86_64_SIZE32".to_owned(),
        33 => "R_X86_64_SIZE64".to_owned(),
        41 => "R_X86_64_GOTPCRELX".to_owned(),
        42 => "R_X86_64_REX_GOTPCRELX".to_owned(),
        value => format!("R_X86_64_{value}"),
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
