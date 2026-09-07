use mini_elf_toolchain::elf64::{Elf64Header, Elf64SectionHeader, SHT_STRTAB};
use mini_elf_toolchain::symbol_names::symbol_name;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str =
    "usage: mini-elf-readelf -h|--file-header|-l|--program-headers|-S|--section-headers|-s|--symbols <input>...";
const ELF64_PROGRAM_HEADER_SIZE: u64 = 56;

#[derive(Clone, Copy)]
enum Inspection {
    FileHeader,
    ProgramHeaders,
    SectionHeaders,
    Symbols,
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
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
    let mut args = args.collect::<Vec<_>>();
    if args.is_empty() {
        return Err(USAGE.to_owned());
    }
    if args[0] == "--help" || args[0] == "-H" {
        if args.len() != 1 {
            return Err(USAGE.to_owned());
        }
        return Ok(format!("{USAGE}\n"));
    }

    let inspection = match args[0].to_string_lossy().as_ref() {
        "-h" | "--file-header" => Inspection::FileHeader,
        "-l" | "--program-headers" => Inspection::ProgramHeaders,
        "-S" | "--section-headers" => Inspection::SectionHeaders,
        "-s" | "--symbols" => Inspection::Symbols,
        _ => return Err(USAGE.to_owned()),
    };
    args.remove(0);
    if args.is_empty() {
        return Err(USAGE.to_owned());
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = match inspection {
            Inspection::FileHeader => {
                header
                    .section_headers(&file)
                    .map_err(|error| format!("{display}: {error}"))?;
                format_header(header)
            }
            Inspection::ProgramHeaders => format_program_headers(header, &file)
                .map_err(|error| format!("{display}: {error}"))?,
            Inspection::SectionHeaders => format_section_headers(header, &file)
                .map_err(|error| format!("{display}: {error}"))?,
            Inspection::Symbols => {
                format_symbols(header, &file).map_err(|error| format!("{display}: {error}"))?
            }
        };
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

fn format_header(header: Elf64Header) -> String {
    format!(
        "ELF Header:\n  Class:                             ELF64\n  Data:                              2's complement, little endian\n  Type:                              {}\n  Machine:                           Advanced Micro Devices X86-64\n  Entry point address:               {:#x}\n  Start of program headers:          {} (bytes into file)\n  Start of section headers:          {} (bytes into file)\n  Flags:                             {:#x}\n  Size of this header:               {} (bytes)\n  Size of program headers:           {} (bytes)\n  Number of program headers:         {}\n  Size of section headers:           {} (bytes)\n  Number of section headers:         {}\n  Section header string table index: {}\n",
        type_name(header.elf_type),
        header.entry,
        header.program_header_offset,
        header.section_header_offset,
        header.flags,
        header.header_size,
        header.program_header_entry_size,
        header.program_header_count,
        header.section_header_entry_size,
        header.section_header_count,
        header.section_name_string_table_index,
    )
}

fn format_program_headers(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let mut program_headers = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let entry_offset = header
            .program_header_offset
            .checked_add(u64::from(index) * ELF64_PROGRAM_HEADER_SIZE)
            .ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let entry_end = entry_offset
            .checked_add(ELF64_PROGRAM_HEADER_SIZE)
            .ok_or_else(|| "program-header entry range overflows u64".to_owned())?;
        if entry_end > file.len() as u64 {
            return Err(format!(
                "program header {index} ends at file offset {entry_end}, beyond file length {}",
                file.len()
            ));
        }
        let entry_offset = usize::try_from(entry_offset)
            .map_err(|_| "program-header entry offset does not fit usize".to_owned())?;
        let program_header = ProgramHeader {
            segment_type: read_u32(file, entry_offset),
            flags: read_u32(file, entry_offset + 4),
            offset: read_u64(file, entry_offset + 8),
            virtual_address: read_u64(file, entry_offset + 16),
            physical_address: read_u64(file, entry_offset + 24),
            file_size: read_u64(file, entry_offset + 32),
            memory_size: read_u64(file, entry_offset + 40),
            alignment: read_u64(file, entry_offset + 48),
        };
        if program_header.alignment > 1 && !program_header.alignment.is_power_of_two() {
            return Err(format!(
                "program header {index} has invalid alignment {}; expected zero, one, or a power of two",
                program_header.alignment
            ));
        }
        let file_end = program_header
            .offset
            .checked_add(program_header.file_size)
            .ok_or_else(|| format!("program header {index} file range overflows u64"))?;
        if file_end > file.len() as u64 {
            return Err(format!(
                "program header {index} file range ends at offset {file_end}, beyond file length {}",
                file.len()
            ));
        }
        program_headers.push(program_header);
    }

    let mut output = "Program Headers:\n  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz             Flg Align\n".to_owned();
    for program_header in program_headers {
        output.push_str(&format!(
            "  {:<14} {:#018x} {:#018x} {:#018x} {:#018x} {:#018x} {:<3} {:#x}\n",
            program_type_name(program_header.segment_type),
            program_header.offset,
            program_header.virtual_address,
            program_header.physical_address,
            program_header.file_size,
            program_header.memory_size,
            program_flags(program_header.flags),
            program_header.alignment,
        ));
    }
    Ok(output)
}

fn format_section_headers(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let sections = header
        .section_headers(file)
        .map_err(|error| error.to_string())?;
    let names = section_names(header, file, &sections)?;

    let mut output = "Section Headers:\n  [Nr] Name                 Type             Address            Offset             Size               EntSize            Flg Lk Inf Al\n".to_owned();
    for (index, (section, name)) in sections.iter().zip(names).enumerate() {
        output.push_str(&format!(
            "  [{index:2}] {:<20} {:<16} {:#018x} {:#018x} {:#018x} {:#018x} {:<3} {:>2} {:>3} {}\n",
            name,
            section_type_name(section.section_type),
            section.address,
            section.offset,
            section.size,
            section.entry_size,
            section_flags(section.flags),
            section.link,
            section.info,
            section.address_alignment,
        ));
    }
    Ok(output)
}

fn format_symbols(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let sections = header
        .section_headers(file)
        .map_err(|error| error.to_string())?;
    let tables = header
        .symbol_tables(file, &sections)
        .map_err(|error| error.to_string())?;

    let mut output = String::new();
    for (table_index, table) in tables.iter().enumerate() {
        if table_index != 0 {
            output.push('\n');
        }
        output.push_str(&format!(
            "Symbol table section {} contains {} entries:\n",
            table.section_index,
            table.symbols.len()
        ));
        output.push_str("   Num: Value              Size Type    Bind   Vis      Ndx Name\n");
        for (symbol_index, symbol) in table.symbols.iter().enumerate() {
            let name = symbol_name(file, &sections, table, symbol_index)
                .map_err(|error| error.to_string())?;
            output.push_str(&format!(
                "  {symbol_index:4}: {:016x} {:>5} {:<7} {:<6} {:<8} {:>3} {}\n",
                symbol.value,
                symbol.size,
                symbol_type_name(symbol.info & 0x0f),
                symbol_binding_name(symbol.info >> 4),
                symbol_visibility_name(symbol.other & 0x03),
                symbol_section_name(symbol.section_index),
                String::from_utf8_lossy(name),
            ));
        }
    }
    Ok(output)
}

fn section_names(
    header: Elf64Header,
    file: &[u8],
    sections: &[Elf64SectionHeader],
) -> Result<Vec<String>, String> {
    if sections.is_empty() || header.section_name_string_table_index == 0 {
        return Ok(vec![String::new(); sections.len()]);
    }

    let string_table_index = usize::from(header.section_name_string_table_index);
    let string_table = &sections[string_table_index];
    if string_table.section_type != SHT_STRTAB {
        return Err(format!(
            "section-name string table {string_table_index} has type {}, expected SHT_STRTAB",
            string_table.section_type
        ));
    }
    let start = usize::try_from(string_table.offset)
        .map_err(|_| "section-name string-table offset does not fit usize".to_owned())?;
    let size = usize::try_from(string_table.size)
        .map_err(|_| "section-name string-table size does not fit usize".to_owned())?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| "section-name string-table range overflows usize".to_owned())?;
    let bytes = file
        .get(start..end)
        .ok_or_else(|| "section-name string-table range is outside file".to_owned())?;

    sections
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let offset = usize::try_from(section.name_offset)
                .map_err(|_| format!("section {index} name offset does not fit usize"))?;
            if offset >= bytes.len() {
                return Err(format!(
                    "section {index} name offset {} is outside section-name string-table size {}",
                    section.name_offset,
                    bytes.len()
                ));
            }
            let tail = &bytes[offset..];
            let terminator = tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
                format!(
                    "section {index} name at offset {} is not NUL-terminated within the section-name string table",
                    section.name_offset
                )
            })?;
            Ok(String::from_utf8_lossy(&tail[..terminator]).into_owned())
        })
        .collect()
}

fn type_name(elf_type: u16) -> String {
    match elf_type {
        0 => "NONE (None)".to_owned(),
        1 => "REL (Relocatable file)".to_owned(),
        2 => "EXEC (Executable file)".to_owned(),
        3 => "DYN (Shared object file)".to_owned(),
        4 => "CORE (Core file)".to_owned(),
        value => format!("0x{value:x}"),
    }
}

fn program_type_name(segment_type: u32) -> String {
    match segment_type {
        0 => "NULL".to_owned(),
        1 => "LOAD".to_owned(),
        2 => "DYNAMIC".to_owned(),
        3 => "INTERP".to_owned(),
        4 => "NOTE".to_owned(),
        5 => "SHLIB".to_owned(),
        6 => "PHDR".to_owned(),
        7 => "TLS".to_owned(),
        0x6474_e550 => "GNU_EH_FRAME".to_owned(),
        0x6474_e551 => "GNU_STACK".to_owned(),
        0x6474_e552 => "GNU_RELRO".to_owned(),
        0x6474_e553 => "GNU_PROPERTY".to_owned(),
        value => format!("0x{value:x}"),
    }
}

fn program_flags(flags: u32) -> String {
    let mut rendered = String::with_capacity(3);
    rendered.push(if flags & 4 != 0 { 'R' } else { ' ' });
    rendered.push(if flags & 2 != 0 { 'W' } else { ' ' });
    rendered.push(if flags & 1 != 0 { 'E' } else { ' ' });
    rendered
}

fn section_type_name(section_type: u32) -> String {
    match section_type {
        0 => "NULL".to_owned(),
        1 => "PROGBITS".to_owned(),
        2 => "SYMTAB".to_owned(),
        3 => "STRTAB".to_owned(),
        4 => "RELA".to_owned(),
        5 => "HASH".to_owned(),
        6 => "DYNAMIC".to_owned(),
        7 => "NOTE".to_owned(),
        8 => "NOBITS".to_owned(),
        9 => "REL".to_owned(),
        10 => "SHLIB".to_owned(),
        11 => "DYNSYM".to_owned(),
        14 => "INIT_ARRAY".to_owned(),
        15 => "FINI_ARRAY".to_owned(),
        16 => "PREINIT_ARRAY".to_owned(),
        17 => "GROUP".to_owned(),
        18 => "SYMTAB_SHNDX".to_owned(),
        value => format!("0x{value:x}"),
    }
}

fn section_flags(flags: u64) -> String {
    let mut rendered = String::new();
    if flags & 0x1 != 0 {
        rendered.push('W');
    }
    if flags & 0x2 != 0 {
        rendered.push('A');
    }
    if flags & 0x4 != 0 {
        rendered.push('X');
    }
    if flags & 0x10 != 0 {
        rendered.push('M');
    }
    if flags & 0x20 != 0 {
        rendered.push('S');
    }
    if flags & 0x40 != 0 {
        rendered.push('I');
    }
    if flags & 0x80 != 0 {
        rendered.push('L');
    }
    if flags & 0x100 != 0 {
        rendered.push('O');
    }
    if flags & 0x200 != 0 {
        rendered.push('G');
    }
    if flags & 0x400 != 0 {
        rendered.push('T');
    }
    if flags & 0x800 != 0 {
        rendered.push('C');
    }
    if flags & 0x1000 != 0 {
        rendered.push('x');
    }
    rendered
}

fn symbol_binding_name(binding: u8) -> String {
    match binding {
        0 => "LOCAL".to_owned(),
        1 => "GLOBAL".to_owned(),
        2 => "WEAK".to_owned(),
        value => format!("BIND{value}"),
    }
}

fn symbol_type_name(symbol_type: u8) -> String {
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

fn symbol_visibility_name(visibility: u8) -> String {
    match visibility {
        0 => "DEFAULT".to_owned(),
        1 => "INTERNAL".to_owned(),
        2 => "HIDDEN".to_owned(),
        3 => "PROTECTED".to_owned(),
        _ => unreachable!(),
    }
}

fn symbol_section_name(section_index: u16) -> String {
    match section_index {
        0 => "UND".to_owned(),
        0xfff1 => "ABS".to_owned(),
        0xfff2 => "COM".to_owned(),
        value => value.to_string(),
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
