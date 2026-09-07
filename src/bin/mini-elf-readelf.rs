use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-readelf -h|--file-header|-l|--program-headers <input>...";
const ELF64_PROGRAM_HEADER_SIZE: u64 = 56;

#[derive(Clone, Copy)]
enum Inspection {
    FileHeader,
    ProgramHeaders,
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

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
