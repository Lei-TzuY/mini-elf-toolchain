use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_RELA_SIZE: u64 = 24;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

#[derive(Clone, Copy)]
struct DynamicEntry {
    tag: i64,
    value: u64,
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
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-dynrela <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynrela <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_dynamic_relocations(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_dynamic_relocations(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let rela = unique_tag_value(&entries, DT_RELA, "DT_RELA")?;
    let rela_size = unique_tag_value(&entries, DT_RELASZ, "DT_RELASZ")?;
    let rela_entry_size = unique_tag_value(&entries, DT_RELAENT, "DT_RELAENT")?;

    let present = usize::from(rela.is_some())
        + usize::from(rela_size.is_some())
        + usize::from(rela_entry_size.is_some());
    if present == 0 {
        return Ok("No DT_RELA relocation table found.\n".to_owned());
    }
    if present != 3 {
        return Err("PT_DYNAMIC must provide DT_RELA, DT_RELASZ, and DT_RELAENT together".to_owned());
    }

    let rela_address = rela.unwrap();
    let rela_size = rela_size.unwrap();
    let rela_entry_size = rela_entry_size.unwrap();
    if rela_entry_size != ELF64_RELA_SIZE {
        return Err(format!(
            "DT_RELAENT is {rela_entry_size}, expected {ELF64_RELA_SIZE} for ELF64"
        ));
    }
    if rela_size % rela_entry_size != 0 {
        return Err(format!(
            "DT_RELASZ {rela_size} is not a multiple of DT_RELAENT {rela_entry_size}"
        ));
    }

    let table_offset = map_virtual_range(
        &program_headers,
        file.len(),
        rela_address,
        rela_size,
        "DT_RELA table",
    )?;
    let count = rela_size / rela_entry_size;
    let mut output = format!("DT_RELA contains {count} entries:\n");
    output.push_str("  Offset             Info               Type                 Sym  Addend\n");
    for index in 0..count {
        let relative = index
            .checked_mul(rela_entry_size)
            .ok_or_else(|| "DT_RELA entry offset overflows u64".to_owned())?;
        let offset = table_offset
            .checked_add(relative)
            .ok_or_else(|| "DT_RELA entry offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_RELA entry offset does not fit usize".to_owned())?;
        let relocation_offset = read_u64(file, offset);
        let info = read_u64(file, offset + 8);
        let addend = read_i64(file, offset + 16);
        let symbol = info >> 32;
        let relocation_type = info as u32;
        output.push_str(&format!(
            "  {relocation_offset:#018x} {info:#018x} {:<20} {symbol:>4}  {addend}\n",
            relocation_type_name(relocation_type)
        ));
    }
    Ok(output)
}

fn dynamic_entries(program_headers: &[ProgramHeader], file: &[u8]) -> Result<Vec<DynamicEntry>, String> {
    let dynamic_segments = program_headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if dynamic_segments.len() > 1 {
        return Err(format!(
            "found {} PT_DYNAMIC segments; expected at most one",
            dynamic_segments.len()
        ));
    }
    let Some((segment_index, dynamic)) = dynamic_segments.first().copied() else {
        return Ok(Vec::new());
    };
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} has file size {}, which is not a multiple of {ELF64_DYNAMIC_SIZE}",
            dynamic.file_size
        ));
    }
    checked_file_end(
        dynamic.offset,
        dynamic.file_size,
        file.len(),
        &format!("PT_DYNAMIC segment {segment_index}"),
    )?;

    let entry_count = dynamic.file_size / ELF64_DYNAMIC_SIZE;
    let mut entries = Vec::new();
    for index in 0..entry_count {
        let relative = index
            .checked_mul(ELF64_DYNAMIC_SIZE)
            .ok_or_else(|| "PT_DYNAMIC entry offset overflows u64".to_owned())?;
        let offset = dynamic
            .offset
            .checked_add(relative)
            .ok_or_else(|| "PT_DYNAMIC entry offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "PT_DYNAMIC entry offset does not fit usize".to_owned())?;
        let entry = DynamicEntry {
            tag: read_i64(file, offset),
            value: read_u64(file, offset + 8),
        };
        entries.push(entry);
        if entry.tag == DT_NULL {
            return Ok(entries);
        }
    }
    Err(format!(
        "PT_DYNAMIC segment {segment_index} has no DT_NULL terminator"
    ))
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let mut headers = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let relative = u64::from(index)
            .checked_mul(u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let offset = header
            .program_header_offset
            .checked_add(relative)
            .ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let end = offset
            .checked_add(u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program-header entry range overflows u64".to_owned())?;
        if end > file.len() as u64 {
            return Err(format!(
                "program header {index} ends at file offset {end}, beyond file length {}",
                file.len()
            ));
        }
        let offset = usize::try_from(offset)
            .map_err(|_| "program-header entry offset does not fit usize".to_owned())?;
        let header = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if header.file_size > header.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                header.file_size, header.memory_size
            ));
        }
        checked_file_end(
            header.offset,
            header.file_size,
            file.len(),
            &format!("program header {index}"),
        )?;
        headers.push(header);
    }
    Ok(headers)
}

fn map_virtual_range(
    program_headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    what: &str,
) -> Result<u64, String> {
    let address_end = address
        .checked_add(size)
        .ok_or_else(|| format!("{what} virtual range overflows u64"))?;
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual file range overflows u64"))?;
        if address < header.virtual_address || address_end > load_end {
            continue;
        }
        let delta = address - header.virtual_address;
        let offset = header
            .offset
            .checked_add(delta)
            .ok_or_else(|| format!("{what} file offset overflows u64"))?;
        checked_file_end(offset, size, file_len, what)?;
        return Ok(offset);
    }
    Err(format!(
        "{what} virtual range {address:#x}..{address_end:#x} is not backed by a PT_LOAD file range"
    ))
}

fn unique_tag_value(
    entries: &[DynamicEntry],
    wanted_tag: i64,
    name: &str,
) -> Result<Option<u64>, String> {
    let mut value = None;
    for entry in entries {
        if entry.tag != wanted_tag {
            continue;
        }
        if value.replace(entry.value).is_some() {
            return Err(format!("PT_DYNAMIC contains duplicate {name} entries"));
        }
    }
    Ok(value)
}

fn relocation_type_name(relocation_type: u32) -> String {
    match relocation_type {
        0 => "R_X86_64_NONE".to_owned(),
        1 => "R_X86_64_64".to_owned(),
        2 => "R_X86_64_PC32".to_owned(),
        5 => "R_X86_64_COPY".to_owned(),
        6 => "R_X86_64_GLOB_DAT".to_owned(),
        7 => "R_X86_64_JUMP_SLOT".to_owned(),
        8 => "R_X86_64_RELATIVE".to_owned(),
        10 => "R_X86_64_32".to_owned(),
        11 => "R_X86_64_32S".to_owned(),
        value => format!("R_X86_64_{value}"),
    }
}

fn checked_file_end(offset: u64, size: u64, file_len: usize, what: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{what} file range overflows u64"))?;
    if end > file_len as u64 {
        return Err(format!(
            "{what} ends at file offset {end}, beyond file length {file_len}"
        ));
    }
    Ok(end)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
