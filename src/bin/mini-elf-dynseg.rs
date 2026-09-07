use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;

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
            Ok("usage: mini-elf-dynseg <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynseg <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_dynamic_segment(header, &file)
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

fn format_dynamic_segment(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
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
        return Ok("No PT_DYNAMIC segment found.\n".to_owned());
    };

    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} has file size {}, which is not a multiple of {ELF64_DYNAMIC_SIZE}",
            dynamic.file_size
        ));
    }
    let dynamic_end = checked_file_end(
        dynamic.offset,
        dynamic.file_size,
        file.len(),
        &format!("PT_DYNAMIC segment {segment_index}"),
    )?;
    let entry_count = dynamic.file_size / ELF64_DYNAMIC_SIZE;
    let mut entries = Vec::new();
    let mut saw_null = false;
    for entry_index in 0..entry_count {
        let relative = entry_index
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
        if entry.tag == 0 {
            saw_null = true;
            break;
        }
    }
    if !saw_null {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} has no DT_NULL terminator before file offset {dynamic_end}"
        ));
    }

    let string_table_address = unique_tag_value(&entries, 5, "DT_STRTAB")?;
    let string_table_size = unique_tag_value(&entries, 10, "DT_STRSZ")?;
    let string_table = match (string_table_address, string_table_size) {
        (Some(address), Some(size)) => Some(map_virtual_range(&program_headers, file.len(), address, size)?),
        (None, None) => None,
        _ => {
            return Err(
                "PT_DYNAMIC must provide DT_STRTAB and DT_STRSZ together for string-valued tags"
                    .to_owned(),
            )
        }
    };

    let mut output = format!(
        "PT_DYNAMIC segment {segment_index} contains {} entries through DT_NULL:\n",
        entries.len()
    );
    output.push_str("  Tag                Type                 Name/Value\n");
    for entry in entries {
        let rendered_value = if is_string_tag(entry.tag) {
            let (table_offset, table_size) = string_table.ok_or_else(|| {
                format!(
                    "{} requires DT_STRTAB and DT_STRSZ",
                    dynamic_tag_name(entry.tag)
                )
            })?;
            let name = dynamic_string(file, table_offset, table_size, entry.value)?;
            format!("[{}]", String::from_utf8_lossy(name))
        } else {
            format!("{:#x}", entry.value)
        };
        output.push_str(&format!(
            "  {:#018x} {:<20} {rendered_value}\n",
            entry.tag,
            dynamic_tag_name(entry.tag)
        ));
    }
    Ok(output)
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
) -> Result<(u64, u64), String> {
    let address_end = address
        .checked_add(size)
        .ok_or_else(|| "dynamic string-table virtual range overflows u64".to_owned())?;
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_file_vaddr_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual file range overflows u64"))?;
        if address < header.virtual_address || address_end > load_file_vaddr_end {
            continue;
        }
        let delta = address - header.virtual_address;
        let offset = header
            .offset
            .checked_add(delta)
            .ok_or_else(|| "dynamic string-table file offset overflows u64".to_owned())?;
        checked_file_end(offset, size, file_len, "dynamic string table")?;
        return Ok((offset, size));
    }
    Err(format!(
        "dynamic string-table virtual range {address:#x}..{address_end:#x} is not backed by a PT_LOAD file range"
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

fn dynamic_string(
    file: &[u8],
    table_offset: u64,
    table_size: u64,
    name_offset: u64,
) -> Result<&[u8], String> {
    if name_offset >= table_size {
        return Err(format!(
            "dynamic string offset {name_offset} is outside string-table size {table_size}"
        ));
    }
    let start = table_offset
        .checked_add(name_offset)
        .ok_or_else(|| "dynamic string offset overflows u64".to_owned())?;
    let end = table_offset
        .checked_add(table_size)
        .ok_or_else(|| "dynamic string-table range overflows u64".to_owned())?;
    let start = usize::try_from(start)
        .map_err(|_| "dynamic string offset does not fit usize".to_owned())?;
    let end = usize::try_from(end)
        .map_err(|_| "dynamic string-table end does not fit usize".to_owned())?;
    let bytes = file
        .get(start..end)
        .ok_or_else(|| "dynamic string-table range is outside the file".to_owned())?;
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "dynamic string is not NUL-terminated within its string table".to_owned())?;
    Ok(&bytes[..nul])
}

fn is_string_tag(tag: i64) -> bool {
    matches!(tag, 1 | 14 | 15 | 29)
}

fn dynamic_tag_name(tag: i64) -> String {
    match tag {
        0 => "NULL".to_owned(),
        1 => "NEEDED".to_owned(),
        2 => "PLTRELSZ".to_owned(),
        3 => "PLTGOT".to_owned(),
        4 => "HASH".to_owned(),
        5 => "STRTAB".to_owned(),
        6 => "SYMTAB".to_owned(),
        7 => "RELA".to_owned(),
        8 => "RELASZ".to_owned(),
        9 => "RELAENT".to_owned(),
        10 => "STRSZ".to_owned(),
        11 => "SYMENT".to_owned(),
        12 => "INIT".to_owned(),
        13 => "FINI".to_owned(),
        14 => "SONAME".to_owned(),
        15 => "RPATH".to_owned(),
        16 => "SYMBOLIC".to_owned(),
        17 => "REL".to_owned(),
        18 => "RELSZ".to_owned(),
        19 => "RELENT".to_owned(),
        20 => "PLTREL".to_owned(),
        21 => "DEBUG".to_owned(),
        22 => "TEXTREL".to_owned(),
        23 => "JMPREL".to_owned(),
        24 => "BIND_NOW".to_owned(),
        25 => "INIT_ARRAY".to_owned(),
        26 => "FINI_ARRAY".to_owned(),
        27 => "INIT_ARRAYSZ".to_owned(),
        28 => "FINI_ARRAYSZ".to_owned(),
        29 => "RUNPATH".to_owned(),
        30 => "FLAGS".to_owned(),
        value => format!("DT_{value:#x}"),
    }
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
