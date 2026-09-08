use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_VERNEED_SIZE: u64 = 16;
const VER_NEED_CURRENT: u16 = 1;

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
            Ok("usage: mini-elf-needed-check <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-needed-check <input>...".to_owned())
        };
    }

    let multiple = args.len() > 1;
    let mut reports = Vec::with_capacity(args.len());
    for input in args {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(&input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let report = inspect(header, &file).map_err(|error| format!("{display}: {error}"))?;
        reports.push((display, report));
    }

    let mut output = String::new();
    for (index, (display, report)) in reports.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&report);
    }
    Ok(output)
}

fn inspect(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let entries = dynamic_entries(&headers, file)?;
    let needed_offsets = entries
        .iter()
        .filter(|entry| entry.tag == DT_NEEDED)
        .map(|entry| entry.value)
        .collect::<Vec<_>>();
    let verneed_address = unique_tag_value(&entries, DT_VERNEED, "DT_VERNEED")?;
    let verneed_count = unique_tag_value(&entries, DT_VERNEEDNUM, "DT_VERNEEDNUM")?;

    match (verneed_address, verneed_count) {
        (None, None) => {
            return Ok(format!(
                "No DT_VERNEED requirements found; {} DT_NEEDED entries declared.\n",
                needed_offsets.len()
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned());
        }
        _ => {}
    }

    let count = verneed_count.unwrap();
    if count == 0 {
        return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
    }
    let (strtab_offset, strsz) = dynamic_string_table(&entries, &headers, file)?;
    let mut needed = BTreeSet::new();
    for offset in needed_offsets {
        needed.insert(dynamic_string(
            file,
            strtab_offset,
            strsz,
            offset,
            "DT_NEEDED name",
        )?);
    }

    let mut current = verneed_address.unwrap();
    let mut requirements = BTreeSet::new();
    for record_index in 0..count {
        let offset = mapped_offset(
            &headers,
            file,
            current,
            ELF64_VERNEED_SIZE,
            "DT_VERNEED entry",
        )?;
        let version = read_u16(file, offset);
        let aux_count = read_u16(file, offset + 2);
        let dependency_offset = u64::from(read_u32(file, offset + 4));
        let aux_relative = read_u32(file, offset + 8);
        let next = read_u32(file, offset + 12);
        if version != VER_NEED_CURRENT {
            return Err(format!(
                "DT_VERNEED entry {record_index} has unsupported version {version}"
            ));
        }
        if aux_count == 0 || aux_relative == 0 {
            return Err(format!(
                "DT_VERNEED entry {record_index} has an invalid Vernaux chain"
            ));
        }
        let dependency = dynamic_string(
            file,
            strtab_offset,
            strsz,
            dependency_offset,
            "DT_VERNEED dependency name",
        )?;
        if !needed.contains(&dependency) {
            return Err(format!(
                "DT_VERNEED dependency '{dependency}' is not declared by DT_NEEDED"
            ));
        }
        requirements.insert(dependency);

        let last = record_index + 1 == count;
        if last {
            if next != 0 {
                return Err(format!(
                    "final DT_VERNEED entry has non-zero next offset beyond count {count}"
                ));
            }
        } else {
            if next == 0 {
                return Err(format!("DT_VERNEED chain ends before count {count}"));
            }
            current = current
                .checked_add(u64::from(next))
                .ok_or_else(|| "DT_VERNEED next-entry address overflows u64".to_owned())?;
        }
    }

    let mut output = format!(
        "DT_VERNEED dependencies are backed by DT_NEEDED: {} requirement libraries, {} needed libraries.\n",
        requirements.len(),
        needed.len()
    );
    for dependency in requirements {
        output.push_str(&format!("  dependency={dependency}\n"));
    }
    Ok(output)
}

fn dynamic_string_table(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
) -> Result<(u64, u64), String> {
    let address = unique_tag_value(entries, DT_STRTAB, "DT_STRTAB")?
        .ok_or_else(|| "DT_VERNEED/DT_NEEDED validation requires DT_STRTAB".to_owned())?;
    let size = unique_tag_value(entries, DT_STRSZ, "DT_STRSZ")?
        .ok_or_else(|| "DT_VERNEED/DT_NEEDED validation requires DT_STRSZ".to_owned())?;
    let offset = map_virtual_range(headers, file.len(), address, size, "DT_STRTAB table")?;
    Ok((offset, size))
}

fn dynamic_entries(headers: &[ProgramHeader], file: &[u8]) -> Result<Vec<DynamicEntry>, String> {
    let segments = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if segments.len() != 1 {
        return Err(format!(
            "found {} PT_DYNAMIC segments; expected exactly one",
            segments.len()
        ));
    }
    let (segment_index, dynamic) = segments[0];
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} file size is not a multiple of 16"
        ));
    }
    let mut entries = Vec::new();
    for index in 0..dynamic.file_size / ELF64_DYNAMIC_SIZE {
        let offset = dynamic
            .offset
            .checked_add(index * ELF64_DYNAMIC_SIZE)
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
    Err("PT_DYNAMIC has no DT_NULL terminator".to_owned())
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        ));
    }
    let mut result = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let offset = header
            .program_header_offset
            .checked_add(u64::from(index) * u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        checked_file_end(
            offset,
            u64::from(ELF64_PROGRAM_HEADER_SIZE),
            file.len(),
            "program header",
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program header offset does not fit usize".to_owned())?;
        let entry = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if entry.file_size > entry.memory_size {
            return Err(format!(
                "program header {index} has p_filesz greater than p_memsz"
            ));
        }
        checked_file_end(
            entry.offset,
            entry.file_size,
            file.len(),
            "program header segment",
        )?;
        entry
            .virtual_address
            .checked_add(entry.memory_size)
            .ok_or_else(|| format!("program header {index} virtual range overflows u64"))?;
        result.push(entry);
    }
    Ok(result)
}

fn mapped_offset(
    headers: &[ProgramHeader],
    file: &[u8],
    address: u64,
    size: u64,
    label: &str,
) -> Result<usize, String> {
    let offset = map_virtual_range(headers, file.len(), address, size, label)?;
    usize::try_from(offset).map_err(|_| format!("{label} file offset does not fit usize"))
}

fn map_virtual_range(
    headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    label: &str,
) -> Result<u64, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        let backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| "PT_LOAD virtual file range overflows u64".to_owned())?;
        if address >= header.virtual_address && end <= backed_end {
            let delta = address - header.virtual_address;
            let offset = header
                .offset
                .checked_add(delta)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            checked_file_end(offset, size, file_len, label)?;
            return Ok(offset);
        }
    }
    Err(format!(
        "{label} virtual range {address:#x}..{end:#x} is not file-backed by PT_LOAD"
    ))
}

fn dynamic_string(
    file: &[u8],
    strtab_offset: u64,
    strsz: u64,
    offset: u64,
    label: &str,
) -> Result<String, String> {
    if offset >= strsz {
        return Err(format!(
            "{label} offset {offset} is outside DT_STRSZ {strsz}"
        ));
    }
    let start = strtab_offset
        .checked_add(offset)
        .ok_or_else(|| format!("{label} file offset overflows u64"))?;
    let start =
        usize::try_from(start).map_err(|_| format!("{label} file offset does not fit usize"))?;
    let remaining = usize::try_from(strsz - offset)
        .map_err(|_| format!("{label} remaining size does not fit usize"))?;
    let bytes = &file[start..start + remaining];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{label} is not NUL-terminated within DT_STRSZ"))?;
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn unique_tag_value(entries: &[DynamicEntry], tag: i64, name: &str) -> Result<Option<u64>, String> {
    let mut value = None;
    for entry in entries.iter().filter(|entry| entry.tag == tag) {
        if value.replace(entry.value).is_some() {
            return Err(format!("PT_DYNAMIC contains duplicate {name} entries"));
        }
    }
    Ok(value)
}

fn checked_file_end(offset: u64, size: u64, file_len: usize, label: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows u64"))?;
    if end > file_len as u64 {
        return Err(format!(
            "{label} ends at file offset {end}, beyond file length {file_len}"
        ));
    }
    Ok(end)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
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
