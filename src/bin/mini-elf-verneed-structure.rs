use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_VERNEED_SIZE: u64 = 16;
const ELF64_VERNAUX_SIZE: u64 = 16;
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
        Err(error) => {
            eprintln!("error: {error}");
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
            Ok("usage: mini-elf-verneed-structure <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-verneed-structure <input>...".to_owned())
        };
    }
    if args.iter().any(|arg| arg.to_string_lossy().starts_with('-')) {
        return Err("usage: mini-elf-verneed-structure <input>...".to_owned());
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
    let address = unique_tag_value(&entries, DT_VERNEED, "DT_VERNEED")?;
    let count = unique_tag_value(&entries, DT_VERNEEDNUM, "DT_VERNEEDNUM")?;
    match (address, count) {
        (None, None) => return Ok("No DT_VERNEED version-requirement table found.\n".to_owned()),
        (Some(_), None) | (None, Some(_)) => {
            return Err("PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned());
        }
        _ => {}
    }
    let count = count.unwrap();
    if count == 0 {
        return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
    }

    let mut current = address.unwrap();
    let mut aux_total = 0u64;
    for record_index in 0..count {
        let offset = mapped_offset(
            &headers,
            file,
            current,
            ELF64_VERNEED_SIZE,
            &format!("DT_VERNEED entry {record_index}"),
        )?;
        let version = read_u16(file, offset);
        let aux_count = read_u16(file, offset + 2);
        let aux_relative = read_u32(file, offset + 8);
        let next_relative = read_u32(file, offset + 12);

        if version != VER_NEED_CURRENT {
            return Err(format!(
                "DT_VERNEED entry {record_index} has version {version}, expected {VER_NEED_CURRENT}"
            ));
        }
        if aux_count == 0 {
            return Err(format!(
                "DT_VERNEED entry {record_index} must reference at least one Vernaux record"
            ));
        }
        if u64::from(aux_relative) < ELF64_VERNEED_SIZE {
            return Err(format!(
                "DT_VERNEED entry {record_index} vn_aux {aux_relative} overlaps its {ELF64_VERNEED_SIZE}-byte Verneed record"
            ));
        }

        let mut aux_address = current
            .checked_add(u64::from(aux_relative))
            .ok_or_else(|| format!("DT_VERNEED entry {record_index} vn_aux overflows u64"))?;
        for aux_index in 0..u64::from(aux_count) {
            let aux_offset = mapped_offset(
                &headers,
                file,
                aux_address,
                ELF64_VERNAUX_SIZE,
                &format!("DT_VERNEED entry {record_index} Vernaux {aux_index}"),
            )?;
            let next = read_u32(file, aux_offset + 12);
            aux_total = aux_total
                .checked_add(1)
                .ok_or_else(|| "Vernaux count overflows u64".to_owned())?;

            let last = aux_index + 1 == u64::from(aux_count);
            if last {
                if next != 0 {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} final Vernaux has non-zero vna_next {next}"
                    ));
                }
            } else {
                if u64::from(next) < ELF64_VERNAUX_SIZE {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} Vernaux {aux_index} vna_next {next} does not advance past its {ELF64_VERNAUX_SIZE}-byte record"
                    ));
                }
                aux_address = aux_address.checked_add(u64::from(next)).ok_or_else(|| {
                    format!("DT_VERNEED entry {record_index} Vernaux address overflows u64")
                })?;
            }
        }

        let last = record_index + 1 == count;
        if last {
            if next_relative != 0 {
                return Err(format!(
                    "final DT_VERNEED entry has non-zero vn_next {next_relative} beyond DT_VERNEEDNUM {count}"
                ));
            }
        } else {
            if u64::from(next_relative) < ELF64_VERNEED_SIZE {
                return Err(format!(
                    "DT_VERNEED entry {record_index} vn_next {next_relative} does not advance past its {ELF64_VERNEED_SIZE}-byte record"
                ));
            }
            current = current
                .checked_add(u64::from(next_relative))
                .ok_or_else(|| "DT_VERNEED next-entry address overflows u64".to_owned())?;
        }
    }

    Ok(format!(
        "DT_VERNEED structural offsets are forward and non-overlapping across {count} dependency entries and {aux_total} Vernaux records.\n"
    ))
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        ));
    }
    let table_size = u64::from(header.program_header_count)
        .checked_mul(u64::from(header.program_header_entry_size))
        .ok_or_else(|| "program header table size overflows u64".to_owned())?;
    checked_file_range(file.len(), header.program_header_offset, table_size, "program header table")?;

    let mut result = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..u64::from(header.program_header_count) {
        let relative = index
            .checked_mul(u64::from(header.program_header_entry_size))
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        let offset = header
            .program_header_offset
            .checked_add(relative)
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program header offset does not fit usize".to_owned())?;
        let file_size = read_u64(file, offset + 32);
        let memory_size = read_u64(file, offset + 40);
        if file_size > memory_size {
            return Err(format!(
                "program header {index} has p_filesz {file_size} greater than p_memsz {memory_size}"
            ));
        }
        let segment_offset = read_u64(file, offset + 8);
        checked_file_range(file.len(), segment_offset, file_size, &format!("program header {index}"))?;
        let virtual_address = read_u64(file, offset + 16);
        virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| format!("program header {index} virtual range overflows u64"))?;
        result.push(ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: segment_offset,
            virtual_address,
            file_size,
            memory_size,
        });
    }
    Ok(result)
}

fn dynamic_entries(headers: &[ProgramHeader], file: &[u8]) -> Result<Vec<DynamicEntry>, String> {
    let dynamic = headers
        .iter()
        .filter(|header| header.segment_type == PT_DYNAMIC)
        .copied()
        .collect::<Vec<_>>();
    if dynamic.len() != 1 {
        return Err(format!(
            "ELF file has {} PT_DYNAMIC segments, expected exactly one",
            dynamic.len()
        ));
    }
    let dynamic = dynamic[0];
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC file size {} is not a multiple of {ELF64_DYNAMIC_SIZE}",
            dynamic.file_size
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
    Err("PT_DYNAMIC has no DT_NULL terminator within p_filesz".to_owned())
}

fn unique_tag_value(entries: &[DynamicEntry], wanted: i64, name: &str) -> Result<Option<u64>, String> {
    let mut found = None;
    for entry in entries {
        if entry.tag == wanted && found.replace(entry.value).is_some() {
            return Err(format!("PT_DYNAMIC contains duplicate {name} entries"));
        }
    }
    Ok(found)
}

fn mapped_offset(
    headers: &[ProgramHeader],
    file: &[u8],
    address: u64,
    size: u64,
    label: &str,
) -> Result<usize, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let file_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| "PT_LOAD file-backed virtual range overflows u64".to_owned())?;
        let memory_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| "PT_LOAD memory virtual range overflows u64".to_owned())?;
        if address < header.virtual_address || end > file_end || end > memory_end {
            continue;
        }
        let relative = address - header.virtual_address;
        let offset = header
            .offset
            .checked_add(relative)
            .ok_or_else(|| format!("{label} file offset overflows u64"))?;
        checked_file_range(file.len(), offset, size, label)?;
        return usize::try_from(offset)
            .map_err(|_| format!("{label} file offset does not fit usize"));
    }
    Err(format!(
        "{label} virtual range {address:#x}..{end:#x} is not fully file-backed by PT_LOAD"
    ))
}

fn checked_file_range(file_len: usize, offset: u64, size: u64, label: &str) -> Result<(), String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows u64"))?;
    let file_len = u64::try_from(file_len).map_err(|_| "file length does not fit u64".to_owned())?;
    if end > file_len {
        return Err(format!(
            "{label} file range {offset}..{end} exceeds file length {file_len}"
        ));
    }
    Ok(())
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
