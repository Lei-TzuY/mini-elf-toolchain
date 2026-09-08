use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_VERSYM_SIZE: u64 = 2;
const VERSYM_HIDDEN: u16 = 0x8000;
const VERSYM_INDEX_MASK: u16 = 0x7fff;

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
            Ok("usage: mini-elf-versym <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-versym <input>...".to_owned())
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
            format_version_symbols(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_version_symbols(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let Some(versym_address) = unique_tag_value(&entries, DT_VERSYM, "DT_VERSYM")? else {
        return Ok("No DT_VERSYM version-symbol table found.\n".to_owned());
    };
    let symbol_count = dynamic_symbol_count(&entries, &program_headers, file)?;

    let table_size = u64::from(symbol_count)
        .checked_mul(ELF64_VERSYM_SIZE)
        .ok_or_else(|| "DT_VERSYM table size overflows u64".to_owned())?;
    let table_offset = map_virtual_range(
        &program_headers,
        file.len(),
        versym_address,
        table_size,
        "DT_VERSYM table",
    )?;
    let table_offset = usize::try_from(table_offset)
        .map_err(|_| "DT_VERSYM table offset does not fit usize".to_owned())?;

    let mut output = format!("DT_VERSYM at {versym_address:#x} contains {symbol_count} entries:\n");
    for symbol_index in 0..symbol_count {
        let relative = u64::from(symbol_index)
            .checked_mul(ELF64_VERSYM_SIZE)
            .ok_or_else(|| "DT_VERSYM entry offset overflows u64".to_owned())?;
        let relative = usize::try_from(relative)
            .map_err(|_| "DT_VERSYM entry offset does not fit usize".to_owned())?;
        let raw = read_u16(file, table_offset + relative);
        let version_index = raw & VERSYM_INDEX_MASK;
        let hidden = raw & VERSYM_HIDDEN != 0;
        let class = match version_index {
            0 => "local",
            1 => "global",
            _ => "versioned",
        };
        output.push_str(&format!(
            "  symbol[{symbol_index}] raw={raw:#06x} index={version_index} hidden={} class={class}\n",
            if hidden { "yes" } else { "no" }
        ));
    }
    Ok(output)
}

fn dynamic_symbol_count(
    entries: &[DynamicEntry],
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<u32, String> {
    let sysv_hash = unique_tag_value(entries, DT_HASH, "DT_HASH")?;
    let gnu_hash = unique_tag_value(entries, DT_GNU_HASH, "DT_GNU_HASH")?;

    if let Some(hash_address) = sysv_hash {
        let hash_offset = map_virtual_range(
            program_headers,
            file.len(),
            hash_address,
            8,
            "DT_HASH header",
        )?;
        let hash_offset = usize::try_from(hash_offset)
            .map_err(|_| "DT_HASH header offset does not fit usize".to_owned())?;
        return Ok(read_u32(file, hash_offset + 4));
    }

    if let Some(hash_address) = gnu_hash {
        return gnu_hash_symbol_count(program_headers, file, hash_address);
    }

    Err("DT_VERSYM requires DT_HASH or DT_GNU_HASH to derive dynamic-symbol count".to_owned())
}

fn gnu_hash_symbol_count(
    program_headers: &[ProgramHeader],
    file: &[u8],
    hash_address: u64,
) -> Result<u32, String> {
    let header_offset = map_virtual_range(
        program_headers,
        file.len(),
        hash_address,
        16,
        "DT_GNU_HASH header",
    )?;
    let header_offset = usize::try_from(header_offset)
        .map_err(|_| "DT_GNU_HASH header offset does not fit usize".to_owned())?;
    let bucket_count = read_u32(file, header_offset);
    let symbol_offset = read_u32(file, header_offset + 4);
    let bloom_count = read_u32(file, header_offset + 8);

    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }

    let bloom_size = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or_else(|| "DT_GNU_HASH bloom byte size overflows u64".to_owned())?;
    let buckets_size = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH bucket byte size overflows u64".to_owned())?;
    let prefix_size = 16u64
        .checked_add(bloom_size)
        .and_then(|value| value.checked_add(buckets_size))
        .ok_or_else(|| "DT_GNU_HASH prefix byte size overflows u64".to_owned())?;
    let table_offset = map_virtual_range(
        program_headers,
        file.len(),
        hash_address,
        prefix_size,
        "DT_GNU_HASH prefix",
    )?;
    let bucket_file_offset = table_offset
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_size))
        .ok_or_else(|| "DT_GNU_HASH bucket file offset overflows u64".to_owned())?;
    let bucket_file_offset = usize::try_from(bucket_file_offset)
        .map_err(|_| "DT_GNU_HASH bucket file offset does not fit usize".to_owned())?;
    let chain_address = hash_address
        .checked_add(prefix_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;

    let mut symbol_count = symbol_offset;
    for bucket_index in 0..bucket_count {
        let relative = u64::from(bucket_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?;
        let relative = usize::try_from(relative)
            .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
        let symbol = read_u32(file, bucket_file_offset + relative);
        if symbol == 0 {
            continue;
        }
        if symbol < symbol_offset {
            return Err(format!(
                "DT_GNU_HASH bucket {bucket_index} starts at symbol {symbol}, below symbol offset {symbol_offset}"
            ));
        }
        let bucket_end = walk_gnu_hash_chain(
            program_headers,
            file,
            chain_address,
            symbol_offset,
            symbol,
            bucket_index,
        )?;
        symbol_count = symbol_count.max(bucket_end);
    }
    Ok(symbol_count)
}

fn walk_gnu_hash_chain(
    program_headers: &[ProgramHeader],
    file: &[u8],
    chain_address: u64,
    symbol_offset: u32,
    start_symbol: u32,
    bucket_index: u32,
) -> Result<u32, String> {
    let mut symbol = start_symbol;
    loop {
        let chain_index = symbol
            .checked_sub(symbol_offset)
            .ok_or_else(|| "DT_GNU_HASH chain index underflows".to_owned())?;
        let relative = u64::from(chain_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH chain offset overflows u64".to_owned())?;
        let address = chain_address
            .checked_add(relative)
            .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
        let offset = map_virtual_range(
            program_headers,
            file.len(),
            address,
            4,
            &format!("DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"),
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_GNU_HASH chain entry offset does not fit usize".to_owned())?;
        let hash = read_u32(file, offset);
        let next = symbol
            .checked_add(1)
            .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
        if hash & 1 != 0 {
            return Ok(next);
        }
        symbol = next;
    }
}

fn dynamic_entries(
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<DynamicEntry>, String> {
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
        return Err("no PT_DYNAMIC segment found".to_owned());
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
        if entry.tag == DT_NULL {
            return Ok(entries);
        }
    }
    Err(format!(
        "PT_DYNAMIC segment {segment_index} has no DT_NULL terminator before file offset {dynamic_end}"
    ))
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        ));
    }
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
        let program_header = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if program_header.file_size > program_header.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                program_header.file_size, program_header.memory_size
            ));
        }
        checked_file_end(
            program_header.offset,
            program_header.file_size,
            file.len(),
            &format!("program header {index}"),
        )?;
        program_header
            .virtual_address
            .checked_add(program_header.memory_size)
            .ok_or_else(|| format!("program header {index} virtual range overflows u64"))?;
        headers.push(program_header);
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
        let load_file_vaddr_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual file range overflows u64"))?;
        if address < header.virtual_address || address_end > load_file_vaddr_end {
            continue;
        }
        let delta = address
            .checked_sub(header.virtual_address)
            .ok_or_else(|| format!("{what} virtual-to-file translation underflows"))?;
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
