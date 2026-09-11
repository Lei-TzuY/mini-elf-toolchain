use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
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
            Ok("usage: mini-elf-gnu-hash <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-gnu-hash <input>...".to_owned())
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
            format_gnu_hash(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_gnu_hash(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let hash_address = unique_tag_value(&entries, DT_GNU_HASH, "DT_GNU_HASH")?
        .ok_or_else(|| "No DT_GNU_HASH entry found.".to_owned())?;

    let header_offset = map_virtual_range(
        &program_headers,
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
    let bloom_shift = read_u32(file, header_offset + 12);

    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }

    let bloom_bytes = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or_else(|| "DT_GNU_HASH bloom byte size overflows u64".to_owned())?;
    let bucket_bytes = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH bucket byte size overflows u64".to_owned())?;
    let prefix_size = 16u64
        .checked_add(bloom_bytes)
        .and_then(|value| value.checked_add(bucket_bytes))
        .ok_or_else(|| "DT_GNU_HASH prefix byte size overflows u64".to_owned())?;
    let prefix_offset = map_virtual_range(
        &program_headers,
        file.len(),
        hash_address,
        prefix_size,
        "DT_GNU_HASH prefix",
    )?;
    let prefix_offset = usize::try_from(prefix_offset)
        .map_err(|_| "DT_GNU_HASH prefix offset does not fit usize".to_owned())?;

    let bucket_start = 16u64
        .checked_add(bloom_bytes)
        .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?;
    let bucket_start = usize::try_from(bucket_start)
        .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
    let chain_address = hash_address
        .checked_add(prefix_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;

    let mut buckets = Vec::with_capacity(bucket_count as usize);
    let mut symbol_count = symbol_offset;
    let mut max_chain_words = 0u64;
    for bucket_index in 0..bucket_count {
        let bucket_relative = u64::from(bucket_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?;
        let bucket_relative = usize::try_from(bucket_relative)
            .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
        let bucket_offset = prefix_offset
            .checked_add(bucket_start)
            .and_then(|value| value.checked_add(bucket_relative))
            .ok_or_else(|| "DT_GNU_HASH bucket file offset overflows usize".to_owned())?;
        let start_symbol = read_u32(file, bucket_offset);
        buckets.push(start_symbol);
        if start_symbol == 0 {
            continue;
        }
        if start_symbol < symbol_offset {
            return Err(format!(
                "DT_GNU_HASH bucket {bucket_index} starts at symbol {start_symbol}, below symbol offset {symbol_offset}"
            ));
        }

        let mut symbol = start_symbol;
        loop {
            let chain_index = symbol
                .checked_sub(symbol_offset)
                .ok_or_else(|| "DT_GNU_HASH chain index underflows".to_owned())?;
            let chain_relative = u64::from(chain_index)
                .checked_mul(4)
                .ok_or_else(|| "DT_GNU_HASH chain offset overflows u64".to_owned())?;
            let entry_address = chain_address
                .checked_add(chain_relative)
                .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
            let entry_offset = map_virtual_range(
                &program_headers,
                file.len(),
                entry_address,
                4,
                &format!(
                    "DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"
                ),
            )?;
            let entry_offset = usize::try_from(entry_offset)
                .map_err(|_| "DT_GNU_HASH chain offset does not fit usize".to_owned())?;
            let chain_value = read_u32(file, entry_offset);
            let next = symbol
                .checked_add(1)
                .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
            symbol_count = symbol_count.max(next);
            max_chain_words = max_chain_words.max(u64::from(chain_index) + 1);
            if chain_value & 1 != 0 {
                break;
            }
            symbol = next;
        }
    }

    let chain_bytes = max_chain_words
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH chain byte size overflows u64".to_owned())?;
    if chain_bytes != 0 {
        map_virtual_range(
            &program_headers,
            file.len(),
            chain_address,
            chain_bytes,
            "DT_GNU_HASH chain table",
        )?;
    }

    let mut output = format!(
        "GNU DT_GNU_HASH at {hash_address:#x}: {bucket_count} buckets, {bloom_count} bloom words, symbol-offset={symbol_offset}, bloom-shift={bloom_shift}, dynamic symbols: {symbol_count}\n"
    );
    output.push_str("Buckets:\n");
    for (index, value) in buckets.into_iter().enumerate() {
        output.push_str(&format!("  [{index}] {value}\n"));
    }
    output.push_str(&format!("Chain words inspected: {max_chain_words}\n"));
    Ok(output)
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
