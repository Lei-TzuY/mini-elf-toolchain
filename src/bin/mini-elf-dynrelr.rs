use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_RELR_SIZE: u64 = 8;
const DT_NULL: i64 = 0;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;
const RELR_BITMAP_SLOTS: u64 = 63;

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
            Ok("usage: mini-elf-dynrelr <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynrelr <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_dynamic_relr(header, &file)
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

fn format_dynamic_relr(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let relr = unique_tag_value(&entries, DT_RELR, "DT_RELR")?;
    let relr_size = unique_tag_value(&entries, DT_RELRSZ, "DT_RELRSZ")?;
    let relr_entry_size = unique_tag_value(&entries, DT_RELRENT, "DT_RELRENT")?;

    let present = usize::from(relr.is_some())
        + usize::from(relr_size.is_some())
        + usize::from(relr_entry_size.is_some());
    if present == 0 {
        return Ok("No DT_RELR relocation table found.\n".to_owned());
    }
    if present != 3 {
        return Err("PT_DYNAMIC must provide DT_RELR, DT_RELRSZ, and DT_RELRENT together".to_owned());
    }

    let relr_address = relr.unwrap();
    let relr_size = relr_size.unwrap();
    let relr_entry_size = relr_entry_size.unwrap();
    if relr_entry_size != ELF64_RELR_SIZE {
        return Err(format!(
            "DT_RELRENT is {relr_entry_size}, expected {ELF64_RELR_SIZE} for ELF64"
        ));
    }
    if relr_size % relr_entry_size != 0 {
        return Err(format!(
            "DT_RELRSZ {relr_size} is not a multiple of DT_RELRENT {relr_entry_size}"
        ));
    }

    let table_offset = map_virtual_file_range(
        &program_headers,
        file.len(),
        relr_address,
        relr_size,
        "DT_RELR table",
    )?;
    let encoded_count = relr_size / relr_entry_size;
    let mut decoded = Vec::new();
    let mut cursor = None;

    for index in 0..encoded_count {
        let relative = index
            .checked_mul(relr_entry_size)
            .ok_or_else(|| "DT_RELR entry offset overflows u64".to_owned())?;
        let offset = table_offset
            .checked_add(relative)
            .ok_or_else(|| "DT_RELR entry offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_RELR entry offset does not fit usize".to_owned())?;
        let entry = read_u64(file, offset);

        if entry & 1 == 0 {
            if entry % ELF64_RELR_SIZE != 0 {
                return Err(format!(
                    "DT_RELR address entry {index} value {entry:#x} is not 8-byte aligned"
                ));
            }
            validate_relocation_target(&program_headers, entry, index)?;
            decoded.push(entry);
            cursor = Some(
                entry
                    .checked_add(ELF64_RELR_SIZE)
                    .ok_or_else(|| format!("DT_RELR address entry {index} cursor overflows u64"))?,
            );
            continue;
        }

        let base = cursor.ok_or_else(|| {
            format!("DT_RELR bitmap entry {index} appears before any address entry")
        })?;
        for bit in 1..64_u32 {
            if entry & (1_u64 << bit) == 0 {
                continue;
            }
            let slot = u64::from(bit - 1);
            let delta = slot
                .checked_mul(ELF64_RELR_SIZE)
                .ok_or_else(|| format!("DT_RELR bitmap entry {index} slot offset overflows u64"))?;
            let address = base
                .checked_add(delta)
                .ok_or_else(|| format!("DT_RELR bitmap entry {index} relocation address overflows u64"))?;
            validate_relocation_target(&program_headers, address, index)?;
            decoded.push(address);
        }
        let advance = RELR_BITMAP_SLOTS
            .checked_mul(ELF64_RELR_SIZE)
            .ok_or_else(|| "DT_RELR bitmap cursor advance overflows u64".to_owned())?;
        cursor = Some(
            base.checked_add(advance)
                .ok_or_else(|| format!("DT_RELR bitmap entry {index} cursor overflows u64"))?,
        );
    }

    let mut output = format!(
        "DT_RELR contains {encoded_count} encoded entries, {} relocations:\n",
        decoded.len()
    );
    output.push_str("  Offset\n");
    for address in decoded {
        output.push_str(&format!("  {address:#018x}\n"));
    }
    Ok(output)
}

fn validate_relocation_target(
    program_headers: &[ProgramHeader],
    address: u64,
    entry_index: u64,
) -> Result<(), String> {
    let end = address.checked_add(ELF64_RELR_SIZE).ok_or_else(|| {
        format!("DT_RELR entry {entry_index} relocation target range overflows u64")
    })?;
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual memory range overflows u64"))?;
        if address >= header.virtual_address && end <= load_end {
            return Ok(());
        }
    }
    Err(format!(
        "DT_RELR entry {entry_index} relocation target {address:#x}..{end:#x} is not within a PT_LOAD memory range"
    ))
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

fn map_virtual_file_range(
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
