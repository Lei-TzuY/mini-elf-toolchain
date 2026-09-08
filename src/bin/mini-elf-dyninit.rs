use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_ADDR_SIZE: u64 = 8;
const DT_NULL: i64 = 0;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
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
            Ok("usage: mini-elf-dyninit <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dyninit <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = inspect_dynamic_lifecycle(header, &file)
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

fn inspect_dynamic_lifecycle(header: Elf64Header, file: &[u8]) -> Result<String, String> {
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
    let entries = dynamic_entries(dynamic, file, dynamic_end)?;

    let preinit = dynamic_array(
        &entries,
        DT_PREINIT_ARRAY,
        "DT_PREINIT_ARRAY",
        DT_PREINIT_ARRAYSZ,
        "DT_PREINIT_ARRAYSZ",
        &program_headers,
        file,
    )?;
    let init_hook = dynamic_hook(&entries, DT_INIT, "DT_INIT", &program_headers)?;
    let init = dynamic_array(
        &entries,
        DT_INIT_ARRAY,
        "DT_INIT_ARRAY",
        DT_INIT_ARRAYSZ,
        "DT_INIT_ARRAYSZ",
        &program_headers,
        file,
    )?;
    let fini = dynamic_array(
        &entries,
        DT_FINI_ARRAY,
        "DT_FINI_ARRAY",
        DT_FINI_ARRAYSZ,
        "DT_FINI_ARRAYSZ",
        &program_headers,
        file,
    )?;
    let fini_hook = dynamic_hook(&entries, DT_FINI, "DT_FINI", &program_headers)?;

    let mut output = format!("PT_DYNAMIC segment {segment_index} lifecycle metadata:\n");
    render_array(&mut output, "DT_PREINIT_ARRAY", preinit);
    render_hook(&mut output, "DT_INIT", init_hook);
    render_array(&mut output, "DT_INIT_ARRAY", init);
    render_array(&mut output, "DT_FINI_ARRAY", fini);
    render_hook(&mut output, "DT_FINI", fini_hook);
    Ok(output)
}

fn dynamic_entries(
    dynamic: &ProgramHeader,
    file: &[u8],
    dynamic_end: u64,
) -> Result<Vec<DynamicEntry>, String> {
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
        "PT_DYNAMIC segment has no DT_NULL terminator before file offset {dynamic_end}"
    ))
}

fn dynamic_hook(
    entries: &[DynamicEntry],
    tag: i64,
    name: &str,
    program_headers: &[ProgramHeader],
) -> Result<Option<u64>, String> {
    let Some(address) = unique_tag_value(entries, tag, name)? else {
        return Ok(None);
    };
    validate_hook_address(program_headers, address, name)?;
    Ok(Some(address))
}

fn validate_hook_address(
    program_headers: &[ProgramHeader],
    address: u64,
    name: &str,
) -> Result<(), String> {
    let address_end = address
        .checked_add(1)
        .ok_or_else(|| format!("{name} virtual address range overflows u64"))?;
    let mut containing_load = None;
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual memory range overflows u64"))?;
        if address >= header.virtual_address && address_end <= load_end {
            containing_load = Some((index, header.flags));
            if header.flags & PF_X != 0 {
                return Ok(());
            }
        }
    }
    if let Some((index, _)) = containing_load {
        return Err(format!(
            "{name} virtual address {address:#x} is within non-executable PT_LOAD segment {index}"
        ));
    }
    Err(format!(
        "{name} virtual address {address:#x} is not within a PT_LOAD memory range"
    ))
}

fn dynamic_array(
    entries: &[DynamicEntry],
    address_tag: i64,
    address_name: &str,
    size_tag: i64,
    size_name: &str,
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Option<(u64, Vec<u64>)>, String> {
    let address = unique_tag_value(entries, address_tag, address_name)?;
    let size = unique_tag_value(entries, size_tag, size_name)?;
    let (address, size) = match (address, size) {
        (None, None) => return Ok(None),
        (Some(address), Some(size)) => (address, size),
        _ => {
            return Err(format!(
                "PT_DYNAMIC must provide {address_name} and {size_name} together"
            ));
        }
    };
    if size % ELF64_ADDR_SIZE != 0 {
        return Err(format!(
            "{size_name} value {size} is not a multiple of {ELF64_ADDR_SIZE}"
        ));
    }
    if size == 0 {
        return Ok(Some((address, Vec::new())));
    }
    let file_offset = map_virtual_range(program_headers, file.len(), address, size, address_name)?;
    let count = size / ELF64_ADDR_SIZE;
    let mut pointers = Vec::with_capacity(
        usize::try_from(count)
            .map_err(|_| format!("{address_name} entry count does not fit usize"))?,
    );
    for index in 0..count {
        let relative = index
            .checked_mul(ELF64_ADDR_SIZE)
            .ok_or_else(|| format!("{address_name} entry offset overflows u64"))?;
        let offset = file_offset
            .checked_add(relative)
            .ok_or_else(|| format!("{address_name} entry offset overflows u64"))?;
        let offset = usize::try_from(offset)
            .map_err(|_| format!("{address_name} entry offset does not fit usize"))?;
        pointers.push(read_u64(file, offset));
    }
    Ok(Some((address, pointers)))
}

fn render_hook(output: &mut String, name: &str, address: Option<u64>) {
    match address {
        None => output.push_str(&format!("  {name}: absent\n")),
        Some(address) => output.push_str(&format!("  {name}: address={address:#x}\n")),
    }
}

fn render_array(output: &mut String, name: &str, array: Option<(u64, Vec<u64>)>) {
    match array {
        None => output.push_str(&format!("  {name}: absent\n")),
        Some((address, pointers)) => {
            output.push_str(&format!(
                "  {name}: address={address:#x} entries={}\n",
                pointers.len()
            ));
            for (index, pointer) in pointers.into_iter().enumerate() {
                output.push_str(&format!("    [{index}] {pointer:#x}\n"));
            }
        }
    }
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
            flags: read_u32(file, offset + 4),
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
