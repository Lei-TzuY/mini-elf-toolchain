use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_HDR_FIXED_SIZE: u64 = 12;
const EH_FRAME_TABLE_ENTRY_SIZE: u64 = 8;
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_DATAREL_SDATA4: u8 = 0x3b;

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
struct SearchEntry {
    initial_location: u64,
    fde_address: u64,
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
            Ok("usage: mini-elf-eh-frame [--load-bias <address>] <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-eh-frame [--load-bias <address>] <input>...".to_owned())
        };
    }

    let mut load_bias = None;
    let mut inputs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        if arg == "--load-bias" {
            if load_bias.is_some() {
                return Err("--load-bias may be specified at most once".to_owned());
            }
            index += 1;
            if index == args.len() {
                return Err("--load-bias requires an address".to_owned());
            }
            load_bias = Some(parse_u64(&args[index].to_string_lossy(), "--load-bias")?);
        } else if let Some(value) = arg.strip_prefix("--load-bias=") {
            if load_bias.is_some() {
                return Err("--load-bias may be specified at most once".to_owned());
            }
            load_bias = Some(parse_u64(value, "--load-bias")?);
        } else if arg.starts_with('-') {
            return Err(format!("unknown option '{arg}'"));
        } else {
            inputs.push(args[index].clone());
        }
        index += 1;
    }
    if inputs.is_empty() {
        return Err("usage: mini-elf-eh-frame [--load-bias <address>] <input>...".to_owned());
    }

    let multiple_inputs = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_eh_frame(header, &file, load_bias)
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

fn parse_u64(value: &str, option: &str) -> Result<u64, String> {
    if value.is_empty() {
        return Err(format!("{option} requires a non-empty address"));
    }
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.is_empty() {
            None
        } else {
            u64::from_str_radix(hex, 16).ok()
        }
    } else {
        value.parse::<u64>().ok()
    };
    parsed.ok_or_else(|| format!("invalid {option} address '{value}'"))
}

fn format_eh_frame(
    header: Elf64Header,
    file: &[u8],
    load_bias: Option<u64>,
) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let segments = program_headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_GNU_EH_FRAME)
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Ok("No PT_GNU_EH_FRAME segment found.\n".to_owned());
    }
    if segments.len() != 1 {
        return Err(format!(
            "expected at most one PT_GNU_EH_FRAME segment, found {}",
            segments.len()
        ));
    }

    let (segment_index, segment) = segments[0];
    if segment.file_size < EH_FRAME_HDR_FIXED_SIZE {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} file-backed .eh_frame_hdr is only {} bytes; need at least {EH_FRAME_HDR_FIXED_SIZE}",
            segment.file_size
        ));
    }
    let end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or_else(|| {
            format!("PT_GNU_EH_FRAME segment {segment_index} virtual memory range overflows u64")
        })?;
    require_load_containment(
        &program_headers,
        segment.virtual_address,
        end,
        segment_index,
    )?;
    let file_end = segment
        .offset
        .checked_add(segment.file_size)
        .ok_or_else(|| {
            format!("PT_GNU_EH_FRAME segment {segment_index} file range overflows u64")
        })?;
    let file_start = usize::try_from(segment.offset)
        .map_err(|_| "PT_GNU_EH_FRAME file offset does not fit usize".to_owned())?;
    if file[file_start] != 1 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr version {} (expected 1)",
            file[file_start]
        ));
    }

    let eh_frame_ptr_encoding = file[file_start + 1];
    let fde_count_encoding = file[file_start + 2];
    let table_encoding = file[file_start + 3];
    if eh_frame_ptr_encoding != DW_EH_PE_PCREL_SDATA4
        || fde_count_encoding != DW_EH_PE_UDATA4
        || table_encoding != DW_EH_PE_DATAREL_SDATA4
    {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr encodings: eh_frame_ptr={eh_frame_ptr_encoding:#04x}, fde_count={fde_count_encoding:#04x}, table={table_encoding:#04x}; expected 0x1b/0x03/0x3b"
        ));
    }

    let fde_count = u64::from(read_u32(file, file_start + 8));
    let table_size = fde_count
        .checked_mul(EH_FRAME_TABLE_ENTRY_SIZE)
        .ok_or_else(|| {
            format!(
                "PT_GNU_EH_FRAME segment {segment_index} binary-search table size overflows u64"
            )
        })?;
    let required_size = EH_FRAME_HDR_FIXED_SIZE
        .checked_add(table_size)
        .ok_or_else(|| {
            format!("PT_GNU_EH_FRAME segment {segment_index} .eh_frame_hdr size overflows u64")
        })?;
    if required_size > segment.file_size {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} declares {fde_count} FDE table entries requiring {required_size} bytes, but segment has only {} file-backed bytes",
            segment.file_size
        ));
    }

    let table_start = file_start + usize::try_from(EH_FRAME_HDR_FIXED_SIZE).unwrap();
    let mut entries = Vec::with_capacity(
        usize::try_from(fde_count)
            .map_err(|_| "FDE count does not fit usize for table traversal".to_owned())?,
    );
    let mut previous_initial = None;
    for entry_index in 0..fde_count {
        let relative = entry_index
            .checked_mul(EH_FRAME_TABLE_ENTRY_SIZE)
            .ok_or_else(|| "binary-search table entry offset overflows u64".to_owned())?;
        let relative = usize::try_from(relative)
            .map_err(|_| "binary-search table entry offset does not fit usize".to_owned())?;
        let offset = table_start
            .checked_add(relative)
            .ok_or_else(|| "binary-search table file offset overflows usize".to_owned())?;
        let initial_delta = read_i32(file, offset);
        let fde_delta = read_i32(file, offset + 4);
        let initial_location = checked_add_i32(segment.virtual_address, initial_delta).ok_or_else(|| {
            format!(
                "PT_GNU_EH_FRAME segment {segment_index} table entry {entry_index} initial-location arithmetic overflows: datarel base {:#x} + displacement {initial_delta}",
                segment.virtual_address
            )
        })?;
        let fde_address = checked_add_i32(segment.virtual_address, fde_delta).ok_or_else(|| {
            format!(
                "PT_GNU_EH_FRAME segment {segment_index} table entry {entry_index} FDE-address arithmetic overflows: datarel base {:#x} + displacement {fde_delta}",
                segment.virtual_address
            )
        })?;
        require_executable_file_backed_load_address(&program_headers, initial_location, entry_index)?;
        require_file_backed_load_address(&program_headers, fde_address, entry_index)?;
        if let Some(previous) = previous_initial {
            if initial_location <= previous {
                return Err(format!(
                    "PT_GNU_EH_FRAME segment {segment_index} binary-search table is not strictly increasing at entry {entry_index}: {initial_location:#x} <= {previous:#x}"
                ));
            }
        }
        previous_initial = Some(initial_location);
        entries.push(SearchEntry {
            initial_location,
            fde_address,
        });
    }

    let runtime = if let Some(load_bias) = load_bias {
        let runtime_start = load_bias
            .checked_add(segment.virtual_address)
            .ok_or_else(|| {
                format!(
                    "PT_GNU_EH_FRAME segment {segment_index} runtime start overflows u64: load bias {load_bias:#x} + virtual address {:#x}",
                    segment.virtual_address
                )
            })?;
        let runtime_end = runtime_start
            .checked_add(segment.memory_size)
            .ok_or_else(|| {
                format!(
                    "PT_GNU_EH_FRAME segment {segment_index} runtime end overflows u64: runtime start {runtime_start:#x} + memory size {:#x}",
                    segment.memory_size
                )
            })?;
        Some((load_bias, runtime_start, runtime_end))
    } else {
        None
    };

    let mut output = String::new();
    output.push_str("Found 1 PT_GNU_EH_FRAME segment:\n");
    output.push_str(&format!("Header version: {}\n", file[file_start]));
    output.push_str(&format!(
        "Encodings: eh_frame_ptr={eh_frame_ptr_encoding:#04x} fde_count={fde_count_encoding:#04x} table={table_encoding:#04x}\n"
    ));
    output.push_str(&format!("FDE count: {fde_count}\n"));
    output.push_str(&format!("Validated search entries: {}\n", entries.len()));
    for (index, entry) in entries.iter().enumerate() {
        output.push_str(&format!(
            "Entry {index}: initial={:#018x} fde={:#018x}\n",
            entry.initial_location, entry.fde_address
        ));
    }
    output.push_str(&format!(
        "File range: {:#018x}..{file_end:#018x}\n",
        segment.offset
    ));
    output.push_str(&format!(
        "Link-time range: {:#018x}..{end:#018x}\n",
        segment.virtual_address
    ));
    if let Some((load_bias, runtime_start, runtime_end)) = runtime {
        output.push_str(&format!("Load bias: {load_bias:#018x}\n"));
        output.push_str(&format!(
            "Runtime range: {runtime_start:#018x}..{runtime_end:#018x}\n"
        ));
    }
    Ok(output)
}

fn checked_add_i32(base: u64, displacement: i32) -> Option<u64> {
    if displacement >= 0 {
        base.checked_add(displacement as u64)
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs()))
    }
}

fn require_load_containment(
    program_headers: &[ProgramHeader],
    start: u64,
    end: u64,
    segment_index: usize,
) -> Result<(), String> {
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual memory range overflows u64"))?;
        if start >= header.virtual_address && end <= load_end {
            return Ok(());
        }
    }
    Err(format!(
        "PT_GNU_EH_FRAME segment {segment_index} virtual memory range {start:#x}..{end:#x} is not contained in a PT_LOAD memory range"
    ))
}

fn require_executable_file_backed_load_address(
    program_headers: &[ProgramHeader],
    address: u64,
    entry_index: u64,
) -> Result<usize, String> {
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD || header.flags & PF_X == 0 {
            continue;
        }
        let file_backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| {
                format!("PT_LOAD segment {index} file-backed virtual range overflows u64")
            })?;
        if address >= header.virtual_address && address < file_backed_end {
            return Ok(index);
        }
    }
    Err(format!(
        "binary-search table entry {entry_index} initial location {address:#x} is not contained in an executable file-backed PT_LOAD range"
    ))
}

fn require_file_backed_load_address(
    program_headers: &[ProgramHeader],
    address: u64,
    entry_index: u64,
) -> Result<usize, String> {
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let file_backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| {
                format!("PT_LOAD segment {index} file-backed virtual range overflows u64")
            })?;
        if address >= header.virtual_address && address < file_backed_end {
            return Ok(index);
        }
    }
    Err(format!(
        "binary-search table entry {entry_index} FDE address {address:#x} is not contained in a file-backed PT_LOAD range"
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
        header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| format!("program header {index} virtual memory range overflows u64"))?;
        headers.push(header);
    }
    Ok(headers)
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

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
