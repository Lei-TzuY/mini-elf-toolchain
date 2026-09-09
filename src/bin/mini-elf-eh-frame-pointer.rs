use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_PTR_MIN_SIZE: u64 = 8;
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
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
            Ok("usage: mini-elf-eh-frame-pointer [--load-bias <address>] <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-eh-frame-pointer [--load-bias <address>] <input>...".to_owned())
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
        return Err(
            "usage: mini-elf-eh-frame-pointer [--load-bias <address>] <input>...".to_owned(),
        );
    }

    let multiple_inputs = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_pointer(header, &file, load_bias)
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

fn format_pointer(
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
    if segment.file_size < EH_FRAME_PTR_MIN_SIZE {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} file-backed .eh_frame_hdr is only {} bytes; need at least {EH_FRAME_PTR_MIN_SIZE}",
            segment.file_size
        ));
    }
    let segment_end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or_else(|| {
            format!("PT_GNU_EH_FRAME segment {segment_index} virtual memory range overflows u64")
        })?;
    require_load_containment(
        &program_headers,
        segment.virtual_address,
        segment_end,
        segment_index,
    )?;

    let file_start = usize::try_from(segment.offset)
        .map_err(|_| "PT_GNU_EH_FRAME file offset does not fit usize".to_owned())?;
    if file[file_start] != 1 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr version {} (expected 1)",
            file[file_start]
        ));
    }
    let pointer_encoding = file[file_start + 1];
    if pointer_encoding != DW_EH_PE_PCREL_SDATA4 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame pointer encoding {pointer_encoding:#04x} (expected 0x1b)"
        ));
    }

    let pointer_field_address = segment.virtual_address.checked_add(4).ok_or_else(|| {
        format!(
            "PT_GNU_EH_FRAME segment {segment_index} .eh_frame pointer field address overflows u64"
        )
    })?;
    let displacement = read_i32(file, file_start + 4);
    let eh_frame_address = checked_add_i32(pointer_field_address, displacement).ok_or_else(|| {
        format!(
            "PT_GNU_EH_FRAME segment {segment_index} .eh_frame pointer arithmetic overflows: field {pointer_field_address:#x} + displacement {displacement}"
        )
    })?;
    let load_index = require_file_backed_load_address(&program_headers, eh_frame_address)?;

    let runtime = if let Some(load_bias) = load_bias {
        Some(load_bias.checked_add(eh_frame_address).ok_or_else(|| {
            format!(
                "runtime .eh_frame address overflows u64: load bias {load_bias:#x} + link-time address {eh_frame_address:#x}"
            )
        })?)
    } else {
        None
    };

    let mut output = String::new();
    output.push_str("Found checked .eh_frame pointer:\n");
    output.push_str(&format!("PT_GNU_EH_FRAME segment: {segment_index}\n"));
    output.push_str(&format!("Pointer encoding: {pointer_encoding:#04x}\n"));
    output.push_str(&format!("Pointer displacement: {displacement}\n"));
    output.push_str(&format!(
        "Link-time .eh_frame address: {eh_frame_address:#018x}\n"
    ));
    output.push_str(&format!("File-backed PT_LOAD segment: {load_index}\n"));
    if let Some(runtime) = runtime {
        output.push_str(&format!("Runtime .eh_frame address: {runtime:#018x}\n"));
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

fn require_file_backed_load_address(
    program_headers: &[ProgramHeader],
    address: u64,
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
        "decoded .eh_frame address {address:#x} is not contained in a file-backed PT_LOAD range"
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
