use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_HDR_PREFIX_SIZE: u64 = 4;

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
    if segment.file_size < EH_FRAME_HDR_PREFIX_SIZE {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} file-backed .eh_frame_hdr prefix is only {} bytes; need at least {EH_FRAME_HDR_PREFIX_SIZE}",
            segment.file_size
        ));
    }
    let end = segment
        .virtual_address
        .checked_add(segment.memory_size)
        .ok_or_else(|| {
            format!("PT_GNU_EH_FRAME segment {segment_index} virtual memory range overflows u64")
        })?;
    require_load_containment(&program_headers, segment.virtual_address, end, segment_index)?;
    let file_end = segment
        .offset
        .checked_add(segment.file_size)
        .ok_or_else(|| format!("PT_GNU_EH_FRAME segment {segment_index} file range overflows u64"))?;
    let file_start = usize::try_from(segment.offset)
        .map_err(|_| "PT_GNU_EH_FRAME file offset does not fit usize".to_owned())?;
    if file[file_start] != 1 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr version {} (expected 1)",
            file[file_start]
        ));
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

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
