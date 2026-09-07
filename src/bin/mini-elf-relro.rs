use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_GNU_RELRO: u32 = 0x6474_e552;

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
            Ok("usage: mini-elf-relro [--load-bias <address>] <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-relro [--load-bias <address>] <input>...".to_owned())
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
        return Err("usage: mini-elf-relro [--load-bias <address>] <input>...".to_owned());
    }

    let multiple_inputs = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_relro(header, &file, load_bias)
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

fn format_relro(
    header: Elf64Header,
    file: &[u8],
    load_bias: Option<u64>,
) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let relro_segments = program_headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_GNU_RELRO)
        .collect::<Vec<_>>();
    if relro_segments.is_empty() {
        return Ok("No PT_GNU_RELRO segment found.\n".to_owned());
    }

    let mut ranges = Vec::with_capacity(relro_segments.len());
    for (segment_index, relro) in relro_segments {
        let end = relro
            .virtual_address
            .checked_add(relro.memory_size)
            .ok_or_else(|| {
                format!("PT_GNU_RELRO segment {segment_index} virtual memory range overflows u64")
            })?;
        require_load_containment(&program_headers, relro.virtual_address, end, segment_index)?;
        let runtime = if let Some(load_bias) = load_bias {
            let runtime_start = load_bias.checked_add(relro.virtual_address).ok_or_else(|| {
                format!(
                    "PT_GNU_RELRO segment {segment_index} runtime start overflows u64: load bias {load_bias:#x} + virtual address {:#x}",
                    relro.virtual_address
                )
            })?;
            let runtime_end = runtime_start.checked_add(relro.memory_size).ok_or_else(|| {
                format!(
                    "PT_GNU_RELRO segment {segment_index} runtime end overflows u64: runtime start {runtime_start:#x} + memory size {:#x}",
                    relro.memory_size
                )
            })?;
            Some((runtime_start, runtime_end))
        } else {
            None
        };
        ranges.push((segment_index, relro.virtual_address, end, runtime));
    }

    let mut output = format!("Found {} PT_GNU_RELRO segment(s):\n", ranges.len());
    if let Some(load_bias) = load_bias {
        output.push_str(&format!("Load bias: {load_bias:#018x}\n"));
        output.push_str("  Index  Link-time range                                 Runtime range\n");
        for (index, start, end, runtime) in ranges {
            let (runtime_start, runtime_end) = runtime.expect("load bias produces runtime range");
            output.push_str(&format!(
                "  {index:>5}  {start:#018x}..{end:#018x}  {runtime_start:#018x}..{runtime_end:#018x}\n"
            ));
        }
    } else {
        output.push_str("  Index  Link-time range\n");
        for (index, start, end, _) in ranges {
            output.push_str(&format!("  {index:>5}  {start:#018x}..{end:#018x}\n"));
        }
    }
    Ok(output)
}

fn require_load_containment(
    program_headers: &[ProgramHeader],
    start: u64,
    end: u64,
    relro_index: usize,
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
        "PT_GNU_RELRO segment {relro_index} virtual memory range {start:#x}..{end:#x} is not contained in a PT_LOAD memory range"
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
