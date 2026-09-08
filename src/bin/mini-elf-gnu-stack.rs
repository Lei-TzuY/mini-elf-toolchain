use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const KNOWN_FLAGS: u32 = PF_R | PF_W | PF_X;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
    offset: u64,
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
            Ok("usage: mini-elf-gnu-stack <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-gnu-stack <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-gnu-stack <input>...".to_owned());
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_gnu_stack(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_gnu_stack(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let stacks = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_GNU_STACK)
        .collect::<Vec<_>>();

    match stacks.as_slice() {
        [] => Ok("No PT_GNU_STACK segment found.\n".to_owned()),
        [(index, stack)] => {
            let unknown = stack.flags & !KNOWN_FLAGS;
            if unknown != 0 {
                return Err(format!(
                    "PT_GNU_STACK segment {index} has unknown permission flag bits {unknown:#x}"
                ));
            }
            let permissions = format_permissions(stack.flags);
            let executable = if stack.flags & PF_X != 0 { "yes" } else { "no" };
            Ok(format!(
                "PT_GNU_STACK segment {index}: flags={permissions} ({:#x}), executable={executable}\n",
                stack.flags
            ))
        }
        _ => Err(format!(
            "multiple PT_GNU_STACK segments found ({})",
            stacks.len()
        )),
    }
}

fn format_permissions(flags: u32) -> String {
    let mut text = String::with_capacity(3);
    text.push(if flags & PF_R != 0 { 'R' } else { '-' });
    text.push(if flags & PF_W != 0 { 'W' } else { '-' });
    text.push(if flags & PF_X != 0 { 'E' } else { '-' });
    text
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
        let parsed = ProgramHeader {
            segment_type: read_u32(file, offset),
            flags: read_u32(file, offset + 4),
            offset: read_u64(file, offset + 8),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if parsed.file_size > parsed.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                parsed.file_size, parsed.memory_size
            ));
        }
        checked_file_end(
            parsed.offset,
            parsed.file_size,
            file.len(),
            &format!("program header {index}"),
        )?;
        headers.push(parsed);
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
