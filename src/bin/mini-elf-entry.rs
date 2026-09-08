use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
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
            Ok("usage: mini-elf-entry <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-entry <input>...".to_owned())
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
            inspect_entry(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn inspect_entry(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let elf_type = match header.elf_type {
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        other => {
            return Err(format!(
                "ELF type {other} has no executable-image entry-point semantics; expected ET_EXEC or ET_DYN"
            ));
        }
    };
    let program_headers = program_headers(header, file)?;
    if header.entry == 0 {
        return Ok(format!("ELF entry point: absent type={elf_type}\n"));
    }

    let entry_end = header
        .entry
        .checked_add(1)
        .ok_or_else(|| "ELF entry-point virtual range overflows u64".to_owned())?;
    let mut containing_nonexec = None;
    for (index, program) in program_headers.iter().enumerate() {
        if program.segment_type != PT_LOAD {
            continue;
        }
        let load_end = program
            .virtual_address
            .checked_add(program.memory_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual memory range overflows u64"))?;
        if header.entry < program.virtual_address || entry_end > load_end {
            continue;
        }
        if program.flags & PF_X != 0 {
            return Ok(format!(
                "ELF entry point: address={:#x} segment={index} type={elf_type}\n",
                header.entry
            ));
        }
        containing_nonexec = Some(index);
    }

    if let Some(index) = containing_nonexec {
        return Err(format!(
            "ELF entry point {:#x} is within non-executable PT_LOAD segment {index}",
            header.entry
        ));
    }
    Err(format!(
        "ELF entry point {:#x} is not within a PT_LOAD memory range",
        header.entry
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
        let program = ProgramHeader {
            segment_type: read_u32(file, offset),
            flags: read_u32(file, offset + 4),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if program.file_size > program.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                program.file_size, program.memory_size
            ));
        }
        checked_file_end(
            program.offset,
            program.file_size,
            file.len(),
            &format!("program header {index}"),
        )?;
        program
            .virtual_address
            .checked_add(program.memory_size)
            .ok_or_else(|| format!("program header {index} virtual memory range overflows u64"))?;
        headers.push(program);
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
