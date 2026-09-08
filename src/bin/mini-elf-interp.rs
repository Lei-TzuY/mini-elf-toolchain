use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
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
            Ok("usage: mini-elf-interp <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-interp <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-interp <input>...".to_owned());
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_interp(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_interp(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let interps = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_INTERP)
        .collect::<Vec<_>>();

    match interps.as_slice() {
        [] => Ok("No PT_INTERP segment found.\n".to_owned()),
        [(index, interp)] => {
            if headers[..*index]
                .iter()
                .any(|header| header.segment_type == PT_LOAD)
            {
                return Err(format!(
                    "PT_INTERP segment {index} appears after a PT_LOAD segment"
                ));
            }
            if interp.file_size == 0 {
                return Err(format!("PT_INTERP segment {index} has an empty file range"));
            }
            let start = usize::try_from(interp.offset)
                .map_err(|_| "PT_INTERP file offset does not fit usize".to_owned())?;
            let end_u64 = checked_file_end(
                interp.offset,
                interp.file_size,
                file.len(),
                &format!("PT_INTERP segment {index}"),
            )?;
            let end = usize::try_from(end_u64)
                .map_err(|_| "PT_INTERP file end does not fit usize".to_owned())?;
            let bytes = &file[start..end];
            if bytes.last() != Some(&0) {
                return Err(format!("PT_INTERP segment {index} is not NUL-terminated"));
            }
            if bytes.len() == 1 {
                return Err(format!(
                    "PT_INTERP segment {index} has an empty interpreter path"
                ));
            }
            if bytes[..bytes.len() - 1].contains(&0) {
                return Err(format!(
                    "PT_INTERP segment {index} contains an embedded NUL before its terminator"
                ));
            }
            let path = std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| {
                format!("PT_INTERP segment {index} interpreter path is not valid UTF-8")
            })?;
            Ok(format!("PT_INTERP segment {index}: interpreter={path}\n"))
        }
        _ => Err(format!(
            "multiple PT_INTERP segments found ({})",
            interps.len()
        )),
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
        let parsed = ProgramHeader {
            segment_type: read_u32(file, offset),
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
