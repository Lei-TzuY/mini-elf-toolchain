use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;
const NOTE_ALIGN: u64 = 4;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
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
            Ok("usage: mini-elf-note <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-note <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-note <input>...".to_owned());
    }

    let multiple = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_notes(header, &file).map_err(|error| format!("{display}: {error}"))?;
        inspected.push((display, rendered));
    }

    let mut output = String::new();
    for (index, (display, rendered)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&rendered);
    }
    Ok(output)
}

fn format_notes(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let mut output = String::new();
    let mut segment_count = 0usize;
    let mut build_id_seen = false;

    for (segment_index, note) in headers.iter().enumerate() {
        if note.segment_type != PT_NOTE {
            continue;
        }
        segment_count += 1;
        validate_alignment(segment_index, *note)?;
        let segment_end = note
            .offset
            .checked_add(note.file_size)
            .ok_or_else(|| format!("PT_NOTE segment {segment_index} file range overflows u64"))?;
        let mut cursor = note.offset;
        let mut note_index = 0usize;

        while cursor < segment_end {
            let remaining = segment_end - cursor;
            if remaining < 12 {
                return Err(format!(
                    "PT_NOTE segment {segment_index} has {remaining} trailing bytes, too small for an ELF note header"
                ));
            }
            let header_offset = usize::try_from(cursor).map_err(|_| {
                format!("PT_NOTE segment {segment_index} note offset does not fit usize")
            })?;
            let name_size = u64::from(read_u32(file, header_offset));
            let desc_size = u64::from(read_u32(file, header_offset + 4));
            let note_type = read_u32(file, header_offset + 8);

            let name_start = cursor
                .checked_add(12)
                .ok_or_else(|| format!("PT_NOTE segment {segment_index} name offset overflows u64"))?;
            let name_end = name_start
                .checked_add(name_size)
                .ok_or_else(|| format!("PT_NOTE segment {segment_index} name range overflows u64"))?;
            if name_end > segment_end {
                return Err(format!(
                    "PT_NOTE segment {segment_index} note {note_index} name ends beyond the segment"
                ));
            }
            let desc_start = align_up(name_end, NOTE_ALIGN).ok_or_else(|| {
                format!("PT_NOTE segment {segment_index} descriptor offset overflows u64")
            })?;
            if desc_start > segment_end {
                return Err(format!(
                    "PT_NOTE segment {segment_index} note {note_index} name padding ends beyond the segment"
                ));
            }
            let desc_end = desc_start.checked_add(desc_size).ok_or_else(|| {
                format!("PT_NOTE segment {segment_index} descriptor range overflows u64")
            })?;
            if desc_end > segment_end {
                return Err(format!(
                    "PT_NOTE segment {segment_index} note {note_index} descriptor ends beyond the segment"
                ));
            }
            let next = align_up(desc_end, NOTE_ALIGN).ok_or_else(|| {
                format!("PT_NOTE segment {segment_index} note range overflows u64")
            })?;
            if next > segment_end {
                return Err(format!(
                    "PT_NOTE segment {segment_index} note {note_index} descriptor padding ends beyond the segment"
                ));
            }

            let name = slice(file, name_start, name_end, "note name")?;
            let desc = slice(file, desc_start, desc_end, "note descriptor")?;
            let rendered_name = render_name(name);
            output.push_str(&format!(
                "PT_NOTE segment {segment_index} note {note_index}: name={rendered_name} type={note_type:#x} descsz={desc_size:#x}\n"
            ));

            if note_type == NT_GNU_BUILD_ID && name == b"GNU\0" {
                if desc.is_empty() {
                    return Err(format!(
                        "PT_NOTE segment {segment_index} note {note_index} has an empty GNU build-id descriptor"
                    ));
                }
                if build_id_seen {
                    return Err("multiple GNU build-id notes found".to_owned());
                }
                build_id_seen = true;
                output.push_str("  GNU build-id: ");
                for byte in desc {
                    output.push_str(&format!("{byte:02x}"));
                }
                output.push('\n');
            }

            cursor = next;
            note_index += 1;
        }
    }

    if segment_count == 0 {
        Ok("No PT_NOTE segments found.\n".to_owned())
    } else {
        Ok(output)
    }
}

fn validate_alignment(index: usize, note: ProgramHeader) -> Result<(), String> {
    if note.alignment > 1 && !note.alignment.is_power_of_two() {
        return Err(format!(
            "PT_NOTE segment {index} alignment {} is neither 0, 1, nor a power of two",
            note.alignment
        ));
    }
    if note.alignment > 1 && note.offset % note.alignment != note.vaddr % note.alignment {
        return Err(format!(
            "PT_NOTE segment {index} file/virtual addresses are incongruent modulo alignment {}",
            note.alignment
        ));
    }
    Ok(())
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
            vaddr: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
            alignment: read_u64(file, offset + 48),
        };
        if parsed.file_size > parsed.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                parsed.file_size, parsed.memory_size
            ));
        }
        let file_end = parsed
            .offset
            .checked_add(parsed.file_size)
            .ok_or_else(|| format!("program header {index} file range overflows u64"))?;
        if file_end > file.len() as u64 {
            return Err(format!(
                "program header {index} ends at file offset {file_end}, beyond file length {}",
                file.len()
            ));
        }
        headers.push(parsed);
    }
    Ok(headers)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;
    value.checked_add(mask).map(|rounded| rounded & !mask)
}

fn slice<'a>(
    file: &'a [u8],
    start: u64,
    end: u64,
    label: &str,
) -> Result<&'a [u8], String> {
    let start = usize::try_from(start).map_err(|_| format!("{label} offset does not fit usize"))?;
    let end = usize::try_from(end).map_err(|_| format!("{label} end does not fit usize"))?;
    file.get(start..end)
        .ok_or_else(|| format!("{label} range is outside the file"))
}

fn render_name(name: &[u8]) -> String {
    let trimmed = name.strip_suffix(&[0]).unwrap_or(name);
    if trimmed.is_empty() {
        "<empty>".to_owned()
    } else {
        String::from_utf8_lossy(trimmed).into_owned()
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
