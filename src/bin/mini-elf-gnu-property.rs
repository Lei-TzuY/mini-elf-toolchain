use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1;
const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 2;
const NOTE_ALIGN: u64 = 4;
const PROPERTY_ALIGN: u64 = 8;

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
            Ok("usage: mini-elf-gnu-property <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-gnu-property <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-gnu-property <input>...".to_owned());
    }

    let multiple = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_properties(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_properties(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let mut output = String::new();
    let mut segment_count = 0usize;
    let mut feature_seen = false;

    for (segment_index, segment) in headers.iter().enumerate() {
        if segment.segment_type != PT_GNU_PROPERTY {
            continue;
        }
        segment_count += 1;
        let segment_end = segment
            .offset
            .checked_add(segment.file_size)
            .ok_or_else(|| {
                format!("PT_GNU_PROPERTY segment {segment_index} file range overflows u64")
            })?;
        let mut cursor = segment.offset;
        let mut note_index = 0usize;
        while cursor < segment_end {
            if segment_end - cursor < 12 {
                return Err(format!(
                    "PT_GNU_PROPERTY segment {segment_index} has a truncated ELF note header"
                ));
            }
            let at =
                usize::try_from(cursor).map_err(|_| "note offset does not fit usize".to_owned())?;
            let name_size = u64::from(read_u32(file, at));
            let desc_size = u64::from(read_u32(file, at + 4));
            let note_type = read_u32(file, at + 8);
            let name_start = cursor
                .checked_add(12)
                .ok_or_else(|| "note name offset overflows u64".to_owned())?;
            let name_end = name_start
                .checked_add(name_size)
                .ok_or_else(|| "note name range overflows u64".to_owned())?;
            if name_end > segment_end {
                return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} name ends beyond the segment"));
            }
            let desc_start = align_up(name_end, NOTE_ALIGN)
                .ok_or_else(|| "note descriptor offset overflows u64".to_owned())?;
            let desc_end = desc_start
                .checked_add(desc_size)
                .ok_or_else(|| "note descriptor range overflows u64".to_owned())?;
            if desc_end > segment_end {
                return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} descriptor ends beyond the segment"));
            }
            let next = align_up(desc_end, NOTE_ALIGN)
                .ok_or_else(|| "note range overflows u64".to_owned())?;
            if next > segment_end {
                return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} padding ends beyond the segment"));
            }
            let name = slice(file, name_start, name_end, "note name")?;
            if note_type != NT_GNU_PROPERTY_TYPE_0 || name != b"GNU\0" {
                return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} is not a GNU property note"));
            }

            let mut property = desc_start;
            while property < desc_end {
                if desc_end - property < 8 {
                    return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} has a truncated property header"));
                }
                let property_at = usize::try_from(property)
                    .map_err(|_| "property offset does not fit usize".to_owned())?;
                let property_type = read_u32(file, property_at);
                let data_size = u64::from(read_u32(file, property_at + 4));
                let data_start = property
                    .checked_add(8)
                    .ok_or_else(|| "property data offset overflows u64".to_owned())?;
                let data_end = data_start
                    .checked_add(data_size)
                    .ok_or_else(|| "property data range overflows u64".to_owned())?;
                if data_end > desc_end {
                    return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} property data ends beyond the descriptor"));
                }
                let property_next = align_up(data_end, PROPERTY_ALIGN)
                    .ok_or_else(|| "property range overflows u64".to_owned())?;
                if property_next > desc_end {
                    return Err(format!("PT_GNU_PROPERTY segment {segment_index} note {note_index} property padding ends beyond the descriptor"));
                }

                if property_type == GNU_PROPERTY_X86_FEATURE_1_AND {
                    if feature_seen {
                        return Err(
                            "multiple GNU_PROPERTY_X86_FEATURE_1_AND entries found".to_owned()
                        );
                    }
                    feature_seen = true;
                    if data_size != 4 {
                        return Err(format!(
                            "GNU_PROPERTY_X86_FEATURE_1_AND data size is {data_size}, expected 4"
                        ));
                    }
                    let data_at = usize::try_from(data_start)
                        .map_err(|_| "property data offset does not fit usize".to_owned())?;
                    let features = read_u32(file, data_at);
                    let unknown = features
                        & !(GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK);
                    output.push_str(&format!(
                        "PT_GNU_PROPERTY segment {segment_index}: x86 feature_1_and={features:#x}"
                    ));
                    if features & GNU_PROPERTY_X86_FEATURE_1_IBT != 0 {
                        output.push_str(" IBT");
                    }
                    if features & GNU_PROPERTY_X86_FEATURE_1_SHSTK != 0 {
                        output.push_str(" SHSTK");
                    }
                    if unknown != 0 {
                        output.push_str(&format!(" unknown={unknown:#x}"));
                    }
                    output.push('\n');
                }
                property = property_next;
            }
            cursor = next;
            note_index += 1;
        }
    }

    if segment_count == 0 {
        Ok("No PT_GNU_PROPERTY segments found.\n".to_owned())
    } else if !feature_seen {
        Ok("No GNU_PROPERTY_X86_FEATURE_1_AND property found.\n".to_owned())
    } else {
        Ok(output)
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
                "program header {index} ends beyond file length {}",
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

fn slice<'a>(file: &'a [u8], start: u64, end: u64, label: &str) -> Result<&'a [u8], String> {
    let start = usize::try_from(start).map_err(|_| format!("{label} offset does not fit usize"))?;
    let end = usize::try_from(end).map_err(|_| format!("{label} end does not fit usize"))?;
    file.get(start..end)
        .ok_or_else(|| format!("{label} range is outside the file"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
