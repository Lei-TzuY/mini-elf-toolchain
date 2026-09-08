use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const DT_NULL: i64 = 0;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;

const DF_ORIGIN: u64 = 0x1;
const DF_SYMBOLIC: u64 = 0x2;
const DF_TEXTREL: u64 = 0x4;
const DF_BIND_NOW: u64 = 0x8;
const DF_STATIC_TLS: u64 = 0x10;

const DF_1_NOW: u64 = 0x0000_0001;
const DF_1_GLOBAL: u64 = 0x0000_0002;
const DF_1_GROUP: u64 = 0x0000_0004;
const DF_1_NODELETE: u64 = 0x0000_0008;
const DF_1_LOADFLTR: u64 = 0x0000_0010;
const DF_1_INITFIRST: u64 = 0x0000_0020;
const DF_1_NOOPEN: u64 = 0x0000_0040;
const DF_1_ORIGIN: u64 = 0x0000_0080;
const DF_1_DIRECT: u64 = 0x0000_0100;
const DF_1_TRANS: u64 = 0x0000_0200;
const DF_1_INTERPOSE: u64 = 0x0000_0400;
const DF_1_NODEFLIB: u64 = 0x0000_0800;
const DF_1_NODUMP: u64 = 0x0000_1000;
const DF_1_CONFALT: u64 = 0x0000_2000;
const DF_1_ENDFILTEE: u64 = 0x0000_4000;
const DF_1_DISPRELDNE: u64 = 0x0000_8000;
const DF_1_DISPRELPND: u64 = 0x0001_0000;
const DF_1_NODIRECT: u64 = 0x0002_0000;
const DF_1_IGNMULDEF: u64 = 0x0004_0000;
const DF_1_NOKSYMS: u64 = 0x0008_0000;
const DF_1_NOHDR: u64 = 0x0010_0000;
const DF_1_EDITED: u64 = 0x0020_0000;
const DF_1_NORELOC: u64 = 0x0040_0000;
const DF_1_SYMINTPOSE: u64 = 0x0080_0000;
const DF_1_GLOBAUDIT: u64 = 0x0100_0000;
const DF_1_SINGLETON: u64 = 0x0200_0000;
const DF_1_STUB: u64 = 0x0400_0000;
const DF_1_PIE: u64 = 0x0800_0000;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
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
            Ok("usage: mini-elf-dynflags <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynflags <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-dynflags <input>...".to_owned());
    }

    let multiple = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            format_flags(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_flags(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let dynamic_segments = headers
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
    let entry_count = dynamic.file_size / ELF64_DYNAMIC_SIZE;
    let mut entries = Vec::new();
    let mut saw_null = false;
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
            saw_null = true;
            break;
        }
    }
    if !saw_null {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} has no DT_NULL terminator before file offset {dynamic_end}"
        ));
    }

    let flags = unique_tag_value(&entries, DT_FLAGS, "DT_FLAGS")?;
    let flags_1 = unique_tag_value(&entries, DT_FLAGS_1, "DT_FLAGS_1")?;
    if flags.is_none() && flags_1.is_none() {
        return Ok("No DT_FLAGS or DT_FLAGS_1 entries found.\n".to_owned());
    }

    let mut output = format!("PT_DYNAMIC segment {segment_index} dynamic flags:\n");
    if let Some(value) = flags {
        push_flags(&mut output, "DT_FLAGS", value);
    }
    if let Some(value) = flags_1 {
        push_flags_1(&mut output, value);
    }
    Ok(output)
}

fn push_flags(output: &mut String, label: &str, value: u64) {
    let known = DF_ORIGIN | DF_SYMBOLIC | DF_TEXTREL | DF_BIND_NOW | DF_STATIC_TLS;
    output.push_str(&format!("  {label}={value:#x}"));
    push_named_bit(output, value, DF_ORIGIN, "ORIGIN");
    push_named_bit(output, value, DF_SYMBOLIC, "SYMBOLIC");
    push_named_bit(output, value, DF_TEXTREL, "TEXTREL");
    push_named_bit(output, value, DF_BIND_NOW, "BIND_NOW");
    push_named_bit(output, value, DF_STATIC_TLS, "STATIC_TLS");
    let unknown = value & !known;
    if unknown != 0 {
        output.push_str(&format!(" unknown={unknown:#x}"));
    }
    output.push('\n');
}

fn push_flags_1(output: &mut String, value: u64) {
    const BITS: &[(u64, &str)] = &[
        (DF_1_NOW, "NOW"),
        (DF_1_GLOBAL, "GLOBAL"),
        (DF_1_GROUP, "GROUP"),
        (DF_1_NODELETE, "NODELETE"),
        (DF_1_LOADFLTR, "LOADFLTR"),
        (DF_1_INITFIRST, "INITFIRST"),
        (DF_1_NOOPEN, "NOOPEN"),
        (DF_1_ORIGIN, "ORIGIN"),
        (DF_1_DIRECT, "DIRECT"),
        (DF_1_TRANS, "TRANS"),
        (DF_1_INTERPOSE, "INTERPOSE"),
        (DF_1_NODEFLIB, "NODEFLIB"),
        (DF_1_NODUMP, "NODUMP"),
        (DF_1_CONFALT, "CONFALT"),
        (DF_1_ENDFILTEE, "ENDFILTEE"),
        (DF_1_DISPRELDNE, "DISPRELDNE"),
        (DF_1_DISPRELPND, "DISPRELPND"),
        (DF_1_NODIRECT, "NODIRECT"),
        (DF_1_IGNMULDEF, "IGNMULDEF"),
        (DF_1_NOKSYMS, "NOKSYMS"),
        (DF_1_NOHDR, "NOHDR"),
        (DF_1_EDITED, "EDITED"),
        (DF_1_NORELOC, "NORELOC"),
        (DF_1_SYMINTPOSE, "SYMINTPOSE"),
        (DF_1_GLOBAUDIT, "GLOBAUDIT"),
        (DF_1_SINGLETON, "SINGLETON"),
        (DF_1_STUB, "STUB"),
        (DF_1_PIE, "PIE"),
    ];
    let mut known = 0u64;
    output.push_str(&format!("  DT_FLAGS_1={value:#x}"));
    for &(bit, name) in BITS {
        known |= bit;
        push_named_bit(output, value, bit, name);
    }
    let unknown = value & !known;
    if unknown != 0 {
        output.push_str(&format!(" unknown={unknown:#x}"));
    }
    output.push('\n');
}

fn push_named_bit(output: &mut String, value: u64, bit: u64, name: &str) {
    if value & bit != 0 {
        output.push(' ');
        output.push_str(name);
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
