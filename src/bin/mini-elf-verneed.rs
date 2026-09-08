use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_VERNEED_SIZE: u64 = 16;
const ELF64_VERNAUX_SIZE: u64 = 16;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const VER_NEED_CURRENT: u16 = 1;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    virtual_address: u64,
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
            Ok("usage: mini-elf-verneed <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-verneed <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_version_requirements(header, &file)
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

fn format_version_requirements(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let verneed = unique_tag_value(&entries, DT_VERNEED, "DT_VERNEED")?;
    let verneednum = unique_tag_value(&entries, DT_VERNEEDNUM, "DT_VERNEEDNUM")?;
    let present = usize::from(verneed.is_some()) + usize::from(verneednum.is_some());
    if present == 0 {
        return Ok("No DT_VERNEED version-requirement table found.\n".to_owned());
    }
    if present != 2 {
        return Err("PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned());
    }

    let count = verneednum.unwrap();
    if count == 0 {
        return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
    }
    let strtab = unique_tag_value(&entries, DT_STRTAB, "DT_STRTAB")?
        .ok_or_else(|| "DT_VERNEED requires DT_STRTAB".to_owned())?;
    let strsz = unique_tag_value(&entries, DT_STRSZ, "DT_STRSZ")?
        .ok_or_else(|| "DT_VERNEED requires DT_STRSZ".to_owned())?;
    let strtab_offset = map_virtual_range(
        &program_headers,
        file.len(),
        strtab,
        strsz,
        "DT_STRTAB table",
    )?;

    let mut output = format!("DT_VERNEED contains {count} dependency entries:\n");
    let mut address = verneed.unwrap();
    for dependency_index in 0..count {
        let offset = map_virtual_range(
            &program_headers,
            file.len(),
            address,
            ELF64_VERNEED_SIZE,
            &format!("DT_VERNEED entry {dependency_index}"),
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_VERNEED file offset does not fit usize".to_owned())?;
        let version = read_u16(file, offset);
        let aux_count = read_u16(file, offset + 2);
        let file_name_offset = read_u32(file, offset + 4);
        let aux_relative = read_u32(file, offset + 8);
        let next_relative = read_u32(file, offset + 12);

        if version != VER_NEED_CURRENT {
            return Err(format!(
                "DT_VERNEED entry {dependency_index} has version {version}, expected {VER_NEED_CURRENT}"
            ));
        }
        if aux_count == 0 {
            return Err(format!(
                "DT_VERNEED entry {dependency_index} must reference at least one Vernaux record"
            ));
        }
        if aux_relative == 0 {
            return Err(format!(
                "DT_VERNEED entry {dependency_index} has zero vn_aux with non-zero vn_cnt"
            ));
        }

        let dependency = dynamic_string(
            file,
            strtab_offset,
            strsz,
            u64::from(file_name_offset),
            "DT_VERNEED dependency name",
        )?;
        output.push_str(&format!("  {dependency}:\n"));

        let mut aux_address = address
            .checked_add(u64::from(aux_relative))
            .ok_or_else(|| format!("DT_VERNEED entry {dependency_index} vn_aux address overflows u64"))?;
        for aux_index in 0..u64::from(aux_count) {
            let aux_offset = map_virtual_range(
                &program_headers,
                file.len(),
                aux_address,
                ELF64_VERNAUX_SIZE,
                &format!("DT_VERNEED entry {dependency_index} Vernaux {aux_index}"),
            )?;
            let aux_offset = usize::try_from(aux_offset)
                .map_err(|_| "Vernaux file offset does not fit usize".to_owned())?;
            let hash = read_u32(file, aux_offset);
            let flags = read_u16(file, aux_offset + 4);
            let other = read_u16(file, aux_offset + 6);
            let name_offset = read_u32(file, aux_offset + 8);
            let next = read_u32(file, aux_offset + 12);
            let name = dynamic_string(
                file,
                strtab_offset,
                strsz,
                u64::from(name_offset),
                "Vernaux version name",
            )?;
            output.push_str(&format!(
                "    index={other} flags={flags:#06x} hash={hash:#010x} name={name}\n"
            ));

            let last_aux = aux_index + 1 == u64::from(aux_count);
            if last_aux {
                if next != 0 {
                    return Err(format!(
                        "DT_VERNEED entry {dependency_index} final Vernaux record has non-zero vna_next {next}"
                    ));
                }
            } else {
                if next == 0 {
                    return Err(format!(
                        "DT_VERNEED entry {dependency_index} Vernaux chain ends before vn_cnt {aux_count}"
                    ));
                }
                aux_address = aux_address.checked_add(u64::from(next)).ok_or_else(|| {
                    format!("DT_VERNEED entry {dependency_index} Vernaux address overflows u64")
                })?;
            }
        }

        let last_dependency = dependency_index + 1 == count;
        if last_dependency {
            if next_relative != 0 {
                return Err(format!(
                    "final DT_VERNEED entry has non-zero vn_next {next_relative} beyond DT_VERNEEDNUM {count}"
                ));
            }
        } else {
            if next_relative == 0 {
                return Err(format!(
                    "DT_VERNEED chain ends before DT_VERNEEDNUM {count}"
                ));
            }
            address = address
                .checked_add(u64::from(next_relative))
                .ok_or_else(|| "DT_VERNEED next-entry address overflows u64".to_owned())?;
        }
    }
    Ok(output)
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if header.program_header_entry_size as usize != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        ));
    }
    let table_size = u64::from(header.program_header_count)
        .checked_mul(u64::from(header.program_header_entry_size))
        .ok_or_else(|| "program header table size overflows u64".to_owned())?;
    checked_file_range(
        file.len(),
        header.program_header_offset,
        table_size,
        "program header table",
    )?;

    let mut result = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..u64::from(header.program_header_count) {
        let relative = index
            .checked_mul(u64::from(header.program_header_entry_size))
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        let offset = header
            .program_header_offset
            .checked_add(relative)
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program header offset does not fit usize".to_owned())?;
        let segment_type = read_u32(file, offset);
        let segment_offset = read_u64(file, offset + 8);
        let virtual_address = read_u64(file, offset + 16);
        let file_size = read_u64(file, offset + 32);
        let memory_size = read_u64(file, offset + 40);
        if file_size > memory_size {
            return Err(format!(
                "program header {index} has p_filesz {file_size} greater than p_memsz {memory_size}"
            ));
        }
        checked_file_range(
            file.len(),
            segment_offset,
            file_size,
            &format!("program header {index}"),
        )?;
        virtual_address
            .checked_add(memory_size)
            .ok_or_else(|| format!("program header {index} virtual range overflows u64"))?;
        result.push(ProgramHeader {
            segment_type,
            offset: segment_offset,
            virtual_address,
            file_size,
            memory_size,
        });
    }
    Ok(result)
}

fn dynamic_entries(
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<DynamicEntry>, String> {
    let dynamic = program_headers
        .iter()
        .filter(|header| header.segment_type == PT_DYNAMIC)
        .copied()
        .collect::<Vec<_>>();
    if dynamic.is_empty() {
        return Err("ELF file has no PT_DYNAMIC segment".to_owned());
    }
    if dynamic.len() != 1 {
        return Err(format!(
            "ELF file has {} PT_DYNAMIC segments, expected at most one",
            dynamic.len()
        ));
    }
    let dynamic = dynamic[0];
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC file size {} is not a multiple of {ELF64_DYNAMIC_SIZE}",
            dynamic.file_size
        ));
    }
    let mut entries = Vec::new();
    let count = dynamic.file_size / ELF64_DYNAMIC_SIZE;
    for index in 0..count {
        let relative = index
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
            return Ok(entries);
        }
    }
    Err("PT_DYNAMIC has no DT_NULL terminator within p_filesz".to_owned())
}

fn unique_tag_value(
    entries: &[DynamicEntry],
    wanted: i64,
    name: &str,
) -> Result<Option<u64>, String> {
    let mut found = None;
    for entry in entries {
        if entry.tag != wanted {
            continue;
        }
        if found.replace(entry.value).is_some() {
            return Err(format!("PT_DYNAMIC contains duplicate {name} entries"));
        }
    }
    Ok(found)
}

fn map_virtual_range(
    program_headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    label: &str,
) -> Result<u64, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in program_headers {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let file_backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| "PT_LOAD file-backed virtual range overflows u64".to_owned())?;
        let memory_end = header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| "PT_LOAD memory virtual range overflows u64".to_owned())?;
        if end > memory_end || address < header.virtual_address || end > file_backed_end {
            continue;
        }
        let relative = address
            .checked_sub(header.virtual_address)
            .ok_or_else(|| format!("{label} virtual-to-file translation underflows"))?;
        let offset = header
            .offset
            .checked_add(relative)
            .ok_or_else(|| format!("{label} file offset overflows u64"))?;
        checked_file_range(file_len, offset, size, label)?;
        return Ok(offset);
    }
    Err(format!(
        "{label} virtual range {address:#x}..{end:#x} is not fully file-backed by PT_LOAD"
    ))
}

fn dynamic_string(
    file: &[u8],
    strtab_offset: u64,
    strsz: u64,
    string_offset: u64,
    label: &str,
) -> Result<String, String> {
    if string_offset >= strsz {
        return Err(format!(
            "{label} offset {string_offset} is outside DT_STRSZ {strsz}"
        ));
    }
    let start = strtab_offset
        .checked_add(string_offset)
        .ok_or_else(|| format!("{label} file offset overflows u64"))?;
    let remaining = strsz
        .checked_sub(string_offset)
        .ok_or_else(|| format!("{label} remaining size underflows"))?;
    let start = usize::try_from(start)
        .map_err(|_| format!("{label} file offset does not fit usize"))?;
    let remaining = usize::try_from(remaining)
        .map_err(|_| format!("{label} remaining size does not fit usize"))?;
    let bytes = &file[start..start + remaining];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{label} is not NUL-terminated within DT_STRSZ"))?;
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn checked_file_range(
    file_len: usize,
    offset: u64,
    size: u64,
    label: &str,
) -> Result<(), String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows u64"))?;
    let file_len = u64::try_from(file_len).map_err(|_| "file length does not fit u64".to_owned())?;
    if end > file_len {
        return Err(format!(
            "{label} file range {offset}..{end} exceeds file length {file_len}"
        ));
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
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
