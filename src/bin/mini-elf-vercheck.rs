use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const DT_VERSYM: i64 = 0x6fff_fff0;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_VERSYM_SIZE: u64 = 2;
const ELF64_VERDEF_SIZE: u64 = 20;
const ELF64_VERDAUX_SIZE: u64 = 8;
const ELF64_VERNEED_SIZE: u64 = 16;
const ELF64_VERNAUX_SIZE: u64 = 16;
const VER_DEF_CURRENT: u16 = 1;
const VER_NEED_CURRENT: u16 = 1;
const VERSYM_INDEX_MASK: u16 = 0x7fff;

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

#[derive(Clone)]
enum VersionSource {
    Definition { name: String },
    Requirement { dependency: String, name: String },
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
            Ok("usage: mini-elf-vercheck <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-vercheck <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut reports = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let report = inspect(header, &file).map_err(|error| format!("{display}: {error}"))?;
        reports.push((display, report));
    }

    let mut output = String::new();
    for (index, (display, report)) in reports.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&report);
    }
    Ok(output)
}

fn inspect(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let entries = dynamic_entries(&headers, file)?;
    let Some(versym_address) = unique_tag_value(&entries, DT_VERSYM, "DT_VERSYM")? else {
        return Ok("No DT_VERSYM version-symbol table found.\n".to_owned());
    };

    let symbol_count = dynamic_symbol_count(&entries, &headers, file)?;
    let mut namespace = BTreeMap::new();
    for (index, source) in version_definitions(&entries, &headers, file)? {
        insert_version(&mut namespace, index, source)?;
    }
    for (index, source) in version_requirements(&entries, &headers, file)? {
        insert_version(&mut namespace, index, source)?;
    }

    let table_size = u64::from(symbol_count)
        .checked_mul(ELF64_VERSYM_SIZE)
        .ok_or_else(|| "DT_VERSYM table size overflows u64".to_owned())?;
    let table_offset = map_virtual_range(
        &headers,
        file.len(),
        versym_address,
        table_size,
        "DT_VERSYM table",
    )?;
    let table_offset = usize::try_from(table_offset)
        .map_err(|_| "DT_VERSYM table offset does not fit usize".to_owned())?;

    let mut referenced = BTreeSet::new();
    for symbol_index in 0..symbol_count {
        let relative = usize::try_from(u64::from(symbol_index) * ELF64_VERSYM_SIZE)
            .map_err(|_| "DT_VERSYM entry offset does not fit usize".to_owned())?;
        let index = read_u16(file, table_offset + relative) & VERSYM_INDEX_MASK;
        if index >= 2 {
            if !namespace.contains_key(&index) {
                return Err(format!(
                    "DT_VERSYM symbol {symbol_index} references unresolved version index {index}"
                ));
            }
            referenced.insert(index);
        }
    }

    let mut output = format!(
        "DT_VERSYM namespace is consistent across {symbol_count} dynamic symbols; {} referenced version indices:\n",
        referenced.len()
    );
    for index in referenced {
        match namespace
            .get(&index)
            .expect("referenced indices were checked")
        {
            VersionSource::Definition { name } => {
                output.push_str(&format!("  index={index} source=definition name={name}\n"));
            }
            VersionSource::Requirement { dependency, name } => {
                output.push_str(&format!(
                    "  index={index} source=requirement dependency={dependency} name={name}\n"
                ));
            }
        }
    }
    Ok(output)
}

fn insert_version(
    namespace: &mut BTreeMap<u16, VersionSource>,
    index: u16,
    source: VersionSource,
) -> Result<(), String> {
    if index < 2 {
        return Ok(());
    }
    if namespace.insert(index, source).is_some() {
        return Err(format!(
            "version index {index} is defined by more than one VERDEF/VERNEED record"
        ));
    }
    Ok(())
}

fn version_definitions(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<(u16, VersionSource)>, String> {
    let address = unique_tag_value(entries, DT_VERDEF, "DT_VERDEF")?;
    let count = unique_tag_value(entries, DT_VERDEFNUM, "DT_VERDEFNUM")?;
    match (address, count) {
        (None, None) => return Ok(Vec::new()),
        (Some(_), None) | (None, Some(_)) => {
            return Err("PT_DYNAMIC must provide DT_VERDEF and DT_VERDEFNUM together".to_owned());
        }
        _ => {}
    }
    let count = count.unwrap();
    if count == 0 {
        return Err("DT_VERDEFNUM must be non-zero when DT_VERDEF is present".to_owned());
    }
    let (strtab_offset, strsz) = dynamic_string_table(entries, headers, file, "DT_VERDEF")?;
    let mut current = address.unwrap();
    let mut result = Vec::new();
    for record_index in 0..count {
        let offset = mapped_offset(headers, file, current, ELF64_VERDEF_SIZE, "DT_VERDEF entry")?;
        let version = read_u16(file, offset);
        let index = read_u16(file, offset + 4) & VERSYM_INDEX_MASK;
        let aux_count = read_u16(file, offset + 6);
        let aux_relative = read_u32(file, offset + 12);
        let next = read_u32(file, offset + 16);
        if version != VER_DEF_CURRENT {
            return Err(format!(
                "DT_VERDEF entry {record_index} has unsupported version {version}"
            ));
        }
        if aux_count == 0 || aux_relative == 0 {
            return Err(format!(
                "DT_VERDEF entry {record_index} has an invalid Verdaux chain"
            ));
        }
        let aux_address = current
            .checked_add(u64::from(aux_relative))
            .ok_or_else(|| "DT_VERDEF Verdaux address overflows u64".to_owned())?;
        let aux_offset = mapped_offset(
            headers,
            file,
            aux_address,
            ELF64_VERDAUX_SIZE,
            "Verdaux record",
        )?;
        let name = dynamic_string(
            file,
            strtab_offset,
            strsz,
            u64::from(read_u32(file, aux_offset)),
            "Verdaux version name",
        )?;
        validate_verdef_aux_chain(
            headers,
            file,
            current,
            aux_relative,
            aux_count,
            record_index,
        )?;
        result.push((index, VersionSource::Definition { name }));
        current = advance_record(current, next, record_index + 1 == count, "DT_VERDEF", count)?;
    }
    Ok(result)
}

fn validate_verdef_aux_chain(
    headers: &[ProgramHeader],
    file: &[u8],
    base: u64,
    first_relative: u32,
    count: u16,
    record_index: u64,
) -> Result<(), String> {
    let mut address = base
        .checked_add(u64::from(first_relative))
        .ok_or_else(|| "DT_VERDEF Verdaux address overflows u64".to_owned())?;
    for aux_index in 0..u64::from(count) {
        let offset = mapped_offset(headers, file, address, ELF64_VERDAUX_SIZE, "Verdaux record")?;
        let next = read_u32(file, offset + 4);
        let last = aux_index + 1 == u64::from(count);
        if last && next != 0 {
            return Err(format!(
                "DT_VERDEF entry {record_index} final Verdaux has non-zero vda_next"
            ));
        }
        if !last {
            if next == 0 {
                return Err(format!(
                    "DT_VERDEF entry {record_index} Verdaux chain ends early"
                ));
            }
            address = address
                .checked_add(u64::from(next))
                .ok_or_else(|| "DT_VERDEF Verdaux address overflows u64".to_owned())?;
        }
    }
    Ok(())
}

fn version_requirements(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<(u16, VersionSource)>, String> {
    let address = unique_tag_value(entries, DT_VERNEED, "DT_VERNEED")?;
    let count = unique_tag_value(entries, DT_VERNEEDNUM, "DT_VERNEEDNUM")?;
    match (address, count) {
        (None, None) => return Ok(Vec::new()),
        (Some(_), None) | (None, Some(_)) => {
            return Err("PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned());
        }
        _ => {}
    }
    let count = count.unwrap();
    if count == 0 {
        return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
    }
    let (strtab_offset, strsz) = dynamic_string_table(entries, headers, file, "DT_VERNEED")?;
    let mut current = address.unwrap();
    let mut result = Vec::new();
    for record_index in 0..count {
        let offset = mapped_offset(
            headers,
            file,
            current,
            ELF64_VERNEED_SIZE,
            "DT_VERNEED entry",
        )?;
        let version = read_u16(file, offset);
        let aux_count = read_u16(file, offset + 2);
        let dependency_offset = read_u32(file, offset + 4);
        let aux_relative = read_u32(file, offset + 8);
        let next = read_u32(file, offset + 12);
        if version != VER_NEED_CURRENT {
            return Err(format!(
                "DT_VERNEED entry {record_index} has unsupported version {version}"
            ));
        }
        if aux_count == 0 || aux_relative == 0 {
            return Err(format!(
                "DT_VERNEED entry {record_index} has an invalid Vernaux chain"
            ));
        }
        let dependency = dynamic_string(
            file,
            strtab_offset,
            strsz,
            u64::from(dependency_offset),
            "DT_VERNEED dependency name",
        )?;
        let mut aux_address = current
            .checked_add(u64::from(aux_relative))
            .ok_or_else(|| "DT_VERNEED Vernaux address overflows u64".to_owned())?;
        for aux_index in 0..u64::from(aux_count) {
            let aux_offset = mapped_offset(
                headers,
                file,
                aux_address,
                ELF64_VERNAUX_SIZE,
                "Vernaux record",
            )?;
            let index = read_u16(file, aux_offset + 6) & VERSYM_INDEX_MASK;
            let name = dynamic_string(
                file,
                strtab_offset,
                strsz,
                u64::from(read_u32(file, aux_offset + 8)),
                "Vernaux version name",
            )?;
            result.push((
                index,
                VersionSource::Requirement {
                    dependency: dependency.clone(),
                    name,
                },
            ));
            let next_aux = read_u32(file, aux_offset + 12);
            let last = aux_index + 1 == u64::from(aux_count);
            if last && next_aux != 0 {
                return Err(format!(
                    "DT_VERNEED entry {record_index} final Vernaux has non-zero vna_next"
                ));
            }
            if !last {
                if next_aux == 0 {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} Vernaux chain ends early"
                    ));
                }
                aux_address = aux_address
                    .checked_add(u64::from(next_aux))
                    .ok_or_else(|| "DT_VERNEED Vernaux address overflows u64".to_owned())?;
            }
        }
        current = advance_record(
            current,
            next,
            record_index + 1 == count,
            "DT_VERNEED",
            count,
        )?;
    }
    Ok(result)
}

fn advance_record(
    current: u64,
    next: u32,
    last: bool,
    name: &str,
    count: u64,
) -> Result<u64, String> {
    if last {
        if next != 0 {
            return Err(format!(
                "final {name} entry has non-zero next offset beyond count {count}"
            ));
        }
        return Ok(current);
    }
    if next == 0 {
        return Err(format!("{name} chain ends before count {count}"));
    }
    current
        .checked_add(u64::from(next))
        .ok_or_else(|| format!("{name} next-entry address overflows u64"))
}

fn dynamic_string_table(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
    owner: &str,
) -> Result<(u64, u64), String> {
    let address = unique_tag_value(entries, DT_STRTAB, "DT_STRTAB")?
        .ok_or_else(|| format!("{owner} requires DT_STRTAB"))?;
    let size = unique_tag_value(entries, DT_STRSZ, "DT_STRSZ")?
        .ok_or_else(|| format!("{owner} requires DT_STRSZ"))?;
    let offset = map_virtual_range(headers, file.len(), address, size, "DT_STRTAB table")?;
    Ok((offset, size))
}

fn dynamic_symbol_count(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
) -> Result<u32, String> {
    if let Some(address) = unique_tag_value(entries, DT_HASH, "DT_HASH")? {
        let offset = mapped_offset(headers, file, address, 8, "DT_HASH header")?;
        return Ok(read_u32(file, offset + 4));
    }
    let address = unique_tag_value(entries, DT_GNU_HASH, "DT_GNU_HASH")?
        .ok_or_else(|| "DT_VERSYM requires DT_HASH or DT_GNU_HASH".to_owned())?;
    gnu_hash_symbol_count(headers, file, address)
}

fn gnu_hash_symbol_count(
    headers: &[ProgramHeader],
    file: &[u8],
    address: u64,
) -> Result<u32, String> {
    let offset = mapped_offset(headers, file, address, 16, "DT_GNU_HASH header")?;
    let bucket_count = read_u32(file, offset);
    let symbol_offset = read_u32(file, offset + 4);
    let bloom_count = read_u32(file, offset + 8);
    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err("DT_GNU_HASH bloom count must be a non-zero power of two".to_owned());
    }
    let bloom_size = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or_else(|| "DT_GNU_HASH bloom size overflows u64".to_owned())?;
    let bucket_size = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH bucket size overflows u64".to_owned())?;
    let prefix_size = 16u64
        .checked_add(bloom_size)
        .and_then(|value| value.checked_add(bucket_size))
        .ok_or_else(|| "DT_GNU_HASH prefix size overflows u64".to_owned())?;
    let table_offset = map_virtual_range(
        headers,
        file.len(),
        address,
        prefix_size,
        "DT_GNU_HASH prefix",
    )?;
    let bucket_offset = usize::try_from(table_offset + 16 + bloom_size)
        .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
    let chain_address = address
        .checked_add(prefix_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
    let mut count = symbol_offset;
    for bucket_index in 0..bucket_count {
        let symbol = read_u32(
            file,
            bucket_offset + usize::try_from(u64::from(bucket_index) * 4).unwrap(),
        );
        if symbol == 0 {
            continue;
        }
        if symbol < symbol_offset {
            return Err(format!(
                "DT_GNU_HASH bucket {bucket_index} starts below symbol offset"
            ));
        }
        let mut current = symbol;
        loop {
            let chain_index = current - symbol_offset;
            let chain_entry_address = chain_address
                .checked_add(u64::from(chain_index) * 4)
                .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
            let chain_offset = mapped_offset(
                headers,
                file,
                chain_entry_address,
                4,
                "DT_GNU_HASH chain entry",
            )?;
            let hash = read_u32(file, chain_offset);
            current = current
                .checked_add(1)
                .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
            if hash & 1 != 0 {
                break;
            }
        }
        count = count.max(current);
    }
    Ok(count)
}

fn dynamic_entries(headers: &[ProgramHeader], file: &[u8]) -> Result<Vec<DynamicEntry>, String> {
    let segments = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if segments.len() != 1 {
        return Err(format!(
            "found {} PT_DYNAMIC segments; expected exactly one",
            segments.len()
        ));
    }
    let (segment_index, dynamic) = segments[0];
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} file size is not a multiple of 16"
        ));
    }
    let mut entries = Vec::new();
    for index in 0..dynamic.file_size / ELF64_DYNAMIC_SIZE {
        let offset = dynamic
            .offset
            .checked_add(index * ELF64_DYNAMIC_SIZE)
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
    Err("PT_DYNAMIC has no DT_NULL terminator".to_owned())
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "program header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        ));
    }
    let mut result = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let offset = header
            .program_header_offset
            .checked_add(u64::from(index) * u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program header offset overflows u64".to_owned())?;
        checked_file_end(
            offset,
            u64::from(ELF64_PROGRAM_HEADER_SIZE),
            file.len(),
            "program header",
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program header offset does not fit usize".to_owned())?;
        let entry = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if entry.file_size > entry.memory_size {
            return Err(format!(
                "program header {index} has p_filesz greater than p_memsz"
            ));
        }
        checked_file_end(
            entry.offset,
            entry.file_size,
            file.len(),
            "program header segment",
        )?;
        entry
            .virtual_address
            .checked_add(entry.memory_size)
            .ok_or_else(|| format!("program header {index} virtual range overflows u64"))?;
        result.push(entry);
    }
    Ok(result)
}

fn mapped_offset(
    headers: &[ProgramHeader],
    file: &[u8],
    address: u64,
    size: u64,
    label: &str,
) -> Result<usize, String> {
    let offset = map_virtual_range(headers, file.len(), address, size, label)?;
    usize::try_from(offset).map_err(|_| format!("{label} file offset does not fit usize"))
}

fn map_virtual_range(
    headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    label: &str,
) -> Result<u64, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        let backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| "PT_LOAD virtual file range overflows u64".to_owned())?;
        if address >= header.virtual_address && end <= backed_end {
            let delta = address - header.virtual_address;
            let offset = header
                .offset
                .checked_add(delta)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            checked_file_end(offset, size, file_len, label)?;
            return Ok(offset);
        }
    }
    Err(format!(
        "{label} virtual range {address:#x}..{end:#x} is not file-backed by PT_LOAD"
    ))
}

fn dynamic_string(
    file: &[u8],
    strtab_offset: u64,
    strsz: u64,
    offset: u64,
    label: &str,
) -> Result<String, String> {
    if offset >= strsz {
        return Err(format!(
            "{label} offset {offset} is outside DT_STRSZ {strsz}"
        ));
    }
    let start = strtab_offset
        .checked_add(offset)
        .ok_or_else(|| format!("{label} file offset overflows u64"))?;
    let start =
        usize::try_from(start).map_err(|_| format!("{label} file offset does not fit usize"))?;
    let remaining = usize::try_from(strsz - offset)
        .map_err(|_| format!("{label} remaining size does not fit usize"))?;
    let bytes = &file[start..start + remaining];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{label} is not NUL-terminated within DT_STRSZ"))?;
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn unique_tag_value(entries: &[DynamicEntry], tag: i64, name: &str) -> Result<Option<u64>, String> {
    let mut value = None;
    for entry in entries.iter().filter(|entry| entry.tag == tag) {
        if value.replace(entry.value).is_some() {
            return Err(format!("PT_DYNAMIC contains duplicate {name} entries"));
        }
    }
    Ok(value)
}

fn checked_file_end(offset: u64, size: u64, file_len: usize, label: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows u64"))?;
    if end > file_len as u64 {
        return Err(format!(
            "{label} ends at file offset {end}, beyond file length {file_len}"
        ));
    }
    Ok(end)
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
