use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_RELA_SIZE: u64 = 24;
const ELF64_SYMBOL_SIZE: u64 = 24;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;

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

#[derive(Clone, Copy)]
struct DynamicSymbols {
    symtab_offset: u64,
    strtab_offset: u64,
    strsz: u64,
    syment: u64,
    symbol_count: u64,
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
            Ok("usage: mini-elf-dynrela <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynrela <input>...".to_owned())
        };
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered = format_dynamic_relocations(header, &file)
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

fn format_dynamic_relocations(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let rela = unique_tag_value(&entries, DT_RELA, "DT_RELA")?;
    let rela_size = unique_tag_value(&entries, DT_RELASZ, "DT_RELASZ")?;
    let rela_entry_size = unique_tag_value(&entries, DT_RELAENT, "DT_RELAENT")?;

    let present = usize::from(rela.is_some())
        + usize::from(rela_size.is_some())
        + usize::from(rela_entry_size.is_some());
    if present == 0 {
        return Ok("No DT_RELA relocation table found.\n".to_owned());
    }
    if present != 3 {
        return Err(
            "PT_DYNAMIC must provide DT_RELA, DT_RELASZ, and DT_RELAENT together".to_owned(),
        );
    }

    let rela_address = rela.unwrap();
    let rela_size = rela_size.unwrap();
    let rela_entry_size = rela_entry_size.unwrap();
    if rela_entry_size != ELF64_RELA_SIZE {
        return Err(format!(
            "DT_RELAENT is {rela_entry_size}, expected {ELF64_RELA_SIZE} for ELF64"
        ));
    }
    if rela_size % rela_entry_size != 0 {
        return Err(format!(
            "DT_RELASZ {rela_size} is not a multiple of DT_RELAENT {rela_entry_size}"
        ));
    }

    let table_offset = map_virtual_range(
        &program_headers,
        file.len(),
        rela_address,
        rela_size,
        "DT_RELA table",
    )?;
    let symbols = dynamic_symbols(&program_headers, &entries, file)?;
    let count = rela_size / rela_entry_size;
    let mut output = format!("DT_RELA contains {count} entries:\n");
    output.push_str("  Offset             Info               Type                 Sym  Addend Name\n");
    for index in 0..count {
        let relative = index
            .checked_mul(rela_entry_size)
            .ok_or_else(|| "DT_RELA entry offset overflows u64".to_owned())?;
        let offset = table_offset
            .checked_add(relative)
            .ok_or_else(|| "DT_RELA entry offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_RELA entry offset does not fit usize".to_owned())?;
        let relocation_offset = read_u64(file, offset);
        let info = read_u64(file, offset + 8);
        let addend = read_i64(file, offset + 16);
        let symbol = info >> 32;
        let relocation_type = info as u32;
        let symbol_name = if symbol == 0 {
            "-".to_owned()
        } else {
            dynamic_symbol_name(file, symbols, symbol)?
        };
        output.push_str(&format!(
            "  {relocation_offset:#018x} {info:#018x} {:<20} {symbol:>4}  {addend:<6} {symbol_name}\n",
            relocation_type_name(relocation_type)
        ));
    }
    Ok(output)
}

fn dynamic_symbols(
    program_headers: &[ProgramHeader],
    entries: &[DynamicEntry],
    file: &[u8],
) -> Result<DynamicSymbols, String> {
    let symtab = unique_tag_value(entries, DT_SYMTAB, "DT_SYMTAB")?;
    let syment = unique_tag_value(entries, DT_SYMENT, "DT_SYMENT")?;
    let strtab = unique_tag_value(entries, DT_STRTAB, "DT_STRTAB")?;
    let strsz = unique_tag_value(entries, DT_STRSZ, "DT_STRSZ")?;
    let Some(hash_address) = unique_tag_value(entries, DT_HASH, "DT_HASH")? else {
        return Err("DT_RELA symbol resolution requires DT_HASH to bound DT_SYMTAB".to_owned());
    };

    let present = usize::from(symtab.is_some())
        + usize::from(syment.is_some())
        + usize::from(strtab.is_some())
        + usize::from(strsz.is_some());
    if present != 4 {
        return Err(
            "DT_RELA symbol resolution requires DT_SYMTAB, DT_SYMENT, DT_STRTAB, and DT_STRSZ together"
                .to_owned(),
        );
    }

    let symtab = symtab.unwrap();
    let syment = syment.unwrap();
    let strtab = strtab.unwrap();
    let strsz = strsz.unwrap();
    if syment != ELF64_SYMBOL_SIZE {
        return Err(format!(
            "DT_SYMENT is {syment}, expected {ELF64_SYMBOL_SIZE} for ELF64"
        ));
    }

    let hash_offset = map_virtual_range(
        program_headers,
        file.len(),
        hash_address,
        8,
        "DT_HASH header",
    )?;
    let hash_offset = usize::try_from(hash_offset)
        .map_err(|_| "DT_HASH header offset does not fit usize".to_owned())?;
    let symbol_count = u64::from(read_u32(file, hash_offset + 4));
    let symtab_size = symbol_count
        .checked_mul(syment)
        .ok_or_else(|| "dynamic symbol table byte size overflows u64".to_owned())?;
    let symtab_offset = map_virtual_range(
        program_headers,
        file.len(),
        symtab,
        symtab_size,
        "DT_SYMTAB table",
    )?;
    let strtab_offset = map_virtual_range(
        program_headers,
        file.len(),
        strtab,
        strsz,
        "DT_STRTAB table",
    )?;

    Ok(DynamicSymbols {
        symtab_offset,
        strtab_offset,
        strsz,
        syment,
        symbol_count,
    })
}

fn dynamic_symbol_name(
    file: &[u8],
    symbols: DynamicSymbols,
    symbol_index: u64,
) -> Result<String, String> {
    if symbol_index >= symbols.symbol_count {
        return Err(format!(
            "DT_RELA symbol index {symbol_index} is outside dynamic symbol count {}",
            symbols.symbol_count
        ));
    }
    let relative = symbol_index
        .checked_mul(symbols.syment)
        .ok_or_else(|| "dynamic symbol entry offset overflows u64".to_owned())?;
    let offset = symbols
        .symtab_offset
        .checked_add(relative)
        .ok_or_else(|| "dynamic symbol entry offset overflows u64".to_owned())?;
    let offset = usize::try_from(offset)
        .map_err(|_| "dynamic symbol entry offset does not fit usize".to_owned())?;
    let name_offset = u64::from(read_u32(file, offset));
    if name_offset >= symbols.strsz {
        return Err(format!(
            "dynamic symbol {symbol_index} name offset {name_offset} is outside DT_STRSZ {}",
            symbols.strsz
        ));
    }
    let start = symbols
        .strtab_offset
        .checked_add(name_offset)
        .ok_or_else(|| "dynamic symbol name file offset overflows u64".to_owned())?;
    let remaining = symbols.strsz - name_offset;
    let end = start
        .checked_add(remaining)
        .ok_or_else(|| "dynamic string range overflows u64".to_owned())?;
    let start = usize::try_from(start)
        .map_err(|_| "dynamic symbol name offset does not fit usize".to_owned())?;
    let end =
        usize::try_from(end).map_err(|_| "dynamic string end does not fit usize".to_owned())?;
    let bytes = &file[start..end];
    let nul = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        format!("dynamic symbol {symbol_index} name is not NUL-terminated within DT_STRTAB")
    })?;
    Ok(String::from_utf8_lossy(&bytes[..nul]).into_owned())
}

fn dynamic_entries(
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<DynamicEntry>, String> {
    let dynamic_segments = program_headers
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
        return Ok(Vec::new());
    };
    if dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(format!(
            "PT_DYNAMIC segment {segment_index} has file size {}, which is not a multiple of {ELF64_DYNAMIC_SIZE}",
            dynamic.file_size
        ));
    }
    checked_file_end(
        dynamic.offset,
        dynamic.file_size,
        file.len(),
        &format!("PT_DYNAMIC segment {segment_index}"),
    )?;

    let entry_count = dynamic.file_size / ELF64_DYNAMIC_SIZE;
    let mut entries = Vec::new();
    for index in 0..entry_count {
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
    Err(format!(
        "PT_DYNAMIC segment {segment_index} has no DT_NULL terminator"
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

fn map_virtual_range(
    program_headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    what: &str,
) -> Result<u64, String> {
    let address_end = address
        .checked_add(size)
        .ok_or_else(|| format!("{what} virtual range overflows u64"))?;
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| format!("PT_LOAD segment {index} virtual file range overflows u64"))?;
        if address < header.virtual_address || address_end > load_end {
            continue;
        }
        let delta = address - header.virtual_address;
        let offset = header
            .offset
            .checked_add(delta)
            .ok_or_else(|| format!("{what} file offset overflows u64"))?;
        checked_file_end(offset, size, file_len, what)?;
        return Ok(offset);
    }
    Err(format!(
        "{what} virtual range {address:#x}..{address_end:#x} is not backed by a PT_LOAD file range"
    ))
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

fn relocation_type_name(relocation_type: u32) -> String {
    match relocation_type {
        0 => "R_X86_64_NONE".to_owned(),
        1 => "R_X86_64_64".to_owned(),
        2 => "R_X86_64_PC32".to_owned(),
        5 => "R_X86_64_COPY".to_owned(),
        6 => "R_X86_64_GLOB_DAT".to_owned(),
        7 => "R_X86_64_JUMP_SLOT".to_owned(),
        8 => "R_X86_64_RELATIVE".to_owned(),
        10 => "R_X86_64_32".to_owned(),
        11 => "R_X86_64_32S".to_owned(),
        value => format!("R_X86_64_{value}"),
    }
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
