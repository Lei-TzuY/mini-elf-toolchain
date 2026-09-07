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
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

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
            Ok("usage: mini-elf-dynplt <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-dynplt <input>...".to_owned())
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
            format_plt_relocations(header, &file).map_err(|error| format!("{display}: {error}"))?;
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

fn format_plt_relocations(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let entries = dynamic_entries(&program_headers, file)?;
    let jmprel = unique_tag_value(&entries, DT_JMPREL, "DT_JMPREL")?;
    let pltrelsz = unique_tag_value(&entries, DT_PLTRELSZ, "DT_PLTRELSZ")?;
    let pltrel = unique_tag_value(&entries, DT_PLTREL, "DT_PLTREL")?;
    let present = usize::from(jmprel.is_some())
        + usize::from(pltrelsz.is_some())
        + usize::from(pltrel.is_some());
    if present == 0 {
        return Ok("No DT_JMPREL relocation table found.\n".to_owned());
    }
    if present != 3 {
        return Err(
            "PT_DYNAMIC must provide DT_JMPREL, DT_PLTRELSZ, and DT_PLTREL together".to_owned(),
        );
    }
    if pltrel.unwrap() != DT_RELA as u64 {
        return Err(format!(
            "DT_PLTREL is {}, expected DT_RELA ({DT_RELA}) for this ELF64 x86-64 slice",
            pltrel.unwrap()
        ));
    }
    let size = pltrelsz.unwrap();
    if size % ELF64_RELA_SIZE != 0 {
        return Err(format!(
            "DT_PLTRELSZ {size} is not a multiple of ELF64 Rela size {ELF64_RELA_SIZE}"
        ));
    }
    let table_offset = map_virtual_range(
        &program_headers,
        file.len(),
        jmprel.unwrap(),
        size,
        "DT_JMPREL table",
    )?;
    let symbols = dynamic_symbols(&program_headers, &entries, file)?;
    let count = size / ELF64_RELA_SIZE;
    let mut output = format!("DT_JMPREL contains {count} entries:\n");
    output.push_str(
        "  Offset             Info               Type                 Sym  Addend Name\n",
    );
    for index in 0..count {
        let relative = index
            .checked_mul(ELF64_RELA_SIZE)
            .ok_or_else(|| "DT_JMPREL entry offset overflows u64".to_owned())?;
        let offset = table_offset
            .checked_add(relative)
            .ok_or_else(|| "DT_JMPREL entry offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_JMPREL entry offset does not fit usize".to_owned())?;
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
    let present = usize::from(symtab.is_some())
        + usize::from(syment.is_some())
        + usize::from(strtab.is_some())
        + usize::from(strsz.is_some());
    if present != 4 {
        return Err("DT_JMPREL symbol resolution requires DT_SYMTAB, DT_SYMENT, DT_STRTAB, and DT_STRSZ together".to_owned());
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
    let symbol_count = dynamic_symbol_count(entries, program_headers, file)?;
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

fn dynamic_symbol_count(
    entries: &[DynamicEntry],
    program_headers: &[ProgramHeader],
    file: &[u8],
) -> Result<u64, String> {
    if let Some(hash_address) = unique_tag_value(entries, DT_HASH, "DT_HASH")? {
        let hash_offset = map_virtual_range(
            program_headers,
            file.len(),
            hash_address,
            8,
            "DT_HASH header",
        )?;
        let hash_offset = usize::try_from(hash_offset)
            .map_err(|_| "DT_HASH header offset does not fit usize".to_owned())?;
        return Ok(u64::from(read_u32(file, hash_offset + 4)));
    }

    let Some(hash_address) = unique_tag_value(entries, DT_GNU_HASH, "DT_GNU_HASH")? else {
        return Err(
            "DT_JMPREL symbol resolution requires DT_HASH or DT_GNU_HASH to bound DT_SYMTAB"
                .to_owned(),
        );
    };
    gnu_hash_symbol_count(program_headers, file, hash_address)
}

fn gnu_hash_symbol_count(
    program_headers: &[ProgramHeader],
    file: &[u8],
    hash_address: u64,
) -> Result<u64, String> {
    let header_offset = map_virtual_range(
        program_headers,
        file.len(),
        hash_address,
        16,
        "DT_GNU_HASH header",
    )?;
    let header_offset = usize::try_from(header_offset)
        .map_err(|_| "DT_GNU_HASH header offset does not fit usize".to_owned())?;
    let bucket_count = read_u32(file, header_offset);
    let symbol_offset = read_u32(file, header_offset + 4);
    let bloom_count = read_u32(file, header_offset + 8);

    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }

    let bloom_size = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or_else(|| "DT_GNU_HASH bloom byte size overflows u64".to_owned())?;
    let buckets_size = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH bucket byte size overflows u64".to_owned())?;
    let prefix_size = 16u64
        .checked_add(bloom_size)
        .and_then(|value| value.checked_add(buckets_size))
        .ok_or_else(|| "DT_GNU_HASH prefix byte size overflows u64".to_owned())?;
    let table_offset = map_virtual_range(
        program_headers,
        file.len(),
        hash_address,
        prefix_size,
        "DT_GNU_HASH prefix",
    )?;

    let bucket_address = hash_address
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_size))
        .ok_or_else(|| "DT_GNU_HASH bucket address overflows u64".to_owned())?;
    let chain_address = bucket_address
        .checked_add(buckets_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
    let bucket_file_offset = table_offset
        .checked_add(16)
        .and_then(|value| value.checked_add(bloom_size))
        .ok_or_else(|| "DT_GNU_HASH bucket file offset overflows u64".to_owned())?;
    let bucket_file_offset = usize::try_from(bucket_file_offset)
        .map_err(|_| "DT_GNU_HASH bucket file offset does not fit usize".to_owned())?;

    let mut symbol_count = symbol_offset;
    for index in 0..bucket_count {
        let relative = u64::from(index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?;
        let relative = usize::try_from(relative)
            .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
        let symbol = read_u32(file, bucket_file_offset + relative);
        if symbol != 0 && symbol < symbol_offset {
            return Err(format!(
                "DT_GNU_HASH bucket {index} starts at symbol {symbol}, below symbol offset {symbol_offset}"
            ));
        }
        if symbol != 0 {
            let end = walk_gnu_hash_chain(
                program_headers,
                file,
                chain_address,
                symbol_offset,
                symbol,
                index,
            )?;
            symbol_count = symbol_count.max(end);
        }
    }
    Ok(u64::from(symbol_count))
}

fn walk_gnu_hash_chain(
    program_headers: &[ProgramHeader],
    file: &[u8],
    chain_address: u64,
    symbol_offset: u32,
    start_symbol: u32,
    bucket_index: u32,
) -> Result<u32, String> {
    let mut symbol = start_symbol;
    loop {
        let chain_index = symbol
            .checked_sub(symbol_offset)
            .ok_or_else(|| "DT_GNU_HASH chain index underflows".to_owned())?;
        let relative = u64::from(chain_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH chain offset overflows u64".to_owned())?;
        let address = chain_address
            .checked_add(relative)
            .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
        let offset = map_virtual_range(
            program_headers,
            file.len(),
            address,
            4,
            &format!("DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"),
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| "DT_GNU_HASH chain entry offset does not fit usize".to_owned())?;
        let hash = read_u32(file, offset);
        let next = symbol
            .checked_add(1)
            .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
        if hash & 1 != 0 {
            return Ok(next);
        }
        symbol = next;
    }
}

fn dynamic_symbol_name(
    file: &[u8],
    symbols: DynamicSymbols,
    symbol_index: u64,
) -> Result<String, String> {
    if symbol_index >= symbols.symbol_count {
        return Err(format!(
            "DT_JMPREL symbol index {symbol_index} is outside dynamic symbol count {}",
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
    let end = start
        .checked_add(symbols.strsz - name_offset)
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
