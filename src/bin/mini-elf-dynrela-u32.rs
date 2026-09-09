use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_DYNAMIC_ENTRY_SIZE: usize = 16;
const ELF64_RELA_SIZE: usize = 24;
const ELF64_SYMBOL_SIZE: usize = 24;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_32: u32 = 10;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_TLS: u8 = 6;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

#[derive(Clone, Copy)]
struct DynamicMetadata {
    rela: u64,
    relasz: u64,
    relaent: u64,
    hash: u64,
    symtab: u64,
    syment: u64,
    strtab: u64,
    strsz: u64,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    let (load_bias, inputs) = parse_args(&args)?;
    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let rendered = inspect(&file, load_bias).map_err(|error| format!("{display}: {error}"))?;
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

fn parse_args(args: &[OsString]) -> Result<(u64, Vec<&OsString>), String> {
    let mut load_bias = None;
    let mut inputs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let text = args[index].to_string_lossy();
        if text == "--load-bias" {
            index += 1;
            if index >= args.len() {
                return Err(usage());
            }
            if load_bias.is_some() {
                return Err("duplicate --load-bias option".to_owned());
            }
            load_bias = Some(parse_u64(&args[index].to_string_lossy(), "load bias")?);
        } else if let Some(value) = text.strip_prefix("--load-bias=") {
            if load_bias.is_some() {
                return Err("duplicate --load-bias option".to_owned());
            }
            load_bias = Some(parse_u64(value, "load bias")?);
        } else if text.starts_with('-') {
            return Err(usage());
        } else {
            inputs.push(&args[index]);
        }
        index += 1;
    }
    if inputs.is_empty() {
        return Err(usage());
    }
    Ok((load_bias.ok_or_else(usage)?, inputs))
}

fn usage() -> String {
    "usage: mini-elf-dynrela-u32 --load-bias <address> <input>...".to_owned()
}

fn parse_u64(text: &str, label: &str) -> Result<u64, String> {
    if text.is_empty() {
        return Err(format!("{label} is empty"));
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() {
            return Err(format!("{label} is empty"));
        }
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid {label} '{text}'"))
    } else {
        text.parse::<u64>()
            .map_err(|_| format!("invalid {label} '{text}'"))
    }
}

fn inspect(file: &[u8], load_bias: u64) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|error| error.to_string())?;
    if file.len() < 64 {
        return Err("ELF64 header is truncated".to_owned());
    }
    if read_u16(file, 16) != ET_DYN {
        return Err("mini-elf-dynrela-u32 requires an ET_DYN image".to_owned());
    }

    let headers = program_headers(file)?;
    let dynamic = unique_dynamic(&headers)?;
    let metadata = dynamic_metadata(program_bytes(file, dynamic, "PT_DYNAMIC")?)?;
    if metadata.relaent != ELF64_RELA_SIZE as u64 {
        return Err(format!(
            "DT_RELAENT value {} is unsupported, expected {ELF64_RELA_SIZE}",
            metadata.relaent
        ));
    }
    if metadata.syment != ELF64_SYMBOL_SIZE as u64 {
        return Err(format!(
            "DT_SYMENT value {} is unsupported, expected {ELF64_SYMBOL_SIZE}",
            metadata.syment
        ));
    }
    if metadata.relasz % metadata.relaent != 0 {
        return Err("DT_RELASZ is not a whole number of DT_RELAENT entries".to_owned());
    }

    let hash = map_file_backed_range(file, &headers, metadata.hash, 8, 0, "DT_HASH header")?;
    let symbol_count = u64::from(read_u32(hash, 4));
    if symbol_count == 0 {
        return Err("DT_HASH reports zero dynamic symbols".to_owned());
    }
    let symtab_size = symbol_count
        .checked_mul(metadata.syment)
        .ok_or_else(|| "dynamic symbol table size overflows u64".to_owned())?;
    let symtab = map_file_backed_range(
        file,
        &headers,
        metadata.symtab,
        symtab_size,
        0,
        "DT_SYMTAB table",
    )?;
    let strtab = map_file_backed_range(
        file,
        &headers,
        metadata.strtab,
        metadata.strsz,
        0,
        "DT_STRTAB table",
    )?;
    let rela = map_file_backed_range(
        file,
        &headers,
        metadata.rela,
        metadata.relasz,
        0,
        "DT_RELA table",
    )?;

    let mut output = format!(
        "Validated R_X86_64_32 relocations: load-bias={load_bias:#018x} rela={:#018x} entries={} symbols={symbol_count}\n",
        metadata.rela,
        metadata.relasz / metadata.relaent
    );
    let mut found = 0usize;
    for (index, entry) in rela.chunks_exact(ELF64_RELA_SIZE).enumerate() {
        let offset = read_u64(entry, 0);
        let info = read_u64(entry, 8);
        let symbol_index = info >> 32;
        let relocation_type = info as u32;
        if relocation_type != R_X86_64_32 {
            continue;
        }
        if symbol_index == 0 || symbol_index >= symbol_count {
            return Err(format!(
                "R_X86_64_32 relocation {index} references invalid dynamic symbol index {symbol_index} (count {symbol_count})"
            ));
        }
        map_memory_range(
            &headers,
            offset,
            4,
            PF_W,
            &format!("R_X86_64_32 relocation {index} target"),
        )?;

        let symbol_offset = usize::try_from(symbol_index)
            .ok()
            .and_then(|value| value.checked_mul(ELF64_SYMBOL_SIZE))
            .ok_or_else(|| format!("dynamic symbol index {symbol_index} offset overflows usize"))?;
        let symbol = &symtab[symbol_offset..symbol_offset + ELF64_SYMBOL_SIZE];
        let name_offset = read_u32(symbol, 0);
        let symbol_info = symbol[4];
        let section_index = read_u16(symbol, 6);
        let value = read_u64(symbol, 8);
        if section_index == SHN_UNDEF {
            return Err(format!(
                "R_X86_64_32 relocation {index} references undefined dynamic symbol index {symbol_index}; external lookup is outside this bounded slice"
            ));
        }
        if section_index == SHN_ABS {
            return Err(format!(
                "R_X86_64_32 relocation {index} references absolute dynamic symbol index {symbol_index}; absolute-symbol semantics are outside this bounded slice"
            ));
        }
        if symbol_info & 0x0f == STT_TLS {
            return Err(format!(
                "R_X86_64_32 relocation {index} references TLS dynamic symbol index {symbol_index}; TLS semantics are outside this bounded slice"
            ));
        }
        map_memory_range(
            &headers,
            value,
            1,
            0,
            &format!("R_X86_64_32 relocation {index} symbol value"),
        )?;
        let name = dynamic_string(strtab, name_offset, symbol_index)?;
        let addend = read_i64(entry, 16);
        let runtime_target = load_bias.checked_add(offset).ok_or_else(|| {
            format!("R_X86_64_32 relocation {index} runtime target overflows u64")
        })?;
        let runtime_symbol = load_bias.checked_add(value).ok_or_else(|| {
            format!("R_X86_64_32 relocation {index} runtime symbol value overflows u64")
        })?;
        let relocated = add_signed(runtime_symbol, addend)
            .ok_or_else(|| format!("R_X86_64_32 relocation {index} S + A overflows u64"))?;
        let narrowed = u32::try_from(relocated).map_err(|_| {
            format!(
                "R_X86_64_32 relocation {index} result {relocated:#x} does not fit unsigned 32 bits"
            )
        })?;
        output.push_str(&format!(
            "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_target:#018x} symbol-value=B+{value:#018x}=>{runtime_symbol:#018x} addend={addend} result={narrowed:#010x}\n"
        ));
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_32 relocations".to_owned());
    }
    Ok(output)
}

fn add_signed(base: u64, addend: i64) -> Option<u64> {
    if addend >= 0 {
        base.checked_add(addend as u64)
    } else {
        base.checked_sub(addend.unsigned_abs())
    }
}

fn dynamic_string(strtab: &[u8], offset: u32, symbol_index: u64) -> Result<String, String> {
    let start = usize::try_from(offset)
        .map_err(|_| format!("dynamic symbol {symbol_index} name offset does not fit usize"))?;
    if start >= strtab.len() {
        return Err(format!(
            "dynamic symbol {symbol_index} name offset {offset} is outside DT_STRTAB"
        ));
    }
    let tail = &strtab[start..];
    let end = tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
        format!("dynamic symbol {symbol_index} name is not NUL-terminated within DT_STRTAB")
    })?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {symbol_index} name is not valid UTF-8"))
}

fn dynamic_metadata(bytes: &[u8]) -> Result<DynamicMetadata, String> {
    if bytes.len() % ELF64_DYNAMIC_ENTRY_SIZE != 0 {
        return Err("PT_DYNAMIC size is not a whole number of ELF64 dynamic entries".to_owned());
    }
    let mut rela = None;
    let mut relasz = None;
    let mut relaent = None;
    let mut hash = None;
    let mut symtab = None;
    let mut syment = None;
    let mut strtab = None;
    let mut strsz = None;
    let mut terminated = false;
    for (index, entry) in bytes.chunks_exact(ELF64_DYNAMIC_ENTRY_SIZE).enumerate() {
        let tag = read_i64(entry, 0);
        let value = read_u64(entry, 8);
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(format!(
                    "PT_DYNAMIC entry {index} contains data after DT_NULL"
                ));
            }
            continue;
        }
        if tag == DT_NULL {
            terminated = true;
            continue;
        }
        match tag {
            DT_RELA => set_once(&mut rela, value, "DT_RELA")?,
            DT_RELASZ => set_once(&mut relasz, value, "DT_RELASZ")?,
            DT_RELAENT => set_once(&mut relaent, value, "DT_RELAENT")?,
            DT_HASH => set_once(&mut hash, value, "DT_HASH")?,
            DT_SYMTAB => set_once(&mut symtab, value, "DT_SYMTAB")?,
            DT_SYMENT => set_once(&mut syment, value, "DT_SYMENT")?,
            DT_STRTAB => set_once(&mut strtab, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut strsz, value, "DT_STRSZ")?,
            _ => {}
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC is missing a DT_NULL terminator".to_owned());
    }
    Ok(DynamicMetadata {
        rela: required(rela, "DT_RELA")?,
        relasz: required(relasz, "DT_RELASZ")?,
        relaent: required(relaent, "DT_RELAENT")?,
        hash: required(hash, "DT_HASH")?,
        symtab: required(symtab, "DT_SYMTAB")?,
        syment: required(syment, "DT_SYMENT")?,
        strtab: required(strtab, "DT_STRTAB")?,
        strsz: required(strsz, "DT_STRSZ")?,
    })
}

fn required(value: Option<u64>, label: &str) -> Result<u64, String> {
    value.ok_or_else(|| format!("PT_DYNAMIC is missing required {label}"))
}

fn set_once(slot: &mut Option<u64>, value: u64, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("PT_DYNAMIC contains duplicate {label}"));
    }
    Ok(())
}

fn unique_dynamic(headers: &[ProgramHeader]) -> Result<ProgramHeader, String> {
    let mut dynamic = None;
    for header in headers
        .iter()
        .copied()
        .filter(|header| header.segment_type == PT_DYNAMIC)
    {
        if dynamic.replace(header).is_some() {
            return Err("multiple PT_DYNAMIC program headers are unsupported".to_owned());
        }
    }
    dynamic.ok_or_else(|| "missing PT_DYNAMIC program header".to_owned())
}

fn program_headers(file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let phoff = usize::try_from(read_u64(file, 32))
        .map_err(|_| "program-header offset does not fit usize".to_owned())?;
    let phentsize = usize::from(read_u16(file, 54));
    let phnum = usize::from(read_u16(file, 56));
    if phentsize != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "unsupported ELF64 program-header size {phentsize}, expected {ELF64_PROGRAM_HEADER_SIZE}"
        ));
    }
    let table_size = phnum
        .checked_mul(phentsize)
        .ok_or_else(|| "program-header table size overflows usize".to_owned())?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or_else(|| "program-header table range overflows usize".to_owned())?;
    if table_end > file.len() {
        return Err("program-header table exceeds input".to_owned());
    }

    let mut headers = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let header = ProgramHeader {
            segment_type: read_u32(file, offset),
            flags: read_u32(file, offset + 4),
            offset: read_u64(file, offset + 8),
            vaddr: read_u64(file, offset + 16),
            filesz: read_u64(file, offset + 32),
            memsz: read_u64(file, offset + 40),
        };
        if header.filesz > header.memsz {
            return Err(format!(
                "program header {index} file size exceeds memory size"
            ));
        }
        let file_start = usize::try_from(header.offset)
            .map_err(|_| format!("program header {index} file offset does not fit usize"))?;
        let file_size = usize::try_from(header.filesz)
            .map_err(|_| format!("program header {index} file size does not fit usize"))?;
        let file_end = file_start
            .checked_add(file_size)
            .ok_or_else(|| format!("program header {index} file range overflows usize"))?;
        if file_end > file.len() {
            return Err(format!("program header {index} file range exceeds input"));
        }
        header.vaddr.checked_add(header.filesz).ok_or_else(|| {
            format!("program header {index} file-backed virtual range overflows u64")
        })?;
        header
            .vaddr
            .checked_add(header.memsz)
            .ok_or_else(|| format!("program header {index} memory virtual range overflows u64"))?;
        headers.push(header);
    }
    Ok(headers)
}

fn program_bytes<'a>(
    file: &'a [u8],
    header: ProgramHeader,
    label: &str,
) -> Result<&'a [u8], String> {
    let start =
        usize::try_from(header.offset).map_err(|_| format!("{label} offset does not fit usize"))?;
    let size =
        usize::try_from(header.filesz).map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{label} file range exceeds input"));
    }
    Ok(&file[start..end])
}

fn map_file_backed_range<'a>(
    file: &'a [u8],
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
    required_flags: u32,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        if header.flags & required_flags != required_flags {
            continue;
        }
        let load_end = header.vaddr + header.filesz;
        if address < header.vaddr || end > load_end {
            continue;
        }
        let relative = address - header.vaddr;
        let file_offset = header
            .offset
            .checked_add(relative)
            .ok_or_else(|| format!("{label} file offset overflows u64"))?;
        let start = usize::try_from(file_offset)
            .map_err(|_| format!("{label} file offset does not fit usize"))?;
        let width =
            usize::try_from(size).map_err(|_| format!("{label} size does not fit usize"))?;
        let file_end = start
            .checked_add(width)
            .ok_or_else(|| format!("{label} file range overflows usize"))?;
        if file_end > file.len() {
            return Err(format!("{label} file range exceeds input"));
        }
        return Ok(&file[start..file_end]);
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a matching file-backed PT_LOAD"
    ))
}

fn map_memory_range(
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
    required_flags: u32,
    label: &str,
) -> Result<(), String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        if header.flags & required_flags != required_flags {
            continue;
        }
        let load_end = header.vaddr + header.memsz;
        if address >= header.vaddr && end <= load_end {
            return Ok(());
        }
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a matching PT_LOAD memory range"
    ))
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
