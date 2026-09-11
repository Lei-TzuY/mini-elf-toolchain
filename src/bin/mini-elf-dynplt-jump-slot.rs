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
const R_X86_64_JUMP_SLOT: u32 = 7;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;

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
    jmprel: u64,
    pltrelsz: u64,
    pltrel: u64,
    hash: Option<u64>,
    gnu_hash: Option<u64>,
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
    "usage: mini-elf-dynplt-jump-slot --load-bias <address> <input>...".to_owned()
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
        return Err("mini-elf-dynplt-jump-slot requires an ET_DYN image".to_owned());
    }

    let headers = program_headers(file)?;
    let dynamic = unique_dynamic(&headers)?;
    let metadata = dynamic_metadata(program_bytes(file, dynamic, "PT_DYNAMIC")?)?;
    if metadata.pltrel != DT_RELA as u64 {
        return Err(format!(
            "DT_PLTREL value {} is unsupported, expected DT_RELA ({DT_RELA})",
            metadata.pltrel
        ));
    }
    if metadata.syment != ELF64_SYMBOL_SIZE as u64 {
        return Err(format!(
            "DT_SYMENT value {} is unsupported, expected {ELF64_SYMBOL_SIZE}",
            metadata.syment
        ));
    }
    if metadata.pltrelsz % ELF64_RELA_SIZE as u64 != 0 {
        return Err(format!(
            "DT_PLTRELSZ {} is not a whole number of ELF64 Rela entries",
            metadata.pltrelsz
        ));
    }

    let symbol_count = dynamic_symbol_count(file, &headers, metadata.hash, metadata.gnu_hash)?;
    if symbol_count == 0 {
        return Err("dynamic hash metadata reports zero dynamic symbols".to_owned());
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
    let jmprel = map_file_backed_range(
        file,
        &headers,
        metadata.jmprel,
        metadata.pltrelsz,
        0,
        "DT_JMPREL table",
    )?;

    let entry_count = metadata.pltrelsz / ELF64_RELA_SIZE as u64;
    if entry_count == 0 {
        return Err("DT_JMPREL table is empty".to_owned());
    }
    let mut output = format!(
        "Validated R_X86_64_JUMP_SLOT relocations: load-bias={load_bias:#018x} jmprel={:#018x} entries={entry_count} symbols={symbol_count}\n",
        metadata.jmprel
    );

    for (index, entry) in jmprel.chunks_exact(ELF64_RELA_SIZE).enumerate() {
        let offset = read_u64(entry, 0);
        let relocation_info = read_u64(entry, 8);
        let symbol_index = relocation_info >> 32;
        let relocation_type = relocation_info as u32;
        if relocation_type != R_X86_64_JUMP_SLOT {
            return Err(format!(
                "DT_JMPREL entry {index} has relocation type {relocation_type}, expected R_X86_64_JUMP_SLOT ({R_X86_64_JUMP_SLOT})"
            ));
        }
        if symbol_index == 0 || symbol_index >= symbol_count {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references invalid dynamic symbol index {symbol_index} (count {symbol_count})"
            ));
        }
        let addend = read_i64(entry, 16);
        if addend != 0 {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} has nonzero RELA addend {addend}; this bounded slice accepts canonical S semantics only"
            ));
        }
        map_memory_range(
            &headers,
            offset,
            8,
            PF_W,
            &format!("JUMP_SLOT relocation {index} target"),
        )?;
        let runtime_slot = load_bias
            .checked_add(offset)
            .ok_or_else(|| format!("JUMP_SLOT relocation {index} runtime target overflows u64"))?;

        let symbol_offset = usize::try_from(symbol_index)
            .ok()
            .and_then(|value| value.checked_mul(ELF64_SYMBOL_SIZE))
            .ok_or_else(|| format!("dynamic symbol index {symbol_index} offset overflows usize"))?;
        let symbol = symtab
            .get(symbol_offset..symbol_offset + ELF64_SYMBOL_SIZE)
            .ok_or_else(|| format!("dynamic symbol index {symbol_index} exceeds DT_SYMTAB"))?;
        let name_offset = read_u32(symbol, 0);
        let symbol_info = symbol[4];
        let section_index = read_u16(symbol, 6);
        let value = read_u64(symbol, 8);
        let symbol_type = symbol_info & 0x0f;
        if section_index == SHN_ABS {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references absolute dynamic symbol index {symbol_index}; absolute-symbol semantics are outside this bounded slice"
            ));
        }
        if symbol_type == STT_TLS {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references TLS dynamic symbol index {symbol_index}; TLS semantics are outside this bounded slice"
            ));
        }
        if section_index != SHN_UNDEF && symbol_type == STT_GNU_IFUNC {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references defined STT_GNU_IFUNC dynamic symbol index {symbol_index}; IFUNC resolver execution is outside this bounded slice"
            ));
        }
        let name = dynamic_string(strtab, name_offset, symbol_index)?;
        if section_index == SHN_UNDEF {
            output.push_str(&format!(
                "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_slot:#018x} binding=external\n"
            ));
        } else {
            map_memory_range(
                &headers,
                value,
                1,
                0,
                &format!("JUMP_SLOT relocation {index} symbol value"),
            )?;
            let runtime_value = load_bias.checked_add(value).ok_or_else(|| {
                format!("JUMP_SLOT relocation {index} runtime symbol value overflows u64")
            })?;
            output.push_str(&format!(
                "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_slot:#018x} binding=defined value=B+{value:#018x}=>{runtime_value:#018x}\n"
            ));
        }
    }
    Ok(output)
}

fn dynamic_symbol_count(
    file: &[u8],
    headers: &[ProgramHeader],
    hash: Option<u64>,
    gnu_hash: Option<u64>,
) -> Result<u64, String> {
    if let Some(address) = hash {
        let header = map_file_backed_range(file, headers, address, 8, 0, "DT_HASH header")?;
        return Ok(u64::from(read_u32(header, 4)));
    }
    let address = gnu_hash.ok_or_else(|| {
        "R_X86_64_JUMP_SLOT validation requires DT_HASH or DT_GNU_HASH to bound DT_SYMTAB"
            .to_owned()
    })?;
    gnu_hash_symbol_count(file, headers, address)
}

fn gnu_hash_symbol_count(
    file: &[u8],
    headers: &[ProgramHeader],
    address: u64,
) -> Result<u64, String> {
    let header = map_file_backed_range(file, headers, address, 16, 0, "DT_GNU_HASH header")?;
    let bucket_count = read_u32(header, 0);
    let symbol_offset = read_u32(header, 4);
    let bloom_count = read_u32(header, 8);
    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }
    let bloom_bytes = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or_else(|| "DT_GNU_HASH bloom byte size overflows u64".to_owned())?;
    let bucket_bytes = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_GNU_HASH bucket byte size overflows u64".to_owned())?;
    let prefix_size = 16u64
        .checked_add(bloom_bytes)
        .and_then(|value| value.checked_add(bucket_bytes))
        .ok_or_else(|| "DT_GNU_HASH prefix byte size overflows u64".to_owned())?;
    let prefix =
        map_file_backed_range(file, headers, address, prefix_size, 0, "DT_GNU_HASH prefix")?;
    let bucket_start = usize::try_from(
        16u64
            .checked_add(bloom_bytes)
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?,
    )
    .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
    let chain_address = address
        .checked_add(prefix_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
    let mut count = symbol_offset;
    for bucket_index in 0..bucket_count {
        let bucket_delta = u64::from(bucket_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows u64".to_owned())?;
        let offset = bucket_start
            .checked_add(
                usize::try_from(bucket_delta)
                    .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?,
            )
            .ok_or_else(|| "DT_GNU_HASH bucket offset overflows usize".to_owned())?;
        let start_symbol = read_u32(prefix, offset);
        if start_symbol == 0 {
            continue;
        }
        if start_symbol < symbol_offset {
            return Err(format!(
                "DT_GNU_HASH bucket {bucket_index} starts at symbol {start_symbol}, below symbol offset {symbol_offset}"
            ));
        }
        let mut symbol = start_symbol;
        loop {
            let chain_index = symbol
                .checked_sub(symbol_offset)
                .ok_or_else(|| "DT_GNU_HASH chain index underflows".to_owned())?;
            let chain_offset = u64::from(chain_index)
                .checked_mul(4)
                .ok_or_else(|| "DT_GNU_HASH chain offset overflows u64".to_owned())?;
            let entry_address = chain_address
                .checked_add(chain_offset)
                .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
            let entry = map_file_backed_range(
                file,
                headers,
                entry_address,
                4,
                0,
                &format!("DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"),
            )?;
            let next = symbol
                .checked_add(1)
                .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
            if read_u32(entry, 0) & 1 != 0 {
                count = count.max(next);
                break;
            }
            symbol = next;
        }
    }
    Ok(u64::from(count))
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
    let mut jmprel = None;
    let mut pltrelsz = None;
    let mut pltrel = None;
    let mut hash = None;
    let mut gnu_hash = None;
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
            DT_JMPREL => set_once(&mut jmprel, value, "DT_JMPREL")?,
            DT_PLTRELSZ => set_once(&mut pltrelsz, value, "DT_PLTRELSZ")?,
            DT_PLTREL => set_once(&mut pltrel, value, "DT_PLTREL")?,
            DT_HASH => set_once(&mut hash, value, "DT_HASH")?,
            DT_GNU_HASH => set_once(&mut gnu_hash, value, "DT_GNU_HASH")?,
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
        jmprel: required(jmprel, "DT_JMPREL")?,
        pltrelsz: required(pltrelsz, "DT_PLTRELSZ")?,
        pltrel: required(pltrel, "DT_PLTREL")?,
        hash,
        gnu_hash,
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
