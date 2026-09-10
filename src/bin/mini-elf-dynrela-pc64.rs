use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_PC64: u32 = 24;
const STT_TLS: u8 = 6;
const SHN_ABS: u16 = 0xfff1;

#[derive(Clone, Copy)]
struct Phdr {
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    filesz: u64,
    memsz: u64,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(s) => {
            print!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run<I: Iterator<Item = OsString>>(args: I) -> Result<String, String> {
    let inputs: Vec<_> = args.collect();
    if inputs.is_empty() {
        return Err("usage: mini-elf-dynrela-pc64 <input>...".into());
    }
    let mut rendered = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let name = input.to_string_lossy().into_owned();
        let bytes = fs::read(input).map_err(|e| format!("cannot read '{name}': {e}"))?;
        let body = inspect(&bytes).map_err(|e| format!("{name}: {e}"))?;
        rendered.push((name, body));
    }
    let multiple = rendered.len() > 1;
    let mut out = String::new();
    for (index, (name, body)) in rendered.into_iter().enumerate() {
        if index != 0 {
            out.push('\n');
        }
        if multiple {
            out.push_str(&format!("File: {name}\n"));
        }
        out.push_str(&body);
    }
    Ok(out)
}

fn inspect(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("requires little-endian ELF64 input".into());
    }
    if read_u16(bytes, 16) != 3 || read_u16(bytes, 18) != 62 {
        return Err("requires x86-64 ET_DYN input".into());
    }
    let phdrs = program_headers(bytes)?;
    let dynamic_headers: Vec<_> = phdrs
        .iter()
        .copied()
        .filter(|h| h.kind == PT_DYNAMIC)
        .collect();
    if dynamic_headers.len() != 1 {
        return Err("requires exactly one PT_DYNAMIC".into());
    }
    let dynamic = file_range(
        bytes,
        dynamic_headers[0].off,
        dynamic_headers[0].filesz,
        "PT_DYNAMIC",
    )?;
    if dynamic.len() % 16 != 0 {
        return Err("PT_DYNAMIC size is not a multiple of 16".into());
    }

    let mut hash = None;
    let mut gnu_hash = None;
    let mut symtab = None;
    let mut syment = None;
    let mut strtab = None;
    let mut strsz = None;
    let mut rela = None;
    let mut relasz = None;
    let mut relaent = None;
    let mut terminated = false;
    for (index, entry) in dynamic.chunks_exact(16).enumerate() {
        let tag = read_i64(entry, 0);
        let value = read_u64(entry, 8);
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        let slot = match tag {
            DT_HASH => &mut hash,
            DT_GNU_HASH => &mut gnu_hash,
            DT_SYMTAB => &mut symtab,
            DT_SYMENT => &mut syment,
            DT_STRTAB => &mut strtab,
            DT_STRSZ => &mut strsz,
            DT_RELA => &mut rela,
            DT_RELASZ => &mut relasz,
            DT_RELAENT => &mut relaent,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate dynamic tag at entry {index}"));
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC lacks DT_NULL".into());
    }
    let symtab = required(symtab, "DT_SYMTAB")?;
    let syment = required(syment, "DT_SYMENT")?;
    let strtab = required(strtab, "DT_STRTAB")?;
    let strsz = required(strsz, "DT_STRSZ")?;
    let rela = required(rela, "DT_RELA")?;
    let relasz = required(relasz, "DT_RELASZ")?;
    let relaent = required(relaent, "DT_RELAENT")?;
    if syment != 24 || relaent != 24 || relasz % 24 != 0 {
        return Err("unsupported dynamic table entry size".into());
    }

    let symbol_count = dynamic_symbol_count(bytes, &phdrs, hash, gnu_hash)?;
    if symbol_count == 0 {
        return Err("dynamic hash metadata reports zero symbols".into());
    }
    let symbol_bytes = map_file(
        bytes,
        &phdrs,
        symtab,
        symbol_count.checked_mul(24).ok_or("dynsym size overflow")?,
        0,
        "DT_SYMTAB",
    )?;
    let string_bytes = map_file(bytes, &phdrs, strtab, strsz, 0, "DT_STRTAB")?;
    let rela_bytes = map_file(bytes, &phdrs, rela, relasz, 0, "DT_RELA")?;

    let mut out = format!(
        "Validated R_X86_64_PC64 relocations: entries={} symbols={symbol_count}\n",
        relasz / 24
    );
    let mut found = 0usize;
    for (index, entry) in rela_bytes.chunks_exact(24).enumerate() {
        let offset = read_u64(entry, 0);
        let info = read_u64(entry, 8);
        if info as u32 != R_X86_64_PC64 {
            continue;
        }
        let symbol_index = info >> 32;
        if symbol_index == 0 || symbol_index >= symbol_count {
            return Err(format!(
                "R_X86_64_PC64 relocation {index} has invalid symbol index {symbol_index}"
            ));
        }
        map_memory(&phdrs, offset, 8, PF_W, "PC64 target")?;
        let symbol_offset = usize::try_from(
            symbol_index
                .checked_mul(24)
                .ok_or("symbol offset overflow")?,
        )
        .map_err(|_| "symbol offset too large")?;
        let symbol = symbol_bytes
            .get(symbol_offset..symbol_offset + 24)
            .ok_or("dynamic symbol exceeds DT_SYMTAB")?;
        let name_offset = read_u32(symbol, 0) as usize;
        let symbol_info = symbol[4];
        let section_index = read_u16(symbol, 6);
        let symbol_value = read_u64(symbol, 8);
        if name_offset >= string_bytes.len() {
            return Err(format!(
                "dynamic symbol {symbol_index} name offset is outside DT_STRTAB"
            ));
        }
        let tail = &string_bytes[name_offset..];
        let nul = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or("dynamic symbol name is not NUL-terminated")?;
        let name =
            std::str::from_utf8(&tail[..nul]).map_err(|_| "dynamic symbol name is not UTF-8")?;
        let addend = read_i64(entry, 16);
        if section_index == 0 {
            out.push_str(&format!("  index={index} symbol={symbol_index}:{name} binding=external target={offset:#x} addend={addend} formula=S+A-P\n"));
        } else {
            if section_index == SHN_ABS {
                return Err(format!("R_X86_64_PC64 relocation {index} references an absolute symbol; absolute-symbol semantics are outside this bounded slice"));
            }
            if symbol_info & 0x0f == STT_TLS {
                return Err(format!("R_X86_64_PC64 relocation {index} references TLS; TLS semantics are outside this bounded slice"));
            }
            map_memory(&phdrs, symbol_value, 1, 0, "PC64 symbol")?;
            let value = i128::from(symbol_value) + i128::from(addend) - i128::from(offset);
            i64::try_from(value)
                .map_err(|_| format!("R_X86_64_PC64 relocation {index} result does not fit i64"))?;
            out.push_str(&format!("  index={index} symbol={symbol_index}:{name} binding=same-image target={offset:#x} addend={addend} result={value}\n"));
        }
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_PC64 relocations".into());
    }
    Ok(out)
}

fn dynamic_symbol_count(
    bytes: &[u8],
    phdrs: &[Phdr],
    hash: Option<u64>,
    gnu_hash: Option<u64>,
) -> Result<u64, String> {
    if let Some(address) = hash {
        let header = map_file(bytes, phdrs, address, 8, 0, "DT_HASH")?;
        return Ok(u64::from(read_u32(header, 4)));
    }
    let address = gnu_hash.ok_or_else(|| {
        "R_X86_64_PC64 validation requires DT_HASH or DT_GNU_HASH to bound DT_SYMTAB".to_owned()
    })?;
    gnu_hash_symbol_count(bytes, phdrs, address)
}

fn gnu_hash_symbol_count(bytes: &[u8], phdrs: &[Phdr], address: u64) -> Result<u64, String> {
    let header = map_file(bytes, phdrs, address, 16, 0, "DT_GNU_HASH header")?;
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
    let prefix = map_file(
        bytes,
        phdrs,
        address,
        prefix_size,
        0,
        "DT_GNU_HASH prefix",
    )?;
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
            let entry = map_file(
                bytes,
                phdrs,
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

fn program_headers(bytes: &[u8]) -> Result<Vec<Phdr>, String> {
    let offset = usize::try_from(read_u64(bytes, 32)).map_err(|_| "phoff too large")?;
    let entry_size = usize::from(read_u16(bytes, 54));
    let count = usize::from(read_u16(bytes, 56));
    if entry_size != 56 {
        return Err("unsupported program-header size".into());
    }
    let end = offset
        .checked_add(
            count
                .checked_mul(entry_size)
                .ok_or("program-header size overflow")?,
        )
        .ok_or("program-header range overflow")?;
    if end > bytes.len() {
        return Err("program-header table exceeds input".into());
    }
    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let start = offset + index * entry_size;
        let header = Phdr {
            kind: read_u32(bytes, start),
            flags: read_u32(bytes, start + 4),
            off: read_u64(bytes, start + 8),
            va: read_u64(bytes, start + 16),
            filesz: read_u64(bytes, start + 32),
            memsz: read_u64(bytes, start + 40),
        };
        if header.filesz > header.memsz {
            return Err(format!("program header {index} filesz exceeds memsz"));
        }
        file_range(bytes, header.off, header.filesz, "program header")?;
        header
            .va
            .checked_add(header.memsz)
            .ok_or("segment address overflow")?;
        headers.push(header);
    }
    Ok(headers)
}

fn file_range<'a>(bytes: &'a [u8], off: u64, size: u64, label: &str) -> Result<&'a [u8], String> {
    let start = usize::try_from(off).map_err(|_| format!("{label} offset too large"))?;
    let width = usize::try_from(size).map_err(|_| format!("{label} size too large"))?;
    let end = start
        .checked_add(width)
        .ok_or_else(|| format!("{label} range overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("{label} exceeds input"))
}

fn map_file<'a>(
    bytes: &'a [u8],
    headers: &[Phdr],
    address: u64,
    size: u64,
    flags: u32,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} address overflow"))?;
    for h in headers
        .iter()
        .filter(|h| h.kind == PT_LOAD && h.flags & flags == flags)
    {
        let load_end = h
            .va
            .checked_add(h.filesz)
            .ok_or_else(|| format!("{label} segment range overflow"))?;
        if address >= h.va && end <= load_end {
            let file_offset = h
                .off
                .checked_add(address - h.va)
                .ok_or_else(|| format!("{label} file offset overflow"))?;
            return file_range(bytes, file_offset, size, label);
        }
    }
    Err(format!("{label} is not file-backed by PT_LOAD"))
}

fn map_memory(
    headers: &[Phdr],
    address: u64,
    size: u64,
    flags: u32,
    label: &str,
) -> Result<(), String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} address overflow"))?;
    for h in headers
        .iter()
        .filter(|h| h.kind == PT_LOAD && h.flags & flags == flags)
    {
        let load_end = h
            .va
            .checked_add(h.memsz)
            .ok_or_else(|| format!("{label} segment range overflow"))?;
        if address >= h.va && end <= load_end {
            return Ok(());
        }
    }
    Err(format!("{label} is not contained in matching PT_LOAD"))
}

fn required(value: Option<u64>, name: &str) -> Result<u64, String> {
    value.ok_or_else(|| format!("missing {name}"))
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
