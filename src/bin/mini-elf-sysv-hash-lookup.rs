use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const PHENT: usize = 56;
const DYNENT: usize = 16;
const SYMENT: usize = 24;

#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    off: u64,
    va: u64,
    filesz: u64,
    memsz: u64,
}

#[derive(Default)]
struct Dyn {
    hash: Option<u64>,
    strtab: Option<u64>,
    symtab: Option<u64>,
    strsz: Option<u64>,
    syment: Option<u64>,
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

fn run<I: Iterator<Item = OsString>>(args: I) -> Result<String, String> {
    let args = args.collect::<Vec<_>>();
    if args.len() < 2 {
        return Err(usage());
    }
    let symbol = args[0]
        .to_str()
        .ok_or_else(|| "symbol name is not UTF-8".to_owned())?;
    if symbol.is_empty() {
        return Err("symbol name must not be empty".to_owned());
    }

    let multi = args.len() > 2;
    let mut rendered = Vec::new();
    for input in &args[1..] {
        let name = input.to_string_lossy().into_owned();
        let bytes = fs::read(input).map_err(|error| format!("cannot read '{name}': {error}"))?;
        rendered.push((name, inspect(&bytes, symbol)?));
    }

    let mut output = String::new();
    for (index, (name, body)) in rendered.into_iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        if multi {
            output.push_str(&format!("File: {name}\n"));
        }
        output.push_str(&body);
    }
    Ok(output)
}

fn usage() -> String {
    "usage: mini-elf-sysv-hash-lookup <symbol> <input>...".to_owned()
}

fn inspect(file: &[u8], symbol: &str) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|error| error.to_string())?;
    if file.len() < 64 || u16at(file, 16) != ET_DYN {
        return Err("mini-elf-sysv-hash-lookup requires an ET_DYN image".to_owned());
    }

    let ph = program_headers(file)?;
    let dynamic = ph
        .iter()
        .copied()
        .filter(|header| header.kind == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if dynamic.len() != 1 {
        return Err("expected exactly one PT_DYNAMIC program header".to_owned());
    }
    let dynamic_bytes = program_bytes(file, dynamic[0])?;
    if dynamic_bytes.len() % DYNENT != 0 {
        return Err("PT_DYNAMIC size is not a whole number of entries".to_owned());
    }

    let mut tags = Dyn::default();
    let mut terminated = false;
    for (index, entry) in dynamic_bytes.chunks_exact(DYNENT).enumerate() {
        let tag = i64at(entry, 0);
        let value = u64at(entry, 8);
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
        let slot = match tag {
            DT_HASH => Some((&mut tags.hash, "DT_HASH")),
            DT_STRTAB => Some((&mut tags.strtab, "DT_STRTAB")),
            DT_SYMTAB => Some((&mut tags.symtab, "DT_SYMTAB")),
            DT_STRSZ => Some((&mut tags.strsz, "DT_STRSZ")),
            DT_SYMENT => Some((&mut tags.syment, "DT_SYMENT")),
            _ => None,
        };
        if let Some((slot, name)) = slot {
            if slot.replace(value).is_some() {
                return Err(format!("duplicate {name}"));
            }
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC is missing DT_NULL".to_owned());
    }

    let required = |value: Option<u64>, name: &str| {
        value.ok_or_else(|| format!("PT_DYNAMIC is missing required {name}"))
    };
    let hash = required(tags.hash, "DT_HASH")?;
    let symtab = required(tags.symtab, "DT_SYMTAB")?;
    let strtab = required(tags.strtab, "DT_STRTAB")?;
    let strsz = required(tags.strsz, "DT_STRSZ")?;
    let syment = required(tags.syment, "DT_SYMENT")?;
    if syment != SYMENT as u64 {
        return Err(format!("unsupported DT_SYMENT {syment}"));
    }

    let strings = map_file(file, &ph, strtab, strsz, "DT_STRTAB table")?;
    let hash_header = map_file(file, &ph, hash, 8, "DT_HASH header")?;
    let bucket_count = u32at(hash_header, 0);
    let chain_count = u32at(hash_header, 4);
    if bucket_count == 0 {
        return Err("DT_HASH bucket count must be non-zero".to_owned());
    }
    if chain_count == 0 {
        return Err("DT_HASH chain count must be non-zero".to_owned());
    }

    let bucket_bytes = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_HASH bucket byte size overflows u64".to_owned())?;
    let chain_bytes = u64::from(chain_count)
        .checked_mul(4)
        .ok_or_else(|| "DT_HASH chain byte size overflows u64".to_owned())?;
    let table_size = 8u64
        .checked_add(bucket_bytes)
        .and_then(|value| value.checked_add(chain_bytes))
        .ok_or_else(|| "DT_HASH table byte size overflows u64".to_owned())?;
    let table = map_file(file, &ph, hash, table_size, "DT_HASH table")?;
    let bucket_start = 8usize;
    let chain_start = usize::try_from(8u64 + bucket_bytes)
        .map_err(|_| "DT_HASH chain offset does not fit usize".to_owned())?;

    for index in 0..bucket_count {
        let offset = bucket_start
            .checked_add(
                usize::try_from(u64::from(index) * 4)
                    .map_err(|_| "DT_HASH bucket offset does not fit usize".to_owned())?,
            )
            .ok_or_else(|| "DT_HASH bucket offset overflows usize".to_owned())?;
        let symbol_index = u32at(table, offset);
        if symbol_index >= chain_count && symbol_index != 0 {
            return Err(format!(
                "DT_HASH bucket {index} references symbol {symbol_index} outside chain count {chain_count}"
            ));
        }
    }
    for index in 0..chain_count {
        let offset = chain_start
            .checked_add(
                usize::try_from(u64::from(index) * 4)
                    .map_err(|_| "DT_HASH chain offset does not fit usize".to_owned())?,
            )
            .ok_or_else(|| "DT_HASH chain offset overflows usize".to_owned())?;
        let next = u32at(table, offset);
        if next >= chain_count && next != 0 {
            return Err(format!(
                "DT_HASH chain {index} references symbol {next} outside chain count {chain_count}"
            ));
        }
    }

    let target_hash = sysv_hash(symbol.as_bytes());
    let bucket_index = target_hash % bucket_count;
    let bucket_offset = bucket_start
        .checked_add(
            usize::try_from(u64::from(bucket_index) * 4)
                .map_err(|_| "DT_HASH bucket offset does not fit usize".to_owned())?,
        )
        .ok_or_else(|| "DT_HASH bucket offset overflows usize".to_owned())?;
    let mut symbol_index = u32at(table, bucket_offset);
    let mut steps = 0u32;

    while symbol_index != 0 {
        if symbol_index >= chain_count {
            return Err(format!(
                "DT_HASH lookup reached symbol {symbol_index} outside chain count {chain_count}"
            ));
        }
        if steps >= chain_count {
            return Err("DT_HASH lookup chain contains a cycle".to_owned());
        }
        steps = steps
            .checked_add(1)
            .ok_or_else(|| "DT_HASH traversal count overflows u32".to_owned())?;

        let symbol_address = symtab
            .checked_add(
                u64::from(symbol_index)
                    .checked_mul(SYMENT as u64)
                    .ok_or_else(|| "dynamic symbol offset overflows u64".to_owned())?,
            )
            .ok_or_else(|| "dynamic symbol address overflows u64".to_owned())?;
        let entry = map_file(
            file,
            &ph,
            symbol_address,
            SYMENT as u64,
            &format!("dynamic symbol {symbol_index}"),
        )?;
        let name_offset = u32at(entry, 0);
        let candidate = dynstr(strings, name_offset, symbol_index)?;
        if candidate == symbol {
            let info = entry[4];
            let other = entry[5];
            let shndx = u16at(entry, 6);
            let value = u64at(entry, 8);
            let size = u64at(entry, 16);
            return Ok(format!(
                "SysV hash lookup: symbol={symbol} index={symbol_index} value={value:#018x} size={size} bind={} type={} visibility={} shndx={shndx:#06x}\n",
                info >> 4,
                info & 0x0f,
                other & 0x03
            ));
        }

        let chain_offset = chain_start
            .checked_add(
                usize::try_from(u64::from(symbol_index) * 4)
                    .map_err(|_| "DT_HASH chain offset does not fit usize".to_owned())?,
            )
            .ok_or_else(|| "DT_HASH chain offset overflows usize".to_owned())?;
        symbol_index = u32at(table, chain_offset);
    }

    Ok(format!("SysV hash lookup: symbol={symbol} not-found\n"))
}

fn sysv_hash(bytes: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in bytes {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

fn dynstr(table: &[u8], offset: u32, symbol_index: u32) -> Result<String, String> {
    let start =
        usize::try_from(offset).map_err(|_| "string offset does not fit usize".to_owned())?;
    if start >= table.len() {
        return Err(format!(
            "dynamic symbol {symbol_index} name offset is outside DT_STRTAB"
        ));
    }
    let tail = &table[start..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("dynamic symbol {symbol_index} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {symbol_index} name is not UTF-8"))
}

fn program_headers(file: &[u8]) -> Result<Vec<Ph>, String> {
    let offset = usize::try_from(u64at(file, 32))
        .map_err(|_| "program-header offset does not fit usize".to_owned())?;
    let entry_size = usize::from(u16at(file, 54));
    let count = usize::from(u16at(file, 56));
    if entry_size != PHENT {
        return Err("unsupported program-header size".to_owned());
    }
    let end = offset
        .checked_add(
            entry_size
                .checked_mul(count)
                .ok_or_else(|| "program-header table size overflow".to_owned())?,
        )
        .ok_or_else(|| "program-header table overflow".to_owned())?;
    if end > file.len() {
        return Err("program-header table exceeds input".to_owned());
    }

    let mut headers = Vec::new();
    for index in 0..count {
        let cursor = offset + index * entry_size;
        let header = Ph {
            kind: u32at(file, cursor),
            off: u64at(file, cursor + 8),
            va: u64at(file, cursor + 16),
            filesz: u64at(file, cursor + 32),
            memsz: u64at(file, cursor + 40),
        };
        if header.filesz > header.memsz
            || header
                .off
                .checked_add(header.filesz)
                .ok_or_else(|| "program file range overflow".to_owned())?
                > file.len() as u64
            || header.va.checked_add(header.memsz).is_none()
        {
            return Err("invalid program header range".to_owned());
        }
        headers.push(header);
    }
    Ok(headers)
}

fn program_bytes(file: &[u8], header: Ph) -> Result<&[u8], String> {
    let start = usize::try_from(header.off)
        .map_err(|_| "PT_DYNAMIC offset does not fit usize".to_owned())?;
    let size = usize::try_from(header.filesz)
        .map_err(|_| "PT_DYNAMIC size does not fit usize".to_owned())?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| "PT_DYNAMIC range overflow".to_owned())?;
    file.get(start..end)
        .ok_or_else(|| "PT_DYNAMIC exceeds input".to_owned())
}

fn map_file<'a>(
    file: &'a [u8],
    ph: &[Ph],
    address: u64,
    size: u64,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in ph.iter().copied().filter(|header| header.kind == PT_LOAD) {
        let segment_end = header
            .va
            .checked_add(header.filesz)
            .ok_or_else(|| "PT_LOAD file-backed virtual range overflows u64".to_owned())?;
        if address >= header.va && end <= segment_end {
            let delta = address - header.va;
            let file_offset = header
                .off
                .checked_add(delta)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            let file_end = file_offset
                .checked_add(size)
                .ok_or_else(|| format!("{label} file range overflows u64"))?;
            let start = usize::try_from(file_offset)
                .map_err(|_| format!("{label} file offset does not fit usize"))?;
            let finish = usize::try_from(file_end)
                .map_err(|_| format!("{label} file end does not fit usize"))?;
            return file
                .get(start..finish)
                .ok_or_else(|| format!("{label} exceeds input"));
        }
    }
    Err(format!("{label} is not wholly file-backed by PT_LOAD"))
}

fn u16at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn i64at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
