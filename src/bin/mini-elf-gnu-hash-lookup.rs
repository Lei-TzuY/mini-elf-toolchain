use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
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
    gnu_hash: Option<u64>,
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
    "usage: mini-elf-gnu-hash-lookup <symbol> <input>...".to_owned()
}

fn inspect(file: &[u8], symbol: &str) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|error| error.to_string())?;
    if file.len() < 64 || u16at(file, 16) != ET_DYN {
        return Err("mini-elf-gnu-hash-lookup requires an ET_DYN image".to_owned());
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
            DT_GNU_HASH => Some((&mut tags.gnu_hash, "DT_GNU_HASH")),
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
    let hash = required(tags.gnu_hash, "DT_GNU_HASH")?;
    let symtab = required(tags.symtab, "DT_SYMTAB")?;
    let strtab = required(tags.strtab, "DT_STRTAB")?;
    let strsz = required(tags.strsz, "DT_STRSZ")?;
    let syment = required(tags.syment, "DT_SYMENT")?;
    if syment != SYMENT as u64 {
        return Err(format!("unsupported DT_SYMENT {syment}"));
    }

    let strings = map_file(file, &ph, strtab, strsz, "DT_STRTAB table")?;
    let header = map_file(file, &ph, hash, 16, "DT_GNU_HASH header")?;
    let bucket_count = u32at(header, 0);
    let symbol_offset = u32at(header, 4);
    let bloom_count = u32at(header, 8);
    let bloom_shift = u32at(header, 12);
    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".to_owned());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }
    if bloom_shift >= 64 {
        return Err(format!(
            "DT_GNU_HASH bloom shift {bloom_shift} must be less than 64"
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
    let prefix = map_file(file, &ph, hash, prefix_size, "DT_GNU_HASH prefix")?;
    let bloom_start = 16usize;
    let bucket_start = usize::try_from(16u64 + bloom_bytes)
        .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?;
    let chain_address = hash
        .checked_add(prefix_size)
        .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;

    let target_hash = gnu_hash(symbol.as_bytes());
    let bloom_index = (target_hash / 64) & (bloom_count - 1);
    let bloom_offset = bloom_start
        .checked_add(
            usize::try_from(u64::from(bloom_index) * 8)
                .map_err(|_| "DT_GNU_HASH bloom offset does not fit usize".to_owned())?,
        )
        .ok_or_else(|| "DT_GNU_HASH bloom offset overflows usize".to_owned())?;
    let bloom_word = u64at(prefix, bloom_offset);
    let first_bit = 1u64 << (target_hash % 64);
    let second_bit = 1u64 << ((target_hash >> bloom_shift) % 64);
    if bloom_word & first_bit == 0 || bloom_word & second_bit == 0 {
        return Ok(format!("GNU hash lookup: symbol={symbol} not-found\n"));
    }

    let bucket_index = target_hash % bucket_count;
    let bucket_offset = bucket_start
        .checked_add(
            usize::try_from(u64::from(bucket_index) * 4)
                .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize".to_owned())?,
        )
        .ok_or_else(|| "DT_GNU_HASH bucket offset overflows usize".to_owned())?;
    let mut symbol_index = u32at(prefix, bucket_offset);
    if symbol_index == 0 {
        return Ok(format!("GNU hash lookup: symbol={symbol} not-found\n"));
    }
    if symbol_index < symbol_offset {
        return Err(format!(
            "DT_GNU_HASH bucket {bucket_index} starts at symbol {symbol_index}, below symbol offset {symbol_offset}"
        ));
    }

    loop {
        let chain_index = symbol_index
            .checked_sub(symbol_offset)
            .ok_or_else(|| "DT_GNU_HASH chain index underflows".to_owned())?;
        let chain_offset = u64::from(chain_index)
            .checked_mul(4)
            .ok_or_else(|| "DT_GNU_HASH chain offset overflows u64".to_owned())?;
        let chain_entry_address = chain_address
            .checked_add(chain_offset)
            .ok_or_else(|| "DT_GNU_HASH chain address overflows u64".to_owned())?;
        let chain_entry = map_file(
            file,
            &ph,
            chain_entry_address,
            4,
            &format!("DT_GNU_HASH chain entry for symbol {symbol_index}"),
        )?;
        let chain_hash = u32at(chain_entry, 0);

        if (chain_hash | 1) == (target_hash | 1) {
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
                let shndx = u16at(entry, 6);
                let value = u64at(entry, 8);
                let size = u64at(entry, 16);
                return Ok(format!(
                    "GNU hash lookup: symbol={symbol} index={symbol_index} value={value:#018x} size={size} bind={} type={} shndx={shndx:#06x}\n",
                    info >> 4,
                    info & 0x0f
                ));
            }
        }

        if chain_hash & 1 != 0 {
            break;
        }
        symbol_index = symbol_index
            .checked_add(1)
            .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
    }

    Ok(format!("GNU hash lookup: symbol={symbol} not-found\n"))
}

fn gnu_hash(bytes: &[u8]) -> u32 {
    let mut hash = 5381u32;
    for byte in bytes {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
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
    for header in ph.iter().filter(|header| header.kind == PT_LOAD) {
        let file_end = header
            .va
            .checked_add(header.filesz)
            .ok_or_else(|| format!("{label} PT_LOAD file range overflows u64"))?;
        if address >= header.va && end <= file_end {
            let start = header
                .off
                .checked_add(address - header.va)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            let finish = start
                .checked_add(size)
                .ok_or_else(|| format!("{label} file range overflows u64"))?;
            let start =
                usize::try_from(start).map_err(|_| format!("{label} offset does not fit usize"))?;
            let finish =
                usize::try_from(finish).map_err(|_| format!("{label} end does not fit usize"))?;
            return file
                .get(start..finish)
                .ok_or_else(|| format!("{label} exceeds input"));
        }
    }
    Err(format!("{label} is not file-backed by PT_LOAD"))
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
