use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const R_X86_64_JUMP_SLOT: u32 = 7;
const STT_TLS: u8 = 6;
const SHN_ABS: u16 = 0xfff1;
const PHENT: usize = 56;
const DYNENT: usize = 16;
const RELAENT: usize = 24;
const SYMENT: usize = 24;

#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    filesz: u64,
    memsz: u64,
}

#[derive(Default)]
struct Dyn {
    pltrelsz: Option<u64>,
    hash: Option<u64>,
    gnu_hash: Option<u64>,
    strtab: Option<u64>,
    symtab: Option<u64>,
    strsz: Option<u64>,
    syment: Option<u64>,
    pltrel: Option<u64>,
    jmprel: Option<u64>,
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
    let mut bias = None;
    let mut inputs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let text = args[i].to_string_lossy();
        if text == "--load-bias" {
            i += 1;
            if i >= args.len() {
                return Err(usage());
            }
            if bias
                .replace(parse_u64(&args[i].to_string_lossy(), "load bias")?)
                .is_some()
            {
                return Err("duplicate --load-bias option".into());
            }
        } else if let Some(value) = text.strip_prefix("--load-bias=") {
            if bias.replace(parse_u64(value, "load bias")?).is_some() {
                return Err("duplicate --load-bias option".into());
            }
        } else if text.starts_with('-') {
            return Err(usage());
        } else {
            inputs.push(&args[i]);
        }
        i += 1;
    }
    if inputs.is_empty() {
        return Err(usage());
    }
    let bias = bias.ok_or_else(usage)?;
    let multiple = inputs.len() > 1;
    let mut rendered = Vec::with_capacity(inputs.len());
    for input in inputs {
        let name = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|e| format!("cannot read '{name}': {e}"))?;
        rendered.push((name, inspect(&file, bias)?));
    }
    let mut output = String::new();
    for (index, (name, text)) in rendered.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {name}\n"));
        }
        output.push_str(&text);
    }
    Ok(output)
}

fn usage() -> String {
    "usage: mini-elf-dynrela-jump-slot --load-bias <address> <input>...".into()
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
        text.parse()
            .map_err(|_| format!("invalid {label} '{text}'"))
    }
}

fn inspect(file: &[u8], bias: u64) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|e| e.to_string())?;
    if file.len() < 64 || u16at(file, 16) != ET_DYN {
        return Err("mini-elf-dynrela-jump-slot requires an ET_DYN image".into());
    }

    let ph = program_headers(file)?;
    let dynamic = ph
        .iter()
        .copied()
        .filter(|p| p.kind == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if dynamic.len() != 1 {
        return Err("expected exactly one PT_DYNAMIC program header".into());
    }
    let bytes = program_bytes(file, dynamic[0])?;
    if bytes.len() % DYNENT != 0 {
        return Err("PT_DYNAMIC size is not a whole number of entries".into());
    }

    let mut d = Dyn::default();
    let mut terminated = false;
    for (index, entry) in bytes.chunks_exact(DYNENT).enumerate() {
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
            DT_PLTRELSZ => Some((&mut d.pltrelsz, "DT_PLTRELSZ")),
            DT_HASH => Some((&mut d.hash, "DT_HASH")),
            DT_GNU_HASH => Some((&mut d.gnu_hash, "DT_GNU_HASH")),
            DT_STRTAB => Some((&mut d.strtab, "DT_STRTAB")),
            DT_SYMTAB => Some((&mut d.symtab, "DT_SYMTAB")),
            DT_STRSZ => Some((&mut d.strsz, "DT_STRSZ")),
            DT_SYMENT => Some((&mut d.syment, "DT_SYMENT")),
            DT_PLTREL => Some((&mut d.pltrel, "DT_PLTREL")),
            DT_JMPREL => Some((&mut d.jmprel, "DT_JMPREL")),
            _ => None,
        };
        if let Some((slot, name)) = slot {
            if slot.replace(value).is_some() {
                return Err(format!("duplicate {name}"));
            }
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC is missing DT_NULL".into());
    }
    let req = |v: Option<u64>, name: &str| {
        v.ok_or_else(|| format!("PT_DYNAMIC is missing required {name}"))
    };
    let jmprel = req(d.jmprel, "DT_JMPREL")?;
    let pltrelsz = req(d.pltrelsz, "DT_PLTRELSZ")?;
    let pltrel = req(d.pltrel, "DT_PLTREL")?;
    if pltrel != DT_RELA as u64 {
        return Err("R_X86_64_JUMP_SLOT requires a RELA-form DT_JMPREL table".into());
    }
    if pltrelsz % RELAENT as u64 != 0 {
        return Err("DT_PLTRELSZ is not a whole number of ELF64 RELA entries".into());
    }
    let symtab = req(d.symtab, "DT_SYMTAB")?;
    let syment = req(d.syment, "DT_SYMENT")?;
    let strtab = req(d.strtab, "DT_STRTAB")?;
    let strsz = req(d.strsz, "DT_STRSZ")?;
    if syment != SYMENT as u64 {
        return Err("unsupported DT_SYMENT".into());
    }

    let symbol_count = dynamic_symbol_count(file, &ph, d.hash, d.gnu_hash)?;
    if symbol_count == 0 {
        return Err("dynamic hash metadata reports zero dynamic symbols".into());
    }
    let symtab_bytes = map_file(
        file,
        &ph,
        symtab,
        symbol_count
            .checked_mul(SYMENT as u64)
            .ok_or("dynamic symbol table size overflows u64")?,
        "DT_SYMTAB table",
    )?;
    let strtab_bytes = map_file(file, &ph, strtab, strsz, "DT_STRTAB table")?;
    let relas = map_file(file, &ph, jmprel, pltrelsz, "DT_JMPREL table")?;

    let mut output = format!(
        "Validated R_X86_64_JUMP_SLOT relocations: load-bias={bias:#018x} jmprel={jmprel:#018x} entries={} symbols={symbol_count}\n",
        pltrelsz / RELAENT as u64
    );
    let mut found = 0usize;
    for (index, entry) in relas.chunks_exact(RELAENT).enumerate() {
        let offset = u64at(entry, 0);
        let info = u64at(entry, 8);
        if info as u32 != R_X86_64_JUMP_SLOT {
            continue;
        }
        let symbol_index = info >> 32;
        if symbol_index == 0 || symbol_index >= symbol_count {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references invalid dynamic symbol index {symbol_index} (count {symbol_count})"
            ));
        }
        let addend = i64at(entry, 16);
        if addend != 0 {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} has nonzero RELA addend {addend}; this bounded slice accepts canonical S semantics only"
            ));
        }
        memory_range(
            &ph,
            offset,
            8,
            PF_W,
            &format!("R_X86_64_JUMP_SLOT relocation {index} target"),
        )?;

        let symbol_offset = usize::try_from(symbol_index)
            .ok()
            .and_then(|value| value.checked_mul(SYMENT))
            .ok_or("dynamic symbol offset overflows usize")?;
        let symbol = &symtab_bytes[symbol_offset..symbol_offset + SYMENT];
        let name_offset = u32at(symbol, 0);
        let typ = symbol[4] & 0x0f;
        let section_index = u16at(symbol, 6);
        if typ == STT_TLS {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references TLS dynamic symbol index {symbol_index}"
            ));
        }
        if section_index == SHN_ABS {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references absolute dynamic symbol index {symbol_index}; absolute-symbol semantics are outside this bounded slice"
            ));
        }
        let name = dynstr(strtab_bytes, name_offset, symbol_index)?;
        if name.is_empty() {
            return Err(format!(
                "R_X86_64_JUMP_SLOT relocation {index} references an unnamed dynamic symbol"
            ));
        }
        let runtime_target = bias.checked_add(offset).ok_or_else(|| {
            format!("R_X86_64_JUMP_SLOT relocation {index} runtime target overflows u64")
        })?;
        runtime_target.checked_add(7).ok_or_else(|| {
            format!("R_X86_64_JUMP_SLOT relocation {index} runtime target range overflows u64")
        })?;
        output.push_str(&format!(
            "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_target:#018x} resolution=external-or-image\n"
        ));
        found += 1;
    }
    if found == 0 {
        return Err("DT_JMPREL contains no R_X86_64_JUMP_SLOT relocations".into());
    }
    Ok(output)
}

fn dynamic_symbol_count(
    file: &[u8],
    ph: &[Ph],
    hash: Option<u64>,
    gnu_hash: Option<u64>,
) -> Result<u64, String> {
    if let Some(address) = hash {
        let header = map_file(file, ph, address, 8, "DT_HASH header")?;
        return Ok(u32at(header, 4) as u64);
    }
    let address = gnu_hash.ok_or(
        "R_X86_64_JUMP_SLOT validation requires DT_HASH or DT_GNU_HASH to bound DT_SYMTAB",
    )?;
    gnu_hash_symbol_count(file, ph, address)
}

fn gnu_hash_symbol_count(file: &[u8], ph: &[Ph], address: u64) -> Result<u64, String> {
    let header = map_file(file, ph, address, 16, "DT_GNU_HASH header")?;
    let bucket_count = u32at(header, 0);
    let symbol_offset = u32at(header, 4);
    let bloom_count = u32at(header, 8);
    if bucket_count == 0 {
        return Err("DT_GNU_HASH bucket count must be non-zero".into());
    }
    if bloom_count == 0 || !bloom_count.is_power_of_two() {
        return Err(format!(
            "DT_GNU_HASH bloom count {bloom_count} must be a non-zero power of two"
        ));
    }
    let bloom_bytes = u64::from(bloom_count)
        .checked_mul(8)
        .ok_or("DT_GNU_HASH bloom byte size overflows u64")?;
    let bucket_bytes = u64::from(bucket_count)
        .checked_mul(4)
        .ok_or("DT_GNU_HASH bucket byte size overflows u64")?;
    let prefix_size = 16u64
        .checked_add(bloom_bytes)
        .and_then(|value| value.checked_add(bucket_bytes))
        .ok_or("DT_GNU_HASH prefix byte size overflows u64")?;
    let prefix = map_file(file, ph, address, prefix_size, "DT_GNU_HASH prefix")?;
    let bucket_start = usize::try_from(
        16u64
            .checked_add(bloom_bytes)
            .ok_or("DT_GNU_HASH bucket offset overflows u64")?,
    )
    .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize")?;
    let chain_address = address
        .checked_add(prefix_size)
        .ok_or("DT_GNU_HASH chain address overflows u64")?;
    let mut count = symbol_offset;
    for bucket_index in 0..bucket_count {
        let off = bucket_start
            .checked_add(
                usize::try_from(u64::from(bucket_index) * 4)
                    .map_err(|_| "DT_GNU_HASH bucket offset does not fit usize")?,
            )
            .ok_or("DT_GNU_HASH bucket offset overflows usize")?;
        let start_symbol = u32at(prefix, off);
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
                .ok_or("DT_GNU_HASH chain index underflows")?;
            let chain_off = u64::from(chain_index)
                .checked_mul(4)
                .ok_or("DT_GNU_HASH chain offset overflows u64")?;
            let entry_address = chain_address
                .checked_add(chain_off)
                .ok_or("DT_GNU_HASH chain address overflows u64")?;
            let entry = map_file(
                file,
                ph,
                entry_address,
                4,
                &format!("DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"),
            )?;
            let next = symbol
                .checked_add(1)
                .ok_or("DT_GNU_HASH symbol index overflows u32")?;
            if u32at(entry, 0) & 1 != 0 {
                count = count.max(next);
                break;
            }
            symbol = next;
        }
    }
    Ok(u64::from(count))
}

fn dynstr(tab: &[u8], off: u32, symbol_index: u64) -> Result<String, String> {
    let start = usize::try_from(off)
        .map_err(|_| format!("dynamic symbol {symbol_index} name offset does not fit usize"))?;
    if start >= tab.len() {
        return Err(format!(
            "dynamic symbol {symbol_index} name offset is outside DT_STRTAB"
        ));
    }
    let tail = &tab[start..];
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| format!("dynamic symbol {symbol_index} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {symbol_index} name is not UTF-8"))
}

fn program_headers(file: &[u8]) -> Result<Vec<Ph>, String> {
    let off = u64at(file, 32) as usize;
    let ent = u16at(file, 54) as usize;
    let num = u16at(file, 56) as usize;
    if ent != PHENT {
        return Err("unsupported program-header size".into());
    }
    let end = off
        .checked_add(
            ent.checked_mul(num)
                .ok_or("program-header table size overflow")?,
        )
        .ok_or("program-header table overflow")?;
    if end > file.len() {
        return Err("program-header table exceeds input".into());
    }
    let mut result = Vec::with_capacity(num);
    for i in 0..num {
        let p = off + i * ent;
        let ph = Ph {
            kind: u32at(file, p),
            flags: u32at(file, p + 4),
            off: u64at(file, p + 8),
            va: u64at(file, p + 16),
            filesz: u64at(file, p + 32),
            memsz: u64at(file, p + 40),
        };
        if ph.filesz > ph.memsz
            || ph
                .off
                .checked_add(ph.filesz)
                .ok_or("program file range overflow")?
                > file.len() as u64
            || ph.va.checked_add(ph.memsz).is_none()
        {
            return Err("invalid program header range".into());
        }
        result.push(ph);
    }
    Ok(result)
}

fn program_bytes(file: &[u8], ph: Ph) -> Result<&[u8], String> {
    let start = usize::try_from(ph.off).map_err(|_| "PT_DYNAMIC offset does not fit usize")?;
    let size = usize::try_from(ph.filesz).map_err(|_| "PT_DYNAMIC size does not fit usize")?;
    let end = start.checked_add(size).ok_or("PT_DYNAMIC range overflow")?;
    file.get(start..end)
        .ok_or_else(|| "PT_DYNAMIC exceeds input".into())
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
    for p in ph.iter().filter(|p| p.kind == PT_LOAD) {
        let file_end =
            p.va.checked_add(p.filesz)
                .ok_or_else(|| format!("{label} backing range overflows u64"))?;
        if address >= p.va && end <= file_end {
            let start = p
                .off
                .checked_add(address - p.va)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            let finish = start
                .checked_add(size)
                .ok_or_else(|| format!("{label} file range overflows u64"))?;
            let start = usize::try_from(start)
                .map_err(|_| format!("{label} file offset does not fit usize"))?;
            let finish = usize::try_from(finish)
                .map_err(|_| format!("{label} file end does not fit usize"))?;
            return file
                .get(start..finish)
                .ok_or_else(|| format!("{label} exceeds input"));
        }
    }
    Err(format!("{label} is not file-backed by PT_LOAD"))
}

fn memory_range(ph: &[Ph], address: u64, size: u64, flags: u32, label: &str) -> Result<(), String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for p in ph
        .iter()
        .filter(|p| p.kind == PT_LOAD && p.flags & flags == flags)
    {
        let segment_end =
            p.va.checked_add(p.memsz)
                .ok_or_else(|| format!("{label} segment range overflows u64"))?;
        if address >= p.va && end <= segment_end {
            return Ok(());
        }
    }
    Err(format!(
        "{label} is not contained in a matching PT_LOAD memory range"
    ))
}

fn u16at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}
fn u32at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}
fn u64at(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
fn i64at(bytes: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
