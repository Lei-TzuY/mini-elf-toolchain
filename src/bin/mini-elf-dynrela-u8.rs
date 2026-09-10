use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const PHDR_SIZE: usize = 56;
const DYN_SIZE: usize = 16;
const RELA_SIZE: usize = 24;
const SYM_SIZE: usize = 24;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_8: u32 = 14;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_TLS: u8 = 6;

#[derive(Clone, Copy)]
struct Phdr {
    kind: u32,
    flags: u32,
    off: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

#[derive(Default)]
struct Dynamic {
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    hash: Option<u64>,
    symtab: Option<u64>,
    syment: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1).collect()) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<OsString>) -> Result<String, String> {
    let (bias, inputs) = parse_args(&args)?;
    let multiple = inputs.len() > 1;
    let mut rendered = Vec::with_capacity(inputs.len());
    for input in inputs {
        let name = input.to_string_lossy().into_owned();
        let bytes = fs::read(input).map_err(|e| format!("cannot read '{name}': {e}"))?;
        let body = inspect(&bytes, bias).map_err(|e| format!("{name}: {e}"))?;
        rendered.push((name, body));
    }
    let mut out = String::new();
    for (i, (name, body)) in rendered.into_iter().enumerate() {
        if i != 0 {
            out.push('\n');
        }
        if multiple {
            out.push_str(&format!("File: {name}\n"));
        }
        out.push_str(&body);
    }
    Ok(out)
}

fn parse_args(args: &[OsString]) -> Result<(u64, Vec<&OsString>), String> {
    let mut bias = None;
    let mut inputs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let text = args[i].to_string_lossy();
        if text == "--load-bias" {
            i += 1;
            if i >= args.len() || bias.is_some() {
                return Err(usage());
            }
            bias = Some(parse_u64(&args[i].to_string_lossy())?);
        } else if let Some(value) = text.strip_prefix("--load-bias=") {
            if bias.is_some() {
                return Err("duplicate --load-bias option".into());
            }
            bias = Some(parse_u64(value)?);
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
    Ok((bias.ok_or_else(usage)?, inputs))
}

fn usage() -> String {
    "usage: mini-elf-dynrela-u8 --load-bias <address> <input>...".into()
}

fn parse_u64(text: &str) -> Result<u64, String> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid load bias '{text}'"))
    } else {
        text.parse()
            .map_err(|_| format!("invalid load bias '{text}'"))
    }
}

fn inspect(file: &[u8], bias: u64) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|e| e.to_string())?;
    if file.len() < 64 || read_u16(file, 16) != ET_DYN {
        return Err("mini-elf-dynrela-u8 requires an ELF64 ET_DYN image".into());
    }
    let phdrs = phdrs(file)?;
    let dynamic = phdrs
        .iter()
        .copied()
        .filter(|p| p.kind == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if dynamic.len() != 1 {
        return Err("expected exactly one PT_DYNAMIC program header".into());
    }
    let dyn_bytes = file_range(file, dynamic[0].off, dynamic[0].filesz, "PT_DYNAMIC")?;
    let meta = parse_dynamic(dyn_bytes)?;
    let rela = required(meta.rela, "DT_RELA")?;
    let relasz = required(meta.relasz, "DT_RELASZ")?;
    let relaent = required(meta.relaent, "DT_RELAENT")?;
    let hash = required(meta.hash, "DT_HASH")?;
    let symtab = required(meta.symtab, "DT_SYMTAB")?;
    let syment = required(meta.syment, "DT_SYMENT")?;
    let strtab = required(meta.strtab, "DT_STRTAB")?;
    let strsz = required(meta.strsz, "DT_STRSZ")?;
    if relaent != RELA_SIZE as u64 || syment != SYM_SIZE as u64 || relasz % relaent != 0 {
        return Err("unsupported dynamic RELA or symbol entry size".into());
    }

    let hash_bytes = map_file(file, &phdrs, hash, 8, "DT_HASH header")?;
    let symbol_count = u64::from(read_u32(hash_bytes, 4));
    if symbol_count == 0 {
        return Err("DT_HASH reports zero dynamic symbols".into());
    }
    let symtab_size = symbol_count
        .checked_mul(syment)
        .ok_or("dynamic symbol table size overflows u64")?;
    let symtab_bytes = map_file(file, &phdrs, symtab, symtab_size, "DT_SYMTAB table")?;
    let strtab_bytes = map_file(file, &phdrs, strtab, strsz, "DT_STRTAB table")?;
    let rela_bytes = map_file(file, &phdrs, rela, relasz, "DT_RELA table")?;

    let mut out = format!(
        "Validated R_X86_64_8 relocations: load-bias={bias:#018x} rela={rela:#018x} entries={} symbols={symbol_count}\n",
        relasz / relaent
    );
    let mut found = 0usize;
    for (index, entry) in rela_bytes.chunks_exact(RELA_SIZE).enumerate() {
        let offset = read_u64(entry, 0);
        let info = read_u64(entry, 8);
        let sym_index = info >> 32;
        if info as u32 != R_X86_64_8 {
            continue;
        }
        if sym_index == 0 || sym_index >= symbol_count {
            return Err(format!("R_X86_64_8 relocation {index} references invalid dynamic symbol index {sym_index} (count {symbol_count})"));
        }
        map_memory(
            &phdrs,
            offset,
            1,
            PF_W,
            &format!("R_X86_64_8 relocation {index} target"),
        )?;
        let sym_off = usize::try_from(sym_index)
            .ok()
            .and_then(|v| v.checked_mul(SYM_SIZE))
            .ok_or_else(|| format!("dynamic symbol index {sym_index} offset overflows usize"))?;
        let sym = symtab_bytes
            .get(sym_off..sym_off + SYM_SIZE)
            .ok_or_else(|| format!("dynamic symbol {sym_index} exceeds DT_SYMTAB"))?;
        let name_off = read_u32(sym, 0);
        let info_byte = sym[4];
        let shndx = read_u16(sym, 6);
        let value = read_u64(sym, 8);
        if shndx == SHN_UNDEF {
            return Err(format!("R_X86_64_8 relocation {index} references undefined dynamic symbol index {sym_index}; external lookup is outside this bounded slice"));
        }
        if shndx == SHN_ABS {
            return Err(format!("R_X86_64_8 relocation {index} references an absolute dynamic symbol; absolute-symbol semantics are outside this bounded slice"));
        }
        if info_byte & 0x0f == STT_TLS {
            return Err(format!("R_X86_64_8 relocation {index} references TLS; TLS semantics are outside this bounded slice"));
        }
        map_memory(
            &phdrs,
            value,
            1,
            0,
            &format!("R_X86_64_8 relocation {index} symbol value"),
        )?;
        let name = dyn_string(strtab_bytes, name_off, sym_index)?;
        let runtime_target = bias
            .checked_add(offset)
            .ok_or_else(|| format!("R_X86_64_8 relocation {index} runtime target overflows u64"))?;
        let runtime_symbol = bias
            .checked_add(value)
            .ok_or_else(|| format!("R_X86_64_8 relocation {index} runtime symbol overflows u64"))?;
        let addend = read_i64(entry, 16);
        let relocated = add_signed(runtime_symbol, addend)
            .ok_or_else(|| format!("R_X86_64_8 relocation {index} S + A overflows u64"))?;
        let value8 = u8::try_from(relocated).map_err(|_| {
            format!(
                "R_X86_64_8 relocation {index} result {relocated:#x} does not fit unsigned 8 bits"
            )
        })?;
        out.push_str(&format!("  index={index} symbol={sym_index}:{name} target=B+{offset:#018x}=>{runtime_target:#018x} symbol-value=B+{value:#018x}=>{runtime_symbol:#018x} addend={addend} result={value8}\n"));
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_8 relocations".into());
    }
    Ok(out)
}

fn parse_dynamic(bytes: &[u8]) -> Result<Dynamic, String> {
    if bytes.len() % DYN_SIZE != 0 {
        return Err("PT_DYNAMIC size is not a whole number of entries".into());
    }
    let mut d = Dynamic::default();
    let mut terminated = false;
    for (i, entry) in bytes.chunks_exact(DYN_SIZE).enumerate() {
        let tag = read_i64(entry, 0);
        let value = read_u64(entry, 8);
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(format!("PT_DYNAMIC entry {i} contains data after DT_NULL"));
            }
            continue;
        }
        if tag == DT_NULL {
            terminated = true;
            continue;
        }
        match tag {
            DT_RELA => set_once(&mut d.rela, value, "DT_RELA")?,
            DT_RELASZ => set_once(&mut d.relasz, value, "DT_RELASZ")?,
            DT_RELAENT => set_once(&mut d.relaent, value, "DT_RELAENT")?,
            DT_HASH => set_once(&mut d.hash, value, "DT_HASH")?,
            DT_SYMTAB => set_once(&mut d.symtab, value, "DT_SYMTAB")?,
            DT_SYMENT => set_once(&mut d.syment, value, "DT_SYMENT")?,
            DT_STRTAB => set_once(&mut d.strtab, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut d.strsz, value, "DT_STRSZ")?,
            _ => {}
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC is missing DT_NULL".into());
    }
    Ok(d)
}

fn required(value: Option<u64>, name: &str) -> Result<u64, String> {
    value.ok_or_else(|| format!("PT_DYNAMIC is missing required {name}"))
}

fn set_once(slot: &mut Option<u64>, value: u64, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("PT_DYNAMIC contains duplicate {name}"));
    }
    Ok(())
}

fn phdrs(file: &[u8]) -> Result<Vec<Phdr>, String> {
    let off = usize::try_from(read_u64(file, 32))
        .map_err(|_| "program-header offset does not fit usize")?;
    let entsize = usize::from(read_u16(file, 54));
    let count = usize::from(read_u16(file, 56));
    if entsize != PHDR_SIZE {
        return Err(format!("unsupported program-header size {entsize}"));
    }
    let size = count
        .checked_mul(entsize)
        .ok_or("program-header table size overflows usize")?;
    let end = off
        .checked_add(size)
        .ok_or("program-header table range overflows usize")?;
    if end > file.len() {
        return Err("program-header table exceeds input".into());
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let p = off + i * entsize;
        let h = Phdr {
            kind: read_u32(file, p),
            flags: read_u32(file, p + 4),
            off: read_u64(file, p + 8),
            vaddr: read_u64(file, p + 16),
            filesz: read_u64(file, p + 32),
            memsz: read_u64(file, p + 40),
        };
        if h.filesz > h.memsz
            || h.vaddr.checked_add(h.filesz).is_none()
            || h.vaddr.checked_add(h.memsz).is_none()
        {
            return Err(format!("program header {i} has invalid ranges"));
        }
        file_range(file, h.off, h.filesz, &format!("program header {i}"))?;
        out.push(h);
    }
    Ok(out)
}

fn file_range<'a>(file: &'a [u8], off: u64, size: u64, label: &str) -> Result<&'a [u8], String> {
    let start = usize::try_from(off).map_err(|_| format!("{label} offset does not fit usize"))?;
    let width = usize::try_from(size).map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(width)
        .ok_or_else(|| format!("{label} range overflows usize"))?;
    file.get(start..end)
        .ok_or_else(|| format!("{label} range exceeds input"))
}

fn map_file<'a>(
    file: &'a [u8],
    phdrs: &[Phdr],
    addr: u64,
    size: u64,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = addr
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for h in phdrs.iter().filter(|h| h.kind == PT_LOAD) {
        let load_end = h.vaddr + h.filesz;
        if addr >= h.vaddr && end <= load_end {
            let off = h
                .off
                .checked_add(addr - h.vaddr)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            return file_range(file, off, size, label);
        }
    }
    Err(format!(
        "{label} [{addr:#x},{end:#x}) is not contained in a file-backed PT_LOAD"
    ))
}

fn map_memory(phdrs: &[Phdr], addr: u64, size: u64, flags: u32, label: &str) -> Result<(), String> {
    let end = addr
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for h in phdrs
        .iter()
        .filter(|h| h.kind == PT_LOAD && h.flags & flags == flags)
    {
        if addr >= h.vaddr && end <= h.vaddr + h.memsz {
            return Ok(());
        }
    }
    Err(format!(
        "{label} [{addr:#x},{end:#x}) is not contained in a matching PT_LOAD memory range"
    ))
}

fn dyn_string(table: &[u8], offset: u32, index: u64) -> Result<String, String> {
    let start = usize::try_from(offset)
        .map_err(|_| format!("dynamic symbol {index} name offset does not fit usize"))?;
    let tail = table
        .get(start..)
        .ok_or_else(|| format!("dynamic symbol {index} name offset is outside DT_STRTAB"))?;
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| format!("dynamic symbol {index} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {index} name is not UTF-8"))
}

fn add_signed(base: u64, addend: i64) -> Option<u64> {
    if addend >= 0 {
        base.checked_add(addend as u64)
    } else {
        base.checked_sub(addend.unsigned_abs())
    }
}

fn read_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}
fn read_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}
fn read_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
fn read_i64(bytes: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}
