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
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_COPY: u32 = 5;
const STT_TLS: u8 = 6;
const SHN_UNDEF: u16 = 0;
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
    hash: Option<u64>,
    strtab: Option<u64>,
    symtab: Option<u64>,
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    strsz: Option<u64>,
    syment: Option<u64>,
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
    let args = args.collect::<Vec<_>>();
    let mut bias = None;
    let mut inputs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let s = args[i].to_string_lossy();
        if s == "--load-bias" {
            i += 1;
            if i >= args.len() {
                return Err(usage());
            }
            if bias.replace(parse_u64(&args[i].to_string_lossy())?).is_some() {
                return Err("duplicate --load-bias option".into());
            }
        } else if let Some(v) = s.strip_prefix("--load-bias=") {
            if bias.replace(parse_u64(v)?).is_some() {
                return Err("duplicate --load-bias option".into());
            }
        } else if s.starts_with('-') {
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
    let multi = inputs.len() > 1;
    let mut rendered = Vec::new();
    for p in inputs {
        let name = p.to_string_lossy().into_owned();
        let b = fs::read(p).map_err(|e| format!("cannot read '{name}': {e}"))?;
        rendered.push((name, inspect(&b, bias)?));
    }
    let mut out = String::new();
    for (n, (name, body)) in rendered.into_iter().enumerate() {
        if n > 0 {
            out.push('\n');
        }
        if multi {
            out.push_str(&format!("File: {name}\n"));
        }
        out.push_str(&body);
    }
    Ok(out)
}

fn usage() -> String {
    "usage: mini-elf-dynrela-copy --load-bias <address> <input>...".into()
}

fn parse_u64(s: &str) -> Result<u64, String> {
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).map_err(|_| format!("invalid load bias '{s}'"))
    } else {
        s.parse().map_err(|_| format!("invalid load bias '{s}'"))
    }
}

fn inspect(file: &[u8], bias: u64) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|e| e.to_string())?;
    if file.len() < 64 || u16at(file, 16) != ET_DYN {
        return Err("mini-elf-dynrela-copy requires an ET_DYN image".into());
    }
    let ph = program_headers(file)?;
    let dynamic = ph.iter().copied().filter(|p| p.kind == PT_DYNAMIC).collect::<Vec<_>>();
    if dynamic.len() != 1 {
        return Err("expected exactly one PT_DYNAMIC program header".into());
    }
    let dbytes = program_bytes(file, dynamic[0])?;
    if dbytes.len() % DYNENT != 0 {
        return Err("PT_DYNAMIC size is not a whole number of entries".into());
    }
    let mut d = Dyn::default();
    let mut term = false;
    for (idx, e) in dbytes.chunks_exact(DYNENT).enumerate() {
        let tag = i64at(e, 0);
        let val = u64at(e, 8);
        if term {
            if tag != DT_NULL || val != 0 {
                return Err(format!("PT_DYNAMIC entry {idx} contains data after DT_NULL"));
            }
            continue;
        }
        if tag == DT_NULL {
            term = true;
            continue;
        }
        let slot = match tag {
            DT_HASH => Some((&mut d.hash, "DT_HASH")),
            DT_STRTAB => Some((&mut d.strtab, "DT_STRTAB")),
            DT_SYMTAB => Some((&mut d.symtab, "DT_SYMTAB")),
            DT_RELA => Some((&mut d.rela, "DT_RELA")),
            DT_RELASZ => Some((&mut d.relasz, "DT_RELASZ")),
            DT_RELAENT => Some((&mut d.relaent, "DT_RELAENT")),
            DT_STRSZ => Some((&mut d.strsz, "DT_STRSZ")),
            DT_SYMENT => Some((&mut d.syment, "DT_SYMENT")),
            _ => None,
        };
        if let Some((s, name)) = slot {
            if s.replace(val).is_some() {
                return Err(format!("duplicate {name}"));
            }
        }
    }
    if !term {
        return Err("PT_DYNAMIC is missing DT_NULL".into());
    }
    let req = |v: Option<u64>, n: &str| v.ok_or_else(|| format!("PT_DYNAMIC is missing required {n}"));
    let rela = req(d.rela, "DT_RELA")?;
    let relasz = req(d.relasz, "DT_RELASZ")?;
    let relaent = req(d.relaent, "DT_RELAENT")?;
    let hash = req(d.hash, "DT_HASH")?;
    let symtab = req(d.symtab, "DT_SYMTAB")?;
    let syment = req(d.syment, "DT_SYMENT")?;
    let strtab = req(d.strtab, "DT_STRTAB")?;
    let strsz = req(d.strsz, "DT_STRSZ")?;
    if relaent != RELAENT as u64 || relasz % relaent != 0 {
        return Err("invalid DT_RELA entry sizing".into());
    }
    if syment != SYMENT as u64 {
        return Err("unsupported DT_SYMENT".into());
    }
    let hb = map_file(file, &ph, hash, 8, "DT_HASH header")?;
    let count = u32at(hb, 4) as u64;
    if count == 0 {
        return Err("DT_HASH reports zero dynamic symbols".into());
    }
    let syms = map_file(file, &ph, symtab, count.checked_mul(SYMENT as u64).ok_or("dynamic symbol table size overflows u64")?, "DT_SYMTAB table")?;
    let strs = map_file(file, &ph, strtab, strsz, "DT_STRTAB table")?;
    let relas = map_file(file, &ph, rela, relasz, "DT_RELA table")?;
    let mut out = format!("Validated R_X86_64_COPY relocations: load-bias={bias:#018x} entries={} symbols={count}\n", relasz / relaent);
    let mut found = 0;
    for (idx, e) in relas.chunks_exact(RELAENT).enumerate() {
        let off = u64at(e, 0);
        let info = u64at(e, 8);
        if info as u32 != R_X86_64_COPY {
            continue;
        }
        let si = info >> 32;
        if si == 0 || si >= count {
            return Err(format!("R_X86_64_COPY relocation {idx} references invalid dynamic symbol index {si} (count {count})"));
        }
        let add = i64at(e, 16);
        if add != 0 {
            return Err(format!("R_X86_64_COPY relocation {idx} has nonzero RELA addend {add}"));
        }
        let so = usize::try_from(si).ok().and_then(|x| x.checked_mul(SYMENT)).ok_or("dynamic symbol offset overflows usize")?;
        let s = &syms[so..so + SYMENT];
        let name_off = u32at(s, 0);
        let typ = s[4] & 0x0f;
        let sh = u16at(s, 6);
        let value = u64at(s, 8);
        let size = u64at(s, 16);
        if sh == SHN_UNDEF {
            return Err(format!("R_X86_64_COPY relocation {idx} requires a defined destination dynamic symbol"));
        }
        if typ == STT_TLS {
            return Err(format!("R_X86_64_COPY relocation {idx} cannot target an STT_TLS symbol"));
        }
        if size == 0 {
            return Err(format!("R_X86_64_COPY relocation {idx} destination symbol has zero size"));
        }
        if off != value {
            return Err(format!("R_X86_64_COPY relocation {idx} target does not match destination symbol value"));
        }
        memory_range(&ph, off, size, PF_W, &format!("R_X86_64_COPY relocation {idx} target"))?;
        let end = off.checked_add(size).ok_or_else(|| format!("R_X86_64_COPY relocation {idx} target range overflows u64"))?;
        let rt = bias.checked_add(off).ok_or_else(|| format!("R_X86_64_COPY relocation {idx} runtime target overflows u64"))?;
        let rt_end = bias.checked_add(end).ok_or_else(|| format!("R_X86_64_COPY relocation {idx} runtime target end overflows u64"))?;
        let name = dynstr(strs, name_off, si)?;
        out.push_str(&format!("  index={idx} symbol={si}:{name} target=B+{off:#018x}=>{rt:#018x} size={size} runtime-end={rt_end:#018x} source=external-definition-required\n"));
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_COPY relocations".into());
    }
    Ok(out)
}

fn dynstr(tab: &[u8], off: u32, si: u64) -> Result<String, String> {
    let start = off as usize;
    if start >= tab.len() {
        return Err(format!("dynamic symbol {si} name offset is outside DT_STRTAB"));
    }
    let tail = &tab[start..];
    let end = tail.iter().position(|b| *b == 0).ok_or_else(|| format!("dynamic symbol {si} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end]).map(str::to_owned).map_err(|_| format!("dynamic symbol {si} name is not UTF-8"))
}

fn program_headers(f: &[u8]) -> Result<Vec<Ph>, String> {
    let off = u64at(f, 32) as usize;
    let ent = u16at(f, 54) as usize;
    let num = u16at(f, 56) as usize;
    if ent != PHENT {
        return Err("unsupported program-header size".into());
    }
    let end = off.checked_add(ent.checked_mul(num).ok_or("program-header table size overflow")?).ok_or("program-header table overflow")?;
    if end > f.len() {
        return Err("program-header table exceeds input".into());
    }
    let mut v = Vec::new();
    for i in 0..num {
        let p = off + i * ent;
        let x = Ph { kind: u32at(f, p), flags: u32at(f, p + 4), off: u64at(f, p + 8), va: u64at(f, p + 16), filesz: u64at(f, p + 32), memsz: u64at(f, p + 40) };
        if x.filesz > x.memsz || x.off.checked_add(x.filesz).ok_or("program file range overflow")? > f.len() as u64 || x.va.checked_add(x.memsz).is_none() {
            return Err("invalid program header range".into());
        }
        v.push(x);
    }
    Ok(v)
}

fn program_bytes(f: &[u8], p: Ph) -> Result<&[u8], String> {
    let start = p.off as usize;
    let end = usize::try_from(p.off.checked_add(p.filesz).ok_or("program range overflow")?).map_err(|_| "program range does not fit usize")?;
    f.get(start..end).ok_or_else(|| "program range exceeds input".into())
}

fn map_file<'a>(f: &'a [u8], ph: &[Ph], addr: u64, size: u64, label: &str) -> Result<&'a [u8], String> {
    let end = addr.checked_add(size).ok_or_else(|| format!("{label} range overflows u64"))?;
    for p in ph.iter().filter(|p| p.kind == PT_LOAD) {
        let file_end = p.va.checked_add(p.filesz).ok_or("PT_LOAD file range overflows u64")?;
        if addr >= p.va && end <= file_end {
            let start = p.off.checked_add(addr - p.va).ok_or_else(|| format!("{label} file offset overflows u64"))?;
            let stop = start.checked_add(size).ok_or_else(|| format!("{label} file range overflows u64"))?;
            return f.get(start as usize..stop as usize).ok_or_else(|| format!("{label} exceeds input"));
        }
    }
    Err(format!("{label} is not fully file-backed by PT_LOAD"))
}

fn memory_range(ph: &[Ph], addr: u64, size: u64, flags: u32, label: &str) -> Result<(), String> {
    let end = addr.checked_add(size).ok_or_else(|| format!("{label} range overflows u64"))?;
    for p in ph.iter().filter(|p| p.kind == PT_LOAD && p.flags & flags == flags) {
        let mem_end = p.va.checked_add(p.memsz).ok_or("PT_LOAD memory range overflows u64")?;
        if addr >= p.va && end <= mem_end {
            return Ok(());
        }
    }
    Err(format!("{label} is not fully contained in a writable PT_LOAD"))
}

fn u16at(b: &[u8], o: usize) -> u16 { u16::from_le_bytes(b[o..o + 2].try_into().unwrap()) }
fn u32at(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn u64at(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
fn i64at(b: &[u8], o: usize) -> i64 { i64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
