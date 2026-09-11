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
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_DTPOFF32: u32 = 21;
const STT_TLS: u8 = 6;
const SHN_UNDEF: u16 = 0;
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
    hash: Option<u64>,
    gnu_hash: Option<u64>,
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

fn usage() -> String {
    "usage: mini-elf-dynrela-dtpoff32 --load-bias <address> <input>...".into()
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
            if bias
                .replace(parse_u64(&args[i].to_string_lossy())?)
                .is_some()
            {
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
    for (n, (name, s)) in rendered.into_iter().enumerate() {
        if n > 0 {
            out.push('\n');
        }
        if multi {
            out.push_str(&format!("File: {name}\n"));
        }
        out.push_str(&s);
    }
    Ok(out)
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
        return Err("mini-elf-dynrela-dtpoff32 requires an ET_DYN image".into());
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
            DT_GNU_HASH => Some((&mut d.gnu_hash, "DT_GNU_HASH")),
            DT_STRTAB => Some((&mut d.strtab, "DT_STRTAB")),
            DT_SYMTAB => Some((&mut d.symtab, "DT_SYMTAB")),
            DT_RELA => Some((&mut d.rela, "DT_RELA")),
            DT_RELASZ => Some((&mut d.relasz, "DT_RELASZ")),
            DT_RELAENT => Some((&mut d.relaent, "DT_RELAENT")),
            DT_STRSZ => Some((&mut d.strsz, "DT_STRSZ")),
            DT_SYMENT => Some((&mut d.syment, "DT_SYMENT")),
            _ => None,
        };
        if let Some((s, n)) = slot {
            if s.replace(val).is_some() {
                return Err(format!("duplicate {n}"));
            }
        }
    }
    if !term {
        return Err("PT_DYNAMIC is missing DT_NULL".into());
    }

    let req =
        |v: Option<u64>, n: &str| v.ok_or_else(|| format!("PT_DYNAMIC is missing required {n}"));
    let rela = req(d.rela, "DT_RELA")?;
    let relasz = req(d.relasz, "DT_RELASZ")?;
    let relaent = req(d.relaent, "DT_RELAENT")?;
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

    let count = dynamic_symbol_count(file, &ph, d.hash, d.gnu_hash)?;
    if count == 0 {
        return Err("dynamic hash metadata reports zero dynamic symbols".into());
    }
    let symbytes = count
        .checked_mul(SYMENT as u64)
        .ok_or("dynamic symbol table size overflows u64")?;
    let syms = map_file(file, &ph, symtab, symbytes, "DT_SYMTAB table")?;
    let strs = map_file(file, &ph, strtab, strsz, "DT_STRTAB table")?;
    let relas = map_file(file, &ph, rela, relasz, "DT_RELA table")?;

    let mut out = format!(
        "Validated R_X86_64_DTPOFF32 relocations: load-bias={bias:#018x} entries={} symbols={count}\n",
        relasz / relaent
    );
    let mut found = 0;
    for (idx, e) in relas.chunks_exact(RELAENT).enumerate() {
        let off = u64at(e, 0);
        let info = u64at(e, 8);
        if info as u32 != R_X86_64_DTPOFF32 {
            continue;
        }
        let si = info >> 32;
        if si == 0 || si >= count {
            return Err(format!("R_X86_64_DTPOFF32 relocation {idx} references invalid dynamic symbol index {si} (count {count})"));
        }
        memory_range(
            &ph,
            off,
            4,
            PF_W,
            &format!("R_X86_64_DTPOFF32 relocation {idx} target"),
        )?;
        let so = usize::try_from(si)
            .ok()
            .and_then(|x| x.checked_mul(SYMENT))
            .ok_or("dynamic symbol offset overflows usize")?;
        let s = syms
            .get(so..so + SYMENT)
            .ok_or("dynamic symbol exceeds DT_SYMTAB")?;
        let no = u32at(s, 0);
        let typ = s[4] & 0x0f;
        let sh = u16at(s, 6);
        let value = u64at(s, 8);
        if sh == SHN_UNDEF {
            return Err(format!("R_X86_64_DTPOFF32 relocation {idx} references undefined TLS symbol; dependency lookup is outside this bounded slice"));
        }
        if sh == SHN_ABS || typ != STT_TLS {
            return Err(format!(
                "R_X86_64_DTPOFF32 relocation {idx} requires a defined STT_TLS symbol"
            ));
        }
        let add = i64at(e, 16);
        let wide = value as i128 + add as i128;
        let result = i32::try_from(wide).map_err(|_| {
            format!("R_X86_64_DTPOFF32 relocation {idx} result does not fit signed 32-bit")
        })?;
        let rt = bias.checked_add(off).ok_or_else(|| {
            format!("R_X86_64_DTPOFF32 relocation {idx} runtime target overflows u64")
        })?;
        let name = dynstr(strs, no, si)?;
        out.push_str(&format!("  index={idx} symbol={si}:{name} target=B+{off:#018x}=>{rt:#018x} result-dtpoff={result}\n"));
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_DTPOFF32 relocations".into());
    }
    Ok(out)
}

fn dynamic_symbol_count(
    file: &[u8],
    ph: &[Ph],
    hash: Option<u64>,
    gnu_hash: Option<u64>,
) -> Result<u64, String> {
    if let Some(address) = hash {
        let header = map_file(file, ph, address, 8, "DT_HASH header")?;
        return Ok(u64::from(u32at(header, 4)));
    }
    let address = gnu_hash.ok_or_else(|| {
        "R_X86_64_DTPOFF32 validation requires DT_HASH or DT_GNU_HASH to bound DT_SYMTAB"
            .to_owned()
    })?;
    gnu_hash_symbol_count(file, ph, address)
}

fn gnu_hash_symbol_count(file: &[u8], ph: &[Ph], address: u64) -> Result<u64, String> {
    let header = map_file(file, ph, address, 16, "DT_GNU_HASH header")?;
    let bucket_count = u32at(header, 0);
    let symbol_offset = u32at(header, 4);
    let bloom_count = u32at(header, 8);
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
    let prefix = map_file(file, ph, address, prefix_size, "DT_GNU_HASH prefix")?;
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
        let start_symbol = u32at(prefix, offset);
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
                file,
                ph,
                entry_address,
                4,
                &format!("DT_GNU_HASH bucket {bucket_index} chain entry for symbol {symbol}"),
            )?;
            let next = symbol
                .checked_add(1)
                .ok_or_else(|| "DT_GNU_HASH symbol index overflows u32".to_owned())?;
            if u32at(entry, 0) & 1 != 0 {
                count = count.max(next);
                break;
            }
            symbol = next;
        }
    }
    Ok(u64::from(count))
}

fn dynstr(tab: &[u8], off: u32, si: u64) -> Result<String, String> {
    let s = off as usize;
    if s >= tab.len() {
        return Err(format!(
            "dynamic symbol {si} name offset is outside DT_STRTAB"
        ));
    }
    let tail = &tab[s..];
    let n = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| format!("dynamic symbol {si} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..n])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {si} name is not UTF-8"))
}

fn program_headers(f: &[u8]) -> Result<Vec<Ph>, String> {
    let off = usize::try_from(u64at(f, 32)).map_err(|_| "program-header offset does not fit usize")?;
    let ent = u16at(f, 54) as usize;
    let num = u16at(f, 56) as usize;
    if ent != PHENT {
        return Err("unsupported program-header size".into());
    }
    let end = off
        .checked_add(
            ent.checked_mul(num)
                .ok_or("program-header table size overflow")?,
        )
        .ok_or("program-header table overflow")?;
    if end > f.len() {
        return Err("program-header table exceeds input".into());
    }
    let mut v = Vec::new();
    for i in 0..num {
        let p = off + i * ent;
        let x = Ph {
            kind: u32at(f, p),
            flags: u32at(f, p + 4),
            off: u64at(f, p + 8),
            va: u64at(f, p + 16),
            filesz: u64at(f, p + 32),
            memsz: u64at(f, p + 40),
        };
        if x.filesz > x.memsz
            || x.off
                .checked_add(x.filesz)
                .ok_or("program file range overflow")?
                > f.len() as u64
            || x.va.checked_add(x.memsz).is_none()
        {
            return Err("invalid program header range".into());
        }
        v.push(x);
    }
    Ok(v)
}

fn program_bytes(f: &[u8], p: Ph) -> Result<&[u8], String> {
    let s = usize::try_from(p.off).map_err(|_| "PT_DYNAMIC offset does not fit usize")?;
    let n = usize::try_from(p.filesz).map_err(|_| "PT_DYNAMIC size does not fit usize")?;
    let e = s.checked_add(n).ok_or("PT_DYNAMIC range overflow")?;
    f.get(s..e).ok_or_else(|| "PT_DYNAMIC exceeds input".into())
}

fn map_file<'a>(f: &'a [u8], ph: &[Ph], a: u64, n: u64, label: &str) -> Result<&'a [u8], String> {
    let end = a
        .checked_add(n)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for p in ph.iter().filter(|p| p.kind == PT_LOAD) {
        let pe = p
            .va
            .checked_add(p.filesz)
            .ok_or_else(|| format!("{label} PT_LOAD file range overflows u64"))?;
        if a >= p.va && end <= pe {
            let s = p
                .off
                .checked_add(a - p.va)
                .ok_or_else(|| format!("{label} file offset overflows u64"))?;
            let e = s
                .checked_add(n)
                .ok_or_else(|| format!("{label} file range overflows u64"))?;
            let su = usize::try_from(s).map_err(|_| format!("{label} offset does not fit usize"))?;
            let eu = usize::try_from(e).map_err(|_| format!("{label} end does not fit usize"))?;
            return f
                .get(su..eu)
                .ok_or_else(|| format!("{label} exceeds input"));
        }
    }
    Err(format!("{label} is not file-backed by PT_LOAD"))
}

fn memory_range(ph: &[Ph], a: u64, n: u64, flags: u32, label: &str) -> Result<(), String> {
    let end = a
        .checked_add(n)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for p in ph
        .iter()
        .filter(|p| p.kind == PT_LOAD && p.flags & flags == flags)
    {
        let pe = p
            .va
            .checked_add(p.memsz)
            .ok_or_else(|| format!("{label} PT_LOAD memory range overflows u64"))?;
        if a >= p.va && end <= pe {
            return Ok(());
        }
    }
    Err(format!(
        "{label} is not contained in a matching PT_LOAD memory range"
    ))
}

fn u16at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn i64at(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
