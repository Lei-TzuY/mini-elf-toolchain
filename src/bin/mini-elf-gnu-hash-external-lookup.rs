use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

#[allow(dead_code)]
mod checked_lookup {
    include!("mini-elf-gnu-hash-lookup.rs");

    pub fn lookup(symbol: &str, input: &std::ffi::OsStr) -> Result<String, String> {
        run([std::ffi::OsString::from(symbol), input.to_os_string()].into_iter())
    }
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_SYMTAB: i64 = 6;
const DT_SYMENT: i64 = 11;
const PHENT: usize = 56;
const DYNENT: usize = 16;
const SYMENT: usize = 24;
const SHN_UNDEF: u16 = 0;
const STB_LOCAL: u8 = 0;
const STV_INTERNAL: u8 = 1;
const STV_HIDDEN: u8 = 2;

#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    off: u64,
    va: u64,
    filesz: u64,
    memsz: u64,
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
        let lookup = checked_lookup::lookup(symbol, input)?;
        let index = parse_lookup_index(&lookup)?;
        let body = if let Some(index) = index {
            let bytes =
                fs::read(input).map_err(|error| format!("cannot read '{name}': {error}"))?;
            let eligibility = external_eligibility(&bytes, index)?;
            if eligibility.eligible {
                format!(
                    "GNU external lookup: symbol={symbol} index={index} bind={} visibility={} shndx={:#06x}\n",
                    eligibility.bind, eligibility.visibility, eligibility.shndx
                )
            } else {
                format!("GNU external lookup: symbol={symbol} not-found\n")
            }
        } else {
            format!("GNU external lookup: symbol={symbol} not-found\n")
        };
        rendered.push((name, body));
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
    "usage: mini-elf-gnu-hash-external-lookup <symbol> <input>...".to_owned()
}

fn parse_lookup_index(output: &str) -> Result<Option<u32>, String> {
    if output.contains(" not-found\n") {
        return Ok(None);
    }
    let marker = " index=";
    let start = output
        .find(marker)
        .ok_or_else(|| "checked GNU hash lookup returned an unrecognized result".to_owned())?
        + marker.len();
    let end = output[start..]
        .find(' ')
        .map(|offset| start + offset)
        .ok_or_else(|| "checked GNU hash lookup omitted the symbol index terminator".to_owned())?;
    output[start..end]
        .parse::<u32>()
        .map(Some)
        .map_err(|_| "checked GNU hash lookup returned an invalid symbol index".to_owned())
}

struct Eligibility {
    bind: u8,
    visibility: u8,
    shndx: u16,
    eligible: bool,
}

fn external_eligibility(file: &[u8], symbol_index: u32) -> Result<Eligibility, String> {
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

    let mut symtab = None;
    let mut syment = None;
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
            DT_SYMTAB => Some((&mut symtab, "DT_SYMTAB")),
            DT_SYMENT => Some((&mut syment, "DT_SYMENT")),
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
    let symtab = symtab.ok_or_else(|| "PT_DYNAMIC is missing required DT_SYMTAB".to_owned())?;
    let syment = syment.ok_or_else(|| "PT_DYNAMIC is missing required DT_SYMENT".to_owned())?;
    if syment != SYMENT as u64 {
        return Err(format!("unsupported DT_SYMENT {syment}"));
    }

    let offset = u64::from(symbol_index)
        .checked_mul(SYMENT as u64)
        .ok_or_else(|| "dynamic symbol offset overflows u64".to_owned())?;
    let address = symtab
        .checked_add(offset)
        .ok_or_else(|| "dynamic symbol address overflows u64".to_owned())?;
    let entry = map_file(
        file,
        &ph,
        address,
        SYMENT as u64,
        &format!("dynamic symbol {symbol_index}"),
    )?;
    let bind = entry[4] >> 4;
    let visibility = entry[5] & 0x03;
    let shndx = u16at(entry, 6);
    let eligible = bind != STB_LOCAL
        && shndx != SHN_UNDEF
        && visibility != STV_INTERNAL
        && visibility != STV_HIDDEN;
    Ok(Eligibility {
        bind,
        visibility,
        shndx,
        eligible,
    })
}

fn program_headers(file: &[u8]) -> Result<Vec<Ph>, String> {
    if file.len() < 64 {
        return Err("ELF header is truncated".to_owned());
    }
    let offset = usize::try_from(u64at(file, 32))
        .map_err(|_| "program-header offset does not fit usize".to_owned())?;
    let entry_size = usize::from(u16at(file, 54));
    let count = usize::from(u16at(file, 56));
    if entry_size != PHENT {
        return Err("unsupported program-header size".to_owned());
    }
    let table_size = entry_size
        .checked_mul(count)
        .ok_or_else(|| "program-header table size overflow".to_owned())?;
    let end = offset
        .checked_add(table_size)
        .ok_or_else(|| "program-header table overflow".to_owned())?;
    if end > file.len() {
        return Err("program-header table exceeds input".to_owned());
    }

    let mut headers = Vec::with_capacity(count);
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
