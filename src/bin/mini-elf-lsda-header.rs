use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ELF64_SECTION_HEADER_SIZE: usize = 64;
const SHF_ALLOC: u64 = 0x2;
const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_ULEB128: u8 = 0x01;

#[derive(Clone, Copy)]
struct SectionHeader {
    name: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
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
    let inputs = args.collect::<Vec<_>>();
    if inputs.is_empty()
        || inputs
            .iter()
            .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-lsda-header <input>...".to_owned());
    }

    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(&input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let rendered = inspect(&file).map_err(|error| format!("{display}: {error}"))?;
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

fn inspect(file: &[u8]) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|error| error.to_string())?;
    if file.len() < 64 {
        return Err("ELF64 header is truncated".to_owned());
    }

    let shoff = read_u64(file, 40);
    let shentsize = usize::from(read_u16(file, 58));
    let shnum = usize::from(read_u16(file, 60));
    let shstrndx = usize::from(read_u16(file, 62));
    if shentsize != ELF64_SECTION_HEADER_SIZE {
        return Err(format!(
            "unsupported ELF64 section-header size {shentsize}, expected {ELF64_SECTION_HEADER_SIZE}"
        ));
    }
    if shnum == 0 {
        return Err("extended ELF section numbering is unsupported in this bounded slice".to_owned());
    }
    if shstrndx >= shnum {
        return Err(format!(
            "section-name string-table index {shstrndx} is outside {shnum} section headers"
        ));
    }

    let headers = section_headers(file, shoff, shentsize, shnum)?;
    let shstr = headers[shstrndx];
    let shstr_bytes = section_bytes(file, shstr, "section-name string table")?;

    let mut lsda = None;
    for (index, header) in headers.iter().copied().enumerate() {
        let name = section_name(shstr_bytes, header.name, index)?;
        if name == ".gcc_except_table" {
            if lsda.replace((index, header)).is_some() {
                return Err("multiple .gcc_except_table sections are unsupported".to_owned());
            }
        }
    }
    let (index, section) = lsda.ok_or_else(|| "missing .gcc_except_table section".to_owned())?;
    if section.flags & SHF_ALLOC == 0 {
        return Err(format!(".gcc_except_table section {index} is not SHF_ALLOC"));
    }
    let bytes = section_bytes(file, section, ".gcc_except_table")?;
    if bytes.len() < 4 {
        return Err(".gcc_except_table is too small for a bounded LSDA header".to_owned());
    }

    let lpstart_encoding = bytes[0];
    if lpstart_encoding != DW_EH_PE_OMIT {
        return Err(format!(
            "unsupported LSDA LPStart encoding {lpstart_encoding:#04x}; expected DW_EH_PE_omit"
        ));
    }
    let ttype_encoding = bytes[1];
    if ttype_encoding != DW_EH_PE_OMIT {
        return Err(format!(
            "unsupported LSDA type-table encoding {ttype_encoding:#04x}; expected DW_EH_PE_omit"
        ));
    }
    let call_site_encoding = bytes[2];
    if call_site_encoding != DW_EH_PE_ULEB128 {
        return Err(format!(
            "unsupported LSDA call-site encoding {call_site_encoding:#04x}; expected uleb128"
        ));
    }
    let (call_site_bytes, cursor) = read_uleb(bytes, 3, bytes.len(), "LSDA call-site table length")?;
    let table_len = usize::try_from(call_site_bytes)
        .map_err(|_| "LSDA call-site table length does not fit usize".to_owned())?;
    let table_end = cursor
        .checked_add(table_len)
        .ok_or_else(|| "LSDA call-site table range overflows usize".to_owned())?;
    if table_end > bytes.len() {
        return Err(format!(
            "LSDA call-site table declares {call_site_bytes} bytes but only {} remain",
            bytes.len().saturating_sub(cursor)
        ));
    }

    Ok(format!(
        "Validated GNU LSDA header: section={} address={:#018x} offset={:#x} size={:#x} call-site-encoding=0x01 call-site-table-bytes={}\n",
        index, section.addr, section.offset, section.size, call_site_bytes
    ))
}

fn section_headers(
    file: &[u8],
    shoff: u64,
    shentsize: usize,
    shnum: usize,
) -> Result<Vec<SectionHeader>, String> {
    let shoff = usize::try_from(shoff).map_err(|_| "section-header offset does not fit usize".to_owned())?;
    let table_bytes = shnum
        .checked_mul(shentsize)
        .ok_or_else(|| "section-header table size overflows usize".to_owned())?;
    let table_end = shoff
        .checked_add(table_bytes)
        .ok_or_else(|| "section-header table range overflows usize".to_owned())?;
    if table_end > file.len() {
        return Err("section-header table exceeds input".to_owned());
    }

    let mut headers = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let offset = shoff
            .checked_add(index.checked_mul(shentsize).ok_or_else(|| {
                format!("section header {index} relative offset overflows usize")
            })?)
            .ok_or_else(|| format!("section header {index} offset overflows usize"))?;
        headers.push(SectionHeader {
            name: read_u32(file, offset),
            flags: read_u64(file, offset + 8),
            addr: read_u64(file, offset + 16),
            offset: read_u64(file, offset + 24),
            size: read_u64(file, offset + 32),
        });
    }
    Ok(headers)
}

fn section_bytes<'a>(
    file: &'a [u8],
    section: SectionHeader,
    label: &str,
) -> Result<&'a [u8], String> {
    let start = usize::try_from(section.offset)
        .map_err(|_| format!("{label} offset does not fit usize"))?;
    let size = usize::try_from(section.size).map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{label} file range exceeds input"));
    }
    Ok(&file[start..end])
}

fn section_name<'a>(
    table: &'a [u8],
    name_offset: u32,
    index: usize,
) -> Result<&'a str, String> {
    let start = usize::try_from(name_offset)
        .map_err(|_| format!("section {index} name offset does not fit usize"))?;
    if start >= table.len() {
        return Err(format!("section {index} name offset exceeds string table"));
    }
    let relative_end = table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("section {index} name is unterminated"))?;
    std::str::from_utf8(&table[start..start + relative_end])
        .map_err(|_| format!("section {index} name is not UTF-8"))
}

fn read_uleb(
    bytes: &[u8],
    mut cursor: usize,
    end: usize,
    label: &str,
) -> Result<(u64, usize), String> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    loop {
        if cursor >= end {
            return Err(format!("truncated {label} ULEB128"));
        }
        let byte = bytes[cursor];
        cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift >= 64 && payload != 0 {
            return Err(format!("{label} ULEB128 overflows u64"));
        }
        let shifted = payload
            .checked_shl(shift)
            .ok_or_else(|| format!("{label} ULEB128 overflows u64"))?;
        value = value
            .checked_add(shifted)
            .ok_or_else(|| format!("{label} ULEB128 overflows u64"))?;
        if byte & 0x80 == 0 {
            return Ok((value, cursor));
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| format!("{label} ULEB128 shift overflows"))?;
        if shift > 70 {
            return Err(format!("{label} ULEB128 is too long"));
        }
    }
}

fn read_u16(file: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(file[offset..offset + 2].try_into().unwrap())
}

fn read_u32(file: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u64(file: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap())
}
