use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_HDR_SIZE: usize = 12;
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_DATAREL_SDATA4: u8 = 0x3b;

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

struct CieEncoding {
    cie: u64,
    augmentation: String,
    fde_encoding: u8,
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
    if inputs.is_empty() || inputs.iter().any(|arg| arg.to_string_lossy().starts_with('-')) {
        return Err("usage: mini-elf-eh-frame-encoding <input>...".to_owned());
    }

    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{display}': {error}"))?;
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
    let headers = program_headers(file)?;
    let eh = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.kind == PT_GNU_EH_FRAME)
        .collect::<Vec<_>>();
    if eh.len() != 1 {
        return Err(format!(
            "expected exactly one PT_GNU_EH_FRAME segment, found {}",
            eh.len()
        ));
    }
    let (eh_index, eh) = eh[0];
    if eh.filesz < EH_FRAME_HDR_SIZE as u64 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {eh_index} is too small for .eh_frame_hdr"
        ));
    }
    let eh_offset = usize::try_from(eh.offset)
        .map_err(|_| "PT_GNU_EH_FRAME offset does not fit usize".to_owned())?;
    let eh_end = eh
        .offset
        .checked_add(eh.filesz)
        .ok_or_else(|| "PT_GNU_EH_FRAME file range overflows u64".to_owned())?;
    if eh_end > file.len() as u64 {
        return Err("PT_GNU_EH_FRAME file range exceeds input".to_owned());
    }
    if file[eh_offset] != 1
        || file[eh_offset + 1] != DW_EH_PE_PCREL_SDATA4
        || file[eh_offset + 2] != DW_EH_PE_UDATA4
        || file[eh_offset + 3] != DW_EH_PE_DATAREL_SDATA4
    {
        return Err("unsupported .eh_frame_hdr version or encoding tuple".to_owned());
    }

    let count = u64::from(read_u32(file, eh_offset + 8));
    let table_bytes = count
        .checked_mul(8)
        .ok_or_else(|| ".eh_frame_hdr table size overflows u64".to_owned())?;
    let required = 12_u64
        .checked_add(table_bytes)
        .ok_or_else(|| ".eh_frame_hdr required size overflows u64".to_owned())?;
    if required > eh.filesz {
        return Err(format!(
            ".eh_frame_hdr declares {count} entries requiring {required} bytes but segment has {}",
            eh.filesz
        ));
    }

    let mut rows = Vec::with_capacity(
        usize::try_from(count).map_err(|_| "FDE count does not fit usize".to_owned())?,
    );
    for index in 0..count {
        let table_offset = eh_offset
            .checked_add(12)
            .and_then(|value| value.checked_add(usize::try_from(index.checked_mul(8)?).ok()?))
            .ok_or_else(|| "search-table offset overflows usize".to_owned())?;
        let fde = checked_add_i32(eh.vaddr, read_i32(file, table_offset + 4)).ok_or_else(|| {
            format!("FDE {index} address arithmetic overflows u64")
        })?;
        rows.push(validate_cie(file, &headers, fde, index)?);
    }

    let mut output = format!("Validated CIE FDE encodings: {}\n", rows.len());
    for (index, row) in rows.iter().enumerate() {
        output.push_str(&format!(
            "FDE {index}: cie={:#018x} augmentation={} fde_encoding={:#04x}\n",
            row.cie, row.augmentation, row.fde_encoding
        ));
    }
    Ok(output)
}

fn validate_cie(
    file: &[u8],
    headers: &[ProgramHeader],
    fde: u64,
    index: u64,
) -> Result<CieEncoding, String> {
    let fde_offset = map_file_backed(headers, fde)
        .ok_or_else(|| format!("FDE {index} is not in a file-backed PT_LOAD"))?;
    let fde_length = read_u32_checked(file, fde_offset, "FDE length")?;
    if fde_length < 4 || fde_length == u32::MAX {
        return Err(format!("FDE {index} has unsupported record length {fde_length:#x}"));
    }
    let fde_end = checked_record_end(file, headers, fde, fde_length, "FDE", index)?;
    if fde_offset + 8 > fde_end {
        return Err(format!("FDE {index} is truncated before CIE pointer"));
    }
    let cie_delta = u64::from(read_u32(file, fde_offset + 4));
    let cie_field = fde
        .checked_add(4)
        .ok_or_else(|| format!("FDE {index} CIE pointer address overflows"))?;
    let cie = cie_field
        .checked_sub(cie_delta)
        .ok_or_else(|| format!("FDE {index} CIE back-reference underflows"))?;
    if cie >= fde {
        return Err(format!("FDE {index} CIE back-reference is not preceding"));
    }

    let cie_offset = map_file_backed(headers, cie)
        .ok_or_else(|| format!("FDE {index} CIE is not in a file-backed PT_LOAD"))?;
    let cie_length = read_u32_checked(file, cie_offset, "CIE length")?;
    if cie_length < 6 || cie_length == u32::MAX {
        return Err(format!("FDE {index} has unsupported CIE record length {cie_length:#x}"));
    }
    let cie_end = checked_record_end(file, headers, cie, cie_length, "CIE", index)?;
    if cie_offset + 9 > cie_end || read_u32(file, cie_offset + 4) != 0 {
        return Err(format!("FDE {index} CIE record is malformed"));
    }
    if file[cie_offset + 8] != 1 {
        return Err(format!("FDE {index} CIE version is not 1"));
    }

    let aug_start = cie_offset + 9;
    let nul = file[aug_start..cie_end]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("FDE {index} CIE augmentation string is unterminated"))?;
    let aug_end = aug_start + nul;
    let augmentation = std::str::from_utf8(&file[aug_start..aug_end])
        .map_err(|_| format!("FDE {index} CIE augmentation string is not UTF-8"))?
        .to_owned();
    if augmentation != "zR" {
        return Err(format!(
            "FDE {index} has unsupported CIE augmentation '{augmentation}' (expected zR)"
        ));
    }

    let mut cursor = aug_end + 1;
    let (_, next) = read_uleb(file, cursor, cie_end, "code alignment")?;
    cursor = next;
    let (_, next) = read_sleb(file, cursor, cie_end, "data alignment")?;
    cursor = next;
    let (_, next) = read_uleb(file, cursor, cie_end, "return register")?;
    cursor = next;
    let (augmentation_length, next) = read_uleb(file, cursor, cie_end, "augmentation length")?;
    cursor = next;
    let payload_end = cursor
        .checked_add(
            usize::try_from(augmentation_length)
                .map_err(|_| format!("FDE {index} augmentation length does not fit usize"))?,
        )
        .ok_or_else(|| format!("FDE {index} augmentation payload range overflows usize"))?;
    if payload_end > cie_end {
        return Err(format!(
            "FDE {index} CIE augmentation payload exceeds record boundary"
        ));
    }
    if augmentation_length != 1 {
        return Err(format!(
            "FDE {index} zR augmentation payload length is {augmentation_length}, expected 1"
        ));
    }
    let fde_encoding = file[cursor];
    if fde_encoding != DW_EH_PE_PCREL_SDATA4 {
        return Err(format!(
            "FDE {index} has unsupported CIE-declared FDE encoding {fde_encoding:#04x} (expected 0x1b)"
        ));
    }

    Ok(CieEncoding {
        cie,
        augmentation,
        fde_encoding,
    })
}

fn checked_record_end(
    file: &[u8],
    headers: &[ProgramHeader],
    address: u64,
    length: u32,
    kind: &str,
    index: u64,
) -> Result<usize, String> {
    let total = 4_u64
        .checked_add(u64::from(length))
        .ok_or_else(|| format!("{kind} {index} size overflows u64"))?;
    let end_address = address
        .checked_add(total)
        .ok_or_else(|| format!("{kind} {index} address range overflows u64"))?;
    let start = map_file_backed(headers, address)
        .ok_or_else(|| format!("{kind} {index} is not file-backed"))?;
    let last = end_address
        .checked_sub(1)
        .ok_or_else(|| format!("{kind} {index} range underflows"))?;
    if map_file_backed(headers, last).is_none() {
        return Err(format!("{kind} {index} crosses a file-backed PT_LOAD boundary"));
    }
    let total = usize::try_from(total)
        .map_err(|_| format!("{kind} {index} size does not fit usize"))?;
    let end = start
        .checked_add(total)
        .ok_or_else(|| format!("{kind} {index} file range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{kind} {index} file range exceeds input"));
    }
    Ok(end)
}

fn read_uleb(
    file: &[u8],
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
        let byte = file[cursor];
        cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift >= 64 && payload != 0 {
            return Err(format!("{label} ULEB128 overflows u64"));
        }
        value = value
            .checked_add(payload.checked_shl(shift).unwrap_or(0))
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

fn read_sleb(
    file: &[u8],
    mut cursor: usize,
    end: usize,
    label: &str,
) -> Result<(i64, usize), String> {
    let mut value = 0_i64;
    let mut shift = 0_u32;
    loop {
        if cursor >= end {
            return Err(format!("truncated {label} SLEB128"));
        }
        let byte = file[cursor];
        cursor += 1;
        let payload = i64::from(byte & 0x7f);
        if shift < 64 {
            value |= payload << shift;
        } else if payload != 0 && payload != 0x7f {
            return Err(format!("{label} SLEB128 overflows i64"));
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| format!("{label} SLEB128 shift overflows"))?;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= (!0_i64) << shift;
            }
            return Ok((value, cursor));
        }
        if shift > 70 {
            return Err(format!("{label} SLEB128 is too long"));
        }
    }
}

fn program_headers(file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    if file.len() < 64 || &file[..4] != b"\x7fELF" || file[4] != 2 || file[5] != 1 {
        return Err("input is not little-endian ELF64".to_owned());
    }
    if read_u16(file, 18) != 62 {
        return Err("input is not x86-64 ELF".to_owned());
    }
    let phoff = read_u64(file, 32);
    let phentsize = read_u16(file, 54);
    let phnum = read_u16(file, 56);
    if phentsize != 56 {
        return Err(format!("unsupported program-header entry size {phentsize}"));
    }
    let table_size = u64::from(phentsize)
        .checked_mul(u64::from(phnum))
        .ok_or_else(|| "program-header table size overflows u64".to_owned())?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or_else(|| "program-header table range overflows u64".to_owned())?;
    if table_end > file.len() as u64 {
        return Err("program-header table exceeds input".to_owned());
    }

    let mut headers = Vec::with_capacity(usize::from(phnum));
    for index in 0..phnum {
        let offset = phoff
            .checked_add(u64::from(index) * 56)
            .ok_or_else(|| "program-header offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program-header offset does not fit usize".to_owned())?;
        let header = ProgramHeader {
            kind: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            vaddr: read_u64(file, offset + 16),
            filesz: read_u64(file, offset + 32),
        };
        let end = header
            .offset
            .checked_add(header.filesz)
            .ok_or_else(|| format!("program header {index} file range overflows u64"))?;
        if end > file.len() as u64 {
            return Err(format!("program header {index} file range exceeds input"));
        }
        header
            .vaddr
            .checked_add(header.filesz)
            .ok_or_else(|| format!("program header {index} virtual file range overflows u64"))?;
        headers.push(header);
    }
    Ok(headers)
}

fn map_file_backed(headers: &[ProgramHeader], address: u64) -> Option<usize> {
    for header in headers {
        if header.kind != PT_LOAD {
            continue;
        }
        let end = header.vaddr.checked_add(header.filesz)?;
        if address < header.vaddr || address >= end {
            continue;
        }
        let delta = address.checked_sub(header.vaddr)?;
        let offset = header.offset.checked_add(delta)?;
        return usize::try_from(offset).ok();
    }
    None
}

fn checked_add_i32(base: u64, displacement: i32) -> Option<u64> {
    if displacement >= 0 {
        base.checked_add(displacement as u64)
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs()))
    }
}

fn read_u16(file: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(file[offset..offset + 2].try_into().unwrap())
}

fn read_u32(file: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u32_checked(file: &[u8], offset: usize, label: &str) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| format!("{label} offset overflows usize"))?;
    if end > file.len() {
        return Err(format!("truncated {label}"));
    }
    Ok(read_u32(file, offset))
}

fn read_i32(file: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u64(file: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap())
}
