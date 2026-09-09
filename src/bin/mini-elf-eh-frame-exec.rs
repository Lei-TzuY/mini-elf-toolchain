use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_HDR_SIZE: u64 = 12;
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_DATAREL_SDATA4: u8 = 0x3b;

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

struct CodeRange {
    initial: u64,
    end: u64,
    load_index: usize,
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
        return Err("usage: mini-elf-eh-frame-exec <input>...".to_owned());
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
    let header = Elf64Header::parse(file).map_err(|error| error.to_string())?;
    let headers = program_headers(header, file)?;
    let eh = headers
        .iter()
        .enumerate()
        .filter(|(_, ph)| ph.kind == PT_GNU_EH_FRAME)
        .collect::<Vec<_>>();
    if eh.len() != 1 {
        return Err(format!(
            "expected exactly one PT_GNU_EH_FRAME segment, found {}",
            eh.len()
        ));
    }
    let (eh_index, eh) = eh[0];
    if eh.filesz < EH_FRAME_HDR_SIZE {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {eh_index} is too small for .eh_frame_hdr"
        ));
    }
    let eh_end = eh
        .offset
        .checked_add(eh.filesz)
        .ok_or_else(|| "PT_GNU_EH_FRAME file range overflows u64".to_owned())?;
    if eh_end > file.len() as u64 {
        return Err("PT_GNU_EH_FRAME file range exceeds input".to_owned());
    }
    let eh_offset = usize::try_from(eh.offset)
        .map_err(|_| "PT_GNU_EH_FRAME offset does not fit usize".to_owned())?;
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
    let required = EH_FRAME_HDR_SIZE
        .checked_add(table_bytes)
        .ok_or_else(|| ".eh_frame_hdr required size overflows u64".to_owned())?;
    if required > eh.filesz {
        return Err(format!(
            ".eh_frame_hdr declares {count} entries requiring {required} bytes but segment has {}",
            eh.filesz
        ));
    }

    let mut ranges = Vec::with_capacity(
        usize::try_from(count).map_err(|_| "FDE count does not fit usize".to_owned())?,
    );
    for index in 0..count {
        let relative = index
            .checked_mul(8)
            .ok_or_else(|| "search-table entry offset overflows u64".to_owned())?;
        let table_offset = eh_offset
            .checked_add(12)
            .and_then(|value| value.checked_add(usize::try_from(relative).ok()?))
            .ok_or_else(|| "search-table offset overflows usize".to_owned())?;
        let fde = checked_add_i32(eh.vaddr, read_i32(file, table_offset + 4))
            .ok_or_else(|| format!("FDE {index} address arithmetic overflows u64"))?;
        ranges.push(validate_fde_range(file, &headers, fde, index)?);
    }

    let mut output = format!("Validated executable FDE ranges: {}\n", ranges.len());
    for (index, range) in ranges.iter().enumerate() {
        output.push_str(&format!(
            "FDE {index}: code={:#018x}..{:#018x} executable_load={}\n",
            range.initial, range.end, range.load_index
        ));
    }
    Ok(output)
}

fn validate_fde_range(
    file: &[u8],
    headers: &[ProgramHeader],
    fde: u64,
    index: u64,
) -> Result<CodeRange, String> {
    let fde_offset = map_file_backed(headers, fde)
        .ok_or_else(|| format!("FDE {index} is not in a file-backed PT_LOAD"))?;
    let fde_length = read_u32_checked(file, fde_offset, "FDE length")?;
    if fde_length < 12 || fde_length == u32::MAX {
        return Err(format!(
            "FDE {index} has unsupported record length {fde_length:#x}"
        ));
    }
    let fde_end = record_end(file, headers, fde, fde_length, "FDE", index)?;
    if fde_offset
        .checked_add(16)
        .ok_or_else(|| format!("FDE {index} fixed fields overflow usize"))?
        > fde_end
    {
        return Err(format!("FDE {index} is truncated before code-range fields"));
    }

    let cie_delta = u64::from(read_u32(file, fde_offset + 4));
    let cie_field = fde
        .checked_add(4)
        .ok_or_else(|| format!("FDE {index} CIE pointer address overflows u64"))?;
    let cie = cie_field
        .checked_sub(cie_delta)
        .ok_or_else(|| format!("FDE {index} CIE back-reference underflows"))?;
    if cie >= fde {
        return Err(format!("FDE {index} CIE back-reference is not preceding"));
    }
    require_pcrel_sdata4_cie(file, headers, cie, index)?;

    let initial_field = fde
        .checked_add(8)
        .ok_or_else(|| format!("FDE {index} initial-location field overflows u64"))?;
    let initial = checked_add_i32(initial_field, read_i32(file, fde_offset + 8))
        .ok_or_else(|| format!("FDE {index} initial-location arithmetic overflows u64"))?;
    let encoded_range = read_i32(file, fde_offset + 12);
    if encoded_range < 0 {
        return Err(format!("FDE {index} has negative encoded address range"));
    }
    let end = initial
        .checked_add(encoded_range as u64)
        .ok_or_else(|| format!("FDE {index} code range overflows u64"))?;

    let load_index = executable_file_backed_range(headers, initial, end).ok_or_else(|| {
        format!(
            "FDE {index} code range {initial:#x}..{end:#x} is not fully contained in one executable file-backed PT_LOAD"
        )
    })?;
    Ok(CodeRange {
        initial,
        end,
        load_index,
    })
}

fn require_pcrel_sdata4_cie(
    file: &[u8],
    headers: &[ProgramHeader],
    cie: u64,
    index: u64,
) -> Result<(), String> {
    let cie_offset = map_file_backed(headers, cie)
        .ok_or_else(|| format!("FDE {index} CIE is not in a file-backed PT_LOAD"))?;
    let cie_length = read_u32_checked(file, cie_offset, "CIE length")?;
    if cie_length < 6 || cie_length == u32::MAX {
        return Err(format!(
            "FDE {index} has unsupported CIE record length {cie_length:#x}"
        ));
    }
    let cie_end = record_end(file, headers, cie, cie_length, "CIE", index)?;
    if cie_offset + 9 > cie_end
        || read_u32(file, cie_offset + 4) != 0
        || file[cie_offset + 8] != 1
    {
        return Err(format!("FDE {index} CIE record is malformed or unsupported"));
    }
    let aug_start = cie_offset + 9;
    let nul = file[aug_start..cie_end]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("FDE {index} CIE augmentation string is unterminated"))?;
    let aug_end = aug_start + nul;
    if &file[aug_start..aug_end] != b"zR" {
        return Err(format!("FDE {index} CIE augmentation is not supported zR"));
    }

    let mut cursor = aug_end + 1;
    cursor = read_uleb(file, cursor, cie_end, "code alignment")?.1;
    cursor = read_sleb(file, cursor, cie_end, "data alignment")?.1;
    cursor = read_uleb(file, cursor, cie_end, "return register")?.1;
    let (augmentation_length, next) = read_uleb(file, cursor, cie_end, "augmentation length")?;
    cursor = next;
    if augmentation_length != 1 || cursor >= cie_end {
        return Err(format!("FDE {index} CIE zR payload is malformed"));
    }
    let payload_end = cursor
        .checked_add(1)
        .ok_or_else(|| format!("FDE {index} CIE augmentation payload overflows usize"))?;
    if payload_end > cie_end || file[cursor] != DW_EH_PE_PCREL_SDATA4 {
        return Err(format!(
            "FDE {index} CIE does not declare pcrel/sdata4 FDE encoding"
        ));
    }
    Ok(())
}

fn executable_file_backed_range(
    headers: &[ProgramHeader],
    start: u64,
    end: u64,
) -> Option<usize> {
    headers.iter().enumerate().find_map(|(index, header)| {
        if header.kind != PT_LOAD || header.flags & PF_X == 0 {
            return None;
        }
        let load_end = header.vaddr.checked_add(header.filesz)?;
        if start >= header.vaddr && start < load_end && end >= start && end <= load_end {
            Some(index)
        } else {
            None
        }
    })
}

fn map_file_backed(headers: &[ProgramHeader], address: u64) -> Option<usize> {
    headers.iter().find_map(|header| {
        if header.kind != PT_LOAD {
            return None;
        }
        let end = header.vaddr.checked_add(header.filesz)?;
        if address < header.vaddr || address >= end {
            return None;
        }
        let delta = address.checked_sub(header.vaddr)?;
        usize::try_from(header.offset.checked_add(delta)?).ok()
    })
}

fn record_end(
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

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let mut headers = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let offset = header
            .program_header_offset
            .checked_add(u64::from(index) * u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program-header offset overflows u64".to_owned())?;
        let offset = usize::try_from(offset)
            .map_err(|_| "program-header offset does not fit usize".to_owned())?;
        let kind = read_u32(file, offset);
        let flags = read_u32(file, offset + 4);
        let file_offset = read_u64(file, offset + 8);
        let vaddr = read_u64(file, offset + 16);
        let filesz = read_u64(file, offset + 32);
        let memsz = read_u64(file, offset + 40);
        if filesz > memsz {
            return Err(format!(
                "program header {index} has p_filesz {filesz:#x} greater than p_memsz {memsz:#x}"
            ));
        }
        let file_end = file_offset
            .checked_add(filesz)
            .ok_or_else(|| format!("program header {index} file range overflows u64"))?;
        if file_end > file.len() as u64 {
            return Err(format!("program header {index} file range exceeds input"));
        }
        vaddr
            .checked_add(memsz)
            .ok_or_else(|| format!("program header {index} virtual memory range overflows u64"))?;
        vaddr
            .checked_add(filesz)
            .ok_or_else(|| format!("program header {index} file-backed virtual range overflows u64"))?;
        headers.push(ProgramHeader {
            kind,
            flags,
            offset: file_offset,
            vaddr,
            filesz,
        });
    }
    Ok(headers)
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

fn checked_add_i32(base: u64, displacement: i32) -> Option<u64> {
    if displacement >= 0 {
        base.checked_add(displacement as u64)
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs()))
    }
}

fn read_u32_checked(file: &[u8], offset: usize, label: &str) -> Result<u32, String> {
    if offset.checked_add(4).is_none_or(|end| end > file.len()) {
        return Err(format!("{label} is truncated"));
    }
    Ok(read_u32(file, offset))
}

fn read_u32(file: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_i32(file: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(file[offset..offset + 4].try_into().unwrap())
}

fn read_u64(file: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(file[offset..offset + 8].try_into().unwrap())
}
