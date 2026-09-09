use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const EH_FRAME_HDR_FIXED_SIZE: u64 = 12;
const EH_FRAME_TABLE_ENTRY_SIZE: u64 = 8;
const DW_EH_PE_PCREL_SDATA4: u8 = 0x1b;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_DATAREL_SDATA4: u8 = 0x3b;
const DWARF64_LENGTH_MARKER: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

#[derive(Clone, Copy)]
struct RecordEnvelope {
    file_offset: usize,
    total_size: u64,
}

struct CieMetadata {
    fde_address: u64,
    cie_address: u64,
    version: u8,
    augmentation: String,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-eh-frame-cie <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-eh-frame-cie <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-eh-frame-cie <input>...".to_owned());
    }

    let multiple_inputs = args.len() > 1;
    let mut inspected = Vec::with_capacity(args.len());
    for input in args {
        let file = fs::read(&input)
            .map_err(|error| format!("cannot read '{}': {error}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let rendered =
            inspect_cies(header, &file).map_err(|error| format!("{display}: {error}"))?;
        inspected.push((display, rendered));
    }

    let mut output = String::new();
    for (index, (display, rendered)) in inspected.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple_inputs {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&rendered);
    }
    Ok(output)
}

fn inspect_cies(header: Elf64Header, file: &[u8]) -> Result<String, String> {
    let program_headers = program_headers(header, file)?;
    let segments = program_headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_GNU_EH_FRAME)
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return Ok("No PT_GNU_EH_FRAME segment found.\n".to_owned());
    }
    if segments.len() != 1 {
        return Err(format!(
            "expected at most one PT_GNU_EH_FRAME segment, found {}",
            segments.len()
        ));
    }

    let (segment_index, segment) = segments[0];
    if segment.file_size < EH_FRAME_HDR_FIXED_SIZE {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} file-backed .eh_frame_hdr is only {} bytes; need at least {EH_FRAME_HDR_FIXED_SIZE}",
            segment.file_size
        ));
    }
    let file_start = usize::try_from(segment.offset)
        .map_err(|_| "PT_GNU_EH_FRAME file offset does not fit usize".to_owned())?;
    if file[file_start] != 1 {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr version {} (expected 1)",
            file[file_start]
        ));
    }
    let pointer_encoding = file[file_start + 1];
    let count_encoding = file[file_start + 2];
    let table_encoding = file[file_start + 3];
    if pointer_encoding != DW_EH_PE_PCREL_SDATA4
        || count_encoding != DW_EH_PE_UDATA4
        || table_encoding != DW_EH_PE_DATAREL_SDATA4
    {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} has unsupported .eh_frame_hdr encodings: eh_frame_ptr={pointer_encoding:#04x}, fde_count={count_encoding:#04x}, table={table_encoding:#04x}; expected 0x1b/0x03/0x3b"
        ));
    }

    let fde_count = u64::from(read_u32(file, file_start + 8));
    let table_size = fde_count
        .checked_mul(EH_FRAME_TABLE_ENTRY_SIZE)
        .ok_or_else(|| "binary-search table size overflows u64".to_owned())?;
    let required_size = EH_FRAME_HDR_FIXED_SIZE
        .checked_add(table_size)
        .ok_or_else(|| ".eh_frame_hdr size overflows u64".to_owned())?;
    if required_size > segment.file_size {
        return Err(format!(
            "PT_GNU_EH_FRAME segment {segment_index} declares {fde_count} entries requiring {required_size} bytes, but has only {} file-backed bytes",
            segment.file_size
        ));
    }

    let table_start = file_start + EH_FRAME_HDR_FIXED_SIZE as usize;
    let mut metadata = Vec::with_capacity(
        usize::try_from(fde_count).map_err(|_| "FDE count does not fit usize".to_owned())?,
    );
    for entry_index in 0..fde_count {
        let relative = entry_index
            .checked_mul(EH_FRAME_TABLE_ENTRY_SIZE)
            .ok_or_else(|| "binary-search table entry offset overflows u64".to_owned())?;
        let offset =
            table_start
                .checked_add(usize::try_from(relative).map_err(|_| {
                    "binary-search table entry offset does not fit usize".to_owned()
                })?)
                .ok_or_else(|| "binary-search table file offset overflows usize".to_owned())?;
        let fde_delta = read_i32(file, offset + 4);
        let fde_address = checked_add_i32(segment.virtual_address, fde_delta).ok_or_else(|| {
            format!(
                "table entry {entry_index} FDE-address arithmetic overflows: datarel base {:#x} + displacement {fde_delta}",
                segment.virtual_address
            )
        })?;
        metadata.push(validate_cie_metadata(
            file,
            &program_headers,
            fde_address,
            entry_index,
        )?);
    }

    let mut output = String::new();
    output.push_str(&format!("Validated CIE metadata: {}\n", metadata.len()));
    for (index, item) in metadata.iter().enumerate() {
        output.push_str(&format!(
            "FDE {index}: address={:#018x} cie={:#018x} version={} augmentation={}\n",
            item.fde_address, item.cie_address, item.version, item.augmentation
        ));
    }
    Ok(output)
}

fn validate_cie_metadata(
    file: &[u8],
    program_headers: &[ProgramHeader],
    fde_address: u64,
    entry_index: u64,
) -> Result<CieMetadata, String> {
    let fde = record_envelope(file, program_headers, fde_address, "FDE", entry_index)?;
    let cie_pointer_address = fde_address
        .checked_add(4)
        .ok_or_else(|| format!("FDE {entry_index} CIE-pointer field address overflows u64"))?;
    let cie_delta = u64::from(read_u32(file, fde.file_offset + 4));
    let cie_address = cie_pointer_address.checked_sub(cie_delta).ok_or_else(|| {
        format!(
            "FDE {entry_index} CIE-pointer back-reference underflows: field {cie_pointer_address:#x} - offset {cie_delta:#x}"
        )
    })?;
    if cie_address >= fde_address {
        return Err(format!(
            "FDE {entry_index} CIE-pointer does not reference a preceding record: {cie_address:#x}"
        ));
    }

    let cie = record_envelope(file, program_headers, cie_address, "CIE", entry_index)?;
    if read_u32(file, cie.file_offset + 4) != 0 {
        return Err(format!(
            "FDE {entry_index} CIE-pointer target {cie_address:#x} is not a CIE record (CIE id is nonzero)"
        ));
    }
    if cie.total_size < 10 {
        return Err(format!(
            "FDE {entry_index} CIE record at {cie_address:#x} is too short to contain version and a terminated augmentation string"
        ));
    }

    let version = file[cie.file_offset + 8];
    if version != 1 {
        return Err(format!(
            "FDE {entry_index} CIE record at {cie_address:#x} has unsupported version {version} (expected 1)"
        ));
    }

    let cie_size = usize::try_from(cie.total_size)
        .map_err(|_| format!("FDE {entry_index} CIE record size does not fit usize"))?;
    let cie_end = cie
        .file_offset
        .checked_add(cie_size)
        .ok_or_else(|| format!("FDE {entry_index} CIE file range overflows usize"))?;
    let augmentation_start = cie
        .file_offset
        .checked_add(9)
        .ok_or_else(|| format!("FDE {entry_index} CIE augmentation offset overflows usize"))?;
    let augmentation_tail = &file[augmentation_start..cie_end];
    let nul = augmentation_tail.iter().position(|byte| *byte == 0).ok_or_else(|| {
        format!(
            "FDE {entry_index} CIE record at {cie_address:#x} has an unterminated augmentation string"
        )
    })?;
    let augmentation = std::str::from_utf8(&augmentation_tail[..nul])
        .map_err(|_| {
            format!(
                "FDE {entry_index} CIE record at {cie_address:#x} has a non-UTF-8 augmentation string"
            )
        })?
        .to_owned();

    Ok(CieMetadata {
        fde_address,
        cie_address,
        version,
        augmentation,
    })
}

fn record_envelope(
    file: &[u8],
    program_headers: &[ProgramHeader],
    address: u64,
    kind: &str,
    entry_index: u64,
) -> Result<RecordEnvelope, String> {
    let (load_index, file_offset, file_backed_end) =
        map_file_backed_address(program_headers, address).ok_or_else(|| {
            format!(
                "{kind} {entry_index} address {address:#x} is not contained in a file-backed PT_LOAD range"
            )
        })?;
    let header_end = address
        .checked_add(4)
        .ok_or_else(|| format!("{kind} {entry_index} length-field range overflows u64"))?;
    if header_end > file_backed_end {
        return Err(format!(
            "{kind} {entry_index} length field crosses PT_LOAD segment {load_index} file-backed boundary"
        ));
    }
    let length = read_u32(file, file_offset);
    if length == 0 {
        return Err(format!(
            "{kind} {entry_index} address {address:#x} points at an .eh_frame terminator"
        ));
    }
    if length == DWARF64_LENGTH_MARKER {
        return Err(format!(
            "{kind} {entry_index} address {address:#x} uses unsupported DWARF64 record length marker"
        ));
    }
    if length < 4 {
        return Err(format!(
            "{kind} {entry_index} record length {length} is too small for the 4-byte id/pointer field"
        ));
    }
    let total_size = 4_u64
        .checked_add(u64::from(length))
        .ok_or_else(|| format!("{kind} {entry_index} total record size overflows u64"))?;
    let record_end = address
        .checked_add(total_size)
        .ok_or_else(|| format!("{kind} {entry_index} record address range overflows u64"))?;
    if record_end > file_backed_end {
        return Err(format!(
            "{kind} {entry_index} record {address:#x}..{record_end:#x} exceeds PT_LOAD segment {load_index} file-backed range ending at {file_backed_end:#x}"
        ));
    }
    let file_end = file_offset
        .checked_add(
            usize::try_from(total_size)
                .map_err(|_| format!("{kind} {entry_index} record size does not fit usize"))?,
        )
        .ok_or_else(|| format!("{kind} {entry_index} file range overflows usize"))?;
    if file_end > file.len() {
        return Err(format!(
            "{kind} {entry_index} record ends at file offset {file_end}, beyond file length {}",
            file.len()
        ));
    }
    Ok(RecordEnvelope {
        file_offset,
        total_size,
    })
}

fn map_file_backed_address(
    program_headers: &[ProgramHeader],
    address: u64,
) -> Option<(usize, usize, u64)> {
    for (index, header) in program_headers.iter().enumerate() {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let file_backed_end = header.virtual_address.checked_add(header.file_size)?;
        if address < header.virtual_address || address >= file_backed_end {
            continue;
        }
        let delta = address.checked_sub(header.virtual_address)?;
        let file_offset = header.offset.checked_add(delta)?;
        return Some((index, usize::try_from(file_offset).ok()?, file_backed_end));
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

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let mut headers = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let relative = u64::from(index)
            .checked_mul(u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let offset = header
            .program_header_offset
            .checked_add(relative)
            .ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let end = offset
            .checked_add(u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| "program-header entry range overflows u64".to_owned())?;
        if end > file.len() as u64 {
            return Err(format!(
                "program header {index} ends at file offset {end}, beyond file length {}",
                file.len()
            ));
        }
        let offset = usize::try_from(offset)
            .map_err(|_| "program-header entry offset does not fit usize".to_owned())?;
        let header = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if header.file_size > header.memory_size {
            return Err(format!(
                "program header {index} has file size {} larger than memory size {}",
                header.file_size, header.memory_size
            ));
        }
        checked_file_end(
            header.offset,
            header.file_size,
            file.len(),
            &format!("program header {index}"),
        )?;
        header
            .virtual_address
            .checked_add(header.memory_size)
            .ok_or_else(|| format!("program header {index} virtual memory range overflows u64"))?;
        headers.push(header);
    }
    Ok(headers)
}

fn checked_file_end(offset: u64, size: u64, file_len: usize, what: &str) -> Result<u64, String> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| format!("{what} file range overflows u64"))?;
    if end > file_len as u64 {
        return Err(format!(
            "{what} ends at file offset {end}, beyond file length {file_len}"
        ));
    }
    Ok(end)
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
