use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const PT_LOAD: u32 = 1;
const SHF_ALLOC: u64 = 0x2;
const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_INDIRECT_PCREL_SDATA4: u8 = 0x9b;
const TYPE_ENTRY_SIZE: usize = 4;
const INDIRECT_POINTER_SIZE: u64 = 8;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

#[derive(Clone, Copy)]
struct SectionHeader {
    name: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
}

#[derive(Clone, Copy)]
struct CallSiteEntry {
    action: u64,
}

#[derive(Clone, Copy)]
struct ActionRecord {
    offset: usize,
    end: usize,
    type_filter: i64,
    next_displacement: i64,
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
        return Err("usage: mini-elf-lsda-ttype <input>...".to_owned());
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

    let program_headers = program_headers(file)?;
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
        return Err("extended ELF section numbering is unsupported".to_owned());
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
        if name == ".gcc_except_table" && lsda.replace((index, header)).is_some() {
            return Err("multiple .gcc_except_table sections are unsupported".to_owned());
        }
    }
    let (section_index, section) =
        lsda.ok_or_else(|| "missing .gcc_except_table section".to_owned())?;
    if section.flags & SHF_ALLOC == 0 {
        return Err(format!(
            ".gcc_except_table section {section_index} is not SHF_ALLOC"
        ));
    }
    let bytes = section_bytes(file, section, ".gcc_except_table")?;
    if bytes.len() < 6 {
        return Err(".gcc_except_table is too small for a bounded typed LSDA".to_owned());
    }

    if bytes[0] != DW_EH_PE_OMIT {
        return Err(format!(
            "unsupported LSDA LPStart encoding {:#04x}; expected DW_EH_PE_omit",
            bytes[0]
        ));
    }
    if bytes[1] != DW_EH_PE_INDIRECT_PCREL_SDATA4 {
        return Err(format!(
            "unsupported LSDA type-table encoding {:#04x}; expected indirect|pcrel|sdata4 (0x9b)",
            bytes[1]
        ));
    }

    let (ttype_offset, after_ttype_offset) =
        read_uleb(bytes, 2, bytes.len(), "LSDA type-table offset")?;
    let ttype_relative = usize::try_from(ttype_offset)
        .map_err(|_| "LSDA type-table offset does not fit usize".to_owned())?;
    let ttype_base = after_ttype_offset
        .checked_add(ttype_relative)
        .ok_or_else(|| "LSDA type-table base overflows usize".to_owned())?;
    if ttype_base > bytes.len() {
        return Err(format!(
            "LSDA type-table base {ttype_base:#x} exceeds .gcc_except_table size {:#x}",
            bytes.len()
        ));
    }

    if after_ttype_offset >= bytes.len() {
        return Err("LSDA is truncated before call-site encoding".to_owned());
    }
    if bytes[after_ttype_offset] != DW_EH_PE_ULEB128 {
        return Err(format!(
            "unsupported LSDA call-site encoding {:#04x}; expected uleb128",
            bytes[after_ttype_offset]
        ));
    }
    let (call_site_bytes, table_start) = read_uleb(
        bytes,
        after_ttype_offset + 1,
        bytes.len(),
        "LSDA call-site table length",
    )?;
    let table_len = usize::try_from(call_site_bytes)
        .map_err(|_| "LSDA call-site table length does not fit usize".to_owned())?;
    let table_end = table_start
        .checked_add(table_len)
        .ok_or_else(|| "LSDA call-site table range overflows usize".to_owned())?;
    if table_end > ttype_base || table_end > bytes.len() {
        return Err(format!(
            "LSDA call-site table ending at {table_end:#x} crosses type-table base {ttype_base:#x}"
        ));
    }

    let entries = parse_call_sites(bytes, table_start, table_end)?;
    let mut records = Vec::new();
    for (entry_index, entry) in entries.iter().enumerate() {
        records.extend(parse_action_chain(
            bytes,
            table_end,
            ttype_base,
            entry.action,
            entry_index,
        )?);
    }

    let max_filter = records
        .iter()
        .map(|record| record.type_filter)
        .max()
        .unwrap_or(0);
    let type_table_start = if max_filter == 0 {
        ttype_base
    } else {
        let max_filter = usize::try_from(max_filter)
            .map_err(|_| "positive LSDA type filter does not fit usize".to_owned())?;
        let bytes_needed = max_filter
            .checked_mul(TYPE_ENTRY_SIZE)
            .ok_or_else(|| "LSDA type-table index byte count overflows usize".to_owned())?;
        ttype_base.checked_sub(bytes_needed).ok_or_else(|| {
            format!("LSDA type-table index {max_filter} underflows the .gcc_except_table section")
        })?
    };
    if type_table_start < table_end {
        return Err(format!(
            "LSDA type-table entries begin at {type_table_start:#x}, overlapping the call-site table ending at {table_end:#x}"
        ));
    }
    if records.iter().any(|record| record.end > type_table_start) {
        return Err(format!(
            "LSDA action records overlap type-table entries beginning at {type_table_start:#x}"
        ));
    }

    let mut output = format!(
        "Validated GNU LSDA type table: section={} address={:#018x} offset={:#x} size={:#x} ttype-encoding=0x9b ttype-base={:#x} max-type-index={}\n",
        section_index,
        section.addr,
        section.offset,
        section.size,
        ttype_base,
        max_filter
    );
    for (index, record) in records.iter().enumerate() {
        if record.type_filter > 0 {
            let type_index = usize::try_from(record.type_filter)
                .map_err(|_| "positive LSDA type filter does not fit usize".to_owned())?;
            let entry_end = ttype_base
                .checked_sub(
                    (type_index - 1)
                        .checked_mul(TYPE_ENTRY_SIZE)
                        .ok_or_else(|| "LSDA type-table entry offset overflows usize".to_owned())?,
                )
                .ok_or_else(|| "LSDA type-table entry end underflows usize".to_owned())?;
            let entry_start = entry_end
                .checked_sub(TYPE_ENTRY_SIZE)
                .ok_or_else(|| "LSDA type-table entry start underflows usize".to_owned())?;
            let raw = read_i32(bytes, entry_start);
            let entry_address = section
                .addr
                .checked_add(
                    u64::try_from(entry_start)
                        .map_err(|_| "LSDA type-table entry offset does not fit u64".to_owned())?,
                )
                .ok_or_else(|| "LSDA type-table entry address overflows u64".to_owned())?;
            let slot_address = checked_add_signed_u64(entry_address, i64::from(raw)).ok_or_else(|| {
                format!(
                    "LSDA type-table index {type_index} PC-relative pointer-slot address overflows u64"
                )
            })?;
            let slot_offset = map_file_backed_range(
                file,
                &program_headers,
                slot_address,
                INDIRECT_POINTER_SIZE,
                &format!("LSDA type-table index {type_index} indirect pointer slot"),
            )?;
            let target = read_u64(file, slot_offset);
            map_file_backed_range(
                file,
                &program_headers,
                target,
                1,
                &format!("LSDA type-table index {type_index} indirect target"),
            )?;
            output.push_str(&format!(
                "  action[{index}]: offset={} type-index={} type-entry=[{:#x},{:#x}) raw-sdata4={} slot={:#018x} target={:#018x} next={}\n",
                record.offset,
                record.type_filter,
                entry_start,
                entry_end,
                raw,
                slot_address,
                target,
                record.next_displacement
            ));
        }
    }
    Ok(output)
}

fn parse_call_sites(
    bytes: &[u8],
    mut cursor: usize,
    table_end: usize,
) -> Result<Vec<CallSiteEntry>, String> {
    let mut entries = Vec::new();
    while cursor < table_end {
        let entry_index = entries.len();
        for label in ["start", "length", "landing-pad"] {
            let (_, next) = read_uleb(
                bytes,
                cursor,
                table_end,
                &format!("LSDA call-site entry {entry_index} {label}"),
            )?;
            cursor = next;
        }
        let (action, next) = read_uleb(
            bytes,
            cursor,
            table_end,
            &format!("LSDA call-site entry {entry_index} action"),
        )?;
        cursor = next;
        entries.push(CallSiteEntry { action });
    }
    Ok(entries)
}

fn parse_action_chain(
    bytes: &[u8],
    action_table_start: usize,
    ttype_base: usize,
    action: u64,
    entry_index: usize,
) -> Result<Vec<ActionRecord>, String> {
    if action == 0 {
        return Ok(Vec::new());
    }
    let relative = usize::try_from(action - 1).map_err(|_| {
        format!("LSDA call-site entry {entry_index} action offset does not fit usize")
    })?;
    let mut cursor = action_table_start.checked_add(relative).ok_or_else(|| {
        format!("LSDA call-site entry {entry_index} action offset overflows usize")
    })?;
    if cursor >= ttype_base {
        return Err(format!(
            "LSDA call-site entry {entry_index} action offset {action} is outside the action table"
        ));
    }

    let mut seen = Vec::new();
    let mut records = Vec::new();
    loop {
        if seen.contains(&cursor) {
            return Err(format!(
                "LSDA call-site entry {entry_index} action chain contains a cycle at section offset {cursor:#x}"
            ));
        }
        seen.push(cursor);
        let one_based_offset = cursor
            .checked_sub(action_table_start)
            .and_then(|offset| offset.checked_add(1))
            .ok_or_else(|| "LSDA action record offset overflows usize".to_owned())?;
        let (type_filter, after_filter) = read_sleb(
            bytes,
            cursor,
            ttype_base,
            &format!("LSDA action record {one_based_offset} type filter"),
        )?;
        if type_filter < 0 {
            return Err(format!(
                "LSDA action record {one_based_offset} negative type filter {type_filter} requires exception-specification semantics"
            ));
        }
        let (next_displacement, end) = read_sleb(
            bytes,
            after_filter,
            ttype_base,
            &format!("LSDA action record {one_based_offset} next displacement"),
        )?;
        records.push(ActionRecord {
            offset: one_based_offset,
            end,
            type_filter,
            next_displacement,
        });
        if next_displacement == 0 {
            break;
        }
        cursor = checked_add_signed(after_filter, next_displacement).ok_or_else(|| {
            format!(
                "LSDA action record {one_based_offset} next displacement overflows section offset"
            )
        })?;
        if cursor < action_table_start || cursor >= ttype_base {
            return Err(format!(
                "LSDA action record {one_based_offset} next displacement leaves the action table"
            ));
        }
    }
    Ok(records)
}

fn checked_add_signed(base: usize, displacement: i64) -> Option<usize> {
    let base = i128::try_from(base).ok()?;
    let next = base.checked_add(i128::from(displacement))?;
    usize::try_from(next).ok()
}

fn checked_add_signed_u64(base: u64, displacement: i64) -> Option<u64> {
    let base = i128::from(base);
    let next = base.checked_add(i128::from(displacement))?;
    u64::try_from(next).ok()
}

fn read_uleb(
    bytes: &[u8],
    mut cursor: usize,
    end: usize,
    label: &str,
) -> Result<(u64, usize), String> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        if cursor >= end {
            return Err(format!("{label} is truncated"));
        }
        let byte = bytes[cursor];
        cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift == 63 && payload > 1 {
            return Err(format!("{label} overflows u64"));
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok((value, cursor));
        }
    }
    Err(format!("{label} overflows u64"))
}

fn read_sleb(
    bytes: &[u8],
    mut cursor: usize,
    end: usize,
    label: &str,
) -> Result<(i64, usize), String> {
    let mut value = 0_i128;
    let mut shift = 0_u32;
    loop {
        if cursor >= end {
            return Err(format!("{label} is truncated"));
        }
        let byte = bytes[cursor];
        cursor += 1;
        value |= i128::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if byte & 0x40 != 0 {
                value |= (!0_i128) << shift;
            }
            return i64::try_from(value)
                .map(|value| (value, cursor))
                .map_err(|_| format!("{label} overflows i64"));
        }
        if shift >= 70 {
            return Err(format!("{label} overflows i64"));
        }
    }
}

fn program_headers(file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let phoff = usize::try_from(read_u64(file, 32))
        .map_err(|_| "program-header offset does not fit usize".to_owned())?;
    let phentsize = usize::from(read_u16(file, 54));
    let phnum = usize::from(read_u16(file, 56));
    if phentsize != ELF64_PROGRAM_HEADER_SIZE {
        return Err(format!(
            "unsupported ELF64 program-header size {phentsize}, expected {ELF64_PROGRAM_HEADER_SIZE}"
        ));
    }
    if phnum == 0 {
        return Err("missing program headers for LSDA pointer mapping".to_owned());
    }
    let table_size = phnum
        .checked_mul(phentsize)
        .ok_or_else(|| "program-header table size overflows usize".to_owned())?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or_else(|| "program-header table range overflows usize".to_owned())?;
    if table_end > file.len() {
        return Err("program-header table exceeds input".to_owned());
    }

    let mut headers = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let header = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            vaddr: read_u64(file, offset + 16),
            filesz: read_u64(file, offset + 32),
        };
        let file_start = usize::try_from(header.offset)
            .map_err(|_| format!("program header {index} file offset does not fit usize"))?;
        let file_size = usize::try_from(header.filesz)
            .map_err(|_| format!("program header {index} file size does not fit usize"))?;
        let file_end = file_start
            .checked_add(file_size)
            .ok_or_else(|| format!("program header {index} file range overflows usize"))?;
        if file_end > file.len() {
            return Err(format!("program header {index} file range exceeds input"));
        }
        header
            .vaddr
            .checked_add(header.filesz)
            .ok_or_else(|| format!("program header {index} file-backed virtual range overflows u64"))?;
        headers.push(header);
    }
    Ok(headers)
}

fn map_file_backed_range(
    file: &[u8],
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
    label: &str,
) -> Result<usize, String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers {
        if header.segment_type != PT_LOAD {
            continue;
        }
        let load_end = header
            .vaddr
            .checked_add(header.filesz)
            .ok_or_else(|| "PT_LOAD file-backed virtual range overflows u64".to_owned())?;
        if address < header.vaddr || end > load_end {
            continue;
        }
        let relative = address - header.vaddr;
        let file_offset = header
            .offset
            .checked_add(relative)
            .ok_or_else(|| format!("{label} file offset overflows u64"))?;
        let file_offset = usize::try_from(file_offset)
            .map_err(|_| format!("{label} file offset does not fit usize"))?;
        let width = usize::try_from(size).map_err(|_| format!("{label} size does not fit usize"))?;
        let file_end = file_offset
            .checked_add(width)
            .ok_or_else(|| format!("{label} file range overflows usize"))?;
        if file_end > file.len() {
            return Err(format!("{label} file range exceeds input"));
        }
        return Ok(file_offset);
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a file-backed PT_LOAD range"
    ))
}

fn section_headers(
    file: &[u8],
    shoff: u64,
    shentsize: usize,
    shnum: usize,
) -> Result<Vec<SectionHeader>, String> {
    let shoff = usize::try_from(shoff)
        .map_err(|_| "section-header offset does not fit usize".to_owned())?;
    let table_size = shnum
        .checked_mul(shentsize)
        .ok_or_else(|| "section-header table size overflows usize".to_owned())?;
    let table_end = shoff
        .checked_add(table_size)
        .ok_or_else(|| "section-header table range overflows usize".to_owned())?;
    if table_end > file.len() {
        return Err("section-header table exceeds input".to_owned());
    }
    let mut headers = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let offset = shoff + index * shentsize;
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
    let size =
        usize::try_from(section.size).map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{label} file range exceeds input"));
    }
    Ok(&file[start..end])
}

fn section_name(table: &[u8], name_offset: u32, index: usize) -> Result<&str, String> {
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

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn read_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
