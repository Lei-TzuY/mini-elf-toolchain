use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_DYNAMIC_ENTRY_SIZE: usize = 16;
const ELF64_RELA_SIZE: usize = 24;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const R_X86_64_IRELATIVE: u32 = 37;

#[derive(Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
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

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    let (load_bias, inputs) = parse_args(&args)?;
    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let display = input.to_string_lossy().into_owned();
        let file = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let rendered = inspect(&file, load_bias).map_err(|error| format!("{display}: {error}"))?;
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

fn parse_args(args: &[OsString]) -> Result<(u64, Vec<&OsString>), String> {
    let mut load_bias = None;
    let mut inputs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let text = args[index].to_string_lossy();
        if text == "--load-bias" {
            index += 1;
            if index >= args.len() {
                return Err(usage());
            }
            if load_bias.is_some() {
                return Err("duplicate --load-bias option".to_owned());
            }
            load_bias = Some(parse_u64(&args[index].to_string_lossy(), "load bias")?);
        } else if let Some(value) = text.strip_prefix("--load-bias=") {
            if load_bias.is_some() {
                return Err("duplicate --load-bias option".to_owned());
            }
            load_bias = Some(parse_u64(value, "load bias")?);
        } else if text.starts_with('-') {
            return Err(usage());
        } else {
            inputs.push(&args[index]);
        }
        index += 1;
    }
    if inputs.is_empty() {
        return Err(usage());
    }
    Ok((load_bias.ok_or_else(usage)?, inputs))
}

fn usage() -> String {
    "usage: mini-elf-dynrela-irelative --load-bias <address> <input>...".to_owned()
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
        text.parse::<u64>()
            .map_err(|_| format!("invalid {label} '{text}'"))
    }
}

fn inspect(file: &[u8], load_bias: u64) -> Result<String, String> {
    Elf64Header::parse(file).map_err(|error| error.to_string())?;
    if file.len() < 64 {
        return Err("ELF64 header is truncated".to_owned());
    }
    if read_u16(file, 16) != ET_DYN {
        return Err("mini-elf-dynrela-irelative requires an ET_DYN image".to_owned());
    }

    let headers = program_headers(file)?;
    let dynamic = unique_dynamic(&headers)?;
    let dynamic_bytes = program_bytes(file, dynamic, "PT_DYNAMIC")?;
    let (rela_address, rela_size, rela_entry_size) = dynamic_rela(dynamic_bytes)?;
    if rela_entry_size != ELF64_RELA_SIZE as u64 {
        return Err(format!(
            "DT_RELAENT value {rela_entry_size} is unsupported, expected {ELF64_RELA_SIZE}"
        ));
    }
    if rela_size % rela_entry_size != 0 {
        return Err("DT_RELASZ is not a whole number of DT_RELAENT entries".to_owned());
    }
    let rela_bytes = map_file_backed_range(
        file,
        &headers,
        rela_address,
        rela_size,
        0,
        "DT_RELA table",
    )?;

    let mut output = format!(
        "Validated R_X86_64_IRELATIVE relocations: load-bias={load_bias:#018x} rela={rela_address:#018x} entries={}\n",
        rela_size / rela_entry_size
    );
    let mut found = 0usize;
    for (index, entry) in rela_bytes.chunks_exact(ELF64_RELA_SIZE).enumerate() {
        let offset = read_u64(entry, 0);
        let info = read_u64(entry, 8);
        let symbol = info >> 32;
        let relocation_type = info as u32;
        if relocation_type != R_X86_64_IRELATIVE {
            continue;
        }
        if symbol != 0 {
            return Err(format!(
                "R_X86_64_IRELATIVE relocation {index} has nonzero symbol index {symbol}"
            ));
        }
        map_memory_range(&headers, offset, 8, PF_W, &format!("IRELATIVE relocation {index} target"))?;
        let addend = read_i64(entry, 16);
        let resolver_offset = u64::try_from(addend).map_err(|_| {
            format!("R_X86_64_IRELATIVE relocation {index} has negative resolver addend {addend}")
        })?;
        map_file_backed_range(
            file,
            &headers,
            resolver_offset,
            1,
            PF_X,
            &format!("IRELATIVE relocation {index} resolver"),
        )?;
        let runtime_target = load_bias
            .checked_add(offset)
            .ok_or_else(|| format!("IRELATIVE relocation {index} runtime target overflows u64"))?;
        let runtime_resolver = load_bias
            .checked_add(resolver_offset)
            .ok_or_else(|| format!("IRELATIVE relocation {index} runtime resolver overflows u64"))?;
        output.push_str(&format!(
            "  index={index} target=B+{offset:#018x}=>{runtime_target:#018x} resolver=B+{resolver_offset:#018x}=>{runtime_resolver:#018x}\n"
        ));
        found += 1;
    }
    if found == 0 {
        return Err("DT_RELA contains no R_X86_64_IRELATIVE relocations".to_owned());
    }
    Ok(output)
}

fn dynamic_rela(bytes: &[u8]) -> Result<(u64, u64, u64), String> {
    if bytes.len() % ELF64_DYNAMIC_ENTRY_SIZE != 0 {
        return Err("PT_DYNAMIC size is not a whole number of ELF64 dynamic entries".to_owned());
    }
    let mut rela = None;
    let mut relasz = None;
    let mut relaent = None;
    let mut terminated = false;
    for (index, entry) in bytes.chunks_exact(ELF64_DYNAMIC_ENTRY_SIZE).enumerate() {
        let tag = read_i64(entry, 0);
        let value = read_u64(entry, 8);
        if terminated {
            if tag != DT_NULL || value != 0 {
                return Err(format!("PT_DYNAMIC entry {index} contains data after DT_NULL"));
            }
            continue;
        }
        if tag == DT_NULL {
            terminated = true;
            continue;
        }
        match tag {
            DT_RELA => set_once(&mut rela, value, "DT_RELA")?,
            DT_RELASZ => set_once(&mut relasz, value, "DT_RELASZ")?,
            DT_RELAENT => set_once(&mut relaent, value, "DT_RELAENT")?,
            _ => {}
        }
    }
    if !terminated {
        return Err("PT_DYNAMIC is missing a DT_NULL terminator".to_owned());
    }
    match (rela, relasz, relaent) {
        (Some(rela), Some(relasz), Some(relaent)) => Ok((rela, relasz, relaent)),
        (None, None, None) => Err("PT_DYNAMIC has no DT_RELA metadata".to_owned()),
        _ => Err("PT_DYNAMIC must provide DT_RELA, DT_RELASZ, and DT_RELAENT together".to_owned()),
    }
}

fn set_once(slot: &mut Option<u64>, value: u64, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("PT_DYNAMIC contains duplicate {label}"));
    }
    Ok(())
}

fn unique_dynamic(headers: &[ProgramHeader]) -> Result<ProgramHeader, String> {
    let mut dynamic = None;
    for header in headers.iter().copied().filter(|header| header.segment_type == PT_DYNAMIC) {
        if dynamic.replace(header).is_some() {
            return Err("multiple PT_DYNAMIC program headers are unsupported".to_owned());
        }
    }
    dynamic.ok_or_else(|| "missing PT_DYNAMIC program header".to_owned())
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
            flags: read_u32(file, offset + 4),
            offset: read_u64(file, offset + 8),
            vaddr: read_u64(file, offset + 16),
            filesz: read_u64(file, offset + 32),
            memsz: read_u64(file, offset + 40),
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
        header.vaddr.checked_add(header.filesz).ok_or_else(|| {
            format!("program header {index} file-backed virtual range overflows u64")
        })?;
        header.vaddr.checked_add(header.memsz).ok_or_else(|| {
            format!("program header {index} memory virtual range overflows u64")
        })?;
        headers.push(header);
    }
    Ok(headers)
}

fn program_bytes<'a>(file: &'a [u8], header: ProgramHeader, label: &str) -> Result<&'a [u8], String> {
    let start = usize::try_from(header.offset).map_err(|_| format!("{label} offset does not fit usize"))?;
    let size = usize::try_from(header.filesz).map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{label} file range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{label} file range exceeds input"));
    }
    Ok(&file[start..end])
}

fn map_file_backed_range<'a>(
    file: &'a [u8],
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
    required_flags: u32,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers.iter().filter(|header| header.segment_type == PT_LOAD) {
        if header.flags & required_flags != required_flags {
            continue;
        }
        let load_end = header.vaddr + header.filesz;
        if address < header.vaddr || end > load_end {
            continue;
        }
        let relative = address - header.vaddr;
        let file_offset = header
            .offset
            .checked_add(relative)
            .ok_or_else(|| format!("{label} file offset overflows u64"))?;
        let start = usize::try_from(file_offset)
            .map_err(|_| format!("{label} file offset does not fit usize"))?;
        let width = usize::try_from(size).map_err(|_| format!("{label} size does not fit usize"))?;
        let file_end = start
            .checked_add(width)
            .ok_or_else(|| format!("{label} file range overflows usize"))?;
        if file_end > file.len() {
            return Err(format!("{label} file range exceeds input"));
        }
        return Ok(&file[start..file_end]);
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a matching file-backed PT_LOAD"
    ))
}

fn map_memory_range(
    headers: &[ProgramHeader],
    address: u64,
    size: u64,
    required_flags: u32,
    label: &str,
) -> Result<(), String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} virtual range overflows u64"))?;
    for header in headers.iter().filter(|header| header.segment_type == PT_LOAD) {
        if header.flags & required_flags != required_flags {
            continue;
        }
        let load_end = header.vaddr + header.memsz;
        if address >= header.vaddr && end <= load_end {
            return Ok(());
        }
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a matching PT_LOAD memory range"
    ))
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

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
