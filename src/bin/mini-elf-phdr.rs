use mini_elf_toolchain::elf64::{Elf64Header, ELF64_PROGRAM_HEADER_SIZE};
use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;

#[derive(Clone, Copy)]
struct ProgramHeader { segment_type: u32, offset: u64, vaddr: u64, file_size: u64, memory_size: u64 }

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => { print!("{output}"); ExitCode::SUCCESS }
        Err(message) => { eprintln!("error: {message}"); ExitCode::FAILURE }
    }
}

fn run<I>(args: I) -> Result<String, String>
where I: Iterator<Item = OsString> {
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 { Ok("usage: mini-elf-phdr [--load-bias <address>] <input>...\n".to_owned()) } else { Err("usage: mini-elf-phdr [--load-bias <address>] <input>...".to_owned()) };
    }
    let mut bias = 0u64;
    let mut inputs = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let text = args[index].to_string_lossy();
        if text == "--load-bias" {
            index += 1;
            let value = args.get(index).ok_or_else(|| "--load-bias requires an address".to_owned())?;
            bias = parse_u64(&value.to_string_lossy())?;
        } else if let Some(value) = text.strip_prefix("--load-bias=") {
            bias = parse_u64(value)?;
        } else if text.starts_with('-') { return Err("usage: mini-elf-phdr [--load-bias <address>] <input>...".to_owned()); }
        else { inputs.push(args[index].clone()); }
        index += 1;
    }
    if inputs.is_empty() { return Err("usage: mini-elf-phdr [--load-bias <address>] <input>...".to_owned()); }
    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in inputs {
        let file = fs::read(&input).map_err(|e| format!("cannot read '{}': {e}", input.to_string_lossy()))?;
        let display = input.to_string_lossy().into_owned();
        let header = Elf64Header::parse(&file).map_err(|e| format!("{display}: {e}"))?;
        let rendered = format_phdr(header, &file, bias).map_err(|e| format!("{display}: {e}"))?;
        inspected.push((display, rendered));
    }
    let mut output = String::new();
    for (i, (display, rendered)) in inspected.into_iter().enumerate() {
        if i != 0 { output.push('\n'); }
        if multiple { output.push_str(&format!("File: {display}\n")); }
        output.push_str(&rendered);
    }
    Ok(output)
}

fn format_phdr(header: Elf64Header, file: &[u8], bias: u64) -> Result<String, String> {
    let headers = program_headers(header, file)?;
    let matches = headers.iter().enumerate().filter(|(_, h)| h.segment_type == PT_PHDR).collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok("No PT_PHDR segment found.\n".to_owned()),
        [(index, phdr)] => {
            let table_size = u64::from(header.program_header_count).checked_mul(u64::from(ELF64_PROGRAM_HEADER_SIZE)).ok_or_else(|| "program-header table size overflows u64".to_owned())?;
            if phdr.offset != header.program_header_offset || phdr.file_size != table_size || phdr.memory_size != table_size {
                return Err(format!("PT_PHDR segment {index} does not exactly describe the program-header table"));
            }
            let end = phdr.vaddr.checked_add(phdr.memory_size).ok_or_else(|| format!("PT_PHDR segment {index} virtual range overflows u64"))?;
            let covered = headers.iter().any(|h| h.segment_type == PT_LOAD && phdr.vaddr >= h.vaddr && end <= h.vaddr.checked_add(h.memory_size).unwrap_or(0));
            if !covered { return Err(format!("PT_PHDR segment {index} is not contained in a PT_LOAD memory range")); }
            let runtime_start = bias.checked_add(phdr.vaddr).ok_or_else(|| "PT_PHDR runtime start overflows u64".to_owned())?;
            let runtime_end = runtime_start.checked_add(phdr.memory_size).ok_or_else(|| "PT_PHDR runtime range overflows u64".to_owned())?;
            Ok(format!("PT_PHDR segment {index}: file={:#x}..{:#x} vaddr={:#x}..{:#x} runtime={:#x}..{:#x}\n", phdr.offset, phdr.offset + phdr.file_size, phdr.vaddr, end, runtime_start, runtime_end))
        }
        _ => Err(format!("multiple PT_PHDR segments found ({})", matches.len())),
    }
}

fn program_headers(header: Elf64Header, file: &[u8]) -> Result<Vec<ProgramHeader>, String> {
    let mut out = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let off = header.program_header_offset.checked_add(u64::from(index).checked_mul(u64::from(ELF64_PROGRAM_HEADER_SIZE)).ok_or_else(|| "program-header entry offset overflows u64".to_owned())?).ok_or_else(|| "program-header entry offset overflows u64".to_owned())?;
        let end = off.checked_add(u64::from(ELF64_PROGRAM_HEADER_SIZE)).ok_or_else(|| "program-header entry range overflows u64".to_owned())?;
        if end > file.len() as u64 { return Err(format!("program header {index} ends at file offset {end}, beyond file length {}", file.len())); }
        let o = usize::try_from(off).map_err(|_| "program-header entry offset does not fit usize".to_owned())?;
        let h = ProgramHeader { segment_type: read_u32(file, o), offset: read_u64(file, o + 8), vaddr: read_u64(file, o + 16), file_size: read_u64(file, o + 32), memory_size: read_u64(file, o + 40) };
        if h.file_size > h.memory_size { return Err(format!("program header {index} has file size {} larger than memory size {}", h.file_size, h.memory_size)); }
        let file_end = h.offset.checked_add(h.file_size).ok_or_else(|| format!("program header {index} file range overflows u64"))?;
        if file_end > file.len() as u64 { return Err(format!("program header {index} ends at file offset {file_end}, beyond file length {}", file.len())); }
        out.push(h);
    }
    Ok(out)
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") { u64::from_str_radix(hex, 16) } else { value.parse() };
    parsed.map_err(|_| format!("invalid load bias '{value}'"))
}
fn read_u32(b: &[u8], o: usize) -> u32 { u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) }
fn read_u64(b: &[u8], o: usize) -> u64 { u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) }
