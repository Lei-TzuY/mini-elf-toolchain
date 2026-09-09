use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_RELA_SIZE: usize = 24;
const ELF64_SYMBOL_SIZE: usize = 24;
const ET_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;
const PF_W: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const R_X86_64_COPY: u32 = 5;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_OBJECT: u8 = 1;
const STT_TLS: u8 = 6;

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    vaddr: u64,
    memsz: u64,
}

#[derive(Clone, Copy)]
struct SectionHeader {
    name: u32,
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
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
    if inputs.is_empty() {
        return Err("usage: mini-elf-copy-reloc <input>...".to_owned());
    }
    let multiple = inputs.len() > 1;
    let mut inspected = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let display = input.to_string_lossy().into_owned();
        let bytes = fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let rendered = inspect(&bytes).map_err(|error| format!("{display}: {error}"))?;
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
    if file.len() < ELF64_HEADER_SIZE {
        return Err("ELF64 header is truncated".to_owned());
    }
    if read_u16(file, 16) != ET_EXEC {
        return Err("mini-elf-copy-reloc requires an ET_EXEC image".to_owned());
    }

    let programs = program_headers(file)?;
    let sections = section_headers(file)?;
    let shstrndx = usize::from(read_u16(file, 62));
    let shstr = section_bytes(file, section_at(&sections, shstrndx, "section-name string table")?, "section-name string table")?;

    let mut rela_index = None;
    for (index, section) in sections.iter().copied().enumerate() {
        if section_name(shstr, section.name, index)? == ".rela.dyn" {
            if rela_index.replace(index).is_some() {
                return Err("multiple .rela.dyn sections are unsupported".to_owned());
            }
        }
    }
    let rela_index = rela_index.ok_or_else(|| "missing .rela.dyn section".to_owned())?;
    let rela_header = sections[rela_index];
    if rela_header.kind != SHT_RELA {
        return Err(".rela.dyn is not SHT_RELA".to_owned());
    }
    if rela_header.entsize != ELF64_RELA_SIZE as u64 {
        return Err(format!(
            ".rela.dyn entry size {} is unsupported, expected {ELF64_RELA_SIZE}",
            rela_header.entsize
        ));
    }
    if rela_header.size % rela_header.entsize != 0 {
        return Err(".rela.dyn size is not a whole number of entries".to_owned());
    }

    let dynsym_index = usize::try_from(rela_header.link)
        .map_err(|_| ".rela.dyn linked symbol-table index does not fit usize".to_owned())?;
    let dynsym_header = section_at(&sections, dynsym_index, ".rela.dyn linked symbol table")?;
    if dynsym_header.kind != SHT_DYNSYM {
        return Err(".rela.dyn does not link to SHT_DYNSYM".to_owned());
    }
    if dynsym_header.entsize != ELF64_SYMBOL_SIZE as u64 {
        return Err(format!(
            "dynamic symbol entry size {} is unsupported, expected {ELF64_SYMBOL_SIZE}",
            dynsym_header.entsize
        ));
    }
    if dynsym_header.size % dynsym_header.entsize != 0 {
        return Err("dynamic symbol table size is not a whole number of entries".to_owned());
    }
    let dynstr_index = usize::try_from(dynsym_header.link)
        .map_err(|_| "dynamic string-table index does not fit usize".to_owned())?;
    let dynstr_header = section_at(&sections, dynstr_index, "dynamic string table")?;
    if dynstr_header.kind != SHT_STRTAB {
        return Err("dynamic symbol table does not link to SHT_STRTAB".to_owned());
    }

    let rela = section_bytes(file, &rela_header, ".rela.dyn")?;
    let dynsym = section_bytes(file, dynsym_header, "dynamic symbol table")?;
    let dynstr = section_bytes(file, dynstr_header, "dynamic string table")?;
    let symbol_count = dynsym.len() / ELF64_SYMBOL_SIZE;

    let mut output = format!(
        "Validated R_X86_64_COPY relocations: entries={} symbols={symbol_count}\n",
        rela.len() / ELF64_RELA_SIZE
    );
    let mut found = 0usize;
    for (index, entry) in rela.chunks_exact(ELF64_RELA_SIZE).enumerate() {
        let target = read_u64(entry, 0);
        let info = read_u64(entry, 8);
        let symbol_index_u64 = info >> 32;
        if info as u32 != R_X86_64_COPY {
            continue;
        }
        let symbol_index = usize::try_from(symbol_index_u64)
            .map_err(|_| format!("COPY relocation {index} symbol index does not fit usize"))?;
        if symbol_index == 0 || symbol_index >= symbol_count {
            return Err(format!(
                "COPY relocation {index} references invalid dynamic symbol index {symbol_index_u64} (count {symbol_count})"
            ));
        }
        let addend = read_i64(entry, 16);
        if addend != 0 {
            return Err(format!(
                "COPY relocation {index} has nonzero RELA addend {addend}; x86-64 COPY uses a zero addend"
            ));
        }
        let symbol_offset = symbol_index
            .checked_mul(ELF64_SYMBOL_SIZE)
            .ok_or_else(|| format!("COPY relocation {index} symbol offset overflows usize"))?;
        let symbol = &dynsym[symbol_offset..symbol_offset + ELF64_SYMBOL_SIZE];
        let name_offset = read_u32(symbol, 0);
        let symbol_info = symbol[4];
        let section_index = read_u16(symbol, 6);
        let value = read_u64(symbol, 8);
        let size = read_u64(symbol, 16);
        if section_index == SHN_UNDEF {
            return Err(format!(
                "COPY relocation {index} destination symbol is undefined; the executable must define the copy destination"
            ));
        }
        if section_index == SHN_ABS {
            return Err(format!(
                "COPY relocation {index} destination symbol is absolute, which cannot describe writable copy storage"
            ));
        }
        let symbol_type = symbol_info & 0x0f;
        if symbol_type == STT_TLS {
            return Err(format!(
                "COPY relocation {index} references a TLS symbol; TLS COPY semantics are unsupported"
            ));
        }
        if symbol_type != STT_OBJECT {
            return Err(format!(
                "COPY relocation {index} destination symbol type {symbol_type} is unsupported, expected STT_OBJECT"
            ));
        }
        if size == 0 {
            return Err(format!("COPY relocation {index} has zero-sized destination symbol"));
        }
        if value != target {
            return Err(format!(
                "COPY relocation {index} target {target:#x} does not equal destination symbol value {value:#x}"
            ));
        }
        map_writable_memory(&programs, target, size, &format!("COPY relocation {index} destination"))?;
        let name = dynamic_string(dynstr, name_offset, symbol_index)?;
        output.push_str(&format!(
            "  index={index} symbol={symbol_index}:{name} destination={target:#018x} size={size} source=external\n"
        ));
        found += 1;
    }
    if found == 0 {
        return Err(".rela.dyn contains no R_X86_64_COPY relocations".to_owned());
    }
    Ok(output)
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
        let kind = read_u32(file, offset);
        let flags = read_u32(file, offset + 4);
        let vaddr = read_u64(file, offset + 16);
        let filesz = read_u64(file, offset + 32);
        let memsz = read_u64(file, offset + 40);
        if filesz > memsz {
            return Err(format!("program header {index} file size exceeds memory size"));
        }
        vaddr
            .checked_add(memsz)
            .ok_or_else(|| format!("program header {index} memory range overflows u64"))?;
        headers.push(ProgramHeader {
            kind,
            flags,
            vaddr,
            memsz,
        });
    }
    Ok(headers)
}

fn section_headers(file: &[u8]) -> Result<Vec<SectionHeader>, String> {
    let shoff = usize::try_from(read_u64(file, 40))
        .map_err(|_| "section-header offset does not fit usize".to_owned())?;
    let shentsize = usize::from(read_u16(file, 58));
    let shnum = usize::from(read_u16(file, 60));
    if shentsize != ELF64_SECTION_HEADER_SIZE {
        return Err(format!(
            "unsupported ELF64 section-header size {shentsize}, expected {ELF64_SECTION_HEADER_SIZE}"
        ));
    }
    let table_size = shnum
        .checked_mul(shentsize)
        .ok_or_else(|| "section-header table size overflows usize".to_owned())?;
    let table_end = shoff
        .checked_add(table_size)
        .ok_or_else(|| "section-header table range overflows usize".to_owned())?;
    if table_end > file.len() {
        return Err("section-header table exceeds input".to_owned());
    }
    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let offset = shoff + index * shentsize;
        let header = SectionHeader {
            name: read_u32(file, offset),
            kind: read_u32(file, offset + 4),
            offset: read_u64(file, offset + 24),
            size: read_u64(file, offset + 32),
            link: read_u32(file, offset + 40),
            entsize: read_u64(file, offset + 56),
        };
        let start = usize::try_from(header.offset)
            .map_err(|_| format!("section {index} file offset does not fit usize"))?;
        let size = usize::try_from(header.size)
            .map_err(|_| format!("section {index} file size does not fit usize"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| format!("section {index} file range overflows usize"))?;
        if header.kind != 8 && end > file.len() {
            return Err(format!("section {index} file range exceeds input"));
        }
        sections.push(header);
    }
    Ok(sections)
}

fn section_at<'a>(sections: &'a [SectionHeader], index: usize, label: &str) -> Result<&'a SectionHeader, String> {
    sections
        .get(index)
        .ok_or_else(|| format!("{label} index {index} is outside section-header table"))
}

fn section_bytes<'a>(file: &'a [u8], section: &SectionHeader, label: &str) -> Result<&'a [u8], String> {
    let start = usize::try_from(section.offset)
        .map_err(|_| format!("{label} offset does not fit usize"))?;
    let size = usize::try_from(section.size)
        .map_err(|_| format!("{label} size does not fit usize"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| format!("{label} range overflows usize"))?;
    if end > file.len() {
        return Err(format!("{label} range exceeds input"));
    }
    Ok(&file[start..end])
}

fn section_name<'a>(shstr: &'a [u8], offset: u32, index: usize) -> Result<&'a str, String> {
    let start = usize::try_from(offset)
        .map_err(|_| format!("section {index} name offset does not fit usize"))?;
    if start >= shstr.len() {
        return Err(format!("section {index} name offset is outside section-name string table"));
    }
    let tail = &shstr[start..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("section {index} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map_err(|_| format!("section {index} name is not valid UTF-8"))
}

fn dynamic_string(strtab: &[u8], offset: u32, symbol_index: usize) -> Result<String, String> {
    let start = usize::try_from(offset)
        .map_err(|_| format!("dynamic symbol {symbol_index} name offset does not fit usize"))?;
    if start >= strtab.len() {
        return Err(format!("dynamic symbol {symbol_index} name offset is outside dynamic string table"));
    }
    let tail = &strtab[start..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("dynamic symbol {symbol_index} name is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| format!("dynamic symbol {symbol_index} name is not valid UTF-8"))
}

fn map_writable_memory(headers: &[ProgramHeader], address: u64, size: u64, label: &str) -> Result<(), String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| format!("{label} range overflows u64"))?;
    for header in headers.iter().filter(|header| header.kind == PT_LOAD) {
        if header.flags & PF_W == 0 {
            continue;
        }
        let load_end = header.vaddr + header.memsz;
        if address >= header.vaddr && end <= load_end {
            return Ok(());
        }
    }
    Err(format!(
        "{label} [{address:#x},{end:#x}) is not contained in a writable PT_LOAD memory range"
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
