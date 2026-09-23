use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::elf64::{Elf64Header, ElfError, ELF64_PROGRAM_HEADER_SIZE};

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_SYMBOL_SIZE: u64 = 24;
const SHN_UNDEF: u16 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STV_INTERNAL: u8 = 1;
const STV_HIDDEN: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicProviderMetadata {
    pub soname: Vec<u8>,
    pub exports: BTreeMap<Vec<u8>, BTreeSet<u8>>,
}

#[derive(Debug)]
pub enum DynamicProviderError {
    Elf(ElfError),
    Malformed(String),
}

impl fmt::Display for DynamicProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(source) => write!(f, "{source}"),
            Self::Malformed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DynamicProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Elf(source) => Some(source),
            Self::Malformed(_) => None,
        }
    }
}

impl From<ElfError> for DynamicProviderError {
    fn from(source: ElfError) -> Self {
        Self::Elf(source)
    }
}

#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

#[derive(Debug, Clone, Copy)]
struct DynamicEntry {
    tag: i64,
    value: u64,
}

pub fn inspect_dynamic_provider(
    file: &[u8],
) -> Result<DynamicProviderMetadata, DynamicProviderError> {
    let header = Elf64Header::parse(file)?;
    if header.elf_type != ET_DYN {
        return Err(malformed(format!(
            "provider ELF type {} is not ET_DYN",
            header.elf_type
        )));
    }

    let headers = program_headers(header, file)?;
    let entries = dynamic_entries(&headers, file)?;
    let strtab_address = required_unique_tag(&entries, DT_STRTAB, "DT_STRTAB")?;
    let strsz = required_unique_tag(&entries, DT_STRSZ, "DT_STRSZ")?;
    let symtab_address = required_unique_tag(&entries, DT_SYMTAB, "DT_SYMTAB")?;
    let syment = required_unique_tag(&entries, DT_SYMENT, "DT_SYMENT")?;
    let hash_address = required_unique_tag(&entries, DT_HASH, "DT_HASH")?;
    let soname_offset = required_unique_tag(&entries, DT_SONAME, "DT_SONAME")?;

    if syment != ELF64_SYMBOL_SIZE {
        return Err(malformed(format!(
            "provider DT_SYMENT is {syment}, expected {ELF64_SYMBOL_SIZE}"
        )));
    }

    let strtab_offset = map_virtual_range(
        &headers,
        file.len(),
        strtab_address,
        strsz,
        "provider DT_STRTAB",
    )?;
    let soname = dynamic_string(
        file,
        strtab_offset,
        strsz,
        soname_offset,
        "provider DT_SONAME",
    )?;
    if soname.is_empty() {
        return Err(malformed("provider DT_SONAME is empty"));
    }

    let hash_header = map_virtual_range(
        &headers,
        file.len(),
        hash_address,
        8,
        "provider DT_HASH header",
    )?;
    let hash_header = usize::try_from(hash_header)
        .map_err(|_| malformed("provider DT_HASH file offset does not fit usize"))?;
    let bucket_count = u64::from(read_u32(file, hash_header));
    let symbol_count = u64::from(read_u32(file, hash_header + 4));
    if bucket_count == 0 {
        return Err(malformed("provider DT_HASH reports zero buckets"));
    }
    if symbol_count == 0 {
        return Err(malformed("provider DT_HASH reports zero dynamic symbols"));
    }
    let hash_words = 2_u64
        .checked_add(bucket_count)
        .and_then(|count| count.checked_add(symbol_count))
        .ok_or_else(|| malformed("provider DT_HASH word count overflows u64"))?;
    let hash_size = hash_words
        .checked_mul(4)
        .ok_or_else(|| malformed("provider DT_HASH byte size overflows u64"))?;
    map_virtual_range(
        &headers,
        file.len(),
        hash_address,
        hash_size,
        "provider DT_HASH table",
    )?;

    let dynsym_size = symbol_count
        .checked_mul(syment)
        .ok_or_else(|| malformed("provider dynamic symbol table size overflows u64"))?;
    let dynsym_offset = map_virtual_range(
        &headers,
        file.len(),
        symtab_address,
        dynsym_size,
        "provider DT_SYMTAB",
    )?;
    let dynsym_offset = usize::try_from(dynsym_offset)
        .map_err(|_| malformed("provider DT_SYMTAB file offset does not fit usize"))?;

    let mut exports = BTreeMap::<Vec<u8>, BTreeSet<u8>>::new();
    for symbol_index in 0..symbol_count {
        let relative = symbol_index
            .checked_mul(syment)
            .ok_or_else(|| malformed("provider dynamic symbol offset overflows u64"))?;
        let relative = usize::try_from(relative)
            .map_err(|_| malformed("provider dynamic symbol offset does not fit usize"))?;
        let offset = dynsym_offset
            .checked_add(relative)
            .ok_or_else(|| malformed("provider dynamic symbol file offset overflows usize"))?;

        let name_offset = u64::from(read_u32(file, offset));
        let info = file[offset + 4];
        let other = file[offset + 5];
        let section_index = read_u16(file, offset + 6);
        let name = if name_offset == 0 {
            Vec::new()
        } else {
            dynamic_string(
                file,
                strtab_offset,
                strsz,
                name_offset,
                "provider dynamic symbol name",
            )?
        };

        let binding = info >> 4;
        let visibility = other & 0x03;
        if section_index != SHN_UNDEF
            && (binding == STB_GLOBAL || binding == STB_WEAK)
            && visibility != STV_INTERNAL
            && visibility != STV_HIDDEN
            && !name.is_empty()
        {
            exports.entry(name).or_default().insert(info & 0x0f);
        }
    }

    Ok(DynamicProviderMetadata { soname, exports })
}

fn program_headers(
    header: Elf64Header,
    file: &[u8],
) -> Result<Vec<ProgramHeader>, DynamicProviderError> {
    if header.program_header_count == 0 {
        return Err(malformed("provider ET_DYN has no program headers"));
    }
    if header.program_header_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(malformed(format!(
            "provider program-header entry size {} does not match ELF64 size {}",
            header.program_header_entry_size, ELF64_PROGRAM_HEADER_SIZE
        )));
    }

    let mut result = Vec::with_capacity(usize::from(header.program_header_count));
    for index in 0..header.program_header_count {
        let offset = header
            .program_header_offset
            .checked_add(u64::from(index) * u64::from(ELF64_PROGRAM_HEADER_SIZE))
            .ok_or_else(|| malformed("provider program-header offset overflows u64"))?;
        checked_file_end(
            offset,
            u64::from(ELF64_PROGRAM_HEADER_SIZE),
            file.len(),
            "provider program header",
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| malformed("provider program-header offset does not fit usize"))?;
        let entry = ProgramHeader {
            segment_type: read_u32(file, offset),
            offset: read_u64(file, offset + 8),
            virtual_address: read_u64(file, offset + 16),
            file_size: read_u64(file, offset + 32),
            memory_size: read_u64(file, offset + 40),
        };
        if entry.file_size > entry.memory_size {
            return Err(malformed(format!(
                "provider program header {index} has p_filesz greater than p_memsz"
            )));
        }
        checked_file_end(
            entry.offset,
            entry.file_size,
            file.len(),
            "provider program-header segment",
        )?;
        entry
            .virtual_address
            .checked_add(entry.memory_size)
            .ok_or_else(|| {
                malformed(format!(
                    "provider program header {index} virtual range overflows u64"
                ))
            })?;
        result.push(entry);
    }
    Ok(result)
}

fn dynamic_entries(
    headers: &[ProgramHeader],
    file: &[u8],
) -> Result<Vec<DynamicEntry>, DynamicProviderError> {
    let segments = headers
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == PT_DYNAMIC)
        .collect::<Vec<_>>();
    if segments.len() != 1 {
        return Err(malformed(format!(
            "provider has {} PT_DYNAMIC segments; expected exactly one",
            segments.len()
        )));
    }
    let (segment_index, dynamic) = segments[0];
    if dynamic.file_size == 0 || dynamic.file_size % ELF64_DYNAMIC_SIZE != 0 {
        return Err(malformed(format!(
            "provider PT_DYNAMIC segment {segment_index} file size is not a non-zero multiple of {ELF64_DYNAMIC_SIZE}"
        )));
    }

    let mut entries = Vec::new();
    for index in 0..dynamic.file_size / ELF64_DYNAMIC_SIZE {
        let offset = dynamic
            .offset
            .checked_add(index * ELF64_DYNAMIC_SIZE)
            .ok_or_else(|| malformed("provider PT_DYNAMIC entry offset overflows u64"))?;
        checked_file_end(
            offset,
            ELF64_DYNAMIC_SIZE,
            file.len(),
            "provider PT_DYNAMIC entry",
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| malformed("provider PT_DYNAMIC entry offset does not fit usize"))?;
        let entry = DynamicEntry {
            tag: read_i64(file, offset),
            value: read_u64(file, offset + 8),
        };
        entries.push(entry);
        if entry.tag == DT_NULL {
            return Ok(entries);
        }
    }

    Err(malformed("provider PT_DYNAMIC has no DT_NULL terminator"))
}

fn required_unique_tag(
    entries: &[DynamicEntry],
    tag: i64,
    name: &str,
) -> Result<u64, DynamicProviderError> {
    let mut value = None;
    for entry in entries.iter().filter(|entry| entry.tag == tag) {
        if value.replace(entry.value).is_some() {
            return Err(malformed(format!(
                "provider PT_DYNAMIC contains duplicate {name} entries"
            )));
        }
    }
    value.ok_or_else(|| malformed(format!("provider PT_DYNAMIC is missing {name}")))
}

fn map_virtual_range(
    headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    size: u64,
    label: &str,
) -> Result<u64, DynamicProviderError> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| malformed(format!("{label} virtual range overflows u64")))?;
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        let backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| malformed("provider PT_LOAD virtual file range overflows u64"))?;
        if address >= header.virtual_address && end <= backed_end {
            let delta = address - header.virtual_address;
            let offset = header
                .offset
                .checked_add(delta)
                .ok_or_else(|| malformed(format!("{label} file offset overflows u64")))?;
            checked_file_end(offset, size, file_len, label)?;
            return Ok(offset);
        }
    }

    Err(malformed(format!(
        "{label} virtual range {address:#x}..{end:#x} is not file-backed by PT_LOAD"
    )))
}

fn dynamic_string(
    file: &[u8],
    strtab_offset: u64,
    strsz: u64,
    offset: u64,
    label: &str,
) -> Result<Vec<u8>, DynamicProviderError> {
    if offset >= strsz {
        return Err(malformed(format!(
            "{label} offset {offset} is outside DT_STRSZ {strsz}"
        )));
    }
    let start = strtab_offset
        .checked_add(offset)
        .ok_or_else(|| malformed(format!("{label} file offset overflows u64")))?;
    let start = usize::try_from(start)
        .map_err(|_| malformed(format!("{label} file offset does not fit usize")))?;
    let remaining = usize::try_from(strsz - offset)
        .map_err(|_| malformed(format!("{label} remaining size does not fit usize")))?;
    let bytes = &file[start..start + remaining];
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed(format!("{label} is not NUL-terminated within DT_STRSZ")))?;
    Ok(bytes[..end].to_vec())
}

fn checked_file_end(
    offset: u64,
    size: u64,
    file_len: usize,
    label: &str,
) -> Result<u64, DynamicProviderError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| malformed(format!("{label} file range overflows u64")))?;
    if end > file_len as u64 {
        return Err(malformed(format!(
            "{label} ends at file offset {end}, beyond file length {file_len}"
        )));
    }
    Ok(end)
}

fn malformed(message: impl Into<String>) -> DynamicProviderError {
    DynamicProviderError::Malformed(message.into())
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
