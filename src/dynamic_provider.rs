use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::elf64::{Elf64Header, ElfError, ELF64_PROGRAM_HEADER_SIZE};

const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const DT_RUNPATH: i64 = 29;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const ELF64_DYNAMIC_SIZE: u64 = 16;
const ELF64_SYMBOL_SIZE: u64 = 24;
const ELF64_VERSYM_SIZE: u64 = 2;
const ELF64_VERDEF_SIZE: u64 = 20;
const ELF64_VERDAUX_SIZE: u64 = 8;
const VER_DEF_CURRENT: u16 = 1;
const VER_FLG_BASE: u16 = 0x1;
const VER_FLG_WEAK: u16 = 0x2;
const VERSYM_HIDDEN: u16 = 0x8000;
const VERSYM_INDEX_MASK: u16 = 0x7fff;
const SHN_UNDEF: u16 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STV_INTERNAL: u8 = 1;
const STV_HIDDEN: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicProviderMetadata {
    pub soname: Vec<u8>,
    pub needed: Vec<Vec<u8>>,
    pub runpath: Option<Vec<u8>>,
    pub exports: BTreeMap<Vec<u8>, BTreeSet<u8>>,
    pub versioned_exports: BTreeMap<(Vec<u8>, Vec<u8>), BTreeSet<u8>>,
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

#[derive(Debug)]
struct ProviderVersionMetadata {
    versym_offset: usize,
    definition_names: BTreeMap<u16, Vec<u8>>,
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
    let sysv_hash_address = optional_unique_tag(&entries, DT_HASH, "DT_HASH")?;
    let gnu_hash_address = optional_unique_tag(&entries, DT_GNU_HASH, "DT_GNU_HASH")?;
    let soname_offset = required_unique_tag(&entries, DT_SONAME, "DT_SONAME")?;
    let runpath_offset = optional_unique_tag(&entries, DT_RUNPATH, "DT_RUNPATH")?;

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

    let mut needed = Vec::new();
    for entry in entries.iter().filter(|entry| entry.tag == DT_NEEDED) {
        let name = dynamic_string(
            file,
            strtab_offset,
            strsz,
            entry.value,
            "provider DT_NEEDED",
        )?;
        if name.is_empty() {
            return Err(malformed("provider DT_NEEDED is empty"));
        }
        needed.push(name);
    }

    let runpath = match runpath_offset {
        Some(offset) => Some(dynamic_string(
            file,
            strtab_offset,
            strsz,
            offset,
            "provider DT_RUNPATH",
        )?),
        None => None,
    };

    let sysv_symbol_count = match sysv_hash_address {
        Some(address) => Some(validate_sysv_hash_metadata(&headers, file, address)?),
        None => None,
    };
    let gnu_symbol_count = match gnu_hash_address {
        Some(address) => Some(validate_gnu_hash_metadata(
            &headers,
            file,
            address,
            sysv_symbol_count,
        )?),
        None => None,
    };
    let symbol_count = match (sysv_symbol_count, gnu_symbol_count) {
        (Some(count), _) | (None, Some(count)) => count,
        (None, None) => {
            return Err(malformed(
                "provider PT_DYNAMIC is missing both DT_HASH and DT_GNU_HASH",
            ));
        }
    };

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
    let versions =
        provider_version_metadata(&entries, &headers, file, symbol_count, strtab_offset, strsz)?;

    let mut exports = BTreeMap::<Vec<u8>, BTreeSet<u8>>::new();
    let mut versioned_exports =
        BTreeMap::<(Vec<u8>, Vec<u8>), BTreeSet<u8>>::new();
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
        let version_allows_unversioned =
            version_allows_unversioned_export(&versions, file, symbol_index, section_index)?;
        let version_name =
            defined_symbol_version_name(&versions, file, symbol_index, section_index)?;
        if section_index != SHN_UNDEF
            && (binding == STB_GLOBAL || binding == STB_WEAK)
            && visibility != STV_INTERNAL
            && visibility != STV_HIDDEN
            && !name.is_empty()
        {
            if version_allows_unversioned {
                exports
                    .entry(name.clone())
                    .or_default()
                    .insert(info & 0x0f);
            }
            if let Some(version_name) = version_name {
                versioned_exports
                    .entry((name, version_name))
                    .or_default()
                    .insert(info & 0x0f);
            }
        }
    }

    Ok(DynamicProviderMetadata {
        soname,
        needed,
        runpath,
        exports,
        versioned_exports,
    })
}

fn provider_version_metadata(
    entries: &[DynamicEntry],
    headers: &[ProgramHeader],
    file: &[u8],
    symbol_count: u64,
    strtab_offset: u64,
    strsz: u64,
) -> Result<Option<ProviderVersionMetadata>, DynamicProviderError> {
    let versym = optional_unique_tag(entries, DT_VERSYM, "DT_VERSYM")?;
    let verdef = optional_unique_tag(entries, DT_VERDEF, "DT_VERDEF")?;
    let verdefnum = optional_unique_tag(entries, DT_VERDEFNUM, "DT_VERDEFNUM")?;

    if versym.is_none() {
        if verdef.is_some() || verdefnum.is_some() {
            return Err(malformed(
                "provider version definitions require DT_VERSYM to associate versions with dynamic symbols",
            ));
        }
        return Ok(None);
    }

    let versym_size = symbol_count
        .checked_mul(ELF64_VERSYM_SIZE)
        .ok_or_else(|| malformed("provider DT_VERSYM table size overflows u64"))?;
    let versym_offset = map_virtual_range(
        headers,
        file.len(),
        versym.unwrap(),
        versym_size,
        "provider DT_VERSYM table",
    )?;
    let versym_offset = usize::try_from(versym_offset)
        .map_err(|_| malformed("provider DT_VERSYM file offset does not fit usize"))?;

    let present = usize::from(verdef.is_some()) + usize::from(verdefnum.is_some());
    if present == 1 {
        return Err(malformed(
            "provider PT_DYNAMIC must provide DT_VERDEF and DT_VERDEFNUM together",
        ));
    }
    let definition_names = if present == 2 {
        parse_version_definition_indices(
            headers,
            file,
            verdef.unwrap(),
            verdefnum.unwrap(),
            strtab_offset,
            strsz,
        )?
    } else {
        BTreeMap::new()
    };

    Ok(Some(ProviderVersionMetadata {
        versym_offset,
        definition_names,
    }))
}

fn version_allows_unversioned_export(
    versions: &Option<ProviderVersionMetadata>,
    file: &[u8],
    symbol_index: u64,
    section_index: u16,
) -> Result<bool, DynamicProviderError> {
    let Some(versions) = versions else {
        return Ok(true);
    };
    let relative = symbol_index
        .checked_mul(ELF64_VERSYM_SIZE)
        .ok_or_else(|| malformed("provider DT_VERSYM symbol offset overflows u64"))?;
    let relative = usize::try_from(relative)
        .map_err(|_| malformed("provider DT_VERSYM symbol offset does not fit usize"))?;
    let offset = versions
        .versym_offset
        .checked_add(relative)
        .ok_or_else(|| malformed("provider DT_VERSYM file offset overflows usize"))?;
    let raw = read_u16(file, offset);
    let version_index = raw & VERSYM_INDEX_MASK;
    let hidden = raw & VERSYM_HIDDEN != 0;

    if hidden && version_index < 2 {
        return Err(malformed(format!(
            "provider DT_VERSYM symbol {symbol_index} sets the hidden bit on reserved version index {version_index}"
        )));
    }

    if section_index != SHN_UNDEF
        && version_index >= 2
        && !versions.definition_names.contains_key(&version_index)
    {
        return Err(malformed(format!(
            "provider DT_VERSYM defined symbol {symbol_index} references version index {version_index} with no matching DT_VERDEF"
        )));
    }

    Ok(match version_index {
        0 => false,
        1 => true,
        _ => !hidden,
    })
}

fn defined_symbol_version_name(
    versions: &Option<ProviderVersionMetadata>,
    file: &[u8],
    symbol_index: u64,
    section_index: u16,
) -> Result<Option<Vec<u8>>, DynamicProviderError> {
    if section_index == SHN_UNDEF {
        return Ok(None);
    }
    let Some(versions) = versions else {
        return Ok(None);
    };
    let relative = symbol_index
        .checked_mul(ELF64_VERSYM_SIZE)
        .ok_or_else(|| malformed("provider DT_VERSYM symbol offset overflows u64"))?;
    let relative = usize::try_from(relative)
        .map_err(|_| malformed("provider DT_VERSYM symbol offset does not fit usize"))?;
    let offset = versions
        .versym_offset
        .checked_add(relative)
        .ok_or_else(|| malformed("provider DT_VERSYM file offset overflows usize"))?;
    let version_index = read_u16(file, offset) & VERSYM_INDEX_MASK;
    if version_index < 2 {
        return Ok(None);
    }
    versions
        .definition_names
        .get(&version_index)
        .cloned()
        .map(Some)
        .ok_or_else(|| {
            malformed(format!(
                "provider DT_VERSYM defined symbol {symbol_index} references version index {version_index} with no matching DT_VERDEF"
            ))
        })
}

fn parse_version_definition_indices(
    headers: &[ProgramHeader],
    file: &[u8],
    mut address: u64,
    count: u64,
    strtab_offset: u64,
    strsz: u64,
) -> Result<BTreeMap<u16, Vec<u8>>, DynamicProviderError> {
    if count == 0 {
        return Err(malformed(
            "provider DT_VERDEFNUM must be non-zero when DT_VERDEF is present",
        ));
    }

    let mut definitions = BTreeMap::new();
    for definition_index in 0..count {
        let offset = map_virtual_range(
            headers,
            file.len(),
            address,
            ELF64_VERDEF_SIZE,
            &format!("provider DT_VERDEF entry {definition_index}"),
        )?;
        let offset = usize::try_from(offset)
            .map_err(|_| malformed("provider DT_VERDEF file offset does not fit usize"))?;
        let version = read_u16(file, offset);
        let flags = read_u16(file, offset + 2);
        let raw_index = read_u16(file, offset + 4);
        let version_index = raw_index & VERSYM_INDEX_MASK;
        let aux_count = read_u16(file, offset + 6);
        let stored_hash = read_u32(file, offset + 8);
        let aux_relative = read_u32(file, offset + 12);
        let next_relative = read_u32(file, offset + 16);

        if version != VER_DEF_CURRENT {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} has version {version}, expected {VER_DEF_CURRENT}"
            )));
        }
        if flags & !(VER_FLG_BASE | VER_FLG_WEAK) != 0 {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} has unsupported flags {flags:#06x}"
            )));
        }
        if raw_index & VERSYM_HIDDEN != 0 {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} sets the reserved hidden bit in vd_ndx"
            )));
        }
        if version_index == 0 {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} uses reserved local version index 0"
            )));
        }
        if aux_count == 0 || aux_relative == 0 {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} has an invalid Verdaux chain"
            )));
        }
        if definitions.contains_key(&version_index) {
            return Err(malformed(format!(
                "provider DT_VERDEF contains duplicate version index {version_index}"
            )));
        }

        let mut aux_address = address
            .checked_add(u64::from(aux_relative))
            .ok_or_else(|| {
                malformed(format!(
                    "provider DT_VERDEF entry {definition_index} vd_aux address overflows u64"
                ))
            })?;
        let mut first_name = None;
        for aux_index in 0..u64::from(aux_count) {
            let aux_offset = map_virtual_range(
                headers,
                file.len(),
                aux_address,
                ELF64_VERDAUX_SIZE,
                &format!("provider DT_VERDEF entry {definition_index} Verdaux {aux_index}"),
            )?;
            let aux_offset = usize::try_from(aux_offset)
                .map_err(|_| malformed("provider Verdaux file offset does not fit usize"))?;
            let name_offset = u64::from(read_u32(file, aux_offset));
            let next = read_u32(file, aux_offset + 4);
            let name = dynamic_string(
                file,
                strtab_offset,
                strsz,
                name_offset,
                "provider Verdaux version name",
            )?;
            if name.is_empty() {
                return Err(malformed(format!(
                    "provider DT_VERDEF entry {definition_index} has an empty version name"
                )));
            }
            if aux_index == 0 {
                first_name = Some(name);
            }

            let last = aux_index + 1 == u64::from(aux_count);
            if last {
                if next != 0 {
                    return Err(malformed(format!(
                        "provider DT_VERDEF entry {definition_index} final Verdaux has non-zero vda_next {next}"
                    )));
                }
            } else {
                if next == 0 {
                    return Err(malformed(format!(
                        "provider DT_VERDEF entry {definition_index} Verdaux chain ends before vd_cnt {aux_count}"
                    )));
                }
                aux_address = aux_address.checked_add(u64::from(next)).ok_or_else(|| {
                    malformed(format!(
                        "provider DT_VERDEF entry {definition_index} Verdaux address overflows u64"
                    ))
                })?;
            }
        }

        let first_name = first_name.expect("non-zero aux count guarantees a first version name");
        if stored_hash != sysv_elf_hash(&first_name) {
            return Err(malformed(format!(
                "provider DT_VERDEF entry {definition_index} has vd_hash {stored_hash:#010x}, expected {:#010x} for version {:?}",
                sysv_elf_hash(&first_name),
                String::from_utf8_lossy(&first_name)
            )));
        }
        definitions.insert(version_index, first_name);

        let last = definition_index + 1 == count;
        if last {
            if next_relative != 0 {
                return Err(malformed(format!(
                    "provider final DT_VERDEF entry has non-zero vd_next {next_relative} beyond DT_VERDEFNUM {count}"
                )));
            }
        } else {
            if next_relative == 0 {
                return Err(malformed(format!(
                    "provider DT_VERDEF chain ends before DT_VERDEFNUM {count}"
                )));
            }
            address = address
                .checked_add(u64::from(next_relative))
                .ok_or_else(|| malformed("provider DT_VERDEF next-entry address overflows u64"))?;
        }
    }

    Ok(definitions)
}

fn sysv_elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
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

fn validate_sysv_hash_metadata(
    headers: &[ProgramHeader],
    file: &[u8],
    hash_address: u64,
) -> Result<u64, DynamicProviderError> {
    let hash_header = map_virtual_range(
        headers,
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
    let hash_offset = map_virtual_range(
        headers,
        file.len(),
        hash_address,
        hash_size,
        "provider DT_HASH table",
    )?;
    validate_sysv_hash_table(file, hash_offset, bucket_count, symbol_count)?;
    Ok(symbol_count)
}

fn validate_gnu_hash_metadata(
    headers: &[ProgramHeader],
    file: &[u8],
    hash_address: u64,
    expected_symbol_count: Option<u64>,
) -> Result<u64, DynamicProviderError> {
    let header_offset = map_virtual_range(
        headers,
        file.len(),
        hash_address,
        16,
        "provider DT_GNU_HASH header",
    )?;
    let header_offset = usize::try_from(header_offset)
        .map_err(|_| malformed("provider DT_GNU_HASH file offset does not fit usize"))?;
    let bucket_count = u64::from(read_u32(file, header_offset));
    let symbol_offset = u64::from(read_u32(file, header_offset + 4));
    let bloom_size = u64::from(read_u32(file, header_offset + 8));
    let _bloom_shift = read_u32(file, header_offset + 12);

    if bucket_count == 0 {
        return Err(malformed("provider DT_GNU_HASH reports zero buckets"));
    }
    if bloom_size == 0 {
        return Err(malformed("provider DT_GNU_HASH reports zero bloom words"));
    }

    let bloom_bytes = bloom_size
        .checked_mul(8)
        .ok_or_else(|| malformed("provider DT_GNU_HASH bloom byte size overflows u64"))?;
    let bloom_address = hash_address
        .checked_add(16)
        .ok_or_else(|| malformed("provider DT_GNU_HASH bloom address overflows u64"))?;
    map_virtual_range(
        headers,
        file.len(),
        bloom_address,
        bloom_bytes,
        "provider DT_GNU_HASH bloom filter",
    )?;

    let buckets_address = bloom_address
        .checked_add(bloom_bytes)
        .ok_or_else(|| malformed("provider DT_GNU_HASH bucket address overflows u64"))?;
    let bucket_bytes = bucket_count
        .checked_mul(4)
        .ok_or_else(|| malformed("provider DT_GNU_HASH bucket byte size overflows u64"))?;
    let buckets_offset = map_virtual_range(
        headers,
        file.len(),
        buckets_address,
        bucket_bytes,
        "provider DT_GNU_HASH buckets",
    )?;
    let buckets_offset = usize::try_from(buckets_offset)
        .map_err(|_| malformed("provider DT_GNU_HASH bucket offset does not fit usize"))?;

    let chains_address = buckets_address
        .checked_add(bucket_bytes)
        .ok_or_else(|| malformed("provider DT_GNU_HASH chain address overflows u64"))?;
    let chain_bytes = file_backed_bytes_from_virtual(
        headers,
        file.len(),
        chains_address,
        "provider DT_GNU_HASH chains",
    )?;
    let chain_entries = chain_bytes / 4;
    let chains_offset = if chain_entries == 0 {
        None
    } else {
        let offset = map_virtual_range(
            headers,
            file.len(),
            chains_address,
            chain_entries
                .checked_mul(4)
                .ok_or_else(|| malformed("provider DT_GNU_HASH chain byte size overflows u64"))?,
            "provider DT_GNU_HASH chains",
        )?;
        Some(
            usize::try_from(offset)
                .map_err(|_| malformed("provider DT_GNU_HASH chain offset does not fit usize"))?,
        )
    };

    let mut max_symbol = symbol_offset.checked_sub(1);
    for bucket_index in 0..bucket_count {
        let relative = bucket_index
            .checked_mul(4)
            .ok_or_else(|| malformed("provider DT_GNU_HASH bucket offset overflows u64"))?;
        let relative = usize::try_from(relative)
            .map_err(|_| malformed("provider DT_GNU_HASH bucket offset does not fit usize"))?;
        let bucket = u64::from(read_u32(file, buckets_offset + relative));
        if bucket == 0 {
            continue;
        }
        if bucket < symbol_offset {
            return Err(malformed(format!(
                "provider DT_GNU_HASH bucket {bucket_index} references symbol {bucket} before symoffset {symbol_offset}"
            )));
        }

        let mut symbol_index = bucket;
        let mut chain_index = bucket - symbol_offset;
        loop {
            if let Some(expected) = expected_symbol_count {
                if symbol_index >= expected {
                    return Err(malformed(format!(
                        "provider DT_GNU_HASH bucket {bucket_index} references symbol {symbol_index}, outside dynamic symbol count {expected}"
                    )));
                }
            }
            if chain_index >= chain_entries {
                return Err(malformed(format!(
                    "provider DT_GNU_HASH bucket {bucket_index} chain is not terminated within its file-backed PT_LOAD range"
                )));
            }
            let chains_offset = chains_offset.ok_or_else(|| {
                malformed("provider DT_GNU_HASH has no file-backed chain entries")
            })?;
            let relative = chain_index
                .checked_mul(4)
                .ok_or_else(|| malformed("provider DT_GNU_HASH chain offset overflows u64"))?;
            let relative = usize::try_from(relative)
                .map_err(|_| malformed("provider DT_GNU_HASH chain offset does not fit usize"))?;
            let value = read_u32(file, chains_offset + relative);
            max_symbol = Some(max_symbol.map_or(symbol_index, |current| current.max(symbol_index)));
            if value & 1 != 0 {
                break;
            }
            symbol_index = symbol_index
                .checked_add(1)
                .ok_or_else(|| malformed("provider DT_GNU_HASH symbol index overflows u64"))?;
            chain_index = chain_index
                .checked_add(1)
                .ok_or_else(|| malformed("provider DT_GNU_HASH chain index overflows u64"))?;
        }
    }

    let derived_count = match max_symbol {
        Some(index) => index
            .checked_add(1)
            .ok_or_else(|| malformed("provider DT_GNU_HASH symbol count overflows u64"))?,
        None => symbol_offset,
    };
    if derived_count == 0 {
        return Err(malformed(
            "provider DT_GNU_HASH derives zero dynamic symbols",
        ));
    }
    if let Some(expected) = expected_symbol_count {
        if derived_count > expected {
            return Err(malformed(format!(
                "provider DT_GNU_HASH derives {derived_count} symbols, beyond DT_HASH count {expected}"
            )));
        }
        Ok(expected)
    } else {
        Ok(derived_count)
    }
}

fn file_backed_bytes_from_virtual(
    headers: &[ProgramHeader],
    file_len: usize,
    address: u64,
    label: &str,
) -> Result<u64, DynamicProviderError> {
    for header in headers
        .iter()
        .filter(|header| header.segment_type == PT_LOAD)
    {
        let backed_end = header
            .virtual_address
            .checked_add(header.file_size)
            .ok_or_else(|| malformed("provider PT_LOAD virtual file range overflows u64"))?;
        if address >= header.virtual_address && address <= backed_end {
            let delta = address - header.virtual_address;
            let offset = header
                .offset
                .checked_add(delta)
                .ok_or_else(|| malformed(format!("{label} file offset overflows u64")))?;
            let remaining = header.file_size - delta;
            checked_file_end(offset, remaining, file_len, label)?;
            return Ok(remaining);
        }
    }
    Err(malformed(format!(
        "{label} address {address:#x} is not file-backed by PT_LOAD"
    )))
}

fn validate_sysv_hash_table(
    file: &[u8],
    hash_offset: u64,
    bucket_count: u64,
    symbol_count: u64,
) -> Result<(), DynamicProviderError> {
    let hash_offset = usize::try_from(hash_offset)
        .map_err(|_| malformed("provider DT_HASH file offset does not fit usize"))?;
    let bucket_count_usize = usize::try_from(bucket_count)
        .map_err(|_| malformed("provider DT_HASH bucket count does not fit usize"))?;
    let symbol_count_usize = usize::try_from(symbol_count)
        .map_err(|_| malformed("provider DT_HASH symbol count does not fit usize"))?;
    let buckets_offset = hash_offset
        .checked_add(8)
        .ok_or_else(|| malformed("provider DT_HASH bucket offset overflows usize"))?;
    let chains_offset = buckets_offset
        .checked_add(
            bucket_count_usize
                .checked_mul(4)
                .ok_or_else(|| malformed("provider DT_HASH bucket byte size overflows usize"))?,
        )
        .ok_or_else(|| malformed("provider DT_HASH chain offset overflows usize"))?;

    let mut buckets = Vec::with_capacity(bucket_count_usize);
    for index in 0..bucket_count_usize {
        let offset = buckets_offset
            .checked_add(index * 4)
            .ok_or_else(|| malformed("provider DT_HASH bucket file offset overflows usize"))?;
        let value = read_u32(file, offset);
        if u64::from(value) >= symbol_count && value != 0 {
            return Err(malformed(format!(
                "provider DT_HASH bucket {index} references symbol {value}, outside nchain {symbol_count}"
            )));
        }
        buckets.push(value);
    }

    let mut chains = Vec::with_capacity(symbol_count_usize);
    for index in 0..symbol_count_usize {
        let offset = chains_offset
            .checked_add(index * 4)
            .ok_or_else(|| malformed("provider DT_HASH chain file offset overflows usize"))?;
        let value = read_u32(file, offset);
        if u64::from(value) >= symbol_count && value != 0 {
            return Err(malformed(format!(
                "provider DT_HASH chain {index} references symbol {value}, outside nchain {symbol_count}"
            )));
        }
        chains.push(value);
    }

    for (bucket_index, start) in buckets.into_iter().enumerate() {
        let mut current = start;
        let mut steps = 0usize;
        while current != 0 {
            steps = steps
                .checked_add(1)
                .ok_or_else(|| malformed("provider DT_HASH chain step count overflows usize"))?;
            if steps > symbol_count_usize {
                return Err(malformed(format!(
                    "provider DT_HASH bucket {bucket_index} contains a cycle"
                )));
            }
            current = chains[current as usize];
        }
    }

    Ok(())
}

fn optional_unique_tag(
    entries: &[DynamicEntry],
    tag: i64,
    name: &str,
) -> Result<Option<u64>, DynamicProviderError> {
    let mut value = None;
    for entry in entries.iter().filter(|entry| entry.tag == tag) {
        if value.replace(entry.value).is_some() {
            return Err(malformed(format!(
                "provider PT_DYNAMIC contains duplicate {name} entries"
            )));
        }
    }
    Ok(value)
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
