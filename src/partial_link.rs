use core::fmt;
use std::collections::BTreeMap;

use crate::elf64::{
    Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHN_LORESERVE, SHT_DYNSYM, SHT_NOBITS,
    SHT_STRTAB, SHT_SYMTAB,
};
use crate::input_object::{RelocatableObject, RelocatableObjectError};
use crate::load_segments::SHF_ALLOC;
use crate::relocations::{Elf64Rela, ELF64_RELA_SIZE, SHT_RELA};
use crate::resolve::{SHN_COMMON, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_names::{symbol_name, SymbolNameError};

const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const EM_X86_64: u16 = 62;
const ET_REL: u16 = 1;
const SHF_GROUP: u64 = 0x200;
const SHN_XINDEX: u16 = 0xffff;

#[derive(Debug, Clone, Copy)]
pub struct PartialLinkInput<'a> {
    pub file: &'a [u8],
}

#[derive(Debug)]
pub enum PartialLinkError {
    InvalidObject {
        input_index: usize,
        source: RelocatableObjectError,
    },
    MissingSectionNameTable {
        input_index: usize,
    },
    SectionNameTableNotStringTable {
        input_index: usize,
        section_index: u16,
        section_type: u32,
    },
    SectionNameTableRangeOverflow {
        input_index: usize,
    },
    SectionNameTableOutOfBounds {
        input_index: usize,
        end: u64,
        file_len: usize,
    },
    InvalidSectionNameOffset {
        input_index: usize,
        section_index: u16,
        name_offset: u32,
        string_table_size: u64,
    },
    UnterminatedSectionName {
        input_index: usize,
        section_index: u16,
    },
    UnsupportedAllocSectionMetadata {
        input_index: usize,
        section_index: u16,
        link: u32,
        info: u32,
    },
    UnsupportedGroupedAllocSection {
        input_index: usize,
        section_index: u16,
    },
    TooManyStaticSymbolTables {
        input_index: usize,
        count: usize,
    },
    UnsupportedDynamicSymbolTable {
        input_index: usize,
        section_index: u16,
    },
    InvalidSymbolName {
        input_index: usize,
        source: SymbolNameError,
    },
    UnsupportedSymbolBinding {
        input_index: usize,
        symbol_index: usize,
        binding: u8,
    },
    UnsupportedSymbolSection {
        input_index: usize,
        symbol_index: usize,
        section_index: u16,
    },
    UnsupportedNondefaultSymbolVisibility {
        input_index: usize,
        symbol_index: usize,
        other: u8,
    },
    UnsupportedExtendedSymbolSectionIndex {
        input_index: usize,
        symbol_index: usize,
    },
    UnsupportedRelocationTarget {
        input_index: usize,
        rela_section_index: u16,
        target_section_index: u16,
    },
    UnsupportedRelocationSymbolTable {
        input_index: usize,
        rela_section_index: u16,
        symbol_table_index: u16,
    },
    MissingRelocationSymbol {
        input_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
    },
    SectionContributionOverflow {
        input_index: usize,
        section_index: u16,
    },
    SymbolValueOverflow {
        input_index: usize,
        symbol_index: usize,
        contribution_offset: u64,
        value: u64,
    },
    RelocationOffsetOverflow {
        input_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        contribution_offset: u64,
        offset: u64,
    },
    UnsupportedCommonBinding {
        input_index: usize,
        symbol_index: usize,
        binding: u8,
    },
    InvalidCommonAlignment {
        input_index: usize,
        symbol_index: usize,
        alignment: u64,
    },
    MultipleStrongDefinitions {
        name: Vec<u8>,
        first_input_index: usize,
        second_input_index: usize,
    },
    TooManySections {
        count: usize,
    },
    TooManySymbols {
        count: usize,
    },
    StringTableTooLarge,
    SizeOverflow(&'static str),
    FileOffsetOverflow,
}

impl fmt::Display for PartialLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObject {
                input_index,
                source,
            } => write!(f, "partial-link input {input_index} is invalid: {source}"),
            Self::MissingSectionNameTable { input_index } => write!(
                f,
                "partial-link input {input_index} has no section-name string table"
            ),
            Self::SectionNameTableNotStringTable {
                input_index,
                section_index,
                section_type,
            } => write!(
                f,
                "partial-link input {input_index} section-name table {section_index} has type {section_type}, expected SHT_STRTAB"
            ),
            Self::SectionNameTableRangeOverflow { input_index } => write!(
                f,
                "partial-link input {input_index} section-name string-table range overflows"
            ),
            Self::SectionNameTableOutOfBounds {
                input_index,
                end,
                file_len,
            } => write!(
                f,
                "partial-link input {input_index} section-name string table ends at {end}, beyond file length {file_len}"
            ),
            Self::InvalidSectionNameOffset {
                input_index,
                section_index,
                name_offset,
                string_table_size,
            } => write!(
                f,
                "partial-link input {input_index} section {section_index} name offset {name_offset} is outside section-name string table size {string_table_size}"
            ),
            Self::UnterminatedSectionName {
                input_index,
                section_index,
            } => write!(
                f,
                "partial-link input {input_index} section {section_index} has an unterminated name"
            ),
            Self::UnsupportedAllocSectionMetadata {
                input_index,
                section_index,
                link,
                info,
            } => write!(
                f,
                "partial-link input {input_index} allocatable section {section_index} carries unsupported sh_link={link} sh_info={info}; bounded partial linking requires self-contained allocatable sections"
            ),
            Self::UnsupportedGroupedAllocSection {
                input_index,
                section_index,
            } => write!(
                f,
                "partial-link input {input_index} allocatable section {section_index} has SHF_GROUP/COMDAT membership, but bounded partial linking does not preserve SHT_GROUP metadata"
            ),
            Self::TooManyStaticSymbolTables { input_index, count } => write!(
                f,
                "partial-link input {input_index} has {count} static symbol tables; bounded partial linking supports at most one SHT_SYMTAB per input"
            ),
            Self::UnsupportedDynamicSymbolTable {
                input_index,
                section_index,
            } => write!(
                f,
                "partial-link input {input_index} carries dynamic symbol table section {section_index}; ET_REL partial linking accepts static symbol tables only"
            ),
            Self::InvalidSymbolName {
                input_index,
                source,
            } => write!(
                f,
                "partial-link input {input_index} has invalid symbol metadata: {source}"
            ),
            Self::UnsupportedSymbolBinding {
                input_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "partial-link input {input_index} symbol {symbol_index} uses unsupported binding {binding}; bounded partial linking supports local/global/weak"
            ),
            Self::UnsupportedSymbolSection {
                input_index,
                symbol_index,
                section_index,
            } => write!(
                f,
                "partial-link input {input_index} symbol {symbol_index} refers to non-allocatable section {section_index}, which is not preserved by the bounded partial-link output"
            ),
            Self::UnsupportedNondefaultSymbolVisibility {
                input_index,
                symbol_index,
                other,
            } => write!(
                f,
                "partial-link input {input_index} nonlocal symbol {symbol_index} has unsupported st_other/visibility value {other:#x}; bounded canonicalization currently requires default visibility"
            ),
            Self::UnsupportedExtendedSymbolSectionIndex {
                input_index,
                symbol_index,
            } => write!(
                f,
                "partial-link input {input_index} symbol {symbol_index} uses SHN_XINDEX, but bounded partial linking does not preserve SHT_SYMTAB_SHNDX metadata"
            ),
            Self::UnsupportedRelocationTarget {
                input_index,
                rela_section_index,
                target_section_index,
            } => write!(
                f,
                "partial-link input {input_index} RELA section {rela_section_index} targets non-allocatable section {target_section_index}"
            ),
            Self::UnsupportedRelocationSymbolTable {
                input_index,
                rela_section_index,
                symbol_table_index,
            } => write!(
                f,
                "partial-link input {input_index} RELA section {rela_section_index} uses symbol table {symbol_table_index}, not the supported static symbol table"
            ),
            Self::MissingRelocationSymbol {
                input_index,
                rela_section_index,
                symbol_index,
            } => write!(
                f,
                "partial-link input {input_index} RELA section {rela_section_index} cannot remap symbol {symbol_index}"
            ),
            Self::SectionContributionOverflow {
                input_index,
                section_index,
            } => write!(
                f,
                "partial-link input {input_index} section {section_index} overflows while placing its coalesced contribution"
            ),
            Self::SymbolValueOverflow {
                input_index,
                symbol_index,
                contribution_offset,
                value,
            } => write!(
                f,
                "partial-link input {input_index} symbol {symbol_index} value {value:#x} plus contribution offset {contribution_offset:#x} overflows"
            ),
            Self::RelocationOffsetOverflow {
                input_index,
                rela_section_index,
                relocation_index,
                contribution_offset,
                offset,
            } => write!(
                f,
                "partial-link input {input_index} RELA section {rela_section_index} relocation {relocation_index} offset {offset:#x} plus contribution offset {contribution_offset:#x} overflows"
            ),
            Self::UnsupportedCommonBinding {
                input_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "partial-link input {input_index} common symbol {symbol_index} uses unsupported binding {binding}; SHN_COMMON requires STB_GLOBAL in this bounded model"
            ),
            Self::InvalidCommonAlignment {
                input_index,
                symbol_index,
                alignment,
            } => write!(
                f,
                "partial-link input {input_index} common symbol {symbol_index} has invalid alignment {alignment}; expected a non-zero power of two"
            ),
            Self::MultipleStrongDefinitions {
                name,
                first_input_index,
                second_input_index,
            } => write!(
                f,
                "multiple strong definitions for symbol {:?}: first in partial-link input {first_input_index}, second in input {second_input_index}",
                String::from_utf8_lossy(name)
            ),
            Self::TooManySections { count } => write!(
                f,
                "partial-link output requires {count} sections, exceeding the non-extended ELF64 section-index range"
            ),
            Self::TooManySymbols { count } => write!(
                f,
                "partial-link output requires {count} symbols, exceeding the ELF64 relocation symbol-index range"
            ),
            Self::StringTableTooLarge => {
                write!(f, "partial-link output string table exceeds 32-bit ELF name offsets")
            }
            Self::SizeOverflow(what) => write!(f, "partial-link {what} size arithmetic overflow"),
            Self::FileOffsetOverflow => write!(f, "partial-link output file offset arithmetic overflow"),
        }
    }
}

impl std::error::Error for PartialLinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidObject { source, .. } => Some(source),
            Self::InvalidSymbolName { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl PartialLinkError {
    pub fn input_index(&self) -> Option<usize> {
        match self {
            Self::InvalidObject { input_index, .. }
            | Self::MissingSectionNameTable { input_index }
            | Self::SectionNameTableNotStringTable { input_index, .. }
            | Self::SectionNameTableRangeOverflow { input_index }
            | Self::SectionNameTableOutOfBounds { input_index, .. }
            | Self::InvalidSectionNameOffset { input_index, .. }
            | Self::UnterminatedSectionName { input_index, .. }
            | Self::UnsupportedAllocSectionMetadata { input_index, .. }
            | Self::UnsupportedGroupedAllocSection { input_index, .. }
            | Self::TooManyStaticSymbolTables { input_index, .. }
            | Self::UnsupportedDynamicSymbolTable { input_index, .. }
            | Self::InvalidSymbolName { input_index, .. }
            | Self::UnsupportedSymbolBinding { input_index, .. }
            | Self::UnsupportedSymbolSection { input_index, .. }
            | Self::UnsupportedNondefaultSymbolVisibility { input_index, .. }
            | Self::UnsupportedExtendedSymbolSectionIndex { input_index, .. }
            | Self::UnsupportedRelocationTarget { input_index, .. }
            | Self::UnsupportedRelocationSymbolTable { input_index, .. }
            | Self::MissingRelocationSymbol { input_index, .. }
            | Self::SectionContributionOverflow { input_index, .. }
            | Self::SymbolValueOverflow { input_index, .. }
            | Self::RelocationOffsetOverflow { input_index, .. }
            | Self::UnsupportedCommonBinding { input_index, .. }
            | Self::InvalidCommonAlignment { input_index, .. } => Some(*input_index),
            Self::MultipleStrongDefinitions {
                second_input_index, ..
            } => Some(*second_input_index),
            Self::TooManySections { .. }
            | Self::TooManySymbols { .. }
            | Self::StringTableTooLarge
            | Self::SizeOverflow(_)
            | Self::FileOffsetOverflow => None,
        }
    }
}

#[derive(Debug)]
struct ParsedInput<'a> {
    file: &'a [u8],
    object: RelocatableObject,
}

#[derive(Debug, Clone)]
struct OutputSection {
    name: Vec<u8>,
    section_type: u32,
    flags: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
    data: Vec<u8>,
    offset: u64,
}

#[derive(Debug, Clone, Copy)]
struct SectionPlacement {
    output_section_index: u16,
    contribution_offset: u64,
}

type SymbolSource = (usize, u16, usize);

#[derive(Debug, Clone)]
struct PendingSymbol {
    source: SymbolSource,
    name: Vec<u8>,
    symbol: Elf64Symbol,
}

#[derive(Debug, Clone)]
struct CanonicalNonlocal {
    name: Vec<u8>,
    symbol: Elf64Symbol,
    representative_source: SymbolSource,
    sources: Vec<SymbolSource>,
}

pub fn link_relocatable_objects(
    inputs: &[PartialLinkInput<'_>],
) -> Result<Vec<u8>, PartialLinkError> {
    let parsed = inputs
        .iter()
        .enumerate()
        .map(|(input_index, input)| {
            let object = RelocatableObject::parse(input.file).map_err(|source| {
                PartialLinkError::InvalidObject {
                    input_index,
                    source,
                }
            })?;
            Ok(ParsedInput {
                file: input.file,
                object,
            })
        })
        .collect::<Result<Vec<_>, PartialLinkError>>()?;

    let mut output_sections = Vec::<OutputSection>::new();
    let mut section_maps = Vec::with_capacity(parsed.len());
    let mut coalesced_text_sections = BTreeMap::<(Vec<u8>, u32, u64, u64), usize>::new();

    for (input_index, input) in parsed.iter().enumerate() {
        let names = section_names(input_index, input)?;
        let mut mapping = vec![None; input.object.sections.len()];

        for (section_index, section) in input.object.sections.iter().enumerate() {
            if section.flags & SHF_ALLOC == 0 {
                continue;
            }
            let section_index_u16 =
                u16::try_from(section_index).map_err(|_| PartialLinkError::TooManySections {
                    count: input.object.sections.len(),
                })?;
            if section.flags & SHF_GROUP != 0 {
                return Err(PartialLinkError::UnsupportedGroupedAllocSection {
                    input_index,
                    section_index: section_index_u16,
                });
            }
            if section.link != 0 || section.info != 0 {
                return Err(PartialLinkError::UnsupportedAllocSectionMetadata {
                    input_index,
                    section_index: section_index_u16,
                    link: section.link,
                    info: section.info,
                });
            }

            let name = names[section_index].clone();
            let data = section_bytes(input.file, section);
            let merge_key = (
                name.clone(),
                section.section_type,
                section.flags,
                section.entry_size,
            );
            let existing = if name.as_slice() == b".text" {
                coalesced_text_sections.get(&merge_key).copied()
            } else {
                None
            };

            let placement = if let Some(output_slot) = existing {
                let output_section_index = u16::try_from(output_slot + 1).map_err(|_| {
                    PartialLinkError::TooManySections {
                        count: output_slot + 5,
                    }
                })?;
                let output = &mut output_sections[output_slot];
                let contribution_offset =
                    align_section_contribution(output.size, section.address_alignment).ok_or(
                        PartialLinkError::SectionContributionOverflow {
                            input_index,
                            section_index: section_index_u16,
                        },
                    )?;
                let new_size = contribution_offset.checked_add(section.size).ok_or(
                    PartialLinkError::SectionContributionOverflow {
                        input_index,
                        section_index: section_index_u16,
                    },
                )?;

                if section.section_type != SHT_NOBITS {
                    let contribution_offset =
                        usize::try_from(contribution_offset).map_err(|_| {
                            PartialLinkError::SectionContributionOverflow {
                                input_index,
                                section_index: section_index_u16,
                            }
                        })?;
                    if output.data.len() < contribution_offset {
                        output.data.resize(contribution_offset, 0);
                    }
                    output.data.extend_from_slice(&data);
                }
                output.size = new_size;
                output.alignment = output.alignment.max(section.address_alignment);

                SectionPlacement {
                    output_section_index,
                    contribution_offset,
                }
            } else {
                let output_index = output_sections
                    .len()
                    .checked_add(1)
                    .ok_or(PartialLinkError::SizeOverflow("section count"))?;
                if output_index >= usize::from(SHN_LORESERVE) {
                    return Err(PartialLinkError::TooManySections {
                        count: output_index + 4,
                    });
                }
                let output_slot = output_sections.len();
                output_sections.push(OutputSection {
                    name: name.clone(),
                    section_type: section.section_type,
                    flags: section.flags,
                    size: section.size,
                    link: 0,
                    info: 0,
                    alignment: section.address_alignment,
                    entry_size: section.entry_size,
                    data,
                    offset: 0,
                });
                if name.as_slice() == b".text" {
                    coalesced_text_sections.insert(merge_key, output_slot);
                }
                SectionPlacement {
                    output_section_index: output_index as u16,
                    contribution_offset: 0,
                }
            };

            mapping[section_index] = Some(placement);
        }

        section_maps.push(mapping);
    }

    let mut static_tables = Vec::<Option<Elf64SymbolTable>>::with_capacity(parsed.len());
    for (input_index, input) in parsed.iter().enumerate() {
        let mut tables = input
            .object
            .symbol_tables
            .iter()
            .filter(|table| {
                input.object.sections[usize::from(table.section_index)].section_type == SHT_SYMTAB
            })
            .cloned()
            .collect::<Vec<_>>();
        if tables.len() > 1 {
            return Err(PartialLinkError::TooManyStaticSymbolTables {
                input_index,
                count: tables.len(),
            });
        }
        if let Some(dynamic) = input.object.symbol_tables.iter().find(|table| {
            input.object.sections[usize::from(table.section_index)].section_type == SHT_DYNSYM
        }) {
            return Err(PartialLinkError::UnsupportedDynamicSymbolTable {
                input_index,
                section_index: dynamic.section_index,
            });
        }
        static_tables.push(tables.pop());
    }

    let mut locals = Vec::<PendingSymbol>::new();
    let mut nonlocals = Vec::<PendingSymbol>::new();
    let mut symbol_maps = BTreeMap::<(usize, u16, usize), u32>::new();

    for (input_index, input) in parsed.iter().enumerate() {
        let Some(table) = static_tables[input_index].as_ref() else {
            continue;
        };
        if let Some(first) = table.symbols.first() {
            if !is_null_symbol(*first) {
                return Err(PartialLinkError::MissingRelocationSymbol {
                    input_index,
                    rela_section_index: table.section_index,
                    symbol_index: 0,
                });
            }
            symbol_maps.insert((input_index, table.section_index, 0), 0);
        }

        for (symbol_index, symbol) in table.symbols.iter().copied().enumerate().skip(1) {
            let binding = symbol.info >> 4;
            if binding != STB_LOCAL && binding != STB_GLOBAL && binding != STB_WEAK {
                return Err(PartialLinkError::UnsupportedSymbolBinding {
                    input_index,
                    symbol_index,
                    binding,
                });
            }

            let name = symbol_name(input.file, &input.object.sections, table, symbol_index)
                .map_err(|source| PartialLinkError::InvalidSymbolName {
                    input_index,
                    source,
                })?
                .to_vec();
            if binding != STB_LOCAL && symbol.other != 0 {
                return Err(PartialLinkError::UnsupportedNondefaultSymbolVisibility {
                    input_index,
                    symbol_index,
                    other: symbol.other,
                });
            }
            if symbol.section_index == SHN_XINDEX {
                return Err(PartialLinkError::UnsupportedExtendedSymbolSectionIndex {
                    input_index,
                    symbol_index,
                });
            }
            let mut remapped = symbol;
            if symbol.section_index != 0 && symbol.section_index < SHN_LORESERVE {
                let placement = section_maps[input_index]
                    .get(usize::from(symbol.section_index))
                    .copied()
                    .flatten()
                    .ok_or(PartialLinkError::UnsupportedSymbolSection {
                        input_index,
                        symbol_index,
                        section_index: symbol.section_index,
                    })?;
                remapped.section_index = placement.output_section_index;
                remapped.value = placement
                    .contribution_offset
                    .checked_add(symbol.value)
                    .ok_or(PartialLinkError::SymbolValueOverflow {
                        input_index,
                        symbol_index,
                        contribution_offset: placement.contribution_offset,
                        value: symbol.value,
                    })?;
            }

            let pending = PendingSymbol {
                source: (input_index, table.section_index, symbol_index),
                name,
                symbol: remapped,
            };
            if binding == STB_LOCAL {
                locals.push(pending);
            } else {
                nonlocals.push(pending);
            }
        }
    }

    let canonical_nonlocals = canonicalize_nonlocal_symbols(nonlocals)?;
    let first_nonlocal = locals
        .len()
        .checked_add(1)
        .ok_or(PartialLinkError::SizeOverflow("symbol count"))?;
    let symbol_count = locals
        .len()
        .checked_add(canonical_nonlocals.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(PartialLinkError::SizeOverflow("symbol count"))?;
    if symbol_count > u32::MAX as usize {
        return Err(PartialLinkError::TooManySymbols {
            count: symbol_count,
        });
    }

    let mut strtab = vec![0_u8];
    let mut string_offsets = BTreeMap::<Vec<u8>, u32>::new();
    string_offsets.insert(Vec::new(), 0);

    let mut output_symbols = Vec::<Elf64Symbol>::with_capacity(symbol_count);
    output_symbols.push(Elf64Symbol {
        name_offset: 0,
        info: 0,
        other: 0,
        section_index: 0,
        value: 0,
        size: 0,
    });

    for pending in &locals {
        let name_offset = intern_symbol_name(&mut strtab, &mut string_offsets, &pending.name)?;
        let mut symbol = pending.symbol;
        symbol.name_offset = name_offset;
        let output_index =
            u32::try_from(output_symbols.len()).map_err(|_| PartialLinkError::TooManySymbols {
                count: symbol_count,
            })?;
        symbol_maps.insert(pending.source, output_index);
        output_symbols.push(symbol);
    }

    for canonical in &canonical_nonlocals {
        let name_offset = intern_symbol_name(&mut strtab, &mut string_offsets, &canonical.name)?;
        let mut symbol = canonical.symbol;
        symbol.name_offset = name_offset;
        let output_index =
            u32::try_from(output_symbols.len()).map_err(|_| PartialLinkError::TooManySymbols {
                count: symbol_count,
            })?;
        for source in &canonical.sources {
            symbol_maps.insert(*source, output_index);
        }
        output_symbols.push(symbol);
    }

    let strtab_index = next_section_index(output_sections.len(), 1)?;
    output_sections.push(OutputSection {
        name: b".strtab".to_vec(),
        section_type: SHT_STRTAB,
        flags: 0,
        size: strtab.len() as u64,
        link: 0,
        info: 0,
        alignment: 1,
        entry_size: 0,
        data: strtab,
        offset: 0,
    });
    let symtab_index = next_section_index(output_sections.len(), 1)?;
    let symtab_data = serialize_symbols(&output_symbols)?;
    output_sections.push(OutputSection {
        name: b".symtab".to_vec(),
        section_type: SHT_SYMTAB,
        flags: 0,
        size: symtab_data.len() as u64,
        link: u32::from(strtab_index),
        info: u32::try_from(first_nonlocal).map_err(|_| PartialLinkError::TooManySymbols {
            count: symbol_count,
        })?,
        alignment: 8,
        entry_size: ELF64_SYMBOL_SIZE as u64,
        data: symtab_data,
        offset: 0,
    });

    for (input_index, input) in parsed.iter().enumerate() {
        let names = section_names(input_index, input)?;
        let selected_table = static_tables[input_index]
            .as_ref()
            .map(|table| table.section_index);

        for table in &input.object.rela_tables {
            let target = section_maps[input_index]
                .get(usize::from(table.target_section_index))
                .copied()
                .flatten()
                .ok_or(PartialLinkError::UnsupportedRelocationTarget {
                    input_index,
                    rela_section_index: table.section_index,
                    target_section_index: table.target_section_index,
                })?;
            if selected_table != Some(table.symbol_table_index) {
                return Err(PartialLinkError::UnsupportedRelocationSymbolTable {
                    input_index,
                    rela_section_index: table.section_index,
                    symbol_table_index: table.symbol_table_index,
                });
            }

            let mut relocations = Vec::with_capacity(table.relocations.len());
            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                let symbol_index = symbol_maps
                    .get(&(
                        input_index,
                        table.symbol_table_index,
                        relocation.symbol_index as usize,
                    ))
                    .copied()
                    .ok_or(PartialLinkError::MissingRelocationSymbol {
                        input_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let offset = target
                    .contribution_offset
                    .checked_add(relocation.offset)
                    .ok_or(PartialLinkError::RelocationOffsetOverflow {
                        input_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        contribution_offset: target.contribution_offset,
                        offset: relocation.offset,
                    })?;
                relocations.push(Elf64Rela {
                    offset,
                    symbol_index,
                    relocation_type: relocation.relocation_type,
                    addend: relocation.addend,
                });
            }

            let name = names
                .get(usize::from(table.section_index))
                .cloned()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| {
                    format!(".rela.partial.{input_index}.{}", table.section_index).into_bytes()
                });
            let data = serialize_relocations(&relocations)?;
            output_sections.push(OutputSection {
                name,
                section_type: SHT_RELA,
                flags: 0,
                size: data.len() as u64,
                link: u32::from(symtab_index),
                info: u32::from(target.output_section_index),
                alignment: 8,
                entry_size: ELF64_RELA_SIZE,
                data,
                offset: 0,
            });
        }
    }

    let shstrtab_index = next_section_index(output_sections.len(), 1)?;
    let (shstrtab, name_offsets) = build_section_name_table(&output_sections)?;
    output_sections.push(OutputSection {
        name: b".shstrtab".to_vec(),
        section_type: SHT_STRTAB,
        flags: 0,
        size: shstrtab.len() as u64,
        link: 0,
        info: 0,
        alignment: 1,
        entry_size: 0,
        data: shstrtab,
        offset: 0,
    });

    let section_count = output_sections
        .len()
        .checked_add(1)
        .ok_or(PartialLinkError::SizeOverflow("section count"))?;
    if section_count >= usize::from(SHN_LORESERVE) {
        return Err(PartialLinkError::TooManySections {
            count: section_count,
        });
    }

    serialize_object(
        &mut output_sections,
        &name_offsets,
        shstrtab_index,
        section_count as u16,
    )
}

fn section_names(
    input_index: usize,
    input: &ParsedInput<'_>,
) -> Result<Vec<Vec<u8>>, PartialLinkError> {
    let index = input.object.header.section_name_string_table_index;
    if index == 0 {
        return Err(PartialLinkError::MissingSectionNameTable { input_index });
    }
    let table = input
        .object
        .sections
        .get(usize::from(index))
        .ok_or(PartialLinkError::MissingSectionNameTable { input_index })?;
    if table.section_type != SHT_STRTAB {
        return Err(PartialLinkError::SectionNameTableNotStringTable {
            input_index,
            section_index: index,
            section_type: table.section_type,
        });
    }
    let end = table
        .offset
        .checked_add(table.size)
        .ok_or(PartialLinkError::SectionNameTableRangeOverflow { input_index })?;
    if end > input.file.len() as u64 {
        return Err(PartialLinkError::SectionNameTableOutOfBounds {
            input_index,
            end,
            file_len: input.file.len(),
        });
    }

    input
        .object
        .sections
        .iter()
        .enumerate()
        .map(|(section_index, section)| {
            if u64::from(section.name_offset) >= table.size {
                return Err(PartialLinkError::InvalidSectionNameOffset {
                    input_index,
                    section_index: section_index as u16,
                    name_offset: section.name_offset,
                    string_table_size: table.size,
                });
            }
            let start = table.offset as usize + section.name_offset as usize;
            let tail = &input.file[start..end as usize];
            let nul = tail.iter().position(|byte| *byte == 0).ok_or(
                PartialLinkError::UnterminatedSectionName {
                    input_index,
                    section_index: section_index as u16,
                },
            )?;
            Ok(tail[..nul].to_vec())
        })
        .collect()
}

fn canonicalize_nonlocal_symbols(
    candidates: Vec<PendingSymbol>,
) -> Result<Vec<CanonicalNonlocal>, PartialLinkError> {
    let mut canonical = Vec::<CanonicalNonlocal>::new();
    let mut by_name = BTreeMap::<Vec<u8>, usize>::new();

    for candidate in candidates {
        validate_common_candidate(&candidate)?;

        if candidate.name.is_empty() {
            canonical.push(CanonicalNonlocal {
                name: candidate.name,
                symbol: candidate.symbol,
                representative_source: candidate.source,
                sources: vec![candidate.source],
            });
            continue;
        }

        let Some(&index) = by_name.get(&candidate.name) else {
            let index = canonical.len();
            by_name.insert(candidate.name.clone(), index);
            canonical.push(CanonicalNonlocal {
                name: candidate.name,
                symbol: candidate.symbol,
                representative_source: candidate.source,
                sources: vec![candidate.source],
            });
            continue;
        };

        let existing = &mut canonical[index];
        existing.sources.push(candidate.source);
        merge_nonlocal_candidate(existing, &candidate)?;
    }

    Ok(canonical)
}

fn validate_common_candidate(candidate: &PendingSymbol) -> Result<(), PartialLinkError> {
    if candidate.symbol.section_index != SHN_COMMON {
        return Ok(());
    }

    let binding = candidate.symbol.info >> 4;
    if binding != STB_GLOBAL {
        return Err(PartialLinkError::UnsupportedCommonBinding {
            input_index: candidate.source.0,
            symbol_index: candidate.source.2,
            binding,
        });
    }
    let alignment = candidate.symbol.value;
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(PartialLinkError::InvalidCommonAlignment {
            input_index: candidate.source.0,
            symbol_index: candidate.source.2,
            alignment,
        });
    }
    Ok(())
}

fn merge_nonlocal_candidate(
    existing: &mut CanonicalNonlocal,
    candidate: &PendingSymbol,
) -> Result<(), PartialLinkError> {
    let existing_binding = existing.symbol.info >> 4;
    let candidate_binding = candidate.symbol.info >> 4;
    let existing_undefined = existing.symbol.section_index == SHN_UNDEF;
    let candidate_undefined = candidate.symbol.section_index == SHN_UNDEF;
    let existing_common = existing.symbol.section_index == SHN_COMMON;
    let candidate_common = candidate.symbol.section_index == SHN_COMMON;

    if existing_undefined && candidate_undefined {
        if existing_binding == STB_WEAK && candidate_binding == STB_GLOBAL {
            existing.symbol = candidate.symbol;
            existing.representative_source = candidate.source;
        }
        return Ok(());
    }
    if existing_undefined {
        existing.symbol = candidate.symbol;
        existing.representative_source = candidate.source;
        return Ok(());
    }
    if candidate_undefined {
        return Ok(());
    }

    match (existing_common, candidate_common) {
        (true, true) => {
            existing.symbol.size = existing.symbol.size.max(candidate.symbol.size);
            existing.symbol.value = existing.symbol.value.max(candidate.symbol.value);
        }
        (true, false) => {
            if candidate_binding == STB_GLOBAL {
                existing.symbol = candidate.symbol;
                existing.representative_source = candidate.source;
            }
        }
        (false, true) => {
            if existing_binding == STB_WEAK {
                existing.symbol = candidate.symbol;
                existing.representative_source = candidate.source;
            }
        }
        (false, false) => match (existing_binding, candidate_binding) {
            (STB_WEAK, STB_GLOBAL) => {
                existing.symbol = candidate.symbol;
                existing.representative_source = candidate.source;
            }
            (STB_GLOBAL, STB_GLOBAL) => {
                return Err(PartialLinkError::MultipleStrongDefinitions {
                    name: existing.name.clone(),
                    first_input_index: existing.representative_source.0,
                    second_input_index: candidate.source.0,
                });
            }
            (STB_GLOBAL, STB_WEAK) | (STB_WEAK, STB_WEAK) => {}
            _ => unreachable!("nonlocal candidates only use global or weak binding"),
        },
    }

    Ok(())
}

fn intern_symbol_name(
    table: &mut Vec<u8>,
    offsets: &mut BTreeMap<Vec<u8>, u32>,
    name: &[u8],
) -> Result<u32, PartialLinkError> {
    if let Some(offset) = offsets.get(name) {
        return Ok(*offset);
    }
    let offset = u32::try_from(table.len()).map_err(|_| PartialLinkError::StringTableTooLarge)?;
    table.extend_from_slice(name);
    table.push(0);
    offsets.insert(name.to_vec(), offset);
    Ok(offset)
}

fn align_section_contribution(value: u64, alignment: u64) -> Option<u64> {
    let alignment = alignment.max(1);
    if alignment == 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|value| value & !mask)
}

fn section_bytes(file: &[u8], section: &Elf64SectionHeader) -> Vec<u8> {
    if section.section_type == SHT_NOBITS {
        return Vec::new();
    }
    file[section.offset as usize..(section.offset + section.size) as usize].to_vec()
}

fn is_null_symbol(symbol: Elf64Symbol) -> bool {
    symbol.name_offset == 0
        && symbol.info == 0
        && symbol.other == 0
        && symbol.section_index == 0
        && symbol.value == 0
        && symbol.size == 0
}

fn next_section_index(current_len: usize, additional: usize) -> Result<u16, PartialLinkError> {
    let index = current_len
        .checked_add(additional)
        .ok_or(PartialLinkError::SizeOverflow("section count"))?;
    if index >= usize::from(SHN_LORESERVE) {
        return Err(PartialLinkError::TooManySections { count: index + 1 });
    }
    Ok(index as u16)
}

fn serialize_symbols(symbols: &[Elf64Symbol]) -> Result<Vec<u8>, PartialLinkError> {
    let capacity = symbols
        .len()
        .checked_mul(ELF64_SYMBOL_SIZE)
        .ok_or(PartialLinkError::SizeOverflow("symbol table"))?;
    let mut bytes = Vec::with_capacity(capacity);
    for symbol in symbols {
        bytes.extend_from_slice(&symbol.name_offset.to_le_bytes());
        bytes.push(symbol.info);
        bytes.push(symbol.other);
        bytes.extend_from_slice(&symbol.section_index.to_le_bytes());
        bytes.extend_from_slice(&symbol.value.to_le_bytes());
        bytes.extend_from_slice(&symbol.size.to_le_bytes());
    }
    Ok(bytes)
}

fn serialize_relocations(relocations: &[Elf64Rela]) -> Result<Vec<u8>, PartialLinkError> {
    let capacity = relocations
        .len()
        .checked_mul(ELF64_RELA_SIZE as usize)
        .ok_or(PartialLinkError::SizeOverflow("RELA table"))?;
    let mut bytes = Vec::with_capacity(capacity);
    for relocation in relocations {
        bytes.extend_from_slice(&relocation.offset.to_le_bytes());
        let info =
            (u64::from(relocation.symbol_index) << 32) | u64::from(relocation.relocation_type);
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&relocation.addend.to_le_bytes());
    }
    Ok(bytes)
}

fn build_section_name_table(
    sections: &[OutputSection],
) -> Result<(Vec<u8>, Vec<u32>), PartialLinkError> {
    let mut bytes = vec![0_u8];
    let mut offsets = BTreeMap::<Vec<u8>, u32>::new();
    offsets.insert(Vec::new(), 0);
    let mut section_offsets = Vec::with_capacity(sections.len() + 1);

    for section in sections {
        let offset = intern_string(&mut bytes, &mut offsets, &section.name)?;
        section_offsets.push(offset);
    }
    let shstrtab_offset = intern_string(&mut bytes, &mut offsets, b".shstrtab")?;
    section_offsets.push(shstrtab_offset);
    Ok((bytes, section_offsets))
}

fn intern_string(
    table: &mut Vec<u8>,
    offsets: &mut BTreeMap<Vec<u8>, u32>,
    value: &[u8],
) -> Result<u32, PartialLinkError> {
    if let Some(offset) = offsets.get(value) {
        return Ok(*offset);
    }
    let offset = u32::try_from(table.len()).map_err(|_| PartialLinkError::StringTableTooLarge)?;
    table.extend_from_slice(value);
    table.push(0);
    offsets.insert(value.to_vec(), offset);
    Ok(offset)
}

fn serialize_object(
    sections: &mut [OutputSection],
    name_offsets: &[u32],
    shstrtab_index: u16,
    section_count: u16,
) -> Result<Vec<u8>, PartialLinkError> {
    let mut bytes = vec![0_u8; ELF64_HEADER_SIZE];
    let mut cursor = ELF64_HEADER_SIZE as u64;

    for section in sections.iter_mut() {
        let alignment = section.alignment.max(1);
        cursor = align_up(cursor, alignment)?;
        let cursor_usize =
            usize::try_from(cursor).map_err(|_| PartialLinkError::FileOffsetOverflow)?;
        if bytes.len() < cursor_usize {
            bytes.resize(cursor_usize, 0);
        }
        section.offset = cursor;

        if section.section_type != SHT_NOBITS {
            bytes.extend_from_slice(&section.data);
            cursor = cursor
                .checked_add(section.data.len() as u64)
                .ok_or(PartialLinkError::FileOffsetOverflow)?;
        }
    }

    let shoff = align_up(cursor, 8)?;
    let shoff_usize = usize::try_from(shoff).map_err(|_| PartialLinkError::FileOffsetOverflow)?;
    if bytes.len() < shoff_usize {
        bytes.resize(shoff_usize, 0);
    }

    write_elf_header(
        &mut bytes[..ELF64_HEADER_SIZE],
        shoff,
        section_count,
        shstrtab_index,
    );
    bytes.extend_from_slice(&[0_u8; ELF64_SECTION_HEADER_SIZE]);

    if name_offsets.len() != sections.len() {
        return Err(PartialLinkError::SizeOverflow("section-name offset table"));
    }
    for (section, name_offset) in sections.iter().zip(name_offsets) {
        append_section_header(&mut bytes, section, *name_offset);
    }

    Ok(bytes)
}

fn align_up(value: u64, alignment: u64) -> Result<u64, PartialLinkError> {
    if alignment <= 1 {
        return Ok(value);
    }
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or(PartialLinkError::FileOffsetOverflow)
}

fn write_elf_header(header: &mut [u8], shoff: u64, shnum: u16, shstrndx: u16) {
    header[0..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&ET_REL.to_le_bytes());
    header[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    header[20..24].copy_from_slice(&1_u32.to_le_bytes());
    header[40..48].copy_from_slice(&shoff.to_le_bytes());
    header[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
    header[58..60].copy_from_slice(&(ELF64_SECTION_HEADER_SIZE as u16).to_le_bytes());
    header[60..62].copy_from_slice(&shnum.to_le_bytes());
    header[62..64].copy_from_slice(&shstrndx.to_le_bytes());
}

fn append_section_header(bytes: &mut Vec<u8>, section: &OutputSection, name_offset: u32) {
    bytes.extend_from_slice(&name_offset.to_le_bytes());
    bytes.extend_from_slice(&section.section_type.to_le_bytes());
    bytes.extend_from_slice(&section.flags.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&section.offset.to_le_bytes());
    bytes.extend_from_slice(&section.size.to_le_bytes());
    bytes.extend_from_slice(&section.link.to_le_bytes());
    bytes.extend_from_slice(&section.info.to_le_bytes());
    bytes.extend_from_slice(&section.alignment.to_le_bytes());
    bytes.extend_from_slice(&section.entry_size.to_le_bytes());
}
