use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::elf64::SHT_NOBITS;
use crate::executable_pipeline::ExecutableSectionInput;
use crate::layout::LaidOutSection;
use crate::link_context::{
    build_link_context_with_got_entries, LinkContextBuildError, LinkContextRelocationError,
};
use crate::link_symbols::{resolve_validated_objects_with_common, LinkSymbolError};
use crate::linker_input::{LinkerInputError, LinkerInputObject};
use crate::load_segments::{SHF_ALLOC, SHF_WRITE};
use crate::object_symbols::named_symbols_from_table;
use crate::permission_layout::{
    layout_sections_by_permissions, PermissionLayoutError, PermissionLayoutInput,
};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{COMMON_OBJECT_INDEX, COMMON_SECTION_INDEX, STB_GLOBAL, STB_WEAK};
use crate::x86_64_relocations::R_X86_64_GOTPCREL;

const SHT_PROGBITS: u32 = 1;
const GOT_OBJECT_INDEX: usize = usize::MAX - 1;
const GOT_SECTION_INDEX: u16 = 1;
const GOT_ENTRY_SIZE: u64 = 8;
const GOT_ALIGNMENT: u64 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedSectionImage {
    pub object_index: usize,
    pub section_index: u16,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub size: u64,
    pub alignment: u64,
    pub bytes: Vec<u8>,
}

impl RelocatedSectionImage {
    pub fn executable_input(&self) -> ExecutableSectionInput<'_> {
        ExecutableSectionInput {
            object_index: self.object_index,
            section_index: self.section_index,
            section_type: self.section_type,
            flags: self.flags,
            size: self.size,
            alignment: self.alignment,
            bytes: &self.bytes,
        }
    }
}

#[derive(Debug)]
pub enum RelocatedSectionError {
    NonCanonicalObjectIndex {
        position: usize,
        object_index: usize,
    },
    Input(LinkerInputError),
    Symbols(LinkSymbolError),
    Layout(PermissionLayoutError),
    LinkContext(LinkContextBuildError),
    MissingLayout {
        object_index: usize,
        section_index: u16,
    },
    MissingGotSymbolMetadata {
        object_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
    },
    UnsupportedGotBinding {
        object_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
        binding: u8,
    },
    GotSizeOverflow {
        symbol_count: usize,
    },
    GotAddressOverflow {
        entry_index: usize,
    },
    MissingGotSymbolAddress {
        name: Vec<u8>,
    },
    RelocationAgainstMemoryOnlySection {
        object_index: usize,
        section_index: u16,
        rela_section_index: u16,
    },
    Relocation {
        object_index: usize,
        section_index: u16,
        rela_section_index: u16,
        source: LinkContextRelocationError,
    },
}

impl fmt::Display for RelocatedSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalObjectIndex {
                position,
                object_index,
            } => write!(
                f,
                "link input at position {position} has object index {object_index}; expected canonical index {position}"
            ),
            Self::Input(source) => write!(f, "cannot extract linker input sections: {source}"),
            Self::Symbols(source) => write!(f, "cannot resolve linker symbols: {source}"),
            Self::Layout(source) => write!(f, "cannot lay out linker input sections: {source}"),
            Self::LinkContext(source) => write!(f, "cannot build link context: {source}"),
            Self::MissingLayout {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} has no matching output layout"
            ),
            Self::MissingGotSymbolMetadata {
                object_index,
                rela_section_index,
                symbol_index,
            } => write!(
                f,
                "GOTPCREL relocation in object {object_index} RELA section {rela_section_index} refers to missing symbol {symbol_index} metadata"
            ),
            Self::UnsupportedGotBinding {
                object_index,
                rela_section_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "GOTPCREL relocation in object {object_index} RELA section {rela_section_index} symbol {symbol_index} uses unsupported binding {binding}; bounded static GOT entries require global/weak symbols"
            ),
            Self::GotSizeOverflow { symbol_count } => write!(
                f,
                "synthetic GOT size overflows u64 for {symbol_count} unique symbols"
            ),
            Self::GotAddressOverflow { entry_index } => write!(
                f,
                "synthetic GOT entry address overflows u64 at entry {entry_index}"
            ),
            Self::MissingGotSymbolAddress { name } => write!(
                f,
                "synthetic GOT symbol {:?} has no resolved final address",
                String::from_utf8_lossy(name)
            ),
            Self::RelocationAgainstMemoryOnlySection {
                object_index,
                section_index,
                rela_section_index,
            } => write!(
                f,
                "RELA section {rela_section_index} targets memory-only object {object_index} section {section_index}; materializing relocated NOBITS contents is not supported"
            ),
            Self::Relocation {
                object_index,
                section_index,
                rela_section_index,
                source,
            } => write!(
                f,
                "cannot apply RELA section {rela_section_index} to object {object_index} section {section_index}: {source}"
            ),
        }
    }
}

impl std::error::Error for RelocatedSectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Input(source) => Some(source),
            Self::Symbols(source) => Some(source),
            Self::Layout(source) => Some(source),
            Self::LinkContext(source) => Some(source),
            Self::Relocation { source, .. } => Some(source),
            Self::NonCanonicalObjectIndex { .. }
            | Self::MissingLayout { .. }
            | Self::MissingGotSymbolMetadata { .. }
            | Self::UnsupportedGotBinding { .. }
            | Self::GotSizeOverflow { .. }
            | Self::GotAddressOverflow { .. }
            | Self::MissingGotSymbolAddress { .. }
            | Self::RelocationAgainstMemoryOnlySection { .. } => None,
        }
    }
}

pub fn relocate_allocatable_sections(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
) -> Result<Vec<RelocatedSectionImage>, RelocatedSectionError> {
    for (position, input) in inputs.iter().enumerate() {
        if input.object_index != position {
            return Err(RelocatedSectionError::NonCanonicalObjectIndex {
                position,
                object_index: input.object_index,
            });
        }
    }

    let mut sections = Vec::new();
    for input in inputs {
        sections.extend(
            input
                .allocatable_sections()
                .map_err(RelocatedSectionError::Input)?,
        );
    }

    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let common_section = resolve_validated_objects_with_common(&validated_objects)
        .map_err(RelocatedSectionError::Symbols)?
        .common_section;
    let got_symbols = collect_gotpcrel_symbols(inputs)?;
    let got_size = got_size(got_symbols.len())?;

    let mut layout_inputs = sections
        .iter()
        .map(|section| section.permission_layout_input())
        .collect::<Vec<_>>();
    if let Some(common) = common_section {
        layout_inputs.push(PermissionLayoutInput {
            object_index: COMMON_OBJECT_INDEX,
            section_index: COMMON_SECTION_INDEX,
            size: common.size,
            alignment: common.alignment,
            flags: SHF_ALLOC | SHF_WRITE,
        });
    }
    if got_size != 0 {
        layout_inputs.push(PermissionLayoutInput {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
            size: got_size,
            alignment: GOT_ALIGNMENT,
            flags: SHF_ALLOC | SHF_WRITE,
        });
    }

    let layout = layout_sections_by_permissions(start_address, page_alignment, layout_inputs)
        .map_err(RelocatedSectionError::Layout)?;
    let got_entries = got_entry_addresses(&layout, &got_symbols)?;

    let context = build_link_context_with_got_entries(&validated_objects, &layout, got_entries)
        .map_err(RelocatedSectionError::LinkContext)?;

    let mut relocated = sections
        .into_iter()
        .map(|section| {
            let section_layout =
                matching_layout(&layout, section.object_index, section.section_index).ok_or(
                    RelocatedSectionError::MissingLayout {
                        object_index: section.object_index,
                        section_index: section.section_index,
                    },
                )?;
            let mut bytes = section.bytes.to_vec();

            for table in &section.rela_tables {
                reject_memory_only_relocation(&section, table)?;
                context
                    .apply_rela_table(
                        &mut bytes,
                        section_layout.address,
                        table,
                        section.object_index,
                    )
                    .map_err(|source| RelocatedSectionError::Relocation {
                        object_index: section.object_index,
                        section_index: section.section_index,
                        rela_section_index: table.section_index,
                        source,
                    })?;
            }

            Ok(RelocatedSectionImage {
                object_index: section.object_index,
                section_index: section.section_index,
                section_type: section.section_type,
                flags: section.flags,
                address: section_layout.address,
                size: section.size,
                alignment: section.alignment,
                bytes,
            })
        })
        .collect::<Result<Vec<_>, RelocatedSectionError>>()?;

    if let Some(common) = common_section {
        let common_layout = matching_layout(&layout, COMMON_OBJECT_INDEX, COMMON_SECTION_INDEX)
            .ok_or(RelocatedSectionError::MissingLayout {
                object_index: COMMON_OBJECT_INDEX,
                section_index: COMMON_SECTION_INDEX,
            })?;
        relocated.push(RelocatedSectionImage {
            object_index: COMMON_OBJECT_INDEX,
            section_index: COMMON_SECTION_INDEX,
            section_type: SHT_NOBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: common_layout.address,
            size: common.size,
            alignment: common.alignment,
            bytes: Vec::new(),
        });
    }

    if got_size != 0 {
        let got_layout = matching_layout(&layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
            RelocatedSectionError::MissingLayout {
                object_index: GOT_OBJECT_INDEX,
                section_index: GOT_SECTION_INDEX,
            },
        )?;
        let mut bytes = Vec::with_capacity(got_size as usize);
        for name in &got_symbols {
            let address = context
                .global_addresses()
                .get(name)
                .copied()
                .ok_or_else(|| RelocatedSectionError::MissingGotSymbolAddress {
                    name: name.clone(),
                })?;
            bytes.extend_from_slice(&address.to_le_bytes());
        }
        relocated.push(RelocatedSectionImage {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: got_layout.address,
            size: got_size,
            alignment: GOT_ALIGNMENT,
            bytes,
        });
    }

    Ok(relocated)
}

fn collect_gotpcrel_symbols(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<Vec<u8>>, RelocatedSectionError> {
    let mut names = BTreeSet::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .any(|relocation| relocation.relocation_type == R_X86_64_GOTPCREL)
            {
                continue;
            }

            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: table
                        .relocations
                        .iter()
                        .find(|relocation| relocation.relocation_type == R_X86_64_GOTPCREL)
                        .map(|relocation| relocation.symbol_index)
                        .unwrap_or(0),
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;

            for relocation in table
                .relocations
                .iter()
                .filter(|relocation| relocation.relocation_type == R_X86_64_GOTPCREL)
            {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(RelocatedSectionError::UnsupportedGotBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        binding,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                names.insert(symbol.name.to_vec());
            }
        }
    }

    Ok(names.into_iter().collect())
}

fn got_size(symbol_count: usize) -> Result<u64, RelocatedSectionError> {
    u64::try_from(symbol_count)
        .ok()
        .and_then(|count| count.checked_mul(GOT_ENTRY_SIZE))
        .ok_or(RelocatedSectionError::GotSizeOverflow { symbol_count })
}

fn got_entry_addresses(
    layout: &[LaidOutSection],
    symbols: &[Vec<u8>],
) -> Result<BTreeMap<Vec<u8>, u64>, RelocatedSectionError> {
    if symbols.is_empty() {
        return Ok(BTreeMap::new());
    }
    let got_layout = matching_layout(layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
        RelocatedSectionError::MissingLayout {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
        },
    )?;
    let mut entries = BTreeMap::new();
    for (entry_index, name) in symbols.iter().enumerate() {
        let offset = u64::try_from(entry_index)
            .ok()
            .and_then(|index| index.checked_mul(GOT_ENTRY_SIZE))
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        let address = got_layout
            .address
            .checked_add(offset)
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        entries.insert(name.clone(), address);
    }
    Ok(entries)
}

fn matching_layout(
    layout: &[LaidOutSection],
    object_index: usize,
    section_index: u16,
) -> Option<LaidOutSection> {
    layout
        .iter()
        .copied()
        .find(|entry| entry.object_index == object_index && entry.section_index == section_index)
}

fn reject_memory_only_relocation(
    section: &crate::linker_input::LinkerInputSection<'_>,
    table: &Elf64RelaTable,
) -> Result<(), RelocatedSectionError> {
    if section.bytes.is_empty() && section.size != 0 && !table.relocations.is_empty() {
        return Err(RelocatedSectionError::RelocationAgainstMemoryOnlySection {
            object_index: section.object_index,
            section_index: section.section_index,
            rela_section_index: table.section_index,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf64::{
        Elf64Header, Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, EM_X86_64, SHT_STRTAB,
        SHT_SYMTAB,
    };
    use crate::input_object::{RelocatableObject, ET_REL};
    use crate::load_segments::{SHF_EXECINSTR, SHF_WRITE};
    use crate::relocations::{Elf64Rela, Elf64RelaTable};
    use crate::x86_64_relocations::R_X86_64_64;

    fn header(section_count: u16) -> Elf64Header {
        Elf64Header {
            elf_type: ET_REL,
            machine: EM_X86_64,
            entry: 0,
            program_header_offset: 0,
            section_header_offset: 0,
            flags: 0,
            header_size: 64,
            program_header_entry_size: 0,
            program_header_count: 0,
            section_header_entry_size: 64,
            section_header_count: section_count,
            section_name_string_table_index: 0,
        }
    }

    fn section(
        section_type: u32,
        flags: u64,
        offset: u64,
        size: u64,
        alignment: u64,
    ) -> Elf64SectionHeader {
        Elf64SectionHeader {
            name_offset: 0,
            section_type,
            flags,
            address: 0,
            offset,
            size,
            link: 0,
            info: 0,
            address_alignment: alignment,
            entry_size: 0,
        }
    }

    #[test]
    fn lays_out_and_applies_local_absolute_relocation() {
        let file = [0_u8; 9];
        let sections = vec![
            section(0, 0, 0, 0, 0),
            section(SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 8, 16),
            section(SHT_STRTAB, 0, 8, 1, 1),
            section(SHT_SYMTAB, 0, 9, 0, 8),
        ];
        let symbol_tables = vec![Elf64SymbolTable {
            section_index: 3,
            string_table_index: 2,
            symbols: vec![Elf64Symbol {
                name_offset: 0,
                info: 0,
                other: 0,
                section_index: 1,
                value: 4,
                size: 0,
            }],
        }];
        let rela_tables = vec![Elf64RelaTable {
            section_index: 4,
            symbol_table_index: 3,
            target_section_index: 1,
            relocations: vec![Elf64Rela {
                offset: 0,
                symbol_index: 0,
                relocation_type: R_X86_64_64,
                addend: 0,
            }],
        }];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(4),
                sections,
                symbol_tables,
                rela_tables,
            },
        };

        let relocated = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap();

        assert_eq!(relocated.len(), 1);
        assert_eq!(relocated[0].address, 0x400000);
        assert_eq!(
            u64::from_le_bytes(relocated[0].bytes[..8].try_into().unwrap()),
            0x400004
        );
        let executable = relocated[0].executable_input();
        assert_eq!(executable.bytes, relocated[0].bytes.as_slice());
        assert_eq!(executable.flags, SHF_ALLOC | SHF_EXECINSTR);
    }

    #[test]
    fn separates_permission_classes_across_pages() {
        let file = [1_u8, 2, 3];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(4),
                sections: vec![
                    section(0, 0, 0, 0, 0),
                    section(SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 1, 1),
                    section(SHT_PROGBITS, SHF_ALLOC, 1, 1, 1),
                    section(SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 2, 1, 1),
                ],
                symbol_tables: Vec::new(),
                rela_tables: Vec::new(),
            },
        };

        let relocated = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap();

        assert_eq!(
            relocated
                .iter()
                .map(|section| section.address)
                .collect::<Vec<_>>(),
            vec![0x400000, 0x401000, 0x402000]
        );
        assert_eq!(relocated[0].bytes, vec![1]);
        assert_eq!(relocated[1].bytes, vec![2]);
        assert_eq!(relocated[2].bytes, vec![3]);
    }

    #[test]
    fn rejects_noncanonical_object_indices_before_symbol_resolution() {
        let file = [0_u8; 1];
        let input = LinkerInputObject {
            object_index: 3,
            file: &file,
            object: RelocatableObject {
                header: header(1),
                sections: vec![section(0, 0, 0, 0, 0)],
                symbol_tables: Vec::new(),
                rela_tables: Vec::new(),
            },
        };

        let error = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap_err();
        assert!(matches!(
            error,
            RelocatedSectionError::NonCanonicalObjectIndex {
                position: 0,
                object_index: 3
            }
        ));
    }

    #[test]
    fn rejects_relocations_against_nobits_sections() {
        let file = [0_u8; 1];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(2),
                sections: vec![
                    section(0, 0, 0, 0, 0),
                    section(SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0, 8, 8),
                ],
                symbol_tables: Vec::new(),
                rela_tables: vec![Elf64RelaTable {
                    section_index: 2,
                    symbol_table_index: 3,
                    target_section_index: 1,
                    relocations: vec![Elf64Rela {
                        offset: 0,
                        symbol_index: 0,
                        relocation_type: R_X86_64_64,
                        addend: 0,
                    }],
                }],
            },
        };

        let error = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap_err();
        assert!(matches!(
            error,
            RelocatedSectionError::RelocationAgainstMemoryOnlySection {
                object_index: 0,
                section_index: 1,
                rela_section_index: 2
            }
        ));
    }
}
