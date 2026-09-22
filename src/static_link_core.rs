use core::fmt;

use crate::executable_writer::{
    write_elf64_x86_64_executable_segments, write_elf64_x86_64_position_independent_segments,
    ExecutableImage, ExecutableWriteError, LoadSegmentInput,
};
use crate::layout::LaidOutSection;
use crate::link_map::{build_link_map, LinkMap};
use crate::link_symbols::{resolve_validated_objects, LinkSymbolError};
use crate::linker_input::LinkerInputObject;
use crate::load_segments::{build_load_segments, LoadSegmentBuildError, LoadableSectionInput};
use crate::object_symbols::named_symbols_from_table;
use crate::pie_runtime::{add_runtime_relative_relocations, PieDynamicSegment, PieRuntimeError};
use crate::relocated_sections::{RelocatedSectionError, RelocatedSectionImage};
use crate::resolve::{SHN_UNDEF, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};
use crate::tls::{
    inject_static_tls_program_header, relocate_allocatable_sections_with_static_tls,
    StaticTlsProgramHeaderError, StaticTlsRelocationError,
};
use crate::x86_64_relocations::{
    is_static_pie_pc_relative_relocation_type, is_static_pie_relocation_type,
};

#[derive(Debug)]
pub enum StaticLinkError {
    Relocation(RelocatedSectionError),
    TlsRelocation(StaticTlsRelocationError),
    Symbols(LinkSymbolError),
    MissingEntrySymbol {
        name: Vec<u8>,
    },
    EntryAddress(FinalSymbolAddressError),
    LinkMap(FinalSymbolAddressError),
    LoadSegments(LoadSegmentBuildError),
    Write(ExecutableWriteError),
    TlsProgramHeader(StaticTlsProgramHeaderError),
    PieRuntime(PieRuntimeError),
    PositionIndependentRelocation {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        relocation_type: u32,
    },
    PositionIndependentAbsoluteSymbol {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
    },
    PositionIndependentUndefinedWeakSymbol {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
    },
    PositionIndependentAbsoluteEntrySymbol {
        name: Vec<u8>,
    },
}

impl fmt::Display for StaticLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocation(source) => write!(f, "cannot relocate input sections: {source}"),
            Self::TlsRelocation(source) => write!(f, "cannot relocate static TLS: {source}"),
            Self::Symbols(source) => write!(f, "cannot resolve entry symbol: {source}"),
            Self::MissingEntrySymbol { name } => write!(
                f,
                "entry symbol {:?} is not defined by any input object",
                String::from_utf8_lossy(name)
            ),
            Self::EntryAddress(source) => write!(f, "cannot resolve entry address: {source}"),
            Self::LinkMap(source) => write!(f, "cannot build link map: {source}"),
            Self::LoadSegments(source) => write!(f, "cannot build load segments: {source}"),
            Self::Write(source) => write!(f, "cannot emit executable: {source}"),
            Self::TlsProgramHeader(source) => {
                write!(f, "cannot emit static TLS program header: {source}")
            }
            Self::PieRuntime(source) => {
                write!(f, "cannot build PIE runtime relocations: {source}")
            }
            Self::PositionIndependentRelocation {
                object_index,
                rela_section_index,
                relocation_index,
                relocation_type,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} uses relocation type {relocation_type}, which is not load-bias invariant for bounded position-independent static linking"
            ),
            Self::PositionIndependentAbsoluteSymbol {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} references SHN_ABS symbol {symbol_index} with a PC-relative relocation; the result is not load-bias invariant"
            ),
            Self::PositionIndependentUndefinedWeakSymbol {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} references undefined weak symbol {symbol_index} with a PC-relative relocation; the zero-valued weak reference is not load-bias invariant"
            ),
            Self::PositionIndependentAbsoluteEntrySymbol { name } => write!(
                f,
                "entry symbol {:?} resolves to SHN_ABS; bounded ET_DYN entry addresses must be load-bias relative",
                String::from_utf8_lossy(name)
            ),
        }
    }
}

impl std::error::Error for StaticLinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Relocation(source) => Some(source),
            Self::TlsRelocation(source) => Some(source),
            Self::Symbols(source) => Some(source),
            Self::EntryAddress(source) | Self::LinkMap(source) => Some(source),
            Self::LoadSegments(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::TlsProgramHeader(source) => Some(source),
            Self::PieRuntime(source) => Some(source),
            Self::MissingEntrySymbol { .. }
            | Self::PositionIndependentRelocation { .. }
            | Self::PositionIndependentAbsoluteSymbol { .. }
            | Self::PositionIndependentUndefinedWeakSymbol { .. }
            | Self::PositionIndependentAbsoluteEntrySymbol { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLinkOutput {
    pub image: ExecutableImage,
    pub link_map: LinkMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticPositionIndependentArtifact {
    pub output: StaticLinkOutput,
    pub dynamic: Option<PieDynamicSegment>,
}

pub fn link_static_executable(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<ExecutableImage, StaticLinkError> {
    link_static_executable_with_map(inputs, start_address, page_alignment, entry_symbol)
        .map(|output| output.image)
}

pub fn link_static_executable_with_map(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<StaticLinkOutput, StaticLinkError> {
    link_static_image_artifact(inputs, start_address, page_alignment, entry_symbol, false)
        .map(|artifact| artifact.output)
}

pub(crate) fn link_static_position_independent_artifact_with_map(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<StaticPositionIndependentArtifact, StaticLinkError> {
    validate_position_independent_inputs(inputs)?;
    link_static_image_artifact(inputs, 0, page_alignment, entry_symbol, true)
}

fn validate_position_independent_inputs(
    inputs: &[LinkerInputObject<'_>],
) -> Result<(), StaticLinkError> {
    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let definitions =
        resolve_validated_objects(&validated_objects).map_err(StaticLinkError::Symbols)?;

    for input in inputs {
        for table in &input.object.rela_tables {
            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .expect("validated RELA table references a validated symbol table");
            let named_symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                StaticLinkError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;

            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                if !is_static_pie_relocation_type(relocation.relocation_type) {
                    return Err(StaticLinkError::PositionIndependentRelocation {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        relocation_type: relocation.relocation_type,
                    });
                }
                if !is_static_pie_pc_relative_relocation_type(relocation.relocation_type) {
                    continue;
                }

                let symbol = &named_symbols[relocation.symbol_index as usize];
                let binding = symbol.symbol.info >> 4;
                let resolved = if binding == STB_LOCAL {
                    Some(symbol.symbol)
                } else {
                    definitions
                        .get(symbol.name)
                        .map(|definition| definition.symbol)
                };

                if resolved.is_some_and(|symbol| symbol.section_index == SHN_ABS) {
                    return Err(StaticLinkError::PositionIndependentAbsoluteSymbol {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                if resolved.is_none()
                    && binding == STB_WEAK
                    && symbol.symbol.section_index == SHN_UNDEF
                {
                    return Err(StaticLinkError::PositionIndependentUndefinedWeakSymbol {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
            }
        }
    }
    Ok(())
}

fn link_static_image_artifact(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
    position_independent: bool,
) -> Result<StaticPositionIndependentArtifact, StaticLinkError> {
    let relocated_output =
        relocate_allocatable_sections_with_static_tls(inputs, start_address, page_alignment)
            .map_err(|source| match source {
                StaticTlsRelocationError::Regular(source) => StaticLinkError::Relocation(source),
                source => StaticLinkError::TlsRelocation(source),
            })?;
    let got_entries = relocated_output.got_entries;
    let tls_layout = relocated_output.tls_layout;
    let relocated = relocated_output.sections;

    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let definitions =
        resolve_validated_objects(&validated_objects).map_err(StaticLinkError::Symbols)?;
    let entry_definition =
        definitions
            .get(entry_symbol)
            .ok_or_else(|| StaticLinkError::MissingEntrySymbol {
                name: entry_symbol.to_vec(),
            })?;
    if position_independent && entry_definition.symbol.section_index == SHN_ABS {
        return Err(StaticLinkError::PositionIndependentAbsoluteEntrySymbol {
            name: entry_symbol.to_vec(),
        });
    }

    let layout = relocated_layout(&relocated);
    let user_entry_address =
        final_symbol_address(entry_definition, &layout).map_err(StaticLinkError::EntryAddress)?;
    let (relocated, runtime_entry_address, dynamic) = if position_independent {
        let runtime = add_runtime_relative_relocations(
            inputs,
            relocated,
            &definitions,
            &got_entries,
            user_entry_address,
            page_alignment,
        )
        .map_err(StaticLinkError::PieRuntime)?;
        (runtime.sections, runtime.entry_address, runtime.dynamic)
    } else {
        (relocated, user_entry_address, None)
    };

    let load_segments = build_load_segments(relocated.iter().map(|section| LoadableSectionInput {
        layout: LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        },
        section_type: section.section_type,
        flags: section.flags,
        bytes: &section.bytes,
    }))
    .map_err(StaticLinkError::LoadSegments)?;

    let writer_segments = load_segments
        .iter()
        .map(|segment| LoadSegmentInput {
            image: &segment.image,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        })
        .collect::<Vec<_>>();

    let mut image = if position_independent {
        write_elf64_x86_64_position_independent_segments(
            &writer_segments,
            runtime_entry_address,
            page_alignment,
        )
    } else {
        write_elf64_x86_64_executable_segments(
            &writer_segments,
            runtime_entry_address,
            page_alignment,
        )
    }
    .map_err(StaticLinkError::Write)?;
    if let Some(tls) = tls_layout {
        image = inject_static_tls_program_header(image, tls, page_alignment)
            .map_err(StaticLinkError::TlsProgramHeader)?;
    }
    let link_map = build_link_map(
        &relocated,
        &definitions,
        &image,
        entry_symbol,
        user_entry_address,
    )
    .map_err(StaticLinkError::LinkMap)?;

    Ok(StaticPositionIndependentArtifact {
        output: StaticLinkOutput { image, link_map },
        dynamic,
    })
}

fn relocated_layout(sections: &[RelocatedSectionImage]) -> Vec<LaidOutSection> {
    sections
        .iter()
        .map(|section| LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf64::{
        Elf64Header, Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, EM_X86_64, SHT_STRTAB,
        SHT_SYMTAB,
    };
    use crate::executable_writer::{ExecutableWriteError, LoadSegmentPermissions};
    use crate::input_object::{RelocatableObject, ET_REL};
    use crate::load_segments::{SHF_ALLOC, SHF_EXECINSTR};

    const SHT_PROGBITS: u32 = 1;
    const STB_GLOBAL: u8 = 1;

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

    fn input_with_entry(text_flags: u64, symbol_name: &[u8]) -> (Vec<u8>, RelocatableObject) {
        let mut file = vec![0xc3, 0];
        file.extend_from_slice(symbol_name);
        file.push(0);
        let string_table_size = (symbol_name.len() + 2) as u64;

        let sections = vec![
            section(0, 0, 0, 0, 0),
            section(SHT_PROGBITS, text_flags, 0, 1, 16),
            section(SHT_STRTAB, 0, 1, string_table_size, 1),
            section(SHT_SYMTAB, 0, 0, 0, 8),
        ];
        let symbol_tables = vec![Elf64SymbolTable {
            section_index: 3,
            string_table_index: 2,
            symbols: vec![Elf64Symbol {
                name_offset: 1,
                info: STB_GLOBAL << 4,
                other: 0,
                section_index: 1,
                value: 0,
                size: 1,
            }],
        }];

        (
            file,
            RelocatableObject {
                header: header(4),
                sections,
                symbol_tables,
                rela_tables: Vec::new(),
            },
        )
    }

    #[test]
    fn links_validated_object_through_entry_to_executable() {
        let (file, object) = input_with_entry(SHF_ALLOC | SHF_EXECINSTR, b"_start");
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object,
        };

        let image = link_static_executable(&[input], 0x400000, 0x1000, b"_start").unwrap();

        assert_eq!(&image.bytes[..4], b"\x7fELF");
        assert_eq!(image.entry_address, 0x400000);
        assert_eq!(image.load_segments.len(), 1);
        assert_eq!(
            image.load_segments[0].permissions,
            LoadSegmentPermissions::ReadExecute
        );
        assert_eq!(image.load_segments[0].virtual_address, 0x400000);
        assert_eq!(image.load_segments[0].file_size, 1);
    }

    #[test]
    fn returns_link_map_from_the_same_final_layout() {
        let (file, object) = input_with_entry(SHF_ALLOC | SHF_EXECINSTR, b"_start");
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object,
        };

        let output =
            link_static_executable_with_map(&[input], 0x400000, 0x1000, b"_start").unwrap();

        assert_eq!(output.link_map.entry_address, output.image.entry_address);
        assert_eq!(output.link_map.sections.len(), 1);
        assert_eq!(output.link_map.sections[0].address, 0x400000);
        assert_eq!(output.link_map.symbols[0].name, b"_start");
        assert_eq!(output.link_map.symbols[0].address, 0x400000);
        assert_eq!(
            output.link_map.segments.len(),
            output.image.load_segments.len()
        );
    }

    #[test]
    fn reports_missing_entry_symbol_before_emission() {
        let (file, object) = input_with_entry(SHF_ALLOC | SHF_EXECINSTR, b"other");
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object,
        };

        let error = link_static_executable(&[input], 0x400000, 0x1000, b"_start").unwrap_err();

        assert!(matches!(
            error,
            StaticLinkError::MissingEntrySymbol { name } if name == b"_start"
        ));
    }

    #[test]
    fn rejects_entry_symbol_in_non_executable_segment() {
        let (file, object) = input_with_entry(SHF_ALLOC, b"_start");
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object,
        };

        let error = link_static_executable(&[input], 0x400000, 0x1000, b"_start").unwrap_err();

        assert!(matches!(
            error,
            StaticLinkError::Write(ExecutableWriteError::EntryOutsideExecutableSegment {
                entry_address: 0x400000
            })
        ));
    }
}
