use core::fmt;

use crate::executable_writer::{
    write_elf64_x86_64_executable_segments, ExecutableImage, ExecutableWriteError,
    LoadSegmentInput,
};
use crate::layout::LaidOutSection;
use crate::link_symbols::{resolve_validated_objects, LinkSymbolError};
use crate::linker_input::LinkerInputObject;
use crate::load_segments::{build_load_segments, LoadSegmentBuildError, LoadableSectionInput};
use crate::relocated_sections::{
    relocate_allocatable_sections, RelocatedSectionError, RelocatedSectionImage,
};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError};

#[derive(Debug)]
pub enum StaticLinkError {
    Relocation(RelocatedSectionError),
    Symbols(LinkSymbolError),
    MissingEntrySymbol { name: Vec<u8> },
    EntryAddress(FinalSymbolAddressError),
    LoadSegments(LoadSegmentBuildError),
    Write(ExecutableWriteError),
}

impl fmt::Display for StaticLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocation(source) => write!(f, "cannot relocate input sections: {source}"),
            Self::Symbols(source) => write!(f, "cannot resolve entry symbol: {source}"),
            Self::MissingEntrySymbol { name } => write!(
                f,
                "entry symbol {:?} is not defined by any input object",
                String::from_utf8_lossy(name)
            ),
            Self::EntryAddress(source) => write!(f, "cannot resolve entry address: {source}"),
            Self::LoadSegments(source) => write!(f, "cannot build load segments: {source}"),
            Self::Write(source) => write!(f, "cannot emit executable: {source}"),
        }
    }
}

impl std::error::Error for StaticLinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Relocation(source) => Some(source),
            Self::Symbols(source) => Some(source),
            Self::EntryAddress(source) => Some(source),
            Self::LoadSegments(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::MissingEntrySymbol { .. } => None,
        }
    }
}

pub fn link_static_executable(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    entry_symbol: &[u8],
) -> Result<ExecutableImage, StaticLinkError> {
    let relocated = relocate_allocatable_sections(inputs, start_address, page_alignment)
        .map_err(StaticLinkError::Relocation)?;

    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let definitions =
        resolve_validated_objects(&validated_objects).map_err(StaticLinkError::Symbols)?;
    let entry_definition = definitions.get(entry_symbol).ok_or_else(|| {
        StaticLinkError::MissingEntrySymbol {
            name: entry_symbol.to_vec(),
        }
    })?;

    let layout = relocated_layout(&relocated);
    let entry_address =
        final_symbol_address(entry_definition, &layout).map_err(StaticLinkError::EntryAddress)?;

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

    write_elf64_x86_64_executable_segments(&writer_segments, entry_address, page_alignment)
        .map_err(StaticLinkError::Write)
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
