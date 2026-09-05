use core::fmt;

use crate::elf64::{Elf64SectionHeader, SHT_NOBITS};
use crate::input_object::{RelocatableObject, RelocatableObjectError};
use crate::link_symbols::ValidatedObject;
use crate::load_segments::SHF_ALLOC;
use crate::permission_layout::PermissionLayoutInput;
use crate::relocations::Elf64RelaTable;
use crate::x86_64_relocations::{R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX};

#[derive(Debug)]
pub struct LinkerInputObject<'a> {
    pub object_index: usize,
    pub file: &'a [u8],
    pub object: RelocatableObject,
}

#[derive(Debug, Clone)]
pub struct LinkerInputSection<'a> {
    pub object_index: usize,
    pub section_index: u16,
    pub section_type: u32,
    pub flags: u64,
    pub size: u64,
    pub alignment: u64,
    pub bytes: &'a [u8],
    pub rela_tables: Vec<&'a Elf64RelaTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkerInputError {
    SectionIndexTooLarge {
        object_index: usize,
        section_index: usize,
    },
    SectionDataRangeOverflow {
        object_index: usize,
        section_index: u16,
        offset: u64,
        size: u64,
    },
    SectionDataOutOfBounds {
        object_index: usize,
        section_index: u16,
        end: u64,
        file_len: usize,
    },
}

impl fmt::Display for LinkerInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SectionIndexTooLarge {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section index {section_index} cannot be represented as ELF64 u16 section index"
            ),
            Self::SectionDataRangeOverflow {
                object_index,
                section_index,
                offset,
                size,
            } => write!(
                f,
                "object {object_index} section {section_index} file range {offset}+{size} overflows u64"
            ),
            Self::SectionDataOutOfBounds {
                object_index,
                section_index,
                end,
                file_len,
            } => write!(
                f,
                "object {object_index} section {section_index} data ends at file offset {end}, beyond file length {file_len}"
            ),
        }
    }
}

impl std::error::Error for LinkerInputError {}

impl<'a> LinkerInputObject<'a> {
    pub fn parse(object_index: usize, file: &'a [u8]) -> Result<Self, RelocatableObjectError> {
        let mut object = RelocatableObject::parse(file)?;
        canonicalize_relaxable_static_got_relocations(&mut object);
        Ok(Self {
            object_index,
            file,
            object,
        })
    }

    pub fn validated_object(&self) -> ValidatedObject<'_> {
        ValidatedObject {
            file: self.file,
            sections: &self.object.sections,
            symbol_tables: &self.object.symbol_tables,
        }
    }

    pub fn allocatable_sections(&self) -> Result<Vec<LinkerInputSection<'_>>, LinkerInputError> {
        let mut sections = Vec::new();

        for (section_index, section) in self.object.sections.iter().enumerate() {
            if section.flags & SHF_ALLOC == 0 {
                continue;
            }

            let section_index = u16::try_from(section_index).map_err(|_| {
                LinkerInputError::SectionIndexTooLarge {
                    object_index: self.object_index,
                    section_index,
                }
            })?;
            let bytes = self.section_bytes(section_index, section)?;
            let mut rela_tables: Vec<_> = self
                .object
                .rela_tables
                .iter()
                .filter(|table| table.target_section_index == section_index)
                .collect();
            rela_tables.sort_by_key(|table| table.section_index);

            sections.push(LinkerInputSection {
                object_index: self.object_index,
                section_index,
                section_type: section.section_type,
                flags: section.flags,
                size: section.size,
                alignment: section.address_alignment,
                bytes,
                rela_tables,
            });
        }

        Ok(sections)
    }

    fn section_bytes(
        &self,
        section_index: u16,
        section: &Elf64SectionHeader,
    ) -> Result<&'a [u8], LinkerInputError> {
        if section.section_type == SHT_NOBITS {
            return Ok(&[]);
        }

        let end = section.offset.checked_add(section.size).ok_or(
            LinkerInputError::SectionDataRangeOverflow {
                object_index: self.object_index,
                section_index,
                offset: section.offset,
                size: section.size,
            },
        )?;
        if end > self.file.len() as u64 {
            return Err(LinkerInputError::SectionDataOutOfBounds {
                object_index: self.object_index,
                section_index,
                end,
                file_len: self.file.len(),
            });
        }

        Ok(&self.file[section.offset as usize..end as usize])
    }
}

fn canonicalize_relaxable_static_got_relocations(object: &mut RelocatableObject) {
    for table in &mut object.rela_tables {
        for relocation in &mut table.relocations {
            if matches!(
                relocation.relocation_type,
                R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX
            ) {
                relocation.relocation_type = R_X86_64_GOTPCREL;
            }
        }
    }
}

impl LinkerInputSection<'_> {
    pub fn permission_layout_input(&self) -> PermissionLayoutInput {
        PermissionLayoutInput {
            object_index: self.object_index,
            section_index: self.section_index,
            size: self.size,
            alignment: self.alignment,
            flags: self.flags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf64::{Elf64Header, Elf64SymbolTable};
    use crate::load_segments::{SHF_EXECINSTR, SHF_WRITE};
    use crate::relocations::{Elf64Rela, Elf64RelaTable};

    fn header() -> Elf64Header {
        Elf64Header {
            elf_type: 1,
            machine: 62,
            entry: 0,
            program_header_offset: 0,
            section_header_offset: 0,
            flags: 0,
            header_size: 64,
            program_header_entry_size: 0,
            program_header_count: 0,
            section_header_entry_size: 64,
            section_header_count: 5,
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

    fn input<'a>(file: &'a [u8]) -> LinkerInputObject<'a> {
        LinkerInputObject {
            object_index: 7,
            file,
            object: RelocatableObject {
                header: header(),
                sections: vec![
                    section(0, 0, 0, 0, 0),
                    section(1, SHF_ALLOC | SHF_EXECINSTR, 2, 4, 16),
                    section(1, SHF_ALLOC | SHF_WRITE, 6, 2, 8),
                    section(SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 8, 8, 8),
                    section(1, 0, 8, 2, 1),
                ],
                symbol_tables: vec![Elf64SymbolTable {
                    section_index: 4,
                    string_table_index: 0,
                    symbols: Vec::new(),
                }],
                rela_tables: vec![
                    Elf64RelaTable {
                        section_index: 9,
                        symbol_table_index: 4,
                        target_section_index: 1,
                        relocations: vec![Elf64Rela {
                            offset: 1,
                            symbol_index: 0,
                            relocation_type: 2,
                            addend: -4,
                        }],
                    },
                    Elf64RelaTable {
                        section_index: 8,
                        symbol_table_index: 4,
                        target_section_index: 1,
                        relocations: Vec::new(),
                    },
                ],
            },
        }
    }

    #[test]
    fn extracts_allocatable_sections_bytes_and_target_relocations() {
        let file = [0xaa, 0xbb, 1, 2, 3, 4, 5, 6, 0xcc, 0xdd];
        let input = input(&file);

        let sections = input.allocatable_sections().unwrap();

        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].object_index, 7);
        assert_eq!(sections[0].section_index, 1);
        assert_eq!(sections[0].bytes, &[1, 2, 3, 4]);
        assert_eq!(sections[0].rela_tables.len(), 2);
        assert_eq!(sections[0].rela_tables[0].section_index, 8);
        assert_eq!(sections[0].rela_tables[1].section_index, 9);
        assert_eq!(sections[1].section_index, 2);
        assert_eq!(sections[1].bytes, &[5, 6]);
        assert!(sections[1].rela_tables.is_empty());
        assert_eq!(sections[2].section_index, 3);
        assert!(sections[2].bytes.is_empty());
        assert_eq!(sections[2].size, 8);
    }

    #[test]
    fn exposes_direct_symbol_resolution_adapter() {
        let file = [0; 10];
        let input = input(&file);

        let validated = input.validated_object();

        assert!(core::ptr::eq(validated.file.as_ptr(), file.as_ptr()));
        assert_eq!(validated.sections, input.object.sections.as_slice());
        assert_eq!(
            validated.symbol_tables,
            input.object.symbol_tables.as_slice()
        );
    }

    #[test]
    fn produces_permission_layout_inputs_with_provenance() {
        let file = [0; 10];
        let input = input(&file);
        let sections = input.allocatable_sections().unwrap();

        let layout = sections[0].permission_layout_input();

        assert_eq!(layout.object_index, 7);
        assert_eq!(layout.section_index, 1);
        assert_eq!(layout.size, 4);
        assert_eq!(layout.alignment, 16);
        assert_eq!(layout.flags, SHF_ALLOC | SHF_EXECINSTR);
    }

    #[test]
    fn defensively_rejects_out_of_bounds_section_metadata() {
        let file = [0; 4];
        let mut input = input(&file);
        input.object.sections[1].offset = 3;
        input.object.sections[1].size = 2;

        let error = input.allocatable_sections().unwrap_err();
        assert_eq!(
            error,
            LinkerInputError::SectionDataOutOfBounds {
                object_index: 7,
                section_index: 1,
                end: 5,
                file_len: 4,
            }
        );
    }

    #[test]
    fn defensively_rejects_section_range_overflow() {
        let file = [0; 4];
        let mut input = input(&file);
        input.object.sections[1].offset = u64::MAX;
        input.object.sections[1].size = 2;

        let error = input.allocatable_sections().unwrap_err();
        assert_eq!(
            error,
            LinkerInputError::SectionDataRangeOverflow {
                object_index: 7,
                section_index: 1,
                offset: u64::MAX,
                size: 2,
            }
        );
    }
}
