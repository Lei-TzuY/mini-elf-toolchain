use core::fmt;

use crate::elf64::{Elf64SectionHeader, Elf64SymbolTable, SHT_DYNSYM, SHT_SYMTAB};

pub const SHT_RELA: u32 = 4;
pub const ELF64_RELA_SIZE: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Rela {
    pub offset: u64,
    pub symbol_index: u32,
    pub relocation_type: u32,
    pub addend: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64RelaTable {
    pub section_index: u16,
    pub symbol_table_index: u16,
    pub target_section_index: u16,
    pub relocations: Vec<Elf64Rela>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaError {
    InvalidEntrySize {
        section_index: u16,
        entry_size: u64,
    },
    InvalidTableSize {
        section_index: u16,
        size: u64,
        entry_size: u64,
    },
    InvalidSymbolTableIndex {
        section_index: u16,
        symbol_table_index: u32,
        section_count: usize,
    },
    LinkedSectionNotSymbolTable {
        section_index: u16,
        symbol_table_index: u16,
        section_type: u32,
    },
    MissingValidatedSymbolTable {
        section_index: u16,
        symbol_table_index: u16,
    },
    InvalidTargetSectionIndex {
        section_index: u16,
        target_section_index: u32,
        section_count: usize,
    },
    DataRangeOverflow {
        section_index: u16,
    },
    DataOutOfBounds {
        section_index: u16,
        end: u64,
        file_len: usize,
    },
    InvalidRelocationSymbolIndex {
        section_index: u16,
        relocation_index: u64,
        symbol_index: u32,
        symbol_count: usize,
    },
}

impl fmt::Display for RelaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntrySize {
                section_index,
                entry_size,
            } => write!(
                f,
                "RELA section {section_index} has entry size {entry_size}; expected {ELF64_RELA_SIZE}"
            ),
            Self::InvalidTableSize {
                section_index,
                size,
                entry_size,
            } => write!(
                f,
                "RELA section {section_index} has size {size}, which is not a multiple of entry size {entry_size}"
            ),
            Self::InvalidSymbolTableIndex {
                section_index,
                symbol_table_index,
                section_count,
            } => write!(
                f,
                "RELA section {section_index} links to section {symbol_table_index}, outside section count {section_count}"
            ),
            Self::LinkedSectionNotSymbolTable {
                section_index,
                symbol_table_index,
                section_type,
            } => write!(
                f,
                "RELA section {section_index} links to section {symbol_table_index} of type {section_type}, expected a symbol table"
            ),
            Self::MissingValidatedSymbolTable {
                section_index,
                symbol_table_index,
            } => write!(
                f,
                "RELA section {section_index} links to symbol-table section {symbol_table_index}, but no validated symbol table was supplied"
            ),
            Self::InvalidTargetSectionIndex {
                section_index,
                target_section_index,
                section_count,
            } => write!(
                f,
                "RELA section {section_index} targets section {target_section_index}, outside section count {section_count}"
            ),
            Self::DataRangeOverflow { section_index } => {
                write!(f, "RELA section {section_index} file range overflows u64")
            }
            Self::DataOutOfBounds {
                section_index,
                end,
                file_len,
            } => write!(
                f,
                "RELA section {section_index} data ends at file offset {end}, beyond file length {file_len}"
            ),
            Self::InvalidRelocationSymbolIndex {
                section_index,
                relocation_index,
                symbol_index,
                symbol_count,
            } => write!(
                f,
                "relocation {relocation_index} in RELA section {section_index} refers to symbol {symbol_index}, outside symbol count {symbol_count}"
            ),
        }
    }
}

impl std::error::Error for RelaError {}

pub fn rela_tables(
    file: &[u8],
    sections: &[Elf64SectionHeader],
    symbol_tables: &[Elf64SymbolTable],
) -> Result<Vec<Elf64RelaTable>, RelaError> {
    let mut tables = Vec::new();

    for (section_index, section) in sections.iter().enumerate() {
        if section.section_type != SHT_RELA {
            continue;
        }
        let section_index = section_index as u16;

        if section.entry_size != ELF64_RELA_SIZE {
            return Err(RelaError::InvalidEntrySize {
                section_index,
                entry_size: section.entry_size,
            });
        }
        if section.size % section.entry_size != 0 {
            return Err(RelaError::InvalidTableSize {
                section_index,
                size: section.size,
                entry_size: section.entry_size,
            });
        }
        if section.link >= sections.len() as u32 {
            return Err(RelaError::InvalidSymbolTableIndex {
                section_index,
                symbol_table_index: section.link,
                section_count: sections.len(),
            });
        }
        if section.info >= sections.len() as u32 {
            return Err(RelaError::InvalidTargetSectionIndex {
                section_index,
                target_section_index: section.info,
                section_count: sections.len(),
            });
        }

        let symbol_table_index = section.link as u16;
        let linked_section = &sections[usize::from(symbol_table_index)];
        if linked_section.section_type != SHT_SYMTAB && linked_section.section_type != SHT_DYNSYM {
            return Err(RelaError::LinkedSectionNotSymbolTable {
                section_index,
                symbol_table_index,
                section_type: linked_section.section_type,
            });
        }
        let symbol_table = symbol_tables
            .iter()
            .find(|table| table.section_index == symbol_table_index)
            .ok_or(RelaError::MissingValidatedSymbolTable {
                section_index,
                symbol_table_index,
            })?;

        let end = section
            .offset
            .checked_add(section.size)
            .ok_or(RelaError::DataRangeOverflow { section_index })?;
        if end > file.len() as u64 {
            return Err(RelaError::DataOutOfBounds {
                section_index,
                end,
                file_len: file.len(),
            });
        }

        let relocation_count = section.size / section.entry_size;
        let mut relocations = Vec::with_capacity(relocation_count as usize);
        for relocation_index in 0..relocation_count {
            let relative_offset = relocation_index
                .checked_mul(ELF64_RELA_SIZE)
                .ok_or(RelaError::DataRangeOverflow { section_index })?;
            let entry_offset = section
                .offset
                .checked_add(relative_offset)
                .ok_or(RelaError::DataRangeOverflow { section_index })?
                as usize;

            let offset = read_u64(file, entry_offset);
            let info = read_u64(file, entry_offset + 8);
            let symbol_index = (info >> 32) as u32;
            let relocation_type = info as u32;
            let addend = read_i64(file, entry_offset + 16);

            if symbol_index as usize >= symbol_table.symbols.len() {
                return Err(RelaError::InvalidRelocationSymbolIndex {
                    section_index,
                    relocation_index,
                    symbol_index,
                    symbol_count: symbol_table.symbols.len(),
                });
            }

            relocations.push(Elf64Rela {
                offset,
                symbol_index,
                relocation_type,
                addend,
            });
        }

        tables.push(Elf64RelaTable {
            section_index,
            symbol_table_index,
            target_section_index: section.info as u16,
            relocations,
        });
    }

    Ok(tables)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
