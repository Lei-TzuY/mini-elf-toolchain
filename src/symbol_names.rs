use core::fmt;

use crate::elf64::{Elf64SectionHeader, Elf64SymbolTable, SHT_STRTAB};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolNameError {
    InvalidSymbolIndex {
        symbol_index: usize,
        symbol_count: usize,
    },
    InvalidStringTableIndex {
        string_table_index: u16,
        section_count: usize,
    },
    StringTableNotStringTable {
        string_table_index: u16,
        section_type: u32,
    },
    StringTableRangeOverflow {
        string_table_index: u16,
    },
    StringTableOutOfBounds {
        string_table_index: u16,
        end: u64,
        file_len: usize,
    },
    InvalidNameOffset {
        symbol_index: usize,
        name_offset: u32,
        string_table_size: u64,
    },
    UnterminatedName {
        symbol_index: usize,
        name_offset: u32,
    },
}

impl fmt::Display for SymbolNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSymbolIndex {
                symbol_index,
                symbol_count,
            } => write!(
                f,
                "symbol index {symbol_index} is outside symbol count {symbol_count}"
            ),
            Self::InvalidStringTableIndex {
                string_table_index,
                section_count,
            } => write!(
                f,
                "string-table index {string_table_index} is outside section count {section_count}"
            ),
            Self::StringTableNotStringTable {
                string_table_index,
                section_type,
            } => write!(
                f,
                "section {string_table_index} has type {section_type}, expected SHT_STRTAB"
            ),
            Self::StringTableRangeOverflow { string_table_index } => write!(
                f,
                "string-table section {string_table_index} file range overflows u64"
            ),
            Self::StringTableOutOfBounds {
                string_table_index,
                end,
                file_len,
            } => write!(
                f,
                "string-table section {string_table_index} ends at file offset {end}, beyond file length {file_len}"
            ),
            Self::InvalidNameOffset {
                symbol_index,
                name_offset,
                string_table_size,
            } => write!(
                f,
                "symbol {symbol_index} has name offset {name_offset}, outside string-table size {string_table_size}"
            ),
            Self::UnterminatedName {
                symbol_index,
                name_offset,
            } => write!(
                f,
                "symbol {symbol_index} name at string-table offset {name_offset} is not NUL-terminated"
            ),
        }
    }
}

impl std::error::Error for SymbolNameError {}

pub fn symbol_name<'a>(
    file: &'a [u8],
    sections: &[Elf64SectionHeader],
    table: &Elf64SymbolTable,
    symbol_index: usize,
) -> Result<&'a [u8], SymbolNameError> {
    let symbol = table
        .symbols
        .get(symbol_index)
        .ok_or(SymbolNameError::InvalidSymbolIndex {
            symbol_index,
            symbol_count: table.symbols.len(),
        })?;

    let string_table = sections.get(usize::from(table.string_table_index)).ok_or(
        SymbolNameError::InvalidStringTableIndex {
            string_table_index: table.string_table_index,
            section_count: sections.len(),
        },
    )?;
    if string_table.section_type != SHT_STRTAB {
        return Err(SymbolNameError::StringTableNotStringTable {
            string_table_index: table.string_table_index,
            section_type: string_table.section_type,
        });
    }

    let string_table_end = string_table.offset.checked_add(string_table.size).ok_or(
        SymbolNameError::StringTableRangeOverflow {
            string_table_index: table.string_table_index,
        },
    )?;
    if string_table_end > file.len() as u64 {
        return Err(SymbolNameError::StringTableOutOfBounds {
            string_table_index: table.string_table_index,
            end: string_table_end,
            file_len: file.len(),
        });
    }
    if u64::from(symbol.name_offset) >= string_table.size {
        return Err(SymbolNameError::InvalidNameOffset {
            symbol_index,
            name_offset: symbol.name_offset,
            string_table_size: string_table.size,
        });
    }

    let name_start = string_table
        .offset
        .checked_add(u64::from(symbol.name_offset))
        .ok_or(SymbolNameError::StringTableRangeOverflow {
            string_table_index: table.string_table_index,
        })? as usize;
    let name_region = &file[name_start..string_table_end as usize];
    let nul = name_region.iter().position(|byte| *byte == 0).ok_or(
        SymbolNameError::UnterminatedName {
            symbol_index,
            name_offset: symbol.name_offset,
        },
    )?;

    Ok(&name_region[..nul])
}
