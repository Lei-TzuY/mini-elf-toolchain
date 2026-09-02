use core::fmt;

use crate::elf64::{Elf64SectionHeader, Elf64SymbolTable};
use crate::resolve::NamedSymbol;
use crate::symbol_names::{symbol_name, SymbolNameError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectSymbolError {
    InvalidName {
        table_section_index: u16,
        symbol_index: usize,
        source: SymbolNameError,
    },
}

impl fmt::Display for ObjectSymbolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName {
                table_section_index,
                symbol_index,
                source,
            } => write!(
                f,
                "cannot read symbol {symbol_index} from table section {table_section_index}: {source}"
            ),
        }
    }
}

impl std::error::Error for ObjectSymbolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName { source, .. } => Some(source),
        }
    }
}

pub fn named_symbols_from_table<'a>(
    file: &'a [u8],
    sections: &[Elf64SectionHeader],
    table: &Elf64SymbolTable,
    object_index: usize,
) -> Result<Vec<NamedSymbol<'a>>, ObjectSymbolError> {
    table
        .symbols
        .iter()
        .copied()
        .enumerate()
        .map(|(symbol_index, symbol)| {
            let name = symbol_name(file, sections, table, symbol_index).map_err(|source| {
                ObjectSymbolError::InvalidName {
                    table_section_index: table.section_index,
                    symbol_index,
                    source,
                }
            })?;

            Ok(NamedSymbol {
                name,
                object_index,
                table_section_index: table.section_index,
                symbol_index,
                symbol,
            })
        })
        .collect()
}
