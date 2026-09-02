use core::fmt;
use std::collections::BTreeMap;

use crate::elf64::{Elf64SectionHeader, Elf64SymbolTable};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::resolve::{resolve_symbols, ResolutionError, SymbolDefinition};

#[derive(Debug, Clone, Copy)]
pub struct ValidatedObject<'a> {
    pub file: &'a [u8],
    pub sections: &'a [Elf64SectionHeader],
    pub symbol_tables: &'a [Elf64SymbolTable],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSymbolError {
    ObjectSymbols {
        object_index: usize,
        source: ObjectSymbolError,
    },
    Resolution(ResolutionError),
}

impl fmt::Display for LinkSymbolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectSymbols {
                object_index,
                source,
            } => write!(
                f,
                "cannot read symbols from object {object_index}: {source}"
            ),
            Self::Resolution(source) => write!(f, "symbol resolution failed: {source:?}"),
        }
    }
}

impl std::error::Error for LinkSymbolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectSymbols { source, .. } => Some(source),
            Self::Resolution(_) => None,
        }
    }
}

pub fn resolve_validated_objects(
    objects: &[ValidatedObject<'_>],
) -> Result<BTreeMap<Vec<u8>, SymbolDefinition>, LinkSymbolError> {
    let mut named_symbols = Vec::new();

    for (object_index, object) in objects.iter().enumerate() {
        let mut tables: Vec<_> = object.symbol_tables.iter().collect();
        tables.sort_by_key(|table| table.section_index);

        for table in tables {
            let mut table_symbols =
                named_symbols_from_table(object.file, object.sections, table, object_index)
                    .map_err(|source| LinkSymbolError::ObjectSymbols {
                        object_index,
                        source,
                    })?;
            named_symbols.append(&mut table_symbols);
        }
    }

    resolve_symbols(named_symbols).map_err(LinkSymbolError::Resolution)
}
