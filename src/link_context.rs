use core::fmt;
use std::collections::BTreeMap;

use crate::layout::LaidOutSection;
use crate::link_relocations::{
    apply_rela_table_with_resolved_symbols_and_definitions, LinkRelocationError,
    ResolvedGlobalSymbols,
};
use crate::link_symbols::ValidatedObject;
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{resolve_symbols, NamedSymbol, ResolutionError, SymbolDefinition};
use crate::symbol_addresses::{final_symbol_addresses, FinalSymbolAddressError};

#[derive(Debug)]
pub struct LinkContext<'a> {
    symbols_by_object: Vec<Vec<NamedSymbol<'a>>>,
    definitions: BTreeMap<Vec<u8>, SymbolDefinition>,
    global_addresses: BTreeMap<Vec<u8>, u64>,
    layout: Vec<LaidOutSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkContextBuildError {
    ObjectSymbols {
        object_index: usize,
        source: ObjectSymbolError,
    },
    Resolution(ResolutionError),
    FinalAddress(FinalSymbolAddressError),
}

impl fmt::Display for LinkContextBuildError {
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
            Self::FinalAddress(source) => {
                write!(f, "cannot resolve final symbol address: {source}")
            }
        }
    }
}

impl std::error::Error for LinkContextBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectSymbols { source, .. } => Some(source),
            Self::FinalAddress(source) => Some(source),
            Self::Resolution(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkContextRelocationError {
    ObjectIndexOutOfRange {
        object_index: usize,
        object_count: usize,
    },
    Apply(LinkRelocationError),
}

impl fmt::Display for LinkContextRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectIndexOutOfRange {
                object_index,
                object_count,
            } => write!(
                f,
                "cannot apply relocations for object {object_index}; link context contains {object_count} objects"
            ),
            Self::Apply(source) => write!(f, "cannot apply resolved relocation table: {source}"),
        }
    }
}

impl std::error::Error for LinkContextRelocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectIndexOutOfRange { .. } => None,
            Self::Apply(source) => Some(source),
        }
    }
}

pub fn build_link_context<'a>(
    objects: &[ValidatedObject<'a>],
    layout: &[LaidOutSection],
) -> Result<LinkContext<'a>, LinkContextBuildError> {
    let mut symbols_by_object = Vec::with_capacity(objects.len());

    for (object_index, object) in objects.iter().enumerate() {
        let mut tables: Vec<_> = object.symbol_tables.iter().collect();
        tables.sort_by_key(|table| table.section_index);

        let mut object_symbols = Vec::new();
        for table in tables {
            let mut table_symbols =
                named_symbols_from_table(object.file, object.sections, table, object_index)
                    .map_err(|source| LinkContextBuildError::ObjectSymbols {
                        object_index,
                        source,
                    })?;
            object_symbols.append(&mut table_symbols);
        }
        symbols_by_object.push(object_symbols);
    }

    let definitions = resolve_symbols(symbols_by_object.iter().flatten().copied())
        .map_err(LinkContextBuildError::Resolution)?;
    let global_addresses = final_symbol_addresses(&definitions, layout)
        .map_err(LinkContextBuildError::FinalAddress)?;

    Ok(LinkContext {
        symbols_by_object,
        definitions,
        global_addresses,
        layout: layout.to_vec(),
    })
}

impl LinkContext<'_> {
    pub fn definitions(&self) -> &BTreeMap<Vec<u8>, SymbolDefinition> {
        &self.definitions
    }

    pub fn global_addresses(&self) -> &BTreeMap<Vec<u8>, u64> {
        &self.global_addresses
    }

    pub fn layout(&self) -> &[LaidOutSection] {
        &self.layout
    }

    pub fn apply_rela_table(
        &self,
        section: &mut [u8],
        section_address: u64,
        table: &Elf64RelaTable,
        object_index: usize,
    ) -> Result<(), LinkContextRelocationError> {
        let symbols = self.symbols_by_object.get(object_index).ok_or(
            LinkContextRelocationError::ObjectIndexOutOfRange {
                object_index,
                object_count: self.symbols_by_object.len(),
            },
        )?;

        apply_rela_table_with_resolved_symbols_and_definitions(
            section,
            section_address,
            table,
            object_index,
            symbols,
            ResolvedGlobalSymbols {
                addresses: &self.global_addresses,
                definitions: &self.definitions,
            },
            &self.layout,
        )
        .map_err(LinkContextRelocationError::Apply)
    }
}
