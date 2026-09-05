use core::fmt;
use std::collections::BTreeMap;

use crate::layout::LaidOutSection;
use crate::rela_apply::{apply_rela_table_with_values, RelaTableApplyError};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{NamedSymbol, SymbolDefinition, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError};
use crate::x86_64_relocations::{
    is_static_got_entry_type, is_static_gotpcrel_type, R_X86_64_GOT32, R_X86_64_SIZE32,
    R_X86_64_SIZE64,
};

const R_X86_64_NONE: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRelocationError {
    MissingSymbolMetadata {
        relocation_index: usize,
        symbol_index: u32,
        symbol_table_index: u16,
    },
    WrongObject {
        relocation_index: usize,
        symbol_index: u32,
        expected_object_index: usize,
        actual_object_index: usize,
    },
    UnsupportedBinding {
        relocation_index: usize,
        symbol_index: u32,
        binding: u8,
    },
    MissingGlobalAddress {
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    MissingGlobalDefinition {
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    MissingGotEntry {
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    LocalSymbolAddress {
        relocation_index: usize,
        symbol_index: u32,
        source: FinalSymbolAddressError,
    },
    Apply(RelaTableApplyError),
}

impl fmt::Display for LinkRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSymbolMetadata {
                relocation_index,
                symbol_index,
                symbol_table_index,
            } => write!(
                f,
                "relocation {relocation_index} refers to symbol {symbol_index}, but symbol-table section {symbol_table_index} has no matching symbol metadata"
            ),
            Self::WrongObject {
                relocation_index,
                symbol_index,
                expected_object_index,
                actual_object_index,
            } => write!(
                f,
                "relocation {relocation_index} symbol {symbol_index} belongs to object {actual_object_index}, expected object {expected_object_index}"
            ),
            Self::UnsupportedBinding {
                relocation_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "relocation {relocation_index} symbol {symbol_index} uses unsupported binding {binding}"
            ),
            Self::MissingGlobalAddress {
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "relocation {relocation_index} symbol {symbol_index} ({:?}) has no resolved global address",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGlobalDefinition {
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "relocation {relocation_index} symbol {symbol_index} ({:?}) has no resolved global definition for symbol-size relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGotEntry {
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "relocation {relocation_index} symbol {symbol_index} ({:?}) has no synthetic GOT entry",
                String::from_utf8_lossy(name)
            ),
            Self::LocalSymbolAddress {
                relocation_index,
                symbol_index,
                source,
            } => write!(
                f,
                "relocation {relocation_index} local symbol {symbol_index} has no usable final address: {source}"
            ),
            Self::Apply(source) => write!(f, "cannot apply relocation table: {source}"),
        }
    }
}

impl std::error::Error for LinkRelocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LocalSymbolAddress { source, .. } => Some(source),
            Self::Apply(source) => Some(source),
            Self::MissingSymbolMetadata { .. }
            | Self::WrongObject { .. }
            | Self::UnsupportedBinding { .. }
            | Self::MissingGlobalAddress { .. }
            | Self::MissingGlobalDefinition { .. }
            | Self::MissingGotEntry { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RelocationSymbolValues {
    address: u64,
    size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedGlobalSymbols<'a> {
    pub addresses: &'a BTreeMap<Vec<u8>, u64>,
    pub definitions: &'a BTreeMap<Vec<u8>, SymbolDefinition>,
    pub got_entries: &'a BTreeMap<Vec<u8>, u64>,
}

pub fn apply_rela_table_with_resolved_symbols(
    section: &mut [u8],
    section_address: u64,
    table: &Elf64RelaTable,
    object_index: usize,
    symbols: &[NamedSymbol<'_>],
    global_addresses: &BTreeMap<Vec<u8>, u64>,
    layout: &[LaidOutSection],
) -> Result<(), LinkRelocationError> {
    let global_definitions = BTreeMap::new();
    let got_entries = BTreeMap::new();
    apply_rela_table_with_resolved_symbols_and_definitions(
        section,
        section_address,
        table,
        object_index,
        symbols,
        ResolvedGlobalSymbols {
            addresses: global_addresses,
            definitions: &global_definitions,
            got_entries: &got_entries,
        },
        layout,
    )
}

pub fn apply_rela_table_with_resolved_symbols_and_definitions(
    section: &mut [u8],
    section_address: u64,
    table: &Elf64RelaTable,
    object_index: usize,
    symbols: &[NamedSymbol<'_>],
    globals: ResolvedGlobalSymbols<'_>,
    layout: &[LaidOutSection],
) -> Result<(), LinkRelocationError> {
    let mut values = BTreeMap::new();

    for (relocation_index, relocation) in table.relocations.iter().enumerate() {
        if relocation.relocation_type == R_X86_64_NONE {
            continue;
        }
        if values.contains_key(&relocation.symbol_index) {
            continue;
        }

        let symbol = symbols
            .iter()
            .find(|symbol| {
                symbol.table_section_index == table.symbol_table_index
                    && symbol.symbol_index == relocation.symbol_index as usize
            })
            .ok_or(LinkRelocationError::MissingSymbolMetadata {
                relocation_index,
                symbol_index: relocation.symbol_index,
                symbol_table_index: table.symbol_table_index,
            })?;

        if symbol.object_index != object_index {
            return Err(LinkRelocationError::WrongObject {
                relocation_index,
                symbol_index: relocation.symbol_index,
                expected_object_index: object_index,
                actual_object_index: symbol.object_index,
            });
        }

        let needs_size = table.relocations.iter().any(|candidate| {
            candidate.symbol_index == relocation.symbol_index
                && (candidate.relocation_type == R_X86_64_SIZE32
                    || candidate.relocation_type == R_X86_64_SIZE64)
        });
        let binding = symbol.symbol.info >> 4;
        let (address, size) = match binding {
            STB_LOCAL => {
                let definition = SymbolDefinition {
                    name: symbol.name.to_vec(),
                    object_index: symbol.object_index,
                    table_section_index: symbol.table_section_index,
                    symbol_index: symbol.symbol_index,
                    symbol: symbol.symbol,
                };
                let address = final_symbol_address(&definition, layout).map_err(|source| {
                    LinkRelocationError::LocalSymbolAddress {
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        source,
                    }
                })?;
                (address, symbol.symbol.size)
            }
            STB_GLOBAL | STB_WEAK => {
                let address = match globals.addresses.get(symbol.name) {
                    Some(address) => *address,
                    None if binding == STB_WEAK && symbol.symbol.section_index == SHN_UNDEF => 0,
                    None => {
                        return Err(LinkRelocationError::MissingGlobalAddress {
                            relocation_index,
                            symbol_index: relocation.symbol_index,
                            name: symbol.name.to_vec(),
                        });
                    }
                };
                let size = if !needs_size {
                    0
                } else {
                    match globals.definitions.get(symbol.name) {
                        Some(definition) => definition.symbol.size,
                        None if symbol.symbol.section_index != SHN_UNDEF => symbol.symbol.size,
                        None if binding == STB_WEAK => 0,
                        None => {
                            return Err(LinkRelocationError::MissingGlobalDefinition {
                                relocation_index,
                                symbol_index: relocation.symbol_index,
                                name: symbol.name.to_vec(),
                            });
                        }
                    }
                };
                (address, size)
            }
            _ => {
                return Err(LinkRelocationError::UnsupportedBinding {
                    relocation_index,
                    symbol_index: relocation.symbol_index,
                    binding,
                });
            }
        };

        values.insert(
            relocation.symbol_index,
            RelocationSymbolValues { address, size },
        );
    }

    apply_rela_table_with_values(section, section_address, table, |relocation| {
        let values = values.get(&relocation.symbol_index)?;
        if relocation.relocation_type == R_X86_64_SIZE32
            || relocation.relocation_type == R_X86_64_SIZE64
        {
            Some(values.size)
        } else if relocation.relocation_type == R_X86_64_GOT32 {
            let symbol = symbols.iter().find(|symbol| {
                symbol.table_section_index == table.symbol_table_index
                    && symbol.symbol_index == relocation.symbol_index as usize
            })?;
            let entry = globals.got_entries.get(symbol.name).copied()?;
            let base = globals.got_entries.values().copied().min()?;
            entry.checked_sub(base)
        } else if is_static_gotpcrel_type(relocation.relocation_type) {
            let symbol = symbols.iter().find(|symbol| {
                symbol.table_section_index == table.symbol_table_index
                    && symbol.symbol_index == relocation.symbol_index as usize
            })?;
            globals.got_entries.get(symbol.name).copied()
        } else {
            Some(values.address)
        }
    })
    .map_err(|source| {
        if let RelaTableApplyError::MissingSymbolValue {
            relocation_index,
            symbol_index,
        } = &source
        {
            if let Some(relocation) = table.relocations.get(*relocation_index) {
                if is_static_got_entry_type(relocation.relocation_type) {
                    if let Some(symbol) = symbols.iter().find(|symbol| {
                        symbol.table_section_index == table.symbol_table_index
                            && symbol.symbol_index == *symbol_index as usize
                    }) {
                        return LinkRelocationError::MissingGotEntry {
                            relocation_index: *relocation_index,
                            symbol_index: *symbol_index,
                            name: symbol.name.to_vec(),
                        };
                    }
                }
            }
        }
        LinkRelocationError::Apply(source)
    })
}