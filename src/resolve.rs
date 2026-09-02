use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use crate::elf64::Elf64Symbol;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const SHN_UNDEF: u16 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedSymbol<'a> {
    pub name: &'a [u8],
    pub object_index: usize,
    pub table_section_index: u16,
    pub symbol_index: usize,
    pub symbol: Elf64Symbol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolDefinition {
    pub name: Vec<u8>,
    pub object_index: usize,
    pub table_section_index: u16,
    pub symbol_index: usize,
    pub symbol: Elf64Symbol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    UnsupportedBinding {
        object_index: usize,
        table_section_index: u16,
        symbol_index: usize,
        binding: u8,
    },
    MultipleStrongDefinitions {
        name: Vec<u8>,
        first_object_index: usize,
        second_object_index: usize,
    },
}

pub fn resolve_symbols<'a, I>(symbols: I) -> Result<BTreeMap<Vec<u8>, SymbolDefinition>, ResolutionError>
where
    I: IntoIterator<Item = NamedSymbol<'a>>,
{
    let mut definitions = BTreeMap::new();

    for candidate in symbols {
        let binding = candidate.symbol.info >> 4;
        if binding == STB_LOCAL {
            continue;
        }
        if binding != STB_GLOBAL && binding != STB_WEAK {
            return Err(ResolutionError::UnsupportedBinding {
                object_index: candidate.object_index,
                table_section_index: candidate.table_section_index,
                symbol_index: candidate.symbol_index,
                binding,
            });
        }

        if candidate.name.is_empty() || candidate.symbol.section_index == SHN_UNDEF {
            continue;
        }

        let name = candidate.name.to_vec();
        let definition = SymbolDefinition {
            name: name.clone(),
            object_index: candidate.object_index,
            table_section_index: candidate.table_section_index,
            symbol_index: candidate.symbol_index,
            symbol: candidate.symbol,
        };

        match definitions.entry(name.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(definition);
            }
            Entry::Occupied(mut entry) => {
                let existing_binding = entry.get().symbol.info >> 4;
                match (existing_binding, binding) {
                    (STB_WEAK, STB_GLOBAL) => {
                        entry.insert(definition);
                    }
                    (STB_GLOBAL, STB_GLOBAL) => {
                        return Err(ResolutionError::MultipleStrongDefinitions {
                            name,
                            first_object_index: entry.get().object_index,
                            second_object_index: candidate.object_index,
                        });
                    }
                    (STB_GLOBAL, STB_WEAK) | (STB_WEAK, STB_WEAK) => {}
                    _ => unreachable!("stored definitions only use global or weak binding"),
                }
            }
        }
    }

    Ok(definitions)
}
