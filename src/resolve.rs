use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use crate::elf64::Elf64Symbol;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const SHN_UNDEF: u16 = 0;
pub const SHN_COMMON: u16 = 0xfff2;
pub const COMMON_OBJECT_INDEX: usize = usize::MAX;
pub const COMMON_SECTION_INDEX: u16 = 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonSection {
    pub size: u64,
    pub alignment: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSymbols {
    pub definitions: BTreeMap<Vec<u8>, SymbolDefinition>,
    pub common_section: Option<CommonSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    UnsupportedBinding {
        object_index: usize,
        table_section_index: u16,
        symbol_index: usize,
        binding: u8,
    },
    UnsupportedCommonBinding {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
        binding: u8,
    },
    InvalidCommonAlignment {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
        alignment: u64,
    },
    CommonAlignmentOverflow {
        name: Vec<u8>,
        offset: u64,
        alignment: u64,
    },
    CommonSizeOverflow {
        name: Vec<u8>,
        offset: u64,
        size: u64,
    },
    MultipleStrongDefinitions {
        name: Vec<u8>,
        first_object_index: usize,
        second_object_index: usize,
    },
}

pub fn resolve_symbols<'a, I>(
    symbols: I,
) -> Result<BTreeMap<Vec<u8>, SymbolDefinition>, ResolutionError>
where
    I: IntoIterator<Item = NamedSymbol<'a>>,
{
    resolve_symbols_with_common(symbols).map(|resolved| resolved.definitions)
}

pub fn resolve_symbols_with_common<'a, I>(symbols: I) -> Result<ResolvedSymbols, ResolutionError>
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
        if candidate.symbol.section_index == SHN_COMMON {
            if binding != STB_GLOBAL {
                return Err(ResolutionError::UnsupportedCommonBinding {
                    name,
                    object_index: candidate.object_index,
                    symbol_index: candidate.symbol_index,
                    binding,
                });
            }
            let alignment = candidate.symbol.value;
            if alignment == 0 || !alignment.is_power_of_two() {
                return Err(ResolutionError::InvalidCommonAlignment {
                    name,
                    object_index: candidate.object_index,
                    symbol_index: candidate.symbol_index,
                    alignment,
                });
            }
        }

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
                let existing_common = entry.get().symbol.section_index == SHN_COMMON;
                let candidate_common = candidate.symbol.section_index == SHN_COMMON;

                match (existing_common, candidate_common) {
                    (true, true) => {
                        let existing = entry.get_mut();
                        existing.symbol.size = existing.symbol.size.max(candidate.symbol.size);
                        existing.symbol.value = existing.symbol.value.max(candidate.symbol.value);
                    }
                    (true, false) => {
                        if binding == STB_GLOBAL {
                            entry.insert(definition);
                        }
                    }
                    (false, true) => {
                        if existing_binding == STB_WEAK {
                            entry.insert(definition);
                        }
                    }
                    (false, false) => match (existing_binding, binding) {
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
                    },
                }
            }
        }
    }

    let mut common_size = 0u64;
    let mut common_alignment = 1u64;
    let mut has_common = false;

    for definition in definitions.values_mut() {
        if definition.symbol.section_index != SHN_COMMON {
            continue;
        }

        has_common = true;
        let alignment = definition.symbol.value;
        common_alignment = common_alignment.max(alignment);
        let offset = align_up(common_size, alignment).ok_or_else(|| {
            ResolutionError::CommonAlignmentOverflow {
                name: definition.name.clone(),
                offset: common_size,
                alignment,
            }
        })?;
        common_size = offset.checked_add(definition.symbol.size).ok_or_else(|| {
            ResolutionError::CommonSizeOverflow {
                name: definition.name.clone(),
                offset,
                size: definition.symbol.size,
            }
        })?;

        definition.object_index = COMMON_OBJECT_INDEX;
        definition.table_section_index = 0;
        definition.symbol_index = 0;
        definition.symbol.section_index = COMMON_SECTION_INDEX;
        definition.symbol.value = offset;
    }

    Ok(ResolvedSymbols {
        definitions,
        common_section: has_common.then_some(CommonSection {
            size: common_size,
            alignment: common_alignment,
        }),
    })
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}
