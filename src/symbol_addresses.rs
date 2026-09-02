use core::fmt;
use std::collections::BTreeMap;

use crate::elf64::SHN_LORESERVE;
use crate::layout::LaidOutSection;
use crate::resolve::{SymbolDefinition, SHN_UNDEF};

pub const SHN_ABS: u16 = 0xfff1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalSymbolAddressError {
    UndefinedSymbol {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
    },
    UnsupportedSpecialSectionIndex {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
        section_index: u16,
    },
    MissingSectionLayout {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
        section_index: u16,
    },
    AddressOverflow {
        name: Vec<u8>,
        object_index: usize,
        symbol_index: usize,
        section_index: u16,
        section_address: u64,
        symbol_value: u64,
    },
}

impl fmt::Display for FinalSymbolAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndefinedSymbol {
                name,
                object_index,
                symbol_index,
            } => write!(
                f,
                "symbol {:?} at object {object_index} symbol {symbol_index} is undefined",
                String::from_utf8_lossy(name)
            ),
            Self::UnsupportedSpecialSectionIndex {
                name,
                object_index,
                symbol_index,
                section_index,
            } => write!(
                f,
                "symbol {:?} at object {object_index} symbol {symbol_index} uses unsupported special section index {section_index:#x}",
                String::from_utf8_lossy(name)
            ),
            Self::MissingSectionLayout {
                name,
                object_index,
                symbol_index,
                section_index,
            } => write!(
                f,
                "symbol {:?} at object {object_index} symbol {symbol_index} references section {section_index}, which has no output layout",
                String::from_utf8_lossy(name)
            ),
            Self::AddressOverflow {
                name,
                object_index,
                symbol_index,
                section_index,
                section_address,
                symbol_value,
            } => write!(
                f,
                "symbol {:?} at object {object_index} symbol {symbol_index} overflows final address: section {section_index} base {section_address:#x} + value {symbol_value:#x}",
                String::from_utf8_lossy(name)
            ),
        }
    }
}

impl std::error::Error for FinalSymbolAddressError {}

pub fn final_symbol_address(
    definition: &SymbolDefinition,
    layout: &[LaidOutSection],
) -> Result<u64, FinalSymbolAddressError> {
    let section_index = definition.symbol.section_index;

    if section_index == SHN_UNDEF {
        return Err(FinalSymbolAddressError::UndefinedSymbol {
            name: definition.name.clone(),
            object_index: definition.object_index,
            symbol_index: definition.symbol_index,
        });
    }

    if section_index == SHN_ABS {
        return Ok(definition.symbol.value);
    }

    if section_index >= SHN_LORESERVE {
        return Err(FinalSymbolAddressError::UnsupportedSpecialSectionIndex {
            name: definition.name.clone(),
            object_index: definition.object_index,
            symbol_index: definition.symbol_index,
            section_index,
        });
    }

    let section = layout
        .iter()
        .find(|section| {
            section.object_index == definition.object_index
                && section.section_index == section_index
        })
        .ok_or_else(|| FinalSymbolAddressError::MissingSectionLayout {
            name: definition.name.clone(),
            object_index: definition.object_index,
            symbol_index: definition.symbol_index,
            section_index,
        })?;

    section
        .address
        .checked_add(definition.symbol.value)
        .ok_or_else(|| FinalSymbolAddressError::AddressOverflow {
            name: definition.name.clone(),
            object_index: definition.object_index,
            symbol_index: definition.symbol_index,
            section_index,
            section_address: section.address,
            symbol_value: definition.symbol.value,
        })
}

pub fn final_symbol_addresses(
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
    layout: &[LaidOutSection],
) -> Result<BTreeMap<Vec<u8>, u64>, FinalSymbolAddressError> {
    definitions
        .iter()
        .map(|(name, definition)| {
            final_symbol_address(definition, layout).map(|address| (name.clone(), address))
        })
        .collect()
}
