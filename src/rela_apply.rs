use core::fmt;

use crate::relocations::Elf64RelaTable;
use crate::x86_64_relocations::{apply_relocation, RelocationApplyError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaTableApplyError {
    PlaceOverflow {
        relocation_index: usize,
        section_address: u64,
        offset: u64,
    },
    MissingSymbolValue {
        relocation_index: usize,
        symbol_index: u32,
    },
    Relocation {
        relocation_index: usize,
        error: RelocationApplyError,
    },
}

impl fmt::Display for RelaTableApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaceOverflow {
                relocation_index,
                section_address,
                offset,
            } => write!(
                f,
                "relocation {relocation_index} place address {section_address} + offset {offset} overflows u64"
            ),
            Self::MissingSymbolValue {
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "relocation {relocation_index} has no resolved value for symbol {symbol_index}"
            ),
            Self::Relocation {
                relocation_index,
                error,
            } => write!(f, "relocation {relocation_index} failed: {error}"),
        }
    }
}

impl std::error::Error for RelaTableApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Relocation { error, .. } => Some(error),
            Self::PlaceOverflow { .. } | Self::MissingSymbolValue { .. } => None,
        }
    }
}

pub fn apply_rela_table<F>(
    section: &mut [u8],
    section_address: u64,
    table: &Elf64RelaTable,
    mut symbol_value: F,
) -> Result<(), RelaTableApplyError>
where
    F: FnMut(u32) -> Option<u64>,
{
    let mut patched = section.to_vec();

    for (relocation_index, relocation) in table.relocations.iter().enumerate() {
        let place = section_address.checked_add(relocation.offset).ok_or(
            RelaTableApplyError::PlaceOverflow {
                relocation_index,
                section_address,
                offset: relocation.offset,
            },
        )?;
        let value = symbol_value(relocation.symbol_index).ok_or(
            RelaTableApplyError::MissingSymbolValue {
                relocation_index,
                symbol_index: relocation.symbol_index,
            },
        )?;
        apply_relocation(&mut patched, relocation, value, place).map_err(|error| {
            RelaTableApplyError::Relocation {
                relocation_index,
                error,
            }
        })?;
    }

    section.copy_from_slice(&patched);
    Ok(())
}
