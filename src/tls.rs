use core::fmt;

use crate::elf64::SHT_NOBITS;
use crate::layout::LaidOutSection;
use crate::link_context::LinkContext;
use crate::linker_input::{LinkerInputObject, LinkerInputSection};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{SymbolDefinition, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError};

pub const SHF_TLS: u64 = 0x400;
pub const R_X86_64_TPOFF32: u32 = 23;
const STT_TLS: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticTlsLayout {
    pub base_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub block_size: u64,
    pub alignment: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticTlsLayoutError {
    MissingSectionLayout {
        object_index: usize,
        section_index: u16,
    },
    AddressOverflow {
        object_index: usize,
        section_index: u16,
    },
    BlockSizeOverflow {
        memory_size: u64,
        alignment: u64,
    },
    NonTlsSectionInterleaves {
        object_index: usize,
        section_index: u16,
    },
}

impl fmt::Display for StaticTlsLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSectionLayout {
                object_index,
                section_index,
            } => write!(
                f,
                "TLS object {object_index} section {section_index} has no final layout"
            ),
            Self::AddressOverflow {
                object_index,
                section_index,
            } => write!(
                f,
                "TLS object {object_index} section {section_index} end address overflows u64"
            ),
            Self::BlockSizeOverflow {
                memory_size,
                alignment,
            } => write!(
                f,
                "aligning static TLS memory size {memory_size} to {alignment} bytes overflows u64"
            ),
            Self::NonTlsSectionInterleaves {
                object_index,
                section_index,
            } => write!(
                f,
                "non-TLS object {object_index} section {section_index} is interleaved inside the static TLS image"
            ),
        }
    }
}

impl std::error::Error for StaticTlsLayoutError {}

pub fn is_tls_section(flags: u64) -> bool {
    flags & SHF_TLS != 0
}

pub fn compute_static_tls_layout(
    sections: &[LinkerInputSection<'_>],
    layout: &[LaidOutSection],
) -> Result<Option<StaticTlsLayout>, StaticTlsLayoutError> {
    let mut placements = Vec::new();
    let mut alignment = 1_u64;

    for section in sections.iter().filter(|section| is_tls_section(section.flags)) {
        let placed = layout
            .iter()
            .find(|placed| {
                placed.object_index == section.object_index
                    && placed.section_index == section.section_index
            })
            .ok_or(StaticTlsLayoutError::MissingSectionLayout {
                object_index: section.object_index,
                section_index: section.section_index,
            })?;
        let end = placed
            .address
            .checked_add(placed.size)
            .ok_or(StaticTlsLayoutError::AddressOverflow {
                object_index: section.object_index,
                section_index: section.section_index,
            })?;
        alignment = alignment.max(section.alignment.max(1));
        placements.push((section, *placed, end));
    }

    if placements.is_empty() {
        return Ok(None);
    }

    placements.sort_by_key(|(_, placed, _)| placed.address);
    let base_address = placements[0].1.address;
    let memory_end = placements
        .iter()
        .map(|(_, _, end)| *end)
        .max()
        .unwrap_or(base_address);
    let file_end = placements
        .iter()
        .filter(|(section, _, _)| section.section_type != SHT_NOBITS)
        .map(|(_, _, end)| *end)
        .max()
        .unwrap_or(base_address);

    for placed in layout {
        if placed.address < base_address || placed.address >= memory_end {
            continue;
        }
        let is_tls = placements.iter().any(|(section, _, _)| {
            section.object_index == placed.object_index
                && section.section_index == placed.section_index
        });
        if !is_tls {
            return Err(StaticTlsLayoutError::NonTlsSectionInterleaves {
                object_index: placed.object_index,
                section_index: placed.section_index,
            });
        }
    }

    let memory_size = memory_end - base_address;
    let file_size = file_end - base_address;
    let block_size = align_up(memory_size, alignment).ok_or(
        StaticTlsLayoutError::BlockSizeOverflow {
            memory_size,
            alignment,
        },
    )?;

    Ok(Some(StaticTlsLayout {
        base_address,
        file_size,
        memory_size,
        block_size,
        alignment,
    }))
}

#[derive(Debug)]
pub enum Tpoff32ApplyError {
    ObjectSymbols(ObjectSymbolError),
    MissingSymbolMetadata {
        relocation_index: usize,
        symbol_index: u32,
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
    LocalSymbolAddress {
        relocation_index: usize,
        symbol_index: u32,
        source: FinalSymbolAddressError,
    },
    NonTlsSymbol {
        relocation_index: usize,
        symbol_index: u32,
        symbol_type: u8,
    },
    SymbolOutsideTlsImage {
        relocation_index: usize,
        symbol_index: u32,
        address: u64,
    },
    OffsetOutOfRange {
        relocation_index: usize,
        symbol_index: u32,
        value: i128,
    },
    TargetOutOfBounds {
        relocation_index: usize,
        offset: u64,
        section_len: usize,
    },
}

impl fmt::Display for Tpoff32ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObjectSymbols(source) => write!(f, "cannot read TLS symbol metadata: {source}"),
            Self::MissingSymbolMetadata {
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} refers to missing symbol {symbol_index} metadata"
            ),
            Self::UnsupportedBinding {
                relocation_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} symbol {symbol_index} uses unsupported binding {binding}"
            ),
            Self::MissingGlobalAddress {
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} symbol {symbol_index} ({:?}) has no resolved global address",
                String::from_utf8_lossy(name)
            ),
            Self::LocalSymbolAddress {
                relocation_index,
                symbol_index,
                source,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} local symbol {symbol_index} has no final address: {source}"
            ),
            Self::NonTlsSymbol {
                relocation_index,
                symbol_index,
                symbol_type,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} symbol {symbol_index} has ELF symbol type {symbol_type}, expected STT_TLS"
            ),
            Self::SymbolOutsideTlsImage {
                relocation_index,
                symbol_index,
                address,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} symbol {symbol_index} resolves to {address:#x}, outside the static TLS image"
            ),
            Self::OffsetOutOfRange {
                relocation_index,
                symbol_index,
                value,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} symbol {symbol_index} result {value} is outside signed 32-bit range"
            ),
            Self::TargetOutOfBounds {
                relocation_index,
                offset,
                section_len,
            } => write!(
                f,
                "TPOFF32 relocation {relocation_index} writes four bytes at offset {offset}, outside section length {section_len}"
            ),
        }
    }
}

impl std::error::Error for Tpoff32ApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ObjectSymbols(source) => Some(source),
            Self::LocalSymbolAddress { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn apply_tpoff32_relocations(
    section: &mut [u8],
    table: &Elf64RelaTable,
    object: &LinkerInputObject<'_>,
    context: &LinkContext<'_>,
    tls: StaticTlsLayout,
) -> Result<(), Tpoff32ApplyError> {
    if !table
        .relocations
        .iter()
        .any(|relocation| relocation.relocation_type == R_X86_64_TPOFF32)
    {
        return Ok(());
    }

    let symbol_table = object
        .object
        .symbol_tables
        .iter()
        .find(|candidate| candidate.section_index == table.symbol_table_index)
        .ok_or(Tpoff32ApplyError::MissingSymbolMetadata {
            relocation_index: 0,
            symbol_index: table
                .relocations
                .iter()
                .find(|relocation| relocation.relocation_type == R_X86_64_TPOFF32)
                .map(|relocation| relocation.symbol_index)
                .unwrap_or(0),
        })?;
    let symbols = named_symbols_from_table(
        object.file,
        &object.object.sections,
        symbol_table,
        object.object_index,
    )
    .map_err(Tpoff32ApplyError::ObjectSymbols)?;
    let tls_end = tls
        .base_address
        .checked_add(tls.memory_size)
        .unwrap_or(u64::MAX);

    for (relocation_index, relocation) in table.relocations.iter().enumerate() {
        if relocation.relocation_type != R_X86_64_TPOFF32 {
            continue;
        }
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
            .ok_or(Tpoff32ApplyError::MissingSymbolMetadata {
                relocation_index,
                symbol_index: relocation.symbol_index,
            })?;
        let symbol_type = symbol.symbol.info & 0x0f;
        if symbol_type != STT_TLS {
            return Err(Tpoff32ApplyError::NonTlsSymbol {
                relocation_index,
                symbol_index: relocation.symbol_index,
                symbol_type,
            });
        }

        let binding = symbol.symbol.info >> 4;
        let address = match binding {
            STB_LOCAL => {
                let definition = SymbolDefinition {
                    name: symbol.name.to_vec(),
                    object_index: symbol.object_index,
                    table_section_index: symbol.table_section_index,
                    symbol_index: symbol.symbol_index,
                    symbol: symbol.symbol,
                };
                final_symbol_address(&definition, context.layout()).map_err(|source| {
                    Tpoff32ApplyError::LocalSymbolAddress {
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        source,
                    }
                })?
            }
            STB_GLOBAL | STB_WEAK => context
                .global_addresses()
                .get(symbol.name)
                .copied()
                .ok_or_else(|| Tpoff32ApplyError::MissingGlobalAddress {
                    relocation_index,
                    symbol_index: relocation.symbol_index,
                    name: symbol.name.to_vec(),
                })?,
            _ => {
                return Err(Tpoff32ApplyError::UnsupportedBinding {
                    relocation_index,
                    symbol_index: relocation.symbol_index,
                    binding,
                })
            }
        };
        if address < tls.base_address || address >= tls_end {
            return Err(Tpoff32ApplyError::SymbolOutsideTlsImage {
                relocation_index,
                symbol_index: relocation.symbol_index,
                address,
            });
        }

        let value = i128::from(address)
            - i128::from(tls.base_address)
            - i128::from(tls.block_size)
            + i128::from(relocation.addend);
        let value = i32::try_from(value).map_err(|_| Tpoff32ApplyError::OffsetOutOfRange {
            relocation_index,
            symbol_index: relocation.symbol_index,
            value,
        })?;
        let end = relocation.offset.checked_add(4).ok_or(
            Tpoff32ApplyError::TargetOutOfBounds {
                relocation_index,
                offset: relocation.offset,
                section_len: section.len(),
            },
        )?;
        if end > section.len() as u64 {
            return Err(Tpoff32ApplyError::TargetOutOfBounds {
                relocation_index,
                offset: relocation.offset,
                section_len: section.len(),
            });
        }
        section[relocation.offset as usize..end as usize].copy_from_slice(&value.to_le_bytes());
    }

    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linker_input::LinkerInputSection;

    fn section(
        object_index: usize,
        section_index: u16,
        section_type: u32,
        flags: u64,
        size: u64,
        alignment: u64,
    ) -> LinkerInputSection<'static> {
        LinkerInputSection {
            object_index,
            section_index,
            section_type,
            flags,
            size,
            alignment,
            bytes: &[],
            rela_tables: Vec::new(),
        }
    }

    #[test]
    fn computes_aligned_variant_two_tls_span() {
        let sections = vec![
            section(0, 1, 1, SHF_TLS, 4, 4),
            section(0, 2, SHT_NOBITS, SHF_TLS, 4, 8),
        ];
        let layout = vec![
            LaidOutSection {
                object_index: 0,
                section_index: 1,
                address: 0x500000,
                size: 4,
            },
            LaidOutSection {
                object_index: 0,
                section_index: 2,
                address: 0x500008,
                size: 4,
            },
        ];

        let tls = compute_static_tls_layout(&sections, &layout)
            .unwrap()
            .unwrap();

        assert_eq!(tls.base_address, 0x500000);
        assert_eq!(tls.file_size, 4);
        assert_eq!(tls.memory_size, 12);
        assert_eq!(tls.alignment, 8);
        assert_eq!(tls.block_size, 16);
    }

    #[test]
    fn reports_absent_tls_without_synthesizing_a_segment() {
        let sections = vec![section(0, 1, 1, 0, 4, 4)];
        let layout = vec![LaidOutSection {
            object_index: 0,
            section_index: 1,
            address: 0x400000,
            size: 4,
        }];

        assert_eq!(compute_static_tls_layout(&sections, &layout).unwrap(), None);
    }
}
