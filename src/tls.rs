use core::fmt;

use crate::elf64::SHT_NOBITS;
use crate::executable_writer::{ExecutableImage, ExecutableLoadSegment, LoadSegmentPermissions};
use crate::layout::LaidOutSection;
use crate::link_context::{build_link_context, LinkContext, LinkContextBuildError};
use crate::linker_input::{LinkerInputError, LinkerInputObject, LinkerInputSection};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::permission_layout::SHF_TLS;
use crate::relocated_sections::{
    relocate_allocatable_sections, RelocatedSectionError, RelocatedSectionImage,
};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{SymbolDefinition, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError};

pub const R_X86_64_TPOFF32: u32 = 23;
const STT_TLS: u8 = 6;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

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

    for section in sections
        .iter()
        .filter(|section| is_tls_section(section.flags))
    {
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
        let end = placed.address.checked_add(placed.size).ok_or(
            StaticTlsLayoutError::AddressOverflow {
                object_index: section.object_index,
                section_index: section.section_index,
            },
        )?;
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
    let block_size =
        align_up(memory_size, alignment).ok_or(StaticTlsLayoutError::BlockSizeOverflow {
            memory_size,
            alignment,
        })?;

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
    let tls_end = tls.base_address + tls.memory_size;

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

        let value = i128::from(address) - i128::from(tls.base_address) - i128::from(tls.block_size)
            + i128::from(relocation.addend);
        let value = i32::try_from(value).map_err(|_| Tpoff32ApplyError::OffsetOutOfRange {
            relocation_index,
            symbol_index: relocation.symbol_index,
            value,
        })?;
        let end = relocation
            .offset
            .checked_add(4)
            .ok_or(Tpoff32ApplyError::TargetOutOfBounds {
                relocation_index,
                offset: relocation.offset,
                section_len: section.len(),
            })?;
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

#[derive(Debug)]
pub enum StaticTlsRelocationError {
    Regular(RelocatedSectionError),
    Input(LinkerInputError),
    Layout(StaticTlsLayoutError),
    Context(LinkContextBuildError),
    MissingTlsLayout {
        object_index: usize,
        rela_section_index: u16,
    },
    MissingRelocatedTarget {
        object_index: usize,
        section_index: u16,
    },
    Tpoff32 {
        object_index: usize,
        section_index: u16,
        rela_section_index: u16,
        source: Tpoff32ApplyError,
    },
}

impl fmt::Display for StaticTlsRelocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regular(source) => write!(f, "regular relocation failed: {source}"),
            Self::Input(source) => write!(f, "cannot read TLS input sections: {source}"),
            Self::Layout(source) => write!(f, "cannot compute static TLS layout: {source}"),
            Self::Context(source) => write!(f, "cannot build TLS symbol context: {source}"),
            Self::MissingTlsLayout {
                object_index,
                rela_section_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} contains TPOFF32 but no static TLS image exists"
            ),
            Self::MissingRelocatedTarget {
                object_index,
                section_index,
            } => write!(
                f,
                "TLS relocation target object {object_index} section {section_index} was not materialized"
            ),
            Self::Tpoff32 {
                object_index,
                section_index,
                rela_section_index,
                source,
            } => write!(
                f,
                "cannot apply TPOFF32 RELA section {rela_section_index} to object {object_index} section {section_index}: {source}"
            ),
        }
    }
}

impl std::error::Error for StaticTlsRelocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Regular(source) => Some(source),
            Self::Input(source) => Some(source),
            Self::Layout(source) => Some(source),
            Self::Context(source) => Some(source),
            Self::Tpoff32 { source, .. } => Some(source),
            Self::MissingTlsLayout { .. } | Self::MissingRelocatedTarget { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticTlsRelocationOutput {
    pub sections: Vec<RelocatedSectionImage>,
    pub tls_layout: Option<StaticTlsLayout>,
}

pub fn relocate_allocatable_sections_with_static_tls(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
) -> Result<StaticTlsRelocationOutput, StaticTlsRelocationError> {
    let stripped_inputs = inputs
        .iter()
        .map(|input| {
            let mut object = input.object.clone();
            for table in &mut object.rela_tables {
                table
                    .relocations
                    .retain(|relocation| relocation.relocation_type != R_X86_64_TPOFF32);
            }
            LinkerInputObject {
                object_index: input.object_index,
                file: input.file,
                object,
            }
        })
        .collect::<Vec<_>>();

    let mut relocated =
        relocate_allocatable_sections(&stripped_inputs, start_address, page_alignment)
            .map_err(StaticTlsRelocationError::Regular)?;
    let layout = relocated
        .iter()
        .map(|section| LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect::<Vec<_>>();
    let mut input_sections = Vec::new();
    for input in inputs {
        input_sections.extend(
            input
                .allocatable_sections()
                .map_err(StaticTlsRelocationError::Input)?,
        );
    }
    let tls_layout = compute_static_tls_layout(&input_sections, &layout)
        .map_err(StaticTlsRelocationError::Layout)?;

    let has_tpoff32 = inputs.iter().any(|input| {
        input.object.rela_tables.iter().any(|table| {
            table
                .relocations
                .iter()
                .any(|relocation| relocation.relocation_type == R_X86_64_TPOFF32)
        })
    });
    if !has_tpoff32 {
        return Ok(StaticTlsRelocationOutput {
            sections: relocated,
            tls_layout,
        });
    }

    let tls = tls_layout.ok_or_else(|| {
        let (object_index, rela_section_index) = inputs
            .iter()
            .flat_map(|input| {
                input
                    .object
                    .rela_tables
                    .iter()
                    .filter(|table| {
                        table
                            .relocations
                            .iter()
                            .any(|relocation| relocation.relocation_type == R_X86_64_TPOFF32)
                    })
                    .map(move |table| (input.object_index, table.section_index))
            })
            .next()
            .unwrap_or((0, 0));
        StaticTlsRelocationError::MissingTlsLayout {
            object_index,
            rela_section_index,
        }
    })?;
    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let context = build_link_context(&validated_objects, &layout)
        .map_err(StaticTlsRelocationError::Context)?;

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .any(|relocation| relocation.relocation_type == R_X86_64_TPOFF32)
            {
                continue;
            }
            let target = relocated
                .iter_mut()
                .find(|section| {
                    section.object_index == input.object_index
                        && section.section_index == table.target_section_index
                })
                .ok_or(StaticTlsRelocationError::MissingRelocatedTarget {
                    object_index: input.object_index,
                    section_index: table.target_section_index,
                })?;
            apply_tpoff32_relocations(&mut target.bytes, table, input, &context, tls).map_err(
                |source| StaticTlsRelocationError::Tpoff32 {
                    object_index: input.object_index,
                    section_index: table.target_section_index,
                    rela_section_index: table.section_index,
                    source,
                },
            )?;
        }
    }

    Ok(StaticTlsRelocationOutput {
        sections: relocated,
        tls_layout: Some(tls),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticTlsProgramHeaderError {
    TooManyProgramHeaders,
    InvalidSegmentAlignment { alignment: u64 },
    TlsMemoryHasGap,
    TlsFileRangeOutsideOutput,
    OffsetOverflow,
    FileRangeOutOfBounds,
    FileTooLarge,
}

impl fmt::Display for StaticTlsProgramHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProgramHeaders => {
                write!(f, "TLS program header exceeds ELF64 program-header count")
            }
            Self::InvalidSegmentAlignment { alignment } => write!(
                f,
                "TLS executable segment alignment {alignment} must be a non-zero power of two"
            ),
            Self::TlsMemoryHasGap => write!(
                f,
                "PT_LOAD coverage contains a gap inside the static TLS memory image"
            ),
            Self::TlsFileRangeOutsideOutput => write!(
                f,
                "static TLS initialization image is outside rebuilt executable bytes"
            ),
            Self::OffsetOverflow => {
                write!(f, "TLS executable file-offset calculation overflows u64")
            }
            Self::FileRangeOutOfBounds => {
                write!(f, "existing PT_LOAD file range is outside executable bytes")
            }
            Self::FileTooLarge => {
                write!(f, "TLS executable output cannot be represented in memory")
            }
        }
    }
}

impl std::error::Error for StaticTlsProgramHeaderError {}

pub fn inject_static_tls_program_header(
    mut image: ExecutableImage,
    tls: StaticTlsLayout,
    segment_alignment: u64,
) -> Result<ExecutableImage, StaticTlsProgramHeaderError> {
    if segment_alignment == 0 || !segment_alignment.is_power_of_two() {
        return Err(StaticTlsProgramHeaderError::InvalidSegmentAlignment {
            alignment: segment_alignment,
        });
    }
    let program_header_count = image
        .load_segments
        .len()
        .checked_add(1)
        .ok_or(StaticTlsProgramHeaderError::TooManyProgramHeaders)?;
    let program_header_count_u16 = u16::try_from(program_header_count)
        .map_err(|_| StaticTlsProgramHeaderError::TooManyProgramHeaders)?;
    let metadata_end = (ELF64_EHDR_SIZE as u64)
        .checked_add(
            (ELF64_PHDR_SIZE as u64)
                .checked_mul(program_header_count as u64)
                .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?,
        )
        .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;

    let mut old_segments = image.load_segments.clone();
    old_segments.sort_by_key(|segment| segment.virtual_address);
    let mut old_payloads = Vec::with_capacity(old_segments.len());
    for segment in &old_segments {
        let end = segment
            .file_offset
            .checked_add(segment.file_size)
            .ok_or(StaticTlsProgramHeaderError::FileRangeOutOfBounds)?;
        if end > image.bytes.len() as u64 {
            return Err(StaticTlsProgramHeaderError::FileRangeOutOfBounds);
        }
        old_payloads.push(image.bytes[segment.file_offset as usize..end as usize].to_vec());
    }

    let tls_memory_end = tls
        .base_address
        .checked_add(tls.memory_size)
        .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
    let mut tls_indices = Vec::new();
    let mut covered_until = tls.base_address;
    for (index, segment) in old_segments.iter().enumerate() {
        let segment_end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
        if segment_end <= tls.base_address || segment.virtual_address >= tls_memory_end {
            continue;
        }
        let overlap_start = segment.virtual_address.max(tls.base_address);
        if overlap_start > covered_until {
            return Err(StaticTlsProgramHeaderError::TlsMemoryHasGap);
        }
        covered_until = covered_until.max(segment_end.min(tls_memory_end));
        tls_indices.push(index);
    }
    if covered_until < tls_memory_end || tls_indices.is_empty() {
        return Err(StaticTlsProgramHeaderError::TlsMemoryHasGap);
    }
    let first_tls_index = tls_indices[0];

    let mut new_segments = Vec::with_capacity(old_segments.len());
    let mut next_file_offset = metadata_end;
    let mut tls_anchor: Option<(u64, u64)> = None;
    for (index, segment) in old_segments.iter().enumerate() {
        let file_offset = if tls_indices.binary_search(&index).is_ok() {
            if let Some((anchor_offset, anchor_address)) = tls_anchor {
                let offset = anchor_offset
                    .checked_add(segment.virtual_address - anchor_address)
                    .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
                if offset < next_file_offset {
                    return Err(StaticTlsProgramHeaderError::TlsMemoryHasGap);
                }
                offset
            } else {
                let offset = first_congruent_offset_at_or_after(
                    next_file_offset,
                    segment.virtual_address,
                    segment_alignment,
                )?;
                tls_anchor = Some((offset, segment.virtual_address));
                offset
            }
        } else {
            first_congruent_offset_at_or_after(
                next_file_offset,
                segment.virtual_address,
                segment_alignment,
            )?
        };
        let file_end = file_offset
            .checked_add(segment.file_size)
            .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
        next_file_offset = next_file_offset.max(file_end);
        let mut emitted = segment.clone();
        emitted.file_offset = file_offset;
        new_segments.push(emitted);
    }

    let first_tls = &new_segments[first_tls_index];
    let tls_file_offset = first_tls
        .file_offset
        .checked_add(tls.base_address - first_tls.virtual_address)
        .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
    let tls_file_end = tls_file_offset
        .checked_add(tls.file_size)
        .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)?;
    next_file_offset = next_file_offset.max(tls_file_end);

    let file_size =
        usize::try_from(next_file_offset).map_err(|_| StaticTlsProgramHeaderError::FileTooLarge)?;
    let mut bytes = vec![0_u8; file_size];
    if image.bytes.len() < ELF64_EHDR_SIZE {
        return Err(StaticTlsProgramHeaderError::FileRangeOutOfBounds);
    }
    bytes[..ELF64_EHDR_SIZE].copy_from_slice(&image.bytes[..ELF64_EHDR_SIZE]);
    put_u16(&mut bytes, 56, program_header_count_u16);

    for (index, segment) in new_segments.iter().enumerate() {
        let start = ELF64_EHDR_SIZE + index * ELF64_PHDR_SIZE;
        write_load_program_header(
            &mut bytes[start..start + ELF64_PHDR_SIZE],
            segment,
            segment_alignment,
        );
    }
    let tls_header_start = ELF64_EHDR_SIZE + new_segments.len() * ELF64_PHDR_SIZE;
    write_tls_program_header(
        &mut bytes[tls_header_start..tls_header_start + ELF64_PHDR_SIZE],
        tls,
        tls_file_offset,
    );

    for ((segment, payload), emitted) in old_segments
        .iter()
        .zip(old_payloads.iter())
        .zip(new_segments.iter())
    {
        debug_assert_eq!(segment.file_size as usize, payload.len());
        let start = emitted.file_offset as usize;
        let end = start + payload.len();
        bytes[start..end].copy_from_slice(payload);
    }
    if tls_file_end > bytes.len() as u64 {
        return Err(StaticTlsProgramHeaderError::TlsFileRangeOutsideOutput);
    }

    image.bytes = bytes;
    image.load_segments = new_segments;
    if let Some(first) = image.load_segments.first() {
        image.load_file_offset = first.file_offset;
        image.load_virtual_address = first.virtual_address;
        image.load_memory_size = first.memory_size;
    }
    Ok(image)
}

fn first_congruent_offset_at_or_after(
    minimum: u64,
    virtual_address: u64,
    alignment: u64,
) -> Result<u64, StaticTlsProgramHeaderError> {
    let mask = alignment - 1;
    let residue = virtual_address & mask;
    let minimum_residue = minimum & mask;
    let delta = residue.wrapping_sub(minimum_residue) & mask;
    minimum
        .checked_add(delta)
        .ok_or(StaticTlsProgramHeaderError::OffsetOverflow)
}

fn load_flags(permissions: LoadSegmentPermissions) -> u32 {
    match permissions {
        LoadSegmentPermissions::ReadOnly => PF_R,
        LoadSegmentPermissions::ReadExecute => PF_R | PF_X,
        LoadSegmentPermissions::ReadWrite => PF_R | PF_W,
    }
}

fn write_load_program_header(out: &mut [u8], segment: &ExecutableLoadSegment, alignment: u64) {
    put_u32(out, 0, PT_LOAD);
    put_u32(out, 4, load_flags(segment.permissions));
    put_u64(out, 8, segment.file_offset);
    put_u64(out, 16, segment.virtual_address);
    put_u64(out, 24, segment.virtual_address);
    put_u64(out, 32, segment.file_size);
    put_u64(out, 40, segment.memory_size);
    put_u64(out, 48, alignment);
}

fn write_tls_program_header(out: &mut [u8], tls: StaticTlsLayout, file_offset: u64) {
    put_u32(out, 0, PT_TLS);
    put_u32(out, 4, PF_R);
    put_u64(out, 8, file_offset);
    put_u64(out, 16, tls.base_address);
    put_u64(out, 24, tls.base_address);
    put_u64(out, 32, tls.file_size);
    put_u64(out, 40, tls.memory_size);
    put_u64(out, 48, tls.alignment);
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
