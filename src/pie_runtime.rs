use core::fmt;
use std::collections::BTreeMap;

use crate::link_symbols::LinkSymbolError;
use crate::linker_input::LinkerInputObject;
use crate::load_segments::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use crate::object_symbols::named_symbols_from_table;
use crate::relocated_sections::RelocatedSectionImage;
use crate::resolve::{SymbolDefinition, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};
use crate::x86_64_relocations::R_X86_64_64;

const SHT_PROGBITS: u32 = 1;
const R_X86_64_RELATIVE: u32 = 8;

const PIE_RUNTIME_OBJECT_INDEX: usize = usize::MAX - 2;
const PIE_RELA_SECTION_INDEX: u16 = 1;
const PIE_TRAMPOLINE_SECTION_INDEX: u16 = 2;
const PIE_DYNAMIC_SECTION_INDEX: u16 = 3;

const ELF64_RELA_SIZE: u64 = 24;
const ELF64_DYN_SIZE: u64 = 16;

const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_RELACOUNT: i64 = 0x6fff_fff9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieDynamicSegment {
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieRuntimeOutput {
    pub sections: Vec<RelocatedSectionImage>,
    pub entry_address: u64,
    pub dynamic: Option<PieDynamicSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RelativeRelocation {
    offset: u64,
    addend: i64,
}

#[derive(Debug)]
pub enum PieRuntimeError {
    Symbols(LinkSymbolError),
    MissingTargetSection {
        object_index: usize,
        section_index: u16,
    },
    ReadOnlyTarget {
        object_index: usize,
        section_index: u16,
        relocation_index: usize,
    },
    MissingSymbolMetadata {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
    },
    UnsupportedBinding {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        binding: u8,
    },
    AbsoluteSymbol {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
    },
    UndefinedWeakSymbol {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
    },
    MissingGlobalDefinition {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    MissingGotDefinition {
        name: Vec<u8>,
    },
    GotSymbolAddress {
        name: Vec<u8>,
        source: FinalSymbolAddressError,
    },
    MissingGotTarget {
        name: Vec<u8>,
        entry_address: u64,
    },
    GotRelativeAddendOutOfRange {
        name: Vec<u8>,
        value: i128,
    },
    SymbolAddress {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        source: FinalSymbolAddressError,
    },
    RelocationOffsetOverflow {
        object_index: usize,
        section_index: u16,
        relocation_index: usize,
    },
    RelativeAddendOutOfRange {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        value: i128,
    },
    SectionEndOverflow,
    RuntimeAddressOverflow,
    RuntimeSectionTooLarge,
    InvalidPageAlignment {
        alignment: u64,
    },
    TrampolineBranchOutOfRange,
}

impl fmt::Display for PieRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symbols(source) => write!(f, "cannot resolve PIE runtime symbols: {source}"),
            Self::MissingTargetSection {
                object_index,
                section_index,
            } => write!(
                f,
                "PIE runtime relocation target object {object_index} section {section_index} is missing from relocated output"
            ),
            Self::ReadOnlyTarget {
                object_index,
                section_index,
                relocation_index,
            } => write!(
                f,
                "PIE runtime relative relocation {relocation_index} targets non-writable object {object_index} section {section_index}; bounded self-relocation requires writable targets"
            ),
            Self::MissingSymbolMetadata {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} refers to missing symbol {symbol_index} metadata"
            ),
            Self::UnsupportedBinding {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} symbol {symbol_index} uses unsupported binding {binding} for PIE relative relocation"
            ),
            Self::AbsoluteSymbol {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} symbol {symbol_index} resolves to SHN_ABS and cannot become R_X86_64_RELATIVE"
            ),
            Self::UndefinedWeakSymbol {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} references undefined weak symbol {symbol_index}; zero-valued weak semantics cannot become R_X86_64_RELATIVE"
            ),
            Self::MissingGlobalDefinition {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} symbol {symbol_index} ({:?}) has no resolved definition for PIE relative relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGotDefinition { name } => write!(
                f,
                "PIE GOT entry for {:?} has no resolved global definition",
                String::from_utf8_lossy(name)
            ),
            Self::GotSymbolAddress { name, source } => write!(
                f,
                "PIE GOT entry for {:?} has no usable image-relative symbol address: {source}",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGotTarget {
                name,
                entry_address,
            } => write!(
                f,
                "PIE GOT entry for {:?} at {entry_address:#x} is not backed by writable file data",
                String::from_utf8_lossy(name)
            ),
            Self::GotRelativeAddendOutOfRange { name, value } => write!(
                f,
                "PIE GOT entry for {:?} has relative addend {value} outside signed ELF64 Rela range",
                String::from_utf8_lossy(name)
            ),
            Self::SymbolAddress {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                source,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} symbol {symbol_index} has no usable PIE-relative address: {source}"
            ),
            Self::RelocationOffsetOverflow {
                object_index,
                section_index,
                relocation_index,
            } => write!(
                f,
                "object {object_index} section {section_index} runtime relocation {relocation_index} target address overflows u64"
            ),
            Self::RelativeAddendOutOfRange {
                object_index,
                rela_section_index,
                relocation_index,
                value,
            } => write!(
                f,
                "object {object_index} RELA section {rela_section_index} relocation {relocation_index} relative addend {value} does not fit signed ELF64 Rela addend"
            ),
            Self::SectionEndOverflow => write!(f, "PIE runtime section end overflows u64"),
            Self::RuntimeAddressOverflow => write!(f, "PIE runtime synthetic address arithmetic overflows u64"),
            Self::RuntimeSectionTooLarge => write!(f, "PIE runtime synthetic section is too large"),
            Self::InvalidPageAlignment { alignment } => write!(
                f,
                "PIE runtime page alignment {alignment} must be a non-zero power of two"
            ),
            Self::TrampolineBranchOutOfRange => {
                write!(f, "PIE self-relocation trampoline branch exceeds rel8 range")
            }
        }
    }
}

impl std::error::Error for PieRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Symbols(source) => Some(source),
            Self::SymbolAddress { source, .. } => Some(source),
            Self::GotSymbolAddress { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn add_runtime_relative_relocations(
    inputs: &[LinkerInputObject<'_>],
    mut sections: Vec<RelocatedSectionImage>,
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
    got_entries: &BTreeMap<Vec<u8>, u64>,
    user_entry_address: u64,
    page_alignment: u64,
) -> Result<PieRuntimeOutput, PieRuntimeError> {
    if page_alignment == 0 || !page_alignment.is_power_of_two() {
        return Err(PieRuntimeError::InvalidPageAlignment {
            alignment: page_alignment,
        });
    }

    let relocations =
        collect_relative_relocations(inputs, &sections, definitions, got_entries)?;
    if relocations.is_empty() {
        return Ok(PieRuntimeOutput {
            sections,
            entry_address: user_entry_address,
            dynamic: None,
        });
    }

    let rela_bytes = serialize_relative_relocations(&relocations)?;
    let max_end = sections.iter().try_fold(0_u64, |max_end, section| {
        let end = section
            .address
            .checked_add(section.size)
            .ok_or(PieRuntimeError::SectionEndOverflow)?;
        Ok::<_, PieRuntimeError>(max_end.max(end))
    })?;
    let rela_address = align_up(max_end, page_alignment)?;
    let trampoline_address = align_up(
        rela_address
            .checked_add(rela_bytes.len() as u64)
            .ok_or(PieRuntimeError::RuntimeAddressOverflow)?,
        page_alignment,
    )?;
    let trampoline = build_trampoline(
        trampoline_address,
        rela_address,
        relocations.len(),
        user_entry_address,
    )?;
    let dynamic_address = align_up(
        trampoline_address
            .checked_add(trampoline.len() as u64)
            .ok_or(PieRuntimeError::RuntimeAddressOverflow)?,
        page_alignment,
    )?;
    let dynamic = build_dynamic_table(rela_address, rela_bytes.len(), relocations.len())?;

    sections.push(runtime_section(
        PIE_RELA_SECTION_INDEX,
        SHF_ALLOC,
        rela_address,
        8,
        rela_bytes,
    )?);
    sections.push(runtime_section(
        PIE_TRAMPOLINE_SECTION_INDEX,
        SHF_ALLOC | SHF_EXECINSTR,
        trampoline_address,
        16,
        trampoline,
    )?);
    sections.push(runtime_section(
        PIE_DYNAMIC_SECTION_INDEX,
        SHF_ALLOC | SHF_WRITE,
        dynamic_address,
        8,
        dynamic,
    )?);

    Ok(PieRuntimeOutput {
        sections,
        entry_address: trampoline_address,
        dynamic: Some(PieDynamicSegment {
            address: dynamic_address,
            size: 5 * ELF64_DYN_SIZE,
        }),
    })
}

fn collect_relative_relocations(
    inputs: &[LinkerInputObject<'_>],
    sections: &[RelocatedSectionImage],
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
    got_entries: &BTreeMap<Vec<u8>, u64>,
) -> Result<Vec<RelativeRelocation>, PieRuntimeError> {
    let layout = sections
        .iter()
        .map(|section| crate::layout::LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect::<Vec<_>>();
    let mut runtime = Vec::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .any(|relocation| relocation.relocation_type == R_X86_64_64)
            {
                continue;
            }
            let target = sections
                .iter()
                .find(|section| {
                    section.object_index == input.object_index
                        && section.section_index == table.target_section_index
                })
                .ok_or(PieRuntimeError::MissingTargetSection {
                    object_index: input.object_index,
                    section_index: table.target_section_index,
                })?;
            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .expect("validated RELA table references validated symbol table");
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                PieRuntimeError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;

            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                if relocation.relocation_type != R_X86_64_64 {
                    continue;
                }
                if target.flags & SHF_WRITE == 0 {
                    return Err(PieRuntimeError::ReadOnlyTarget {
                        object_index: input.object_index,
                        section_index: table.target_section_index,
                        relocation_index,
                    });
                }
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(PieRuntimeError::MissingSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                let (resolved_symbol, address) = match binding {
                    STB_LOCAL => {
                        if symbol.symbol.section_index == SHN_ABS {
                            return Err(PieRuntimeError::AbsoluteSymbol {
                                object_index: input.object_index,
                                rela_section_index: table.section_index,
                                relocation_index,
                                symbol_index: relocation.symbol_index,
                            });
                        }
                        let definition = SymbolDefinition {
                            name: symbol.name.to_vec(),
                            object_index: symbol.object_index,
                            table_section_index: symbol.table_section_index,
                            symbol_index: symbol.symbol_index,
                            symbol: symbol.symbol,
                        };
                        let address =
                            final_symbol_address(&definition, &layout).map_err(|source| {
                                PieRuntimeError::SymbolAddress {
                                    object_index: input.object_index,
                                    rela_section_index: table.section_index,
                                    relocation_index,
                                    symbol_index: relocation.symbol_index,
                                    source,
                                }
                            })?;
                        (symbol.symbol, address)
                    }
                    STB_GLOBAL | STB_WEAK => {
                        let Some(definition) = definitions.get(symbol.name) else {
                            if binding == STB_WEAK && symbol.symbol.section_index == SHN_UNDEF {
                                return Err(PieRuntimeError::UndefinedWeakSymbol {
                                    object_index: input.object_index,
                                    rela_section_index: table.section_index,
                                    relocation_index,
                                    symbol_index: relocation.symbol_index,
                                });
                            }
                            return Err(PieRuntimeError::MissingGlobalDefinition {
                                object_index: input.object_index,
                                rela_section_index: table.section_index,
                                relocation_index,
                                symbol_index: relocation.symbol_index,
                                name: symbol.name.to_vec(),
                            });
                        };
                        if definition.symbol.section_index == SHN_ABS {
                            return Err(PieRuntimeError::AbsoluteSymbol {
                                object_index: input.object_index,
                                rela_section_index: table.section_index,
                                relocation_index,
                                symbol_index: relocation.symbol_index,
                            });
                        }
                        let address =
                            final_symbol_address(definition, &layout).map_err(|source| {
                                PieRuntimeError::SymbolAddress {
                                    object_index: input.object_index,
                                    rela_section_index: table.section_index,
                                    relocation_index,
                                    symbol_index: relocation.symbol_index,
                                    source,
                                }
                            })?;
                        (definition.symbol, address)
                    }
                    _ => {
                        return Err(PieRuntimeError::UnsupportedBinding {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            symbol_index: relocation.symbol_index,
                            binding,
                        });
                    }
                };
                debug_assert_ne!(resolved_symbol.section_index, SHN_UNDEF);

                let offset = target.address.checked_add(relocation.offset).ok_or(
                    PieRuntimeError::RelocationOffsetOverflow {
                        object_index: input.object_index,
                        section_index: table.target_section_index,
                        relocation_index,
                    },
                )?;
                let value = i128::from(address) + i128::from(relocation.addend);
                let addend = i64::try_from(value).map_err(|_| {
                    PieRuntimeError::RelativeAddendOutOfRange {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        value,
                    }
                })?;
                runtime.push(RelativeRelocation { offset, addend });
            }
        }
    }

    for (name, entry_address) in got_entries {
        let definition = definitions
            .get(name)
            .ok_or_else(|| PieRuntimeError::MissingGotDefinition { name: name.clone() })?;
        if definition.symbol.section_index == SHN_ABS {
            continue;
        }

        let address =
            final_symbol_address(definition, &layout).map_err(|source| PieRuntimeError::GotSymbolAddress {
                name: name.clone(),
                source,
            })?;
        let target_is_writable_file_data = sections.iter().any(|section| {
            if section.flags & SHF_WRITE == 0 {
                return false;
            }
            let Some(offset) = entry_address.checked_sub(section.address) else {
                return false;
            };
            offset
                .checked_add(8)
                .is_some_and(|end| end <= section.bytes.len() as u64)
        });
        if !target_is_writable_file_data {
            return Err(PieRuntimeError::MissingGotTarget {
                name: name.clone(),
                entry_address: *entry_address,
            });
        }
        let value = i128::from(address);
        let addend = i64::try_from(value).map_err(|_| {
            PieRuntimeError::GotRelativeAddendOutOfRange {
                name: name.clone(),
                value,
            }
        })?;
        runtime.push(RelativeRelocation {
            offset: *entry_address,
            addend,
        });
    }

    Ok(runtime)
}

fn serialize_relative_relocations(
    relocations: &[RelativeRelocation],
) -> Result<Vec<u8>, PieRuntimeError> {
    let capacity = relocations
        .len()
        .checked_mul(ELF64_RELA_SIZE as usize)
        .ok_or(PieRuntimeError::RuntimeSectionTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    for relocation in relocations {
        bytes.extend_from_slice(&relocation.offset.to_le_bytes());
        bytes.extend_from_slice(&u64::from(R_X86_64_RELATIVE).to_le_bytes());
        bytes.extend_from_slice(&relocation.addend.to_le_bytes());
    }
    Ok(bytes)
}

fn build_dynamic_table(
    rela_address: u64,
    rela_size: usize,
    relocation_count: usize,
) -> Result<Vec<u8>, PieRuntimeError> {
    let rela_size =
        u64::try_from(rela_size).map_err(|_| PieRuntimeError::RuntimeSectionTooLarge)?;
    let count =
        u64::try_from(relocation_count).map_err(|_| PieRuntimeError::RuntimeSectionTooLarge)?;
    let mut bytes = Vec::with_capacity((5 * ELF64_DYN_SIZE) as usize);
    push_dynamic(&mut bytes, DT_RELA, rela_address);
    push_dynamic(&mut bytes, DT_RELASZ, rela_size);
    push_dynamic(&mut bytes, DT_RELAENT, ELF64_RELA_SIZE);
    push_dynamic(&mut bytes, DT_RELACOUNT, count);
    push_dynamic(&mut bytes, DT_NULL, 0);
    Ok(bytes)
}

fn push_dynamic(bytes: &mut Vec<u8>, tag: i64, value: u64) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn build_trampoline(
    trampoline_address: u64,
    rela_address: u64,
    relocation_count: usize,
    user_entry_address: u64,
) -> Result<Vec<u8>, PieRuntimeError> {
    let relocation_count =
        u64::try_from(relocation_count).map_err(|_| PieRuntimeError::RuntimeSectionTooLarge)?;
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&[0x48, 0x8d, 0x1d, 0, 0, 0, 0]);
    let runtime_pc_link_address = trampoline_address
        .checked_add(bytes.len() as u64)
        .ok_or(PieRuntimeError::RuntimeAddressOverflow)?;
    push_movabs(&mut bytes, 0xb8, runtime_pc_link_address);
    bytes.extend_from_slice(&[0x48, 0x29, 0xc3]);

    push_movabs(&mut bytes, 0xbe, rela_address);
    bytes.extend_from_slice(&[0x48, 0x01, 0xde]);
    push_movabs(&mut bytes, 0xb9, relocation_count);

    let loop_start = bytes.len();
    bytes.extend_from_slice(&[0x48, 0x85, 0xc9]);
    bytes.push(0x74);
    let done_disp = bytes.len();
    bytes.push(0);

    bytes.extend_from_slice(&[0x48, 0x8b, 0x06]);
    bytes.extend_from_slice(&[0x48, 0x8b, 0x56, 0x10]);
    bytes.extend_from_slice(&[0x48, 0x01, 0xd8]);
    bytes.extend_from_slice(&[0x48, 0x01, 0xda]);
    bytes.extend_from_slice(&[0x48, 0x89, 0x10]);
    bytes.extend_from_slice(&[0x48, 0x83, 0xc6, 0x18]);
    bytes.extend_from_slice(&[0x48, 0xff, 0xc9]);
    bytes.push(0xeb);
    let loop_disp = bytes.len();
    bytes.push(0);

    let done = bytes.len();
    patch_rel8(&mut bytes, done_disp, done)?;
    patch_rel8(&mut bytes, loop_disp, loop_start)?;

    push_movabs(&mut bytes, 0xb8, user_entry_address);
    bytes.extend_from_slice(&[0x48, 0x01, 0xd8]);
    bytes.extend_from_slice(&[0xff, 0xe0]);

    Ok(bytes)
}

fn push_movabs(bytes: &mut Vec<u8>, opcode: u8, immediate: u64) {
    bytes.extend_from_slice(&[0x48, opcode]);
    bytes.extend_from_slice(&immediate.to_le_bytes());
}

fn patch_rel8(
    bytes: &mut [u8],
    displacement_index: usize,
    target: usize,
) -> Result<(), PieRuntimeError> {
    let next = displacement_index
        .checked_add(1)
        .ok_or(PieRuntimeError::TrampolineBranchOutOfRange)?;
    let displacement = target as isize - next as isize;
    let displacement =
        i8::try_from(displacement).map_err(|_| PieRuntimeError::TrampolineBranchOutOfRange)?;
    bytes[displacement_index] = displacement as u8;
    Ok(())
}

fn runtime_section(
    section_index: u16,
    flags: u64,
    address: u64,
    alignment: u64,
    bytes: Vec<u8>,
) -> Result<RelocatedSectionImage, PieRuntimeError> {
    let size = u64::try_from(bytes.len()).map_err(|_| PieRuntimeError::RuntimeSectionTooLarge)?;
    Ok(RelocatedSectionImage {
        object_index: PIE_RUNTIME_OBJECT_INDEX,
        section_index,
        section_type: SHT_PROGBITS,
        flags,
        address,
        size,
        alignment,
        bytes,
    })
}

fn align_up(value: u64, alignment: u64) -> Result<u64, PieRuntimeError> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(PieRuntimeError::RuntimeAddressOverflow)
}
