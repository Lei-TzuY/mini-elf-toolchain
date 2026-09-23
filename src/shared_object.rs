use core::fmt;

use crate::executable_writer::{
    write_elf64_x86_64_shared_segments, ExecutableImage, ExecutableWriteError, LoadSegmentInput,
};
use crate::layout::LaidOutSection;
use crate::link_symbols::{resolve_validated_objects_with_common, LinkSymbolError};
use crate::linker_input::LinkerInputObject;
use crate::load_segments::{
    build_load_segments, LoadSegmentBuildError, LoadableSectionInput, SHF_ALLOC, SHF_WRITE,
};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::permission_layout::SHF_TLS;
use crate::program_headers::{
    map_runtime_program_headers_with_dynamic, RuntimeDynamicProgramHeader,
};
use crate::relocated_sections::{
    relocate_allocatable_sections, RelocatedSectionError, RelocatedSectionImage,
};
use crate::resolve::{SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};

const SHT_PROGBITS: u32 = 1;
const SHARED_METADATA_OBJECT_INDEX: usize = usize::MAX - 3;
const SHARED_METADATA_SECTION_INDEX: u16 = 1;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_DYNAMIC_SIZE: usize = 16;

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;

#[derive(Debug)]
pub enum SharedObjectError {
    RelocationUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_count: usize,
    },
    TlsUnsupported {
        object_index: usize,
        section_index: u16,
    },
    Symbols(LinkSymbolError),
    ObjectSymbols {
        object_index: usize,
        source: ObjectSymbolError,
    },
    UnsupportedBinding {
        object_index: usize,
        symbol_index: usize,
        binding: u8,
    },
    UndefinedNonlocal {
        object_index: usize,
        symbol_index: usize,
        name: Vec<u8>,
    },
    NondefaultVisibility {
        object_index: usize,
        symbol_index: usize,
        name: Vec<u8>,
        other: u8,
    },
    NoExports,
    Relocation(RelocatedSectionError),
    SymbolAddress(FinalSymbolAddressError),
    AddressOverflow,
    MetadataTooLarge,
    LoadSegments(LoadSegmentBuildError),
    Write(ExecutableWriteError),
}

impl fmt::Display for SharedObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelocationUnsupported {
                object_index,
                rela_section_index,
                relocation_count,
            } => write!(
                f,
                "shared object first slice rejects RELA section {rela_section_index} in object {object_index} with {relocation_count} relocations; runtime/shared-object relocation is not implemented"
            ),
            Self::TlsUnsupported {
                object_index,
                section_index,
            } => write!(
                f,
                "shared object first slice rejects TLS section {section_index} in object {object_index}; shared-object TLS is not implemented"
            ),
            Self::Symbols(source) => write!(f, "cannot resolve shared object symbols: {source}"),
            Self::ObjectSymbols {
                object_index,
                source,
            } => write!(
                f,
                "cannot inspect shared object symbols from object {object_index}: {source}"
            ),
            Self::UnsupportedBinding {
                object_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "shared object symbol {symbol_index} in object {object_index} uses unsupported binding {binding}"
            ),
            Self::UndefinedNonlocal {
                object_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object symbol {symbol_index} in object {object_index} ({:?}) is undefined; external dynamic binding is not implemented",
                String::from_utf8_lossy(name)
            ),
            Self::NondefaultVisibility {
                object_index,
                symbol_index,
                name,
                other,
            } => write!(
                f,
                "shared object symbol {symbol_index} in object {object_index} ({:?}) has unsupported st_other/visibility value {other:#x}",
                String::from_utf8_lossy(name)
            ),
            Self::NoExports => write!(
                f,
                "shared object first slice requires at least one defined default-visible global/weak export"
            ),
            Self::Relocation(source) => {
                write!(f, "cannot lay out shared object sections: {source}")
            }
            Self::SymbolAddress(source) => {
                write!(f, "cannot resolve shared object export address: {source}")
            }
            Self::AddressOverflow => write!(f, "shared object address arithmetic overflow"),
            Self::MetadataTooLarge => write!(f, "shared object dynamic metadata exceeds ELF32 table fields"),
            Self::LoadSegments(source) => {
                write!(f, "cannot build shared object load segments: {source}")
            }
            Self::Write(source) => write!(f, "cannot emit shared object: {source}"),
        }
    }
}

impl std::error::Error for SharedObjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Symbols(source) => Some(source),
            Self::ObjectSymbols { source, .. } => Some(source),
            Self::Relocation(source) => Some(source),
            Self::SymbolAddress(source) => Some(source),
            Self::LoadSegments(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::RelocationUnsupported { .. }
            | Self::TlsUnsupported { .. }
            | Self::UnsupportedBinding { .. }
            | Self::UndefinedNonlocal { .. }
            | Self::NondefaultVisibility { .. }
            | Self::NoExports
            | Self::AddressOverflow
            | Self::MetadataTooLarge => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ExportSymbol {
    name: Vec<u8>,
    info: u8,
    section_index: u16,
    value: u64,
    size: u64,
}

#[derive(Debug)]
struct DynamicMetadata {
    bytes: Vec<u8>,
    dynamic_offset: u64,
    dynamic_size: u64,
}

pub fn link_shared_object(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
) -> Result<ExecutableImage, SharedObjectError> {
    validate_inputs(inputs)?;

    let validated = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let resolved =
        resolve_validated_objects_with_common(&validated).map_err(SharedObjectError::Symbols)?;

    let relocated = relocate_allocatable_sections(inputs, page_alignment, page_alignment)
        .map_err(SharedObjectError::Relocation)?;
    let layout = relocated
        .iter()
        .map(|section| LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect::<Vec<_>>();

    let exports = resolved
        .definitions
        .values()
        .map(|definition| {
            let value = final_symbol_address(definition, &layout)
                .map_err(SharedObjectError::SymbolAddress)?;
            Ok(ExportSymbol {
                name: definition.name.clone(),
                info: definition.symbol.info,
                section_index: if definition.symbol.section_index == SHN_ABS {
                    SHN_ABS
                } else {
                    1
                },
                value,
                size: definition.symbol.size,
            })
        })
        .collect::<Result<Vec<_>, SharedObjectError>>()?;
    if exports.is_empty() {
        return Err(SharedObjectError::NoExports);
    }

    let metadata_address = align_up(
        relocated
            .iter()
            .map(|section| {
                section
                    .address
                    .checked_add(section.size)
                    .ok_or(SharedObjectError::AddressOverflow)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0),
        page_alignment,
    )
    .ok_or(SharedObjectError::AddressOverflow)?;
    let metadata = build_dynamic_metadata(metadata_address, &exports)?;
    let dynamic_address = metadata_address
        .checked_add(metadata.dynamic_offset)
        .ok_or(SharedObjectError::AddressOverflow)?;

    let mut sections = relocated;
    sections.push(RelocatedSectionImage {
        object_index: SHARED_METADATA_OBJECT_INDEX,
        section_index: SHARED_METADATA_SECTION_INDEX,
        section_type: SHT_PROGBITS,
        flags: SHF_ALLOC | SHF_WRITE,
        address: metadata_address,
        size: u64::try_from(metadata.bytes.len())
            .map_err(|_| SharedObjectError::MetadataTooLarge)?,
        alignment: 8,
        bytes: metadata.bytes,
    });

    let load_segments = build_load_segments(sections.iter().map(|section| LoadableSectionInput {
        layout: LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        },
        section_type: section.section_type,
        flags: section.flags,
        bytes: &section.bytes,
    }))
    .map_err(SharedObjectError::LoadSegments)?;
    let writer_segments = load_segments
        .iter()
        .map(|segment| LoadSegmentInput {
            image: &segment.image,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        })
        .collect::<Vec<_>>();

    let image = write_elf64_x86_64_shared_segments(&writer_segments, page_alignment)
        .map_err(SharedObjectError::Write)?;
    map_runtime_program_headers_with_dynamic(
        image,
        RuntimeDynamicProgramHeader {
            address: dynamic_address,
            size: metadata.dynamic_size,
        },
    )
    .map_err(SharedObjectError::Write)
}

fn validate_inputs(inputs: &[LinkerInputObject<'_>]) -> Result<(), SharedObjectError> {
    for input in inputs {
        for (section_index, section) in input.object.sections.iter().enumerate() {
            if section.flags & SHF_TLS != 0 {
                return Err(SharedObjectError::TlsUnsupported {
                    object_index: input.object_index,
                    section_index: section_index as u16,
                });
            }
        }
        for table in &input.object.rela_tables {
            if !table.relocations.is_empty() {
                return Err(SharedObjectError::RelocationUnsupported {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_count: table.relocations.len(),
                });
            }
        }

        for table in &input.object.symbol_tables {
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                table,
                input.object_index,
            )
            .map_err(|source| SharedObjectError::ObjectSymbols {
                object_index: input.object_index,
                source,
            })?;
            for symbol in symbols {
                let binding = symbol.symbol.info >> 4;
                if binding == STB_LOCAL {
                    continue;
                }
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(SharedObjectError::UnsupportedBinding {
                        object_index: input.object_index,
                        symbol_index: symbol.symbol_index,
                        binding,
                    });
                }
                if symbol.symbol.other != 0 {
                    return Err(SharedObjectError::NondefaultVisibility {
                        object_index: input.object_index,
                        symbol_index: symbol.symbol_index,
                        name: symbol.name.to_vec(),
                        other: symbol.symbol.other,
                    });
                }
                if symbol.symbol.section_index == SHN_UNDEF && !symbol.name.is_empty() {
                    return Err(SharedObjectError::UndefinedNonlocal {
                        object_index: input.object_index,
                        symbol_index: symbol.symbol_index,
                        name: symbol.name.to_vec(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn build_dynamic_metadata(
    base_address: u64,
    exports: &[ExportSymbol],
) -> Result<DynamicMetadata, SharedObjectError> {
    let symbol_count = exports
        .len()
        .checked_add(1)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let symbol_count_u32 =
        u32::try_from(symbol_count).map_err(|_| SharedObjectError::MetadataTooLarge)?;

    let hash_offset = 0usize;
    let hash_words = 2usize
        .checked_add(1)
        .and_then(|value| value.checked_add(symbol_count))
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let hash_size = hash_words
        .checked_mul(4)
        .ok_or(SharedObjectError::MetadataTooLarge)?;

    let dynsym_offset = align_up_usize(hash_size, 8).ok_or(SharedObjectError::MetadataTooLarge)?;
    let dynsym_size = symbol_count
        .checked_mul(ELF64_SYMBOL_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;

    let mut dynstr = vec![0_u8];
    let mut name_offsets = Vec::with_capacity(exports.len());
    for export in exports {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        name_offsets.push(offset);
        dynstr.extend_from_slice(&export.name);
        dynstr.push(0);
    }
    let dynstr_offset = dynsym_offset
        .checked_add(dynsym_size)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let dynamic_offset = align_up_usize(
        dynstr_offset
            .checked_add(dynstr.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;

    let dynamic_entry_count = 6usize;
    let dynamic_size = dynamic_entry_count
        .checked_mul(ELF64_DYNAMIC_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let total_size = dynamic_offset
        .checked_add(dynamic_size)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = vec![0_u8; total_size];

    put_u32(&mut bytes, hash_offset, 1);
    put_u32(&mut bytes, hash_offset + 4, symbol_count_u32);
    put_u32(&mut bytes, hash_offset + 8, 1);
    for symbol_index in 0..symbol_count {
        let value = if symbol_index == 0 || symbol_index + 1 == symbol_count {
            0
        } else {
            u32::try_from(symbol_index + 1).map_err(|_| SharedObjectError::MetadataTooLarge)?
        };
        put_u32(&mut bytes, hash_offset + 12 + symbol_index * 4, value);
    }

    for (index, export) in exports.iter().enumerate() {
        let offset = dynsym_offset + (index + 1) * ELF64_SYMBOL_SIZE;
        put_u32(&mut bytes, offset, name_offsets[index]);
        bytes[offset + 4] = export.info;
        bytes[offset + 5] = 0;
        put_u16(&mut bytes, offset + 6, export.section_index);
        put_u64(&mut bytes, offset + 8, export.value);
        put_u64(&mut bytes, offset + 16, export.size);
    }
    bytes[dynstr_offset..dynstr_offset + dynstr.len()].copy_from_slice(&dynstr);

    let hash_address = checked_metadata_address(base_address, hash_offset)?;
    let dynsym_address = checked_metadata_address(base_address, dynsym_offset)?;
    let dynstr_address = checked_metadata_address(base_address, dynstr_offset)?;
    let entries = [
        (DT_HASH, hash_address),
        (DT_STRTAB, dynstr_address),
        (DT_SYMTAB, dynsym_address),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_SYMENT, ELF64_SYMBOL_SIZE as u64),
        (DT_NULL, 0),
    ];
    for (index, (tag, value)) in entries.into_iter().enumerate() {
        let offset = dynamic_offset + index * ELF64_DYNAMIC_SIZE;
        put_i64(&mut bytes, offset, tag);
        put_u64(&mut bytes, offset + 8, value);
    }

    Ok(DynamicMetadata {
        bytes,
        dynamic_offset: dynamic_offset as u64,
        dynamic_size: dynamic_size as u64,
    })
}

fn checked_metadata_address(base_address: u64, offset: usize) -> Result<u64, SharedObjectError> {
    base_address
        .checked_add(u64::try_from(offset).map_err(|_| SharedObjectError::MetadataTooLarge)?)
        .ok_or(SharedObjectError::AddressOverflow)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

fn align_up_usize(value: usize, alignment: usize) -> Option<usize> {
    if alignment <= 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
