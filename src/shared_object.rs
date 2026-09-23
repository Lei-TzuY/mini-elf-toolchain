use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::executable_writer::{
    write_elf64_x86_64_shared_segments, ExecutableImage, ExecutableWriteError, LoadSegmentInput,
};
use crate::layout::LaidOutSection;
use crate::link_symbols::{resolve_validated_objects_with_common, LinkSymbolError};
use crate::linker_input::LinkerInputObject;
use crate::load_segments::{
    build_load_segments, LoadSegmentBuildError, LoadableSectionInput, SHF_ALLOC, SHF_EXECINSTR,
    SHF_WRITE,
};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::permission_layout::SHF_TLS;
use crate::pie_runtime::{build_relative_relocation_table, PieRuntimeError};
use crate::program_headers::{
    map_runtime_program_headers_with_dynamic, RuntimeDynamicProgramHeader,
};
use crate::relocated_sections::{
    relocate_allocatable_sections_with_external_got_and_plt, RelocatedSectionError,
    RelocatedSectionImage,
};
use crate::resolve::{SymbolDefinition, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};
use crate::x86_64_relocations::{
    R_X86_64_64, R_X86_64_GLOB_DAT, R_X86_64_GOTPCREL, R_X86_64_JUMP_SLOT, R_X86_64_PLT32,
};

const SHT_PROGBITS: u32 = 1;
const SHARED_METADATA_OBJECT_INDEX: usize = usize::MAX - 3;
const SHARED_METADATA_SECTION_INDEX: u16 = 1;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_DYNAMIC_SIZE: usize = 16;
const ELF64_RELA_SIZE: usize = 24;
const R_X86_64_NONE: u32 = 0;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const GLOBAL_OFFSET_TABLE_SYMBOL: &[u8] = b"_GLOBAL_OFFSET_TABLE_";

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const DT_RELA: i64 = 7;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_RUNPATH: i64 = 29;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_RELACOUNT: i64 = 0x6fff_fff9;

#[derive(Debug)]
pub enum SharedObjectError {
    RelocationUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_count: usize,
    },
    PreemptibleRelativeTarget {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        binding: u8,
    },
    ExternalImportUnsupportedBinding {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        binding: u8,
    },
    ExternalImportUnsupportedType {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        symbol_type: u8,
    },
    ExternalImportTargetNotWritable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    ExternalImportRelocationOutOfBounds {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        offset: u64,
        target_size: u64,
    },
    MissingImportRelocationTarget {
        object_index: usize,
        target_section_index: u16,
    },
    MissingImportDynamicSymbol {
        name: Vec<u8>,
    },
    MissingImportGotEntry {
        name: Vec<u8>,
    },
    MissingImportPltGotEntry {
        name: Vec<u8>,
    },
    ExternalPltUnsupportedType {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        symbol_type: u8,
    },
    ExternalPltTargetNotExecutable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    TlsUnsupported {
        object_index: usize,
        section_index: u16,
    },
    EmptyNeededName {
        dependency_index: usize,
    },
    NeededNameContainsNul {
        dependency_index: usize,
    },
    EmptySoname,
    SonameContainsNul,
    EmptyRunpath,
    RunpathContainsNul,
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
    RuntimeRelative(PieRuntimeError),
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
                "shared object bounded relocation set rejects RELA section {rela_section_index} in object {object_index} with {relocation_count} relocations"
            ),
            Self::PreemptibleRelativeTarget {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
                binding,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references default-visible nonlocal symbol {symbol_index} ({:?}) with binding {binding}; bounded shared relocation handling requires a local non-preemptible target or an undefined external data import because general interposition is not implemented",
                String::from_utf8_lossy(name)
            ),
            Self::ExternalImportUnsupportedBinding {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
                binding,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references undefined symbol {symbol_index} ({:?}) with binding {binding}; bounded external data imports require a strong global symbol",
                String::from_utf8_lossy(name)
            ),
            Self::ExternalImportUnsupportedType {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
                symbol_type,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references undefined symbol {symbol_index} ({:?}) with ELF symbol type {symbol_type}; bounded external imports require STT_OBJECT or STT_FUNC",
                String::from_utf8_lossy(name)
            ),
            Self::ExternalImportTargetNotWritable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded external imports require an allocated writable relocation target"
            ),
            Self::ExternalImportRelocationOutOfBounds {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                offset,
                target_size,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} writes 8 bytes at offset {offset} beyond target section {target_section_index} size {target_size}"
            ),
            Self::MissingImportRelocationTarget {
                object_index,
                target_section_index,
            } => write!(
                f,
                "shared object external import target object {object_index} section {target_section_index} has no relocated output section"
            ),
            Self::MissingImportDynamicSymbol { name } => write!(
                f,
                "shared object external import {:?} has no dynamic symbol index",
                String::from_utf8_lossy(name)
            ),
            Self::MissingImportGotEntry { name } => write!(
                f,
                "shared object external GOT import {:?} has no synthetic GOT slot",
                String::from_utf8_lossy(name)
            ),
            Self::MissingImportPltGotEntry { name } => write!(
                f,
                "shared object external PLT import {:?} has no synthetic PLT-GOT slot",
                String::from_utf8_lossy(name)
            ),
            Self::ExternalPltUnsupportedType {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
                symbol_type,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references PLT symbol {symbol_index} ({:?}) with ELF symbol type {symbol_type}; bounded PLT imports require STT_FUNC",
                String::from_utf8_lossy(name)
            ),
            Self::ExternalPltTargetNotExecutable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded PLT32 imports require an allocated executable call site"
            ),
            Self::TlsUnsupported {
                object_index,
                section_index,
            } => write!(
                f,
                "shared object first slice rejects TLS section {section_index} in object {object_index}; shared-object TLS is not implemented"
            ),
            Self::EmptyNeededName { dependency_index } => write!(
                f,
                "shared object DT_NEEDED dependency {dependency_index} has an empty name"
            ),
            Self::NeededNameContainsNul { dependency_index } => write!(
                f,
                "shared object DT_NEEDED dependency {dependency_index} contains an embedded NUL byte"
            ),
            Self::EmptySoname => write!(f, "shared object DT_SONAME cannot be empty"),
            Self::SonameContainsNul => {
                write!(f, "shared object DT_SONAME cannot contain an embedded NUL byte")
            }
            Self::EmptyRunpath => write!(f, "shared object DT_RUNPATH cannot be empty"),
            Self::RunpathContainsNul => {
                write!(f, "shared object DT_RUNPATH cannot contain an embedded NUL byte")
            }
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
                "shared object symbol {symbol_index} in object {object_index} ({:?}) is undefined and is outside the bounded external import surface",
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
            Self::RuntimeRelative(source) => {
                write!(f, "cannot build shared-object relative runtime relocations: {source}")
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
            Self::RuntimeRelative(source) => Some(source),
            Self::SymbolAddress(source) => Some(source),
            Self::LoadSegments(source) => Some(source),
            Self::Write(source) => Some(source),
            Self::RelocationUnsupported { .. }
            | Self::PreemptibleRelativeTarget { .. }
            | Self::ExternalImportUnsupportedBinding { .. }
            | Self::ExternalImportUnsupportedType { .. }
            | Self::ExternalImportTargetNotWritable { .. }
            | Self::ExternalImportRelocationOutOfBounds { .. }
            | Self::MissingImportRelocationTarget { .. }
            | Self::MissingImportDynamicSymbol { .. }
            | Self::MissingImportGotEntry { .. }
            | Self::MissingImportPltGotEntry { .. }
            | Self::ExternalPltUnsupportedType { .. }
            | Self::ExternalPltTargetNotExecutable { .. }
            | Self::TlsUnsupported { .. }
            | Self::EmptyNeededName { .. }
            | Self::NeededNameContainsNul { .. }
            | Self::EmptySoname
            | Self::SonameContainsNul
            | Self::EmptyRunpath
            | Self::RunpathContainsNul
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

#[derive(Debug, Clone)]
struct ImportSymbol {
    name: Vec<u8>,
    info: u8,
    size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ImportRelocationSite {
    object_index: usize,
    rela_section_index: u16,
    relocation_index: usize,
}

#[derive(Debug)]
struct ImportPlan {
    symbols: BTreeMap<Vec<u8>, ImportSymbol>,
    sites: BTreeSet<ImportRelocationSite>,
    got_symbols: BTreeSet<Vec<u8>>,
    plt_symbols: BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
struct DynamicNames<'a> {
    needed: &'a [Vec<u8>],
    soname: Option<&'a [u8]>,
    runpath: Option<&'a [u8]>,
}

#[derive(Debug)]
struct DynamicMetadata {
    bytes: Vec<u8>,
    dynamic_offset: u64,
    dynamic_size: u64,
}

pub fn shared_import_requirements(
    inputs: &[LinkerInputObject<'_>],
) -> Result<BTreeMap<Vec<u8>, u8>, SharedObjectError> {
    let validated = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let resolved =
        resolve_validated_objects_with_common(&validated).map_err(SharedObjectError::Symbols)?;
    let plan = validate_inputs(inputs, &resolved.definitions)?;
    Ok(plan
        .symbols
        .into_iter()
        .map(|(name, symbol)| (name, symbol.info & 0x0f))
        .collect())
}

pub fn link_shared_object(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
) -> Result<ExecutableImage, SharedObjectError> {
    link_shared_object_with_needed_and_soname(inputs, page_alignment, &[], None)
}

pub fn link_shared_object_with_needed(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    needed: &[Vec<u8>],
) -> Result<ExecutableImage, SharedObjectError> {
    link_shared_object_with_needed_and_soname(inputs, page_alignment, needed, None)
}

pub fn link_shared_object_with_needed_and_soname(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    needed: &[Vec<u8>],
    soname: Option<&[u8]>,
) -> Result<ExecutableImage, SharedObjectError> {
    link_shared_object_with_needed_soname_and_runpath(inputs, page_alignment, needed, soname, None)
}

pub fn link_shared_object_with_needed_soname_and_runpath(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    needed: &[Vec<u8>],
    soname: Option<&[u8]>,
    runpath: Option<&[u8]>,
) -> Result<ExecutableImage, SharedObjectError> {
    validate_needed_names(needed)?;
    validate_soname(soname)?;
    validate_runpath(runpath)?;

    let validated = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let resolved =
        resolve_validated_objects_with_common(&validated).map_err(SharedObjectError::Symbols)?;
    let imports = validate_inputs(inputs, &resolved.definitions)?;
    let relocation_inputs = mask_import_relocations(inputs, &imports.sites);

    let relocated_output = relocate_allocatable_sections_with_external_got_and_plt(
        &relocation_inputs,
        page_alignment,
        page_alignment,
        &imports.got_symbols,
        &imports.plt_symbols,
    )
    .map_err(SharedObjectError::Relocation)?;
    let relocated = relocated_output.sections;
    let got_entries = relocated_output.got_entries;
    let plt_got_entries = relocated_output.plt_got_entries;
    let plt_got_base = relocated_output.plt_got_base;
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

    let import_dynamic_indices = import_dynamic_symbol_indices(exports.len(), &imports.symbols)?;
    let (mut rela_bytes, relative_relocation_count) = build_relative_relocation_table(
        &relocation_inputs,
        &relocated,
        &resolved.definitions,
        &BTreeMap::new(),
    )
    .map_err(SharedObjectError::RuntimeRelative)?;
    let import_rela_bytes =
        build_import_relocation_table(inputs, &relocated, &imports.sites, &import_dynamic_indices)?;
    rela_bytes.extend_from_slice(&import_rela_bytes);
    let got_import_rela_bytes = build_got_import_relocation_table(
        &imports.got_symbols,
        &got_entries,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&got_import_rela_bytes);
    let jmprel_bytes = build_plt_import_relocation_table(
        &imports.plt_symbols,
        &plt_got_entries,
        &import_dynamic_indices,
    )?;

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
    let metadata = build_dynamic_metadata(
        metadata_address,
        &exports,
        &imports.symbols,
        DynamicNames {
            needed,
            soname,
            runpath,
        },
        &rela_bytes,
        relative_relocation_count,
        &jmprel_bytes,
        plt_got_base,
    )?;
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

fn validate_needed_names(needed: &[Vec<u8>]) -> Result<(), SharedObjectError> {
    for (dependency_index, name) in needed.iter().enumerate() {
        if name.is_empty() {
            return Err(SharedObjectError::EmptyNeededName { dependency_index });
        }
        if name.contains(&0) {
            return Err(SharedObjectError::NeededNameContainsNul { dependency_index });
        }
    }
    Ok(())
}

fn validate_soname(soname: Option<&[u8]>) -> Result<(), SharedObjectError> {
    if let Some(name) = soname {
        if name.is_empty() {
            return Err(SharedObjectError::EmptySoname);
        }
        if name.contains(&0) {
            return Err(SharedObjectError::SonameContainsNul);
        }
    }
    Ok(())
}

fn validate_runpath(runpath: Option<&[u8]>) -> Result<(), SharedObjectError> {
    if let Some(path) = runpath {
        if path.is_empty() {
            return Err(SharedObjectError::EmptyRunpath);
        }
        if path.contains(&0) {
            return Err(SharedObjectError::RunpathContainsNul);
        }
    }
    Ok(())
}

fn validate_inputs(
    inputs: &[LinkerInputObject<'_>],
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
) -> Result<ImportPlan, SharedObjectError> {
    let mut import_symbols = BTreeMap::<Vec<u8>, ImportSymbol>::new();
    let mut import_sites = BTreeSet::<ImportRelocationSite>::new();
    let mut got_symbols = BTreeSet::<Vec<u8>>::new();
    let mut plt_symbols = BTreeSet::<Vec<u8>>::new();

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
            if table.relocations.iter().any(|relocation| {
                !matches!(
                    relocation.relocation_type,
                    R_X86_64_64 | R_X86_64_GOTPCREL | R_X86_64_PLT32
                )
            }) {
                return Err(SharedObjectError::RelocationUnsupported {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_count: table.relocations.len(),
                });
            }

            let target = &input.object.sections[usize::from(table.target_section_index)];
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
            .map_err(|source| SharedObjectError::ObjectSymbols {
                object_index: input.object_index,
                source,
            })?;

            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                let symbol = &symbols[relocation.symbol_index as usize];
                let binding = symbol.symbol.info >> 4;
                let is_got_import = relocation.relocation_type == R_X86_64_GOTPCREL;
                let is_plt_import = relocation.relocation_type == R_X86_64_PLT32;

                if binding == STB_LOCAL {
                    if is_got_import {
                        return Err(SharedObjectError::RelocationUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_count: table.relocations.len(),
                        });
                    }
                    continue;
                }

                if symbol.symbol.section_index != SHN_UNDEF || definitions.contains_key(symbol.name)
                {
                    return Err(SharedObjectError::PreemptibleRelativeTarget {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
                        binding,
                    });
                }

                if binding != STB_GLOBAL {
                    return Err(SharedObjectError::ExternalImportUnsupportedBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
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

                let symbol_type = symbol.symbol.info & 0x0f;
                if is_plt_import && symbol_type != STT_FUNC {
                    return Err(SharedObjectError::ExternalPltUnsupportedType {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
                        symbol_type,
                    });
                }
                if !is_plt_import && !matches!(symbol_type, STT_OBJECT | STT_FUNC) {
                    return Err(SharedObjectError::ExternalImportUnsupportedType {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
                        symbol_type,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(SharedObjectError::UndefinedNonlocal {
                        object_index: input.object_index,
                        symbol_index: symbol.symbol_index,
                        name: Vec::new(),
                    });
                }

                import_symbols
                    .entry(symbol.name.to_vec())
                    .or_insert_with(|| ImportSymbol {
                        name: symbol.name.to_vec(),
                        info: symbol.symbol.info,
                        size: symbol.symbol.size,
                    });

                if is_got_import {
                    got_symbols.insert(symbol.name.to_vec());
                    continue;
                }
                if is_plt_import {
                    if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                        return Err(SharedObjectError::ExternalPltTargetNotExecutable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        });
                    }
                    plt_symbols.insert(symbol.name.to_vec());
                    continue;
                }

                if target.flags & SHF_ALLOC == 0 || target.flags & SHF_WRITE == 0 {
                    return Err(SharedObjectError::ExternalImportTargetNotWritable {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        target_section_index: table.target_section_index,
                        flags: target.flags,
                    });
                }
                import_sites.insert(ImportRelocationSite {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_index,
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
                    let symbol_type = symbol.symbol.info & 0x0f;
                    let linker_owned_got_symbol = !got_symbols.is_empty()
                        && symbol.name == GLOBAL_OFFSET_TABLE_SYMBOL
                        && binding == STB_GLOBAL
                        && symbol_type == STT_NOTYPE;
                    if linker_owned_got_symbol {
                        continue;
                    }
                    let supported_import = import_symbols.contains_key(symbol.name)
                        && binding == STB_GLOBAL
                        && matches!(symbol_type, STT_OBJECT | STT_FUNC);
                    if !supported_import {
                        return Err(SharedObjectError::UndefinedNonlocal {
                            object_index: input.object_index,
                            symbol_index: symbol.symbol_index,
                            name: symbol.name.to_vec(),
                        });
                    }
                }
            }
        }
    }

    Ok(ImportPlan {
        symbols: import_symbols,
        sites: import_sites,
        got_symbols,
        plt_symbols,
    })
}

fn mask_import_relocations<'a>(
    inputs: &[LinkerInputObject<'a>],
    sites: &BTreeSet<ImportRelocationSite>,
) -> Vec<LinkerInputObject<'a>> {
    inputs
        .iter()
        .map(|input| {
            let mut object = input.object.clone();
            for table in &mut object.rela_tables {
                for (relocation_index, relocation) in table.relocations.iter_mut().enumerate() {
                    if sites.contains(&ImportRelocationSite {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                    }) {
                        relocation.relocation_type = R_X86_64_NONE;
                    }
                }
            }
            LinkerInputObject {
                object_index: input.object_index,
                file: input.file,
                object,
            }
        })
        .collect()
}

fn import_dynamic_symbol_indices(
    export_count: usize,
    imports: &BTreeMap<Vec<u8>, ImportSymbol>,
) -> Result<BTreeMap<Vec<u8>, u32>, SharedObjectError> {
    let first_import_index = export_count
        .checked_add(1)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    imports
        .keys()
        .enumerate()
        .map(|(offset, name)| {
            let index = first_import_index
                .checked_add(offset)
                .ok_or(SharedObjectError::MetadataTooLarge)?;
            let index = u32::try_from(index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
            Ok((name.clone(), index))
        })
        .collect()
}

fn build_import_relocation_table(
    inputs: &[LinkerInputObject<'_>],
    sections: &[RelocatedSectionImage],
    sites: &BTreeSet<ImportRelocationSite>,
    dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let mut bytes = Vec::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .enumerate()
                .any(|(relocation_index, _)| {
                    sites.contains(&ImportRelocationSite {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                    })
                })
            {
                continue;
            }

            let target = sections
                .iter()
                .find(|section| {
                    section.object_index == input.object_index
                        && section.section_index == table.target_section_index
                })
                .ok_or(SharedObjectError::MissingImportRelocationTarget {
                    object_index: input.object_index,
                    target_section_index: table.target_section_index,
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
            .map_err(|source| SharedObjectError::ObjectSymbols {
                object_index: input.object_index,
                source,
            })?;

            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                let site = ImportRelocationSite {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_index,
                };
                if !sites.contains(&site) {
                    continue;
                }

                let end = relocation.offset.checked_add(8).ok_or(
                    SharedObjectError::ExternalImportRelocationOutOfBounds {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        target_section_index: table.target_section_index,
                        offset: relocation.offset,
                        target_size: target.size,
                    },
                )?;
                if end > target.size {
                    return Err(SharedObjectError::ExternalImportRelocationOutOfBounds {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        target_section_index: table.target_section_index,
                        offset: relocation.offset,
                        target_size: target.size,
                    });
                }

                let symbol = &symbols[relocation.symbol_index as usize];
                let dynamic_index = dynamic_indices.get(symbol.name).copied().ok_or_else(|| {
                    SharedObjectError::MissingImportDynamicSymbol {
                        name: symbol.name.to_vec(),
                    }
                })?;
                let offset = target
                    .address
                    .checked_add(relocation.offset)
                    .ok_or(SharedObjectError::AddressOverflow)?;
                let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_64);
                bytes.extend_from_slice(&offset.to_le_bytes());
                bytes.extend_from_slice(&info.to_le_bytes());
                bytes.extend_from_slice(&relocation.addend.to_le_bytes());
            }
        }
    }

    Ok(bytes)
}

fn build_got_import_relocation_table(
    got_symbols: &BTreeSet<Vec<u8>>,
    got_entries: &BTreeMap<Vec<u8>, u64>,
    dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let capacity = got_symbols
        .len()
        .checked_mul(ELF64_RELA_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);

    for name in got_symbols {
        let offset = got_entries
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingImportGotEntry { name: name.clone() })?;
        let dynamic_index = dynamic_indices
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingImportDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_GLOB_DAT);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
}

fn build_plt_import_relocation_table(
    plt_symbols: &BTreeSet<Vec<u8>>,
    plt_got_entries: &BTreeMap<Vec<u8>, u64>,
    dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let capacity = plt_symbols
        .len()
        .checked_mul(ELF64_RELA_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);

    for name in plt_symbols {
        let offset = plt_got_entries
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingImportPltGotEntry { name: name.clone() })?;
        let dynamic_index = dynamic_indices
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingImportDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_JUMP_SLOT);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
}

fn build_dynamic_metadata(
    base_address: u64,
    exports: &[ExportSymbol],
    imports: &BTreeMap<Vec<u8>, ImportSymbol>,
    names: DynamicNames<'_>,
    rela_bytes: &[u8],
    relative_relocation_count: usize,
    jmprel_bytes: &[u8],
    plt_got_address: Option<u64>,
) -> Result<DynamicMetadata, SharedObjectError> {
    let symbol_count = exports
        .len()
        .checked_add(imports.len())
        .and_then(|count| count.checked_add(1))
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
    let mut export_name_offsets = Vec::with_capacity(exports.len());
    for export in exports {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        export_name_offsets.push(offset);
        dynstr.extend_from_slice(&export.name);
        dynstr.push(0);
    }
    let mut import_name_offsets = Vec::with_capacity(imports.len());
    for import in imports.values() {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        import_name_offsets.push(offset);
        dynstr.extend_from_slice(&import.name);
        dynstr.push(0);
    }
    let mut needed_name_offsets = Vec::with_capacity(names.needed.len());
    for name in names.needed {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        needed_name_offsets.push(offset);
        dynstr.extend_from_slice(name);
        dynstr.push(0);
    }
    let soname_offset = if let Some(name) = names.soname {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        dynstr.extend_from_slice(name);
        dynstr.push(0);
        Some(offset)
    } else {
        None
    };
    let runpath_offset = if let Some(path) = names.runpath {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        dynstr.extend_from_slice(path);
        dynstr.push(0);
        Some(offset)
    } else {
        None
    };

    let dynstr_offset = dynsym_offset
        .checked_add(dynsym_size)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let rela_offset = align_up_usize(
        dynstr_offset
            .checked_add(dynstr.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let jmprel_offset = align_up_usize(
        rela_offset
            .checked_add(rela_bytes.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let dynamic_offset = align_up_usize(
        jmprel_offset
            .checked_add(jmprel_bytes.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;

    let has_relocations = !rela_bytes.is_empty();
    let has_plt_relocations = !jmprel_bytes.is_empty();
    debug_assert_eq!(has_plt_relocations, plt_got_address.is_some());
    let dynamic_entry_count = 5usize
        .checked_add(names.needed.len())
        .and_then(|count| count.checked_add(usize::from(soname_offset.is_some())))
        .and_then(|count| count.checked_add(usize::from(runpath_offset.is_some())))
        .and_then(|count| count.checked_add(if has_relocations { 3 } else { 0 }))
        .and_then(|count| count.checked_add(usize::from(relative_relocation_count != 0)))
        .and_then(|count| count.checked_add(if has_plt_relocations { 4 } else { 0 }))
        .and_then(|count| count.checked_add(1))
        .ok_or(SharedObjectError::MetadataTooLarge)?;
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
        put_u32(&mut bytes, offset, export_name_offsets[index]);
        bytes[offset + 4] = export.info;
        bytes[offset + 5] = 0;
        put_u16(&mut bytes, offset + 6, export.section_index);
        put_u64(&mut bytes, offset + 8, export.value);
        put_u64(&mut bytes, offset + 16, export.size);
    }
    for (index, import) in imports.values().enumerate() {
        let symbol_index = 1 + exports.len() + index;
        let offset = dynsym_offset + symbol_index * ELF64_SYMBOL_SIZE;
        put_u32(&mut bytes, offset, import_name_offsets[index]);
        bytes[offset + 4] = import.info;
        bytes[offset + 5] = 0;
        put_u16(&mut bytes, offset + 6, SHN_UNDEF);
        put_u64(&mut bytes, offset + 8, 0);
        put_u64(&mut bytes, offset + 16, import.size);
    }
    bytes[dynstr_offset..dynstr_offset + dynstr.len()].copy_from_slice(&dynstr);
    bytes[rela_offset..rela_offset + rela_bytes.len()].copy_from_slice(rela_bytes);
    bytes[jmprel_offset..jmprel_offset + jmprel_bytes.len()].copy_from_slice(jmprel_bytes);

    let hash_address = checked_metadata_address(base_address, hash_offset)?;
    let dynsym_address = checked_metadata_address(base_address, dynsym_offset)?;
    let dynstr_address = checked_metadata_address(base_address, dynstr_offset)?;
    let mut entries = Vec::with_capacity(dynamic_entry_count);
    for offset in needed_name_offsets {
        entries.push((DT_NEEDED, u64::from(offset)));
    }
    if let Some(offset) = soname_offset {
        entries.push((DT_SONAME, u64::from(offset)));
    }
    if let Some(offset) = runpath_offset {
        entries.push((DT_RUNPATH, u64::from(offset)));
    }
    entries.extend_from_slice(&[
        (DT_HASH, hash_address),
        (DT_STRTAB, dynstr_address),
        (DT_SYMTAB, dynsym_address),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_SYMENT, ELF64_SYMBOL_SIZE as u64),
    ]);
    if has_relocations {
        let rela_address = checked_metadata_address(base_address, rela_offset)?;
        let rela_size =
            u64::try_from(rela_bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        debug_assert_eq!(rela_bytes.len() % ELF64_RELA_SIZE, 0);
        debug_assert!(relative_relocation_count <= rela_bytes.len() / ELF64_RELA_SIZE);
        entries.extend_from_slice(&[
            (DT_RELA, rela_address),
            (DT_RELASZ, rela_size),
            (DT_RELAENT, ELF64_RELA_SIZE as u64),
        ]);
        if relative_relocation_count != 0 {
            let rela_count = u64::try_from(relative_relocation_count)
                .map_err(|_| SharedObjectError::MetadataTooLarge)?;
            entries.push((DT_RELACOUNT, rela_count));
        }
    }
    if has_plt_relocations {
        let jmprel_address = checked_metadata_address(base_address, jmprel_offset)?;
        let jmprel_size =
            u64::try_from(jmprel_bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        debug_assert_eq!(jmprel_bytes.len() % ELF64_RELA_SIZE, 0);
        let plt_got_address =
            plt_got_address.ok_or(SharedObjectError::MetadataTooLarge)?;
        entries.extend_from_slice(&[
            (DT_PLTGOT, plt_got_address),
            (DT_JMPREL, jmprel_address),
            (DT_PLTRELSZ, jmprel_size),
            (DT_PLTREL, DT_RELA as u64),
        ]);
    }
    entries.push((DT_NULL, 0));

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
