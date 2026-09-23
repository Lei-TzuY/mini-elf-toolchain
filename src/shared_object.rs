use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::executable_writer::{
    write_elf64_x86_64_shared_segments, ExecutableImage, ExecutableWriteError, LoadSegmentInput,
};
use crate::layout::LaidOutSection;
use crate::link_symbols::{resolve_validated_objects_with_common, LinkSymbolError};
use crate::linker_input::{LinkerInputError, LinkerInputObject};
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
    relocate_allocatable_sections_with_external_got_plt_tls_gd_tls_ld_and_tls_ie,
    RelocatedSectionError, RelocatedSectionImage,
};
use crate::resolve::{SymbolDefinition, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};
use crate::tls::{
    compute_static_tls_layout, inject_static_tls_program_header, StaticTlsLayout,
    StaticTlsLayoutError, StaticTlsProgramHeaderError,
};
use crate::x86_64_relocations::{
    apply_relocation, RelocationApplyError, R_X86_64_64, R_X86_64_DTPMOD64, R_X86_64_DTPOFF32,
    R_X86_64_DTPOFF64, R_X86_64_GLOB_DAT, R_X86_64_GOTPCREL, R_X86_64_GOTTPOFF, R_X86_64_JUMP_SLOT,
    R_X86_64_PLT32, R_X86_64_TLSGD, R_X86_64_TLSLD, R_X86_64_TPOFF64,
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
const STT_TLS: u8 = 6;
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
const DT_FLAGS: i64 = 30;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const DF_STATIC_TLS: u64 = 0x10;

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
    ConflictingImportSymbolType {
        name: Vec<u8>,
        first_type: u8,
        second_type: u8,
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
    MissingTlsGdEntry {
        name: Vec<u8>,
    },
    MissingTlsDynamicSymbol {
        name: Vec<u8>,
    },
    TlsGdTargetNotExecutable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    TlsIeUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    TlsIeTargetNotExecutable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    MissingTlsIeEntry {
        name: Vec<u8>,
    },
    TlsLdUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        binding: u8,
    },
    TlsLdTargetNotExecutable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    IncompleteTlsLdSequence,
    MissingTlsLdEntry,
    MissingTlsLdRelocationTarget {
        object_index: usize,
        target_section_index: u16,
    },
    TlsLdSymbolOutsideImage {
        name: Vec<u8>,
        address: u64,
    },
    TlsLdOffset {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        source: RelocationApplyError,
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
    TlsRelocationUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    TlsImportUnsupported {
        object_index: usize,
        symbol_index: usize,
        name: Vec<u8>,
    },
    TlsSymbolOutsideImage {
        name: Vec<u8>,
        address: u64,
    },
    TlsInput(LinkerInputError),
    TlsLayout(StaticTlsLayoutError),
    TlsProgramHeader(StaticTlsProgramHeaderError),
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
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references undefined symbol {symbol_index} ({:?}) with unsupported binding {binding}; bounded imports accept strong globals plus weak STT_OBJECT symbols on non-call paths, while PLT imports require a strong global symbol",
                String::from_utf8_lossy(name)
            ),
            Self::ConflictingImportSymbolType {
                name,
                first_type,
                second_type,
            } => write!(
                f,
                "shared object import {:?} is referenced with conflicting ELF symbol types {first_type} and {second_type}",
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
            Self::MissingTlsGdEntry { name } => write!(
                f,
                "shared object TLSGD symbol {:?} has no synthetic general-dynamic descriptor",
                String::from_utf8_lossy(name)
            ),
            Self::MissingTlsDynamicSymbol { name } => write!(
                f,
                "shared object TLS symbol {:?} has no usable dynamic-symbol index",
                String::from_utf8_lossy(name)
            ),
            Self::TlsGdTargetNotExecutable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object TLSGD relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded TLSGD access requires an allocated executable instruction site"
            ),
            Self::TlsIeUnsupported {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references TLS symbol {symbol_index} ({:?}); bounded initial-exec TLS requires a default-visible strong STT_TLS symbol that is either defined in the output DSO or recorded as an external import",
                String::from_utf8_lossy(name)
            ),
            Self::TlsIeTargetNotExecutable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object initial-exec TLS relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} targets section {target_section_index} with flags {flags:#x}; GOTTPOFF access requires an allocated executable code target"
            ),
            Self::MissingTlsIeEntry { name } => write!(
                f,
                "shared object initial-exec TLS symbol {:?} has no synthetic TLS GOT entry",
                String::from_utf8_lossy(name)
            ),
            Self::TlsLdUnsupported {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
                binding,
            } => write!(
                f,
                "shared object local-dynamic TLS relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} references symbol {symbol_index} ({:?}) with binding {binding}; bounded TLSLD requires a defined local TLS symbol",
                String::from_utf8_lossy(name)
            ),
            Self::TlsLdTargetNotExecutable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object local-dynamic TLS relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded TLSLD access requires an allocated executable instruction site"
            ),
            Self::IncompleteTlsLdSequence => write!(
                f,
                "shared object local-dynamic TLS requires both TLSLD module-base and DTPOFF32 symbol-offset relocations"
            ),
            Self::MissingTlsLdEntry => write!(
                f,
                "shared object local-dynamic TLS has no synthetic module descriptor"
            ),
            Self::MissingTlsLdRelocationTarget {
                object_index,
                target_section_index,
            } => write!(
                f,
                "shared object local-dynamic TLS target object {object_index} section {target_section_index} has no relocated output section"
            ),
            Self::TlsLdSymbolOutsideImage { name, address } => write!(
                f,
                "shared object local TLS symbol {:?} resolves to {address:#x}, outside the computed PT_TLS image",
                String::from_utf8_lossy(name)
            ),
            Self::TlsLdOffset {
                object_index,
                rela_section_index,
                relocation_index,
                source,
            } => write!(
                f,
                "cannot apply local-dynamic DTPOFF32 relocation {relocation_index} in RELA section {rela_section_index} of object {object_index}: {source}"
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
            Self::TlsRelocationUnsupported {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object bounded TLS slice rejects TLS relocation use in object {object_index} RELA section {rela_section_index} relocation {relocation_index} symbol {symbol_index} ({:?}); only defined-symbol TLSGD access is implemented",
                String::from_utf8_lossy(name)
            ),
            Self::TlsImportUnsupported {
                object_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object symbol {symbol_index} in object {object_index} ({:?}) is an undefined TLS import; this slice supports defined TLS exports only",
                String::from_utf8_lossy(name)
            ),
            Self::TlsSymbolOutsideImage { name, address } => write!(
                f,
                "shared object TLS export {:?} resolves to {address:#x}, outside the computed PT_TLS image",
                String::from_utf8_lossy(name)
            ),
            Self::TlsInput(source) => write!(f, "cannot read shared TLS input sections: {source}"),
            Self::TlsLayout(source) => write!(f, "cannot compute shared TLS layout: {source}"),
            Self::TlsProgramHeader(source) => {
                write!(f, "cannot emit shared PT_TLS program header: {source}")
            },
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
            Self::TlsInput(source) => Some(source),
            Self::TlsLayout(source) => Some(source),
            Self::TlsProgramHeader(source) => Some(source),
            Self::TlsLdOffset { source, .. } => Some(source),
            Self::RelocationUnsupported { .. }
            | Self::PreemptibleRelativeTarget { .. }
            | Self::ExternalImportUnsupportedBinding { .. }
            | Self::ConflictingImportSymbolType { .. }
            | Self::ExternalImportUnsupportedType { .. }
            | Self::ExternalImportTargetNotWritable { .. }
            | Self::ExternalImportRelocationOutOfBounds { .. }
            | Self::MissingImportRelocationTarget { .. }
            | Self::MissingImportDynamicSymbol { .. }
            | Self::MissingImportGotEntry { .. }
            | Self::MissingImportPltGotEntry { .. }
            | Self::MissingTlsGdEntry { .. }
            | Self::MissingTlsDynamicSymbol { .. }
            | Self::TlsGdTargetNotExecutable { .. }
            | Self::TlsIeUnsupported { .. }
            | Self::TlsIeTargetNotExecutable { .. }
            | Self::MissingTlsIeEntry { .. }
            | Self::TlsLdUnsupported { .. }
            | Self::TlsLdTargetNotExecutable { .. }
            | Self::IncompleteTlsLdSequence
            | Self::MissingTlsLdEntry
            | Self::MissingTlsLdRelocationTarget { .. }
            | Self::TlsLdSymbolOutsideImage { .. }
            | Self::ExternalPltUnsupportedType { .. }
            | Self::ExternalPltTargetNotExecutable { .. }
            | Self::TlsRelocationUnsupported { .. }
            | Self::TlsImportUnsupported { .. }
            | Self::TlsSymbolOutsideImage { .. }
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

fn record_import_symbol(
    imports: &mut BTreeMap<Vec<u8>, ImportSymbol>,
    name: &[u8],
    info: u8,
    size: u64,
) -> Result<(), SharedObjectError> {
    let symbol_type = info & 0x0f;
    let binding = info >> 4;

    match imports.get_mut(name) {
        Some(existing) => {
            let existing_type = existing.info & 0x0f;
            if existing_type != symbol_type {
                return Err(SharedObjectError::ConflictingImportSymbolType {
                    name: name.to_vec(),
                    first_type: existing_type,
                    second_type: symbol_type,
                });
            }

            let existing_binding = existing.info >> 4;
            if existing_binding == STB_WEAK && binding == STB_GLOBAL {
                existing.info = info;
            }
            existing.size = existing.size.max(size);
        }
        None => {
            imports.insert(
                name.to_vec(),
                ImportSymbol {
                    name: name.to_vec(),
                    info,
                    size,
                },
            );
        }
    }

    Ok(())
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
    tls_gd_symbols: BTreeSet<Vec<u8>>,
    tls_ie_symbols: BTreeSet<Vec<u8>>,
    tls_ld_dtpoff_sites: BTreeSet<ImportRelocationSite>,
    uses_tls_ld: bool,
}

#[derive(Debug, Clone, Copy)]
struct DynamicNames<'a> {
    needed: &'a [Vec<u8>],
    soname: Option<&'a [u8]>,
    runpath: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
struct DynamicRelocations<'a> {
    rela: &'a [u8],
    relative_count: usize,
    jmprel: &'a [u8],
    plt_got_address: Option<u64>,
    flags: u64,
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
    let tls_ie_import_symbols = imports
        .tls_ie_symbols
        .iter()
        .filter(|name| imports.symbols.contains_key(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut masked_sites = imports.sites.clone();
    masked_sites.extend(imports.tls_ld_dtpoff_sites.iter().copied());
    let relocation_inputs = mask_import_relocations(inputs, &masked_sites);

    let relocated_output =
        relocate_allocatable_sections_with_external_got_plt_tls_gd_tls_ld_and_tls_ie(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            &imports.tls_gd_symbols,
            imports.uses_tls_ld,
            &tls_ie_import_symbols,
        )
        .map_err(SharedObjectError::Relocation)?;
    let mut relocated = relocated_output.sections;
    let got_entries = relocated_output.got_entries;
    let tls_got_entries = relocated_output.tls_got_entries;
    let tls_gd_entries = relocated_output.tls_gd_entries;
    let tls_ld_entry = relocated_output.tls_ld_entry;
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

    let mut input_sections = Vec::new();
    for input in inputs {
        input_sections.extend(
            input
                .allocatable_sections()
                .map_err(SharedObjectError::TlsInput)?,
        );
    }
    let tls_layout = compute_static_tls_layout(&input_sections, &layout)
        .map_err(SharedObjectError::TlsLayout)?;
    apply_tls_ld_dtpoff32_relocations(
        inputs,
        &mut relocated,
        &imports.tls_ld_dtpoff_sites,
        tls_layout,
        &layout,
    )?;

    let exports = resolved
        .definitions
        .values()
        .map(|definition| {
            let absolute_value = final_symbol_address(definition, &layout)
                .map_err(SharedObjectError::SymbolAddress)?;
            let symbol_type = definition.symbol.info & 0x0f;
            let value = if symbol_type == STT_TLS {
                tls_export_value(definition, absolute_value, tls_layout)?
            } else {
                absolute_value
            };
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

    let export_dynamic_indices = export_dynamic_symbol_indices(&exports)?;
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
    let tls_gd_rela_bytes = build_tls_gd_relocation_table(
        &imports.tls_gd_symbols,
        &tls_gd_entries,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&tls_gd_rela_bytes);
    let tls_ld_rela_bytes = build_tls_ld_relocation_table(tls_ld_entry, imports.uses_tls_ld)?;
    rela_bytes.extend_from_slice(&tls_ld_rela_bytes);
    let tls_ie_rela_bytes = build_tls_ie_relocation_table(
        &imports.tls_ie_symbols,
        &tls_got_entries,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&tls_ie_rela_bytes);
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
        DynamicRelocations {
            rela: &rela_bytes,
            relative_count: relative_relocation_count,
            jmprel: &jmprel_bytes,
            plt_got_address: plt_got_base,
            flags: if imports.tls_ie_symbols.is_empty() {
                0
            } else {
                DF_STATIC_TLS
            },
        },
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
    let image = if let Some(tls) = tls_layout {
        inject_static_tls_program_header(image, tls, page_alignment)
            .map_err(SharedObjectError::TlsProgramHeader)?
    } else {
        image
    };
    map_runtime_program_headers_with_dynamic(
        image,
        RuntimeDynamicProgramHeader {
            address: dynamic_address,
            size: metadata.dynamic_size,
        },
    )
    .map_err(SharedObjectError::Write)
}

fn tls_export_value(
    definition: &SymbolDefinition,
    absolute_value: u64,
    tls: Option<StaticTlsLayout>,
) -> Result<u64, SharedObjectError> {
    let tls = tls.ok_or_else(|| SharedObjectError::TlsSymbolOutsideImage {
        name: definition.name.clone(),
        address: absolute_value,
    })?;
    let tls_end = tls
        .base_address
        .checked_add(tls.memory_size)
        .ok_or(SharedObjectError::AddressOverflow)?;
    let symbol_end = absolute_value
        .checked_add(definition.symbol.size)
        .ok_or(SharedObjectError::AddressOverflow)?;
    if absolute_value < tls.base_address || symbol_end > tls_end {
        return Err(SharedObjectError::TlsSymbolOutsideImage {
            name: definition.name.clone(),
            address: absolute_value,
        });
    }
    Ok(absolute_value - tls.base_address)
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
    let mut tls_gd_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_ie_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_ld_dtpoff_sites = BTreeSet::<ImportRelocationSite>::new();
    let mut uses_tls_ld = false;

    for input in inputs {
        for table in &input.object.rela_tables {
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
                let symbol_type = symbol.symbol.info & 0x0f;
                if relocation.relocation_type == R_X86_64_TLSGD {
                    if symbol_type != STT_TLS {
                        return Err(SharedObjectError::TlsImportUnsupported {
                            object_index: input.object_index,
                            symbol_index: symbol.symbol_index,
                            name: symbol.name.to_vec(),
                        });
                    }
                    if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                        return Err(SharedObjectError::TlsGdTargetNotExecutable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        });
                    }

                    let unresolved = symbol.symbol.section_index == SHN_UNDEF
                        && !definitions.contains_key(symbol.name);
                    if unresolved {
                        let binding = symbol.symbol.info >> 4;
                        if binding != STB_GLOBAL {
                            return Err(SharedObjectError::TlsImportUnsupported {
                                object_index: input.object_index,
                                symbol_index: symbol.symbol_index,
                                name: symbol.name.to_vec(),
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
                        if symbol.name.is_empty() {
                            return Err(SharedObjectError::UndefinedNonlocal {
                                object_index: input.object_index,
                                symbol_index: symbol.symbol_index,
                                name: Vec::new(),
                            });
                        }
                        record_import_symbol(
                            &mut import_symbols,
                            symbol.name,
                            symbol.symbol.info,
                            symbol.symbol.size,
                        )?;
                    }

                    tls_gd_symbols.insert(symbol.name.to_vec());
                    continue;
                }
                if relocation.relocation_type == R_X86_64_GOTTPOFF {
                    let binding = symbol.symbol.info >> 4;
                    let unresolved = symbol.symbol.section_index == SHN_UNDEF
                        && !definitions.contains_key(symbol.name);
                    let supported_definition =
                        definitions.get(symbol.name).is_some_and(|definition| {
                            let definition_binding = definition.symbol.info >> 4;
                            let definition_type = definition.symbol.info & 0x0f;
                            definition_binding == STB_GLOBAL
                                && definition_type == STT_TLS
                                && definition.symbol.other == 0
                        });
                    if symbol_type != STT_TLS
                        || binding != STB_GLOBAL
                        || symbol.symbol.other != 0
                        || symbol.name.is_empty()
                        || (!unresolved && !supported_definition)
                    {
                        return Err(SharedObjectError::TlsIeUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            symbol_index: relocation.symbol_index,
                            name: symbol.name.to_vec(),
                        });
                    }
                    if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                        return Err(SharedObjectError::TlsIeTargetNotExecutable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        });
                    }
                    if unresolved {
                        record_import_symbol(
                            &mut import_symbols,
                            symbol.name,
                            symbol.symbol.info,
                            symbol.symbol.size,
                        )?;
                    }
                    tls_ie_symbols.insert(symbol.name.to_vec());
                    continue;
                }
                if relocation.relocation_type == R_X86_64_TLSLD
                    || relocation.relocation_type == R_X86_64_DTPOFF32
                {
                    let binding = symbol.symbol.info >> 4;
                    let defined_local_tls = symbol_type == STT_TLS
                        && binding == STB_LOCAL
                        && symbol.symbol.section_index != SHN_UNDEF;
                    if !defined_local_tls {
                        return Err(SharedObjectError::TlsLdUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            symbol_index: relocation.symbol_index,
                            name: symbol.name.to_vec(),
                            binding,
                        });
                    }
                    if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                        return Err(SharedObjectError::TlsLdTargetNotExecutable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        });
                    }
                    if relocation.relocation_type == R_X86_64_TLSLD {
                        uses_tls_ld = true;
                    } else {
                        tls_ld_dtpoff_sites.insert(ImportRelocationSite {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                        });
                    }
                    continue;
                }
                if target.flags & SHF_TLS != 0 || symbol_type == STT_TLS {
                    return Err(SharedObjectError::TlsRelocationUnsupported {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
                    });
                }
            }

            if table.relocations.iter().any(|relocation| {
                !matches!(
                    relocation.relocation_type,
                    R_X86_64_64
                        | R_X86_64_GOTPCREL
                        | R_X86_64_PLT32
                        | R_X86_64_TLSGD
                        | R_X86_64_GOTTPOFF
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
                )
            }) {
                return Err(SharedObjectError::RelocationUnsupported {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_count: table.relocations.len(),
                });
            }

            for (relocation_index, relocation) in table.relocations.iter().enumerate() {
                let symbol = &symbols[relocation.symbol_index as usize];
                let binding = symbol.symbol.info >> 4;
                let symbol_type = symbol.symbol.info & 0x0f;
                let is_got_import = relocation.relocation_type == R_X86_64_GOTPCREL;
                let is_plt_import = relocation.relocation_type == R_X86_64_PLT32;
                if matches!(
                    relocation.relocation_type,
                    R_X86_64_TLSGD | R_X86_64_GOTTPOFF | R_X86_64_TLSLD | R_X86_64_DTPOFF32
                ) {
                    continue;
                }

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

                let binding_supported = binding == STB_GLOBAL
                    || (binding == STB_WEAK && !is_plt_import && symbol_type == STT_OBJECT);
                if !binding_supported {
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

                let tls_get_addr_notype =
                    is_plt_import && symbol.name == b"__tls_get_addr" && symbol_type == STT_NOTYPE;
                if is_plt_import && symbol_type != STT_FUNC && !tls_get_addr_notype {
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

                record_import_symbol(
                    &mut import_symbols,
                    symbol.name,
                    symbol.symbol.info,
                    symbol.symbol.size,
                )?;

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
                    if symbol_type == STT_TLS {
                        let supported_tls_import = binding == STB_GLOBAL
                            && import_symbols.contains_key(symbol.name)
                            && (tls_gd_symbols.contains(symbol.name)
                                || tls_ie_symbols.contains(symbol.name));
                        if !supported_tls_import {
                            return Err(SharedObjectError::TlsImportUnsupported {
                                object_index: input.object_index,
                                symbol_index: symbol.symbol_index,
                                name: symbol.name.to_vec(),
                            });
                        }
                        continue;
                    }
                    let linker_owned_got_symbol = (!got_symbols.is_empty()
                        || !tls_gd_symbols.is_empty()
                        || !tls_ie_symbols.is_empty()
                        || uses_tls_ld)
                        && symbol.name == GLOBAL_OFFSET_TABLE_SYMBOL
                        && binding == STB_GLOBAL
                        && symbol_type == STT_NOTYPE;
                    if linker_owned_got_symbol {
                        continue;
                    }
                    let tls_get_addr_notype =
                        symbol.name == b"__tls_get_addr" && symbol_type == STT_NOTYPE;
                    let supported_import = import_symbols.contains_key(symbol.name)
                        && (binding == STB_GLOBAL
                            || (binding == STB_WEAK && symbol_type == STT_OBJECT))
                        && (matches!(symbol_type, STT_OBJECT | STT_FUNC) || tls_get_addr_notype);
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

    if uses_tls_ld != !tls_ld_dtpoff_sites.is_empty() {
        return Err(SharedObjectError::IncompleteTlsLdSequence);
    }

    Ok(ImportPlan {
        symbols: import_symbols,
        sites: import_sites,
        got_symbols,
        plt_symbols,
        tls_gd_symbols,
        tls_ie_symbols,
        tls_ld_dtpoff_sites,
        uses_tls_ld,
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

fn export_dynamic_symbol_indices(
    exports: &[ExportSymbol],
) -> Result<BTreeMap<Vec<u8>, u32>, SharedObjectError> {
    exports
        .iter()
        .enumerate()
        .map(|(offset, export)| {
            let index = offset
                .checked_add(1)
                .ok_or(SharedObjectError::MetadataTooLarge)?;
            let index = u32::try_from(index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
            Ok((export.name.clone(), index))
        })
        .collect()
}

fn apply_tls_ld_dtpoff32_relocations(
    inputs: &[LinkerInputObject<'_>],
    sections: &mut [RelocatedSectionImage],
    sites: &BTreeSet<ImportRelocationSite>,
    tls: Option<StaticTlsLayout>,
    layout: &[LaidOutSection],
) -> Result<(), SharedObjectError> {
    if sites.is_empty() {
        return Ok(());
    }
    let tls = tls.ok_or(SharedObjectError::IncompleteTlsLdSequence)?;
    let tls_end = tls
        .base_address
        .checked_add(tls.memory_size)
        .ok_or(SharedObjectError::AddressOverflow)?;

    for site in sites {
        let input = inputs
            .get(site.object_index)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let table = input
            .object
            .rela_tables
            .iter()
            .find(|table| table.section_index == site.rela_section_index)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let relocation = table
            .relocations
            .get(site.relocation_index)
            .ok_or(SharedObjectError::AddressOverflow)?;
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
        let symbol = symbols
            .iter()
            .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let definition = SymbolDefinition {
            name: symbol.name.to_vec(),
            object_index: symbol.object_index,
            table_section_index: symbol.table_section_index,
            symbol_index: symbol.symbol_index,
            symbol: symbol.symbol,
        };
        let absolute_value =
            final_symbol_address(&definition, layout).map_err(SharedObjectError::SymbolAddress)?;
        let symbol_end = absolute_value
            .checked_add(symbol.symbol.size)
            .ok_or(SharedObjectError::AddressOverflow)?;
        if absolute_value < tls.base_address || symbol_end > tls_end {
            return Err(SharedObjectError::TlsLdSymbolOutsideImage {
                name: symbol.name.to_vec(),
                address: absolute_value,
            });
        }
        let module_offset = absolute_value - tls.base_address;
        let target = sections
            .iter_mut()
            .find(|section| {
                section.object_index == input.object_index
                    && section.section_index == table.target_section_index
            })
            .ok_or(SharedObjectError::MissingTlsLdRelocationTarget {
                object_index: input.object_index,
                target_section_index: table.target_section_index,
            })?;
        apply_relocation(&mut target.bytes, relocation, module_offset, 0).map_err(|source| {
            SharedObjectError::TlsLdOffset {
                object_index: input.object_index,
                rela_section_index: table.section_index,
                relocation_index: site.relocation_index,
                source,
            }
        })?;
    }

    Ok(())
}

fn build_tls_ld_relocation_table(
    entry: Option<u64>,
    enabled: bool,
) -> Result<Vec<u8>, SharedObjectError> {
    if !enabled {
        return Ok(Vec::new());
    }
    let descriptor = entry.ok_or(SharedObjectError::MissingTlsLdEntry)?;
    let mut bytes = Vec::with_capacity(ELF64_RELA_SIZE);
    bytes.extend_from_slice(&descriptor.to_le_bytes());
    bytes.extend_from_slice(&u64::from(R_X86_64_DTPMOD64).to_le_bytes());
    bytes.extend_from_slice(&0_i64.to_le_bytes());
    Ok(bytes)
}

fn build_tls_ie_relocation_table(
    symbols: &BTreeSet<Vec<u8>>,
    entries: &BTreeMap<Vec<u8>, u64>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
    import_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let capacity = symbols
        .len()
        .checked_mul(ELF64_RELA_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);

    for name in symbols {
        let offset = entries
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsIeEntry { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .or_else(|| import_dynamic_indices.get(name))
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_TPOFF64);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
}

fn build_tls_gd_relocation_table(
    symbols: &BTreeSet<Vec<u8>>,
    entries: &BTreeMap<Vec<u8>, u64>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
    import_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let capacity = symbols
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_mul(ELF64_RELA_SIZE))
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);

    for name in symbols {
        let descriptor = entries
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsGdEntry { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .or_else(|| import_dynamic_indices.get(name))
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsDynamicSymbol { name: name.clone() })?;

        let dtpmod_info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_DTPMOD64);
        bytes.extend_from_slice(&descriptor.to_le_bytes());
        bytes.extend_from_slice(&dtpmod_info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());

        let dtpoff_target = descriptor
            .checked_add(8)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let dtpoff_info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_DTPOFF64);
        bytes.extend_from_slice(&dtpoff_target.to_le_bytes());
        bytes.extend_from_slice(&dtpoff_info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
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
    relocations: DynamicRelocations<'_>,
) -> Result<DynamicMetadata, SharedObjectError> {
    let rela_bytes = relocations.rela;
    let relative_relocation_count = relocations.relative_count;
    let jmprel_bytes = relocations.jmprel;
    let plt_got_address = relocations.plt_got_address;
    let dynamic_flags = relocations.flags;
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
        .and_then(|count| count.checked_add(usize::from(dynamic_flags != 0)))
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
    if dynamic_flags != 0 {
        entries.push((DT_FLAGS, dynamic_flags));
    }
    if has_plt_relocations {
        let jmprel_address = checked_metadata_address(base_address, jmprel_offset)?;
        let jmprel_size =
            u64::try_from(jmprel_bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        debug_assert_eq!(jmprel_bytes.len() % ELF64_RELA_SIZE, 0);
        let plt_got_address = plt_got_address.ok_or(SharedObjectError::MetadataTooLarge)?;
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
