use core::{cmp::Ordering, fmt};
use std::collections::{BTreeMap, BTreeSet};

use crate::executable_writer::{
    write_elf64_x86_64_position_independent_segments, write_elf64_x86_64_shared_segments,
    ExecutableImage, ExecutableWriteError, LoadSegmentInput,
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
use crate::pie_runtime::{
    build_relative_relocation_table, build_relr_relocation_table, PieRuntimeError,
};
use crate::program_headers::{
    map_runtime_program_headers_with_dynamic,
    map_runtime_program_headers_with_dynamic_and_gnu_property,
    map_runtime_program_headers_with_dynamic_and_interp,
    map_runtime_program_headers_with_dynamic_and_relros,
    map_runtime_program_headers_with_dynamic_interp_and_gnu_property,
    map_runtime_program_headers_with_dynamic_interp_and_relros,
    map_runtime_program_headers_with_dynamic_interp_relros_and_gnu_property,
    map_runtime_program_headers_with_dynamic_relros_and_gnu_property, RuntimeDynamicProgramHeader,
    RuntimeGnuPropertyProgramHeader, RuntimeInterpProgramHeader, RuntimeRelroProgramHeader,
};
use crate::relocated_sections::{
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests,
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_bind_now,
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_isolated_got,
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_with_layout_tail_order,
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_with_layout_tail_order_and_ibt_plt,
    BindNowRelocationLayout, RelocatedSectionError, RelocatedSectionImage, TlsSyntheticRequests,
};
use crate::resolve::{SymbolDefinition, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use crate::section_names::section_name;
use crate::symbol_addresses::{final_symbol_address, FinalSymbolAddressError, SHN_ABS};
use crate::synthetic_ids::{
    DYNAMIC_COPY_OBJECT_INDEX, DYNAMIC_INTERP_OBJECT_INDEX, GNU_PROPERTY_OBJECT_INDEX,
    SHARED_METADATA_OBJECT_INDEX,
};
use crate::tls::{
    compute_static_tls_layout, inject_static_tls_program_header, StaticTlsLayout,
    StaticTlsLayoutError, StaticTlsProgramHeaderError,
};
use crate::version_script::{VersionScript, VersionScriptMatchError};
use crate::x86_64_relocations::{
    apply_relocation, RelocationApplyError, R_X86_64_64, R_X86_64_COPY, R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF32, R_X86_64_DTPOFF64, R_X86_64_GLOB_DAT, R_X86_64_GOTPC32_TLSDESC,
    R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_GOTTPOFF, R_X86_64_JUMP_SLOT, R_X86_64_PC32,
    R_X86_64_PLT32, R_X86_64_REX_GOTPCRELX, R_X86_64_TLSDESC, R_X86_64_TLSDESC_CALL,
    R_X86_64_TLSGD, R_X86_64_TLSLD, R_X86_64_TPOFF64,
};

const SHT_PROGBITS: u32 = 1;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_INIT_ARRAY: u32 = 14;
const SHT_FINI_ARRAY: u32 = 15;
const SHT_PREINIT_ARRAY: u32 = 16;
const SHARED_METADATA_SECTION_INDEX: u16 = 1;
const DYNAMIC_INTERP_SECTION_INDEX: u16 = 1;
const DYNAMIC_COPY_SECTION_INDEX: u16 = 1;
const DYNAMIC_COPY_ALIGNMENT: u64 = 16;
const GNU_PROPERTY_SECTION_INDEX: u16 = 1;
const GNU_PROPERTY_NOTE_SIZE: u64 = 32;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_DYNAMIC_SIZE: usize = 16;
const ELF64_RELA_SIZE: usize = 24;
const ELF64_RELR_SIZE: usize = 8;
const R_X86_64_NONE: u32 = 0;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;
const STV_PROTECTED: u8 = 3;
const GLOBAL_OFFSET_TABLE_SYMBOL: &[u8] = b"_GLOBAL_OFFSET_TABLE_";

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_SONAME: i64 = 14;
const DT_SYMBOLIC: i64 = 16;
const DT_RELA: i64 = 7;
const DT_PLTREL: i64 = 20;
const DT_DEBUG: i64 = 21;
const DT_JMPREL: i64 = 23;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RUNPATH: i64 = 29;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;
const DT_FLAGS: i64 = 30;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_RELACOUNT: i64 = 0x6fff_fff9;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
const VER_DEF_CURRENT: u16 = 1;
const VER_NEED_CURRENT: u16 = 1;
const VERSYM_GLOBAL: u16 = 1;
const VERSYM_FIRST_VERSION: u16 = 2;
const VERSYM_HIDDEN: u16 = 0x8000;
const VERSYM_INDEX_MASK: u16 = 0x7fff;
const ELF64_VERDEF_SIZE: usize = 20;
const ELF64_VERDAUX_SIZE: usize = 8;
const ELF64_VERNEED_SIZE: usize = 16;
const ELF64_VERNAUX_SIZE: usize = 16;
const DF_SYMBOLIC: u64 = 0x2;
const DF_BIND_NOW: u64 = 0x8;
const DF_STATIC_TLS: u64 = 0x10;
const DF_1_PIE: u64 = 0x0800_0000;

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
    MalformedVersionedImportName {
        name: Vec<u8>,
    },
    MalformedVersionedExportName {
        name: Vec<u8>,
    },
    MultipleDefaultVersionAliases {
        name: Vec<u8>,
    },
    VersionScriptExplicitAliasUnsupported {
        name: Vec<u8>,
    },
    VersionScriptUnknownSymbol {
        name: Vec<u8>,
        version: Vec<u8>,
    },
    VersionScriptPatternConflict {
        name: Vec<u8>,
        first_version: Vec<u8>,
        second_version: Vec<u8>,
    },
    ConflictingDynamicExportName {
        name: Vec<u8>,
    },
    UnsupportedVersionedImportType {
        name: Vec<u8>,
        symbol_type: u8,
    },
    InvalidVersionRequirement {
        name: Vec<u8>,
        version: Vec<u8>,
    },
    VersionRequirementProviderMissing {
        provider: Vec<u8>,
    },
    ExternalImportUnsupportedType {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
        symbol_type: u8,
    },
    DynamicSymbolRelocationTargetNotWritable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    DynamicSymbolRelocationOutOfBounds {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        offset: u64,
        target_size: u64,
    },
    MissingDynamicSymbolRelocationTarget {
        object_index: usize,
        target_section_index: u16,
    },
    MissingDynamicSymbol {
        name: Vec<u8>,
    },
    MissingGotDynamicSymbol {
        name: Vec<u8>,
    },
    MissingGotEntry {
        name: Vec<u8>,
    },
    MissingCopyMetadata {
        name: Vec<u8>,
    },
    UnexpectedCopyMetadata {
        name: Vec<u8>,
    },
    InvalidCopySize {
        name: Vec<u8>,
        size: u64,
    },
    CopyRelocationMixedReference {
        name: Vec<u8>,
    },
    MissingCopyRelocationTarget {
        object_index: usize,
        target_section_index: u16,
    },
    CopyRelocationApply {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        source: RelocationApplyError,
    },
    MissingPltGotEntry {
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
    TlsDescUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        symbol_index: u32,
        name: Vec<u8>,
    },
    TlsDescTargetNotExecutable {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        target_section_index: u16,
        flags: u64,
    },
    IncompleteTlsDescSequence,
    MissingTlsDescEntry {
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
    DynamicExecutableTlsModelUnsupported {
        object_index: usize,
        rela_section_index: u16,
        relocation_index: usize,
        relocation_type: u32,
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
    DynamicLifecycleSectionName {
        object_index: usize,
        section_index: u16,
        reason: String,
    },
    DynamicLifecycleSectionFlags {
        object_index: usize,
        section_index: u16,
        section_type: u32,
        flags: u64,
    },
    DynamicLifecycleSectionSize {
        object_index: usize,
        section_index: u16,
        section_type: u32,
        size: u64,
    },
    DynamicLifecycleMissingRelocatedSection {
        object_index: usize,
        section_index: u16,
        section_type: u32,
    },
    DynamicLifecycleNonContiguous {
        section_type: u32,
        previous_end: u64,
        next_address: u64,
    },
    SharedPreinitUnsupported {
        object_index: usize,
        section_index: u16,
    },
    DynamicLifecycleHookMissing {
        hook: &'static str,
        name: Vec<u8>,
    },
    DynamicLifecycleHookType {
        hook: &'static str,
        name: Vec<u8>,
        symbol_type: u8,
    },
    DynamicLifecycleHookNotImageBacked {
        hook: &'static str,
        name: Vec<u8>,
        object_index: usize,
        section_index: u16,
    },
    DynamicLifecycleHookNotExecutable {
        hook: &'static str,
        name: Vec<u8>,
        object_index: usize,
        section_index: u16,
        flags: u64,
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
    DynamicExecutableMissingEntry {
        name: Vec<u8>,
    },
    EmptyInterpreter,
    InterpreterContainsNul,
    InterpreterNotAbsolute,
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
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references default-visible nonlocal symbol {symbol_index} ({:?}) with binding {binding}; bounded shared relocation handling currently permits undefined external imports plus defined default-visible strong STT_OBJECT/STT_FUNC symbols through writable R_X86_64_64 dynamic relocations or ordinary GOTPCREL/GLOB_DAT interposition, and defined default-visible strong STT_FUNC PLT32 calls through the synthetic PLT/JUMP_SLOT plane",
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
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references undefined symbol {symbol_index} ({:?}) with unsupported binding {binding}; bounded imports accept strong globals, weak STT_OBJECT/STT_FUNC symbols on non-call paths, and weak STT_FUNC symbols on PLT call paths",
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
            Self::MalformedVersionedImportName { name } => write!(
                f,
                "shared object external import {:?} has malformed GNU version syntax; bounded named-version imports require name@VERSION",
                String::from_utf8_lossy(name)
            ),
            Self::MalformedVersionedExportName { name } => write!(
                f,
                "shared object export {:?} has malformed GNU version syntax; bounded producer versions require name@@VERSION",
                String::from_utf8_lossy(name)
            ),
            Self::MultipleDefaultVersionAliases { name } => write!(
                f,
                "shared object dynamic name {:?} has more than one default/unversioned export; bounded producer versioning permits at most one default alias per canonical name",
                String::from_utf8_lossy(name)
            ),
            Self::VersionScriptExplicitAliasUnsupported { name } => write!(
                f,
                "shared object definition {:?} uses explicit GNU .symver syntax; bounded --version-script does not compose with explicit @/@@ producer aliases",
                String::from_utf8_lossy(name)
            ),
            Self::VersionScriptUnknownSymbol { name, version } => write!(
                f,
                "version script assigns undefined/non-exportable symbol {:?} to version {:?}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(version)
            ),
            Self::VersionScriptPatternConflict {
                name,
                first_version,
                second_version,
            } => write!(
                f,
                "version script symbol {:?} matches multiple bounded prefix patterns assigned to different versions {:?} and {:?}",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(first_version),
                String::from_utf8_lossy(second_version)
            ),
            Self::ConflictingDynamicExportName { name } => write!(
                f,
                "shared object exports more than one symbol as dynamic name {:?}; bounded producer versioning requires unique canonical dynamic export names",
                String::from_utf8_lossy(name)
            ),
            Self::UnsupportedVersionedImportType { name, symbol_type } => write!(
                f,
                "shared object external import {:?} requests a GNU symbol version with ELF symbol type {symbol_type}; bounded named-version imports currently require STT_OBJECT, STT_FUNC, or STT_TLS",
                String::from_utf8_lossy(name)
            ),
            Self::InvalidVersionRequirement { name, version } => write!(
                f,
                "shared object version requirement {:?}@{:?} does not match a planned external import",
                String::from_utf8_lossy(name),
                String::from_utf8_lossy(version)
            ),
            Self::VersionRequirementProviderMissing { provider } => write!(
                f,
                "shared object version requirement names provider {:?}, but that provider is not present in the checked direct/transitive provider scope",
                String::from_utf8_lossy(provider)
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
            Self::DynamicSymbolRelocationTargetNotWritable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded dynamic symbol relocations require an allocated writable relocation target"
            ),
            Self::DynamicSymbolRelocationOutOfBounds {
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
            Self::MissingDynamicSymbolRelocationTarget {
                object_index,
                target_section_index,
            } => write!(
                f,
                "shared object dynamic symbol relocation target object {object_index} section {target_section_index} has no relocated output section"
            ),
            Self::MissingDynamicSymbol { name } => write!(
                f,
                "shared object runtime symbol {:?} has no usable dynamic-symbol index",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGotDynamicSymbol { name } => write!(
                f,
                "shared object GOT symbol {:?} has no usable dynamic-symbol index",
                String::from_utf8_lossy(name)
            ),
            Self::MissingGotEntry { name } => write!(
                f,
                "shared object GOT symbol {:?} has no synthetic GOT slot",
                String::from_utf8_lossy(name)
            ),
            Self::MissingCopyMetadata { name } => write!(
                f,
                "dynamic PIE copy relocation {:?} requires checked direct-provider size metadata",
                String::from_utf8_lossy(name)
            ),
            Self::UnexpectedCopyMetadata { name } => write!(
                f,
                "dynamic PIE received copy-relocation metadata for {:?}, but no bounded copy relocation was planned for that symbol",
                String::from_utf8_lossy(name)
            ),
            Self::InvalidCopySize { name, size } => write!(
                f,
                "dynamic PIE copy relocation {:?} requires a nonzero provider size, got {size}",
                String::from_utf8_lossy(name)
            ),
            Self::CopyRelocationMixedReference { name } => write!(
                f,
                "dynamic PIE copy relocation {:?} is mixed with an unsupported loader-binding reference plane; bounded COPY support permits copy-eligible PC32 sites plus ordinary GOTPCREL references to the same executable-owned copy symbol",
                String::from_utf8_lossy(name)
            ),
            Self::MissingCopyRelocationTarget {
                object_index,
                target_section_index,
            } => write!(
                f,
                "dynamic PIE copy relocation target object {object_index} section {target_section_index} has no relocated output section"
            ),
            Self::CopyRelocationApply {
                object_index,
                rela_section_index,
                relocation_index,
                source,
            } => write!(
                f,
                "cannot redirect dynamic PIE copy relocation {relocation_index} in RELA section {rela_section_index} of object {object_index}: {source}"
            ),
            Self::MissingPltGotEntry { name } => write!(
                f,
                "shared object PLT symbol {:?} has no synthetic PLT-GOT slot",
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
                "shared object RELA section {rela_section_index} relocation {relocation_index} in object {object_index} references TLS symbol {symbol_index} ({:?}); bounded initial-exec TLS requires a default-visible global/weak STT_TLS symbol for unresolved/default-visible binding, or a defined global STT_TLS symbol with STV_PROTECTED",
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
            Self::TlsDescUnsupported {
                object_index,
                rela_section_index,
                relocation_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object TLSDESC relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} references TLS symbol {symbol_index} ({:?}); bounded TLSDESC requires a default-visible global/weak STT_TLS symbol for unresolved/default-visible binding, or a defined global STT_TLS symbol with STV_PROTECTED",
                String::from_utf8_lossy(name)
            ),
            Self::TlsDescTargetNotExecutable {
                object_index,
                rela_section_index,
                relocation_index,
                target_section_index,
                flags,
            } => write!(
                f,
                "shared object TLSDESC relocation {relocation_index} in RELA section {rela_section_index} of object {object_index} targets section {target_section_index} with flags {flags:#x}; bounded TLSDESC access requires an allocated executable instruction site"
            ),
            Self::IncompleteTlsDescSequence => write!(
                f,
                "shared object TLSDESC access requires matching GOTPC32_TLSDESC address and TLSDESC_CALL marker relocations"
            ),
            Self::MissingTlsDescEntry { name } => write!(
                f,
                "shared object TLSDESC symbol {:?} has no synthetic 16-byte descriptor",
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
            Self::DynamicExecutableTlsModelUnsupported {
                object_index,
                rela_section_index,
                relocation_index,
                relocation_type,
                name,
            } => write!(
                f,
                "dynamic PIE bounded TLS slice rejects relocation type {relocation_type} in object {object_index} RELA section {rela_section_index} relocation {relocation_index} for symbol {:?}; qualified loader-backed dynamic-executable TLS models require either a default-visible global/weak STT_TLS definition or import through R_X86_64_TLSGD, R_X86_64_GOTTPOFF, or a matched R_X86_64_GOTPC32_TLSDESC/R_X86_64_TLSDESC_CALL sequence, or a defined local STT_TLS symbol through the matched R_X86_64_TLSLD/R_X86_64_DTPOFF32 local-dynamic sequence",
                String::from_utf8_lossy(name)
            ),
            Self::TlsImportUnsupported {
                object_index,
                symbol_index,
                name,
            } => write!(
                f,
                "shared object symbol {symbol_index} in object {object_index} ({:?}) is not supported by bounded TLSGD; TLSGD requires a default-visible global/weak STT_TLS symbol for unresolved/default-visible binding, or a defined global STT_TLS symbol with STV_PROTECTED",
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
            Self::DynamicLifecycleSectionName {
                object_index,
                section_index,
                reason,
            } => write!(
                f,
                "loader lifecycle section name at object {object_index} section {section_index} is malformed: {reason}"
            ),
            Self::DynamicLifecycleSectionFlags {
                object_index,
                section_index,
                section_type,
                flags,
            } => write!(
                f,
                "loader lifecycle section type {section_type} at object {object_index} section {section_index} has flags {flags:#x}; bounded lifecycle arrays require SHF_ALLOC|SHF_WRITE"
            ),
            Self::DynamicLifecycleSectionSize {
                object_index,
                section_index,
                section_type,
                size,
            } => write!(
                f,
                "loader lifecycle section type {section_type} at object {object_index} section {section_index} has size {size}; lifecycle arrays must contain whole 8-byte function pointers"
            ),
            Self::DynamicLifecycleMissingRelocatedSection {
                object_index,
                section_index,
                section_type,
            } => write!(
                f,
                "loader lifecycle section type {section_type} at object {object_index} section {section_index} has no relocated output section"
            ),
            Self::DynamicLifecycleNonContiguous {
                section_type,
                previous_end,
                next_address,
            } => write!(
                f,
                "loader lifecycle section type {section_type} is split into non-contiguous output ranges ending at {previous_end:#x} and restarting at {next_address:#x}; bounded DT_*ARRAY emission requires one exact contiguous range"
            ),
            Self::SharedPreinitUnsupported {
                object_index,
                section_index,
            } => write!(
                f,
                "shared object PREINIT_ARRAY at object {object_index} section {section_index} is unsupported; SHT_PREINIT_ARRAY is executable-only lifecycle metadata"
            ),
            Self::DynamicLifecycleHookMissing { hook, name } => write!(
                f,
                "dynamic PIE lifecycle hook {hook} symbol {:?} is not defined",
                String::from_utf8_lossy(name)
            ),
            Self::DynamicLifecycleHookType {
                hook,
                name,
                symbol_type,
            } => write!(
                f,
                "dynamic PIE lifecycle hook {hook} symbol {:?} has ELF symbol type {symbol_type}; lifecycle hooks must be STT_FUNC",
                String::from_utf8_lossy(name)
            ),
            Self::DynamicLifecycleHookNotImageBacked {
                hook,
                name,
                object_index,
                section_index,
            } => write!(
                f,
                "dynamic PIE lifecycle hook {hook} symbol {:?} resolves to object {object_index} section {section_index}, which is not backed by a relocated image section",
                String::from_utf8_lossy(name)
            ),
            Self::DynamicLifecycleHookNotExecutable {
                hook,
                name,
                object_index,
                section_index,
                flags,
            } => write!(
                f,
                "dynamic PIE lifecycle hook {hook} symbol {:?} resolves to object {object_index} section {section_index} with flags {flags:#x}; lifecycle hooks require an allocated executable section",
                String::from_utf8_lossy(name)
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
            Self::DynamicExecutableMissingEntry { name } => write!(
                f,
                "dynamic PIE entry symbol {:?} is not defined",
                String::from_utf8_lossy(name)
            ),
            Self::EmptyInterpreter => write!(f, "dynamic PIE interpreter path cannot be empty"),
            Self::InterpreterContainsNul => {
                write!(f, "dynamic PIE interpreter path cannot contain an embedded NUL byte")
            }
            Self::InterpreterNotAbsolute => {
                write!(f, "dynamic PIE interpreter path must be absolute")
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
            Self::CopyRelocationApply { source, .. } => Some(source),
            Self::RelocationUnsupported { .. }
            | Self::PreemptibleRelativeTarget { .. }
            | Self::VersionScriptPatternConflict { .. }
            | Self::ExternalImportUnsupportedBinding { .. }
            | Self::ConflictingImportSymbolType { .. }
            | Self::MalformedVersionedImportName { .. }
            | Self::MalformedVersionedExportName { .. }
            | Self::MultipleDefaultVersionAliases { .. }
            | Self::VersionScriptExplicitAliasUnsupported { .. }
            | Self::VersionScriptUnknownSymbol { .. }
            | Self::ConflictingDynamicExportName { .. }
            | Self::UnsupportedVersionedImportType { .. }
            | Self::InvalidVersionRequirement { .. }
            | Self::VersionRequirementProviderMissing { .. }
            | Self::ExternalImportUnsupportedType { .. }
            | Self::DynamicSymbolRelocationTargetNotWritable { .. }
            | Self::DynamicSymbolRelocationOutOfBounds { .. }
            | Self::MissingDynamicSymbolRelocationTarget { .. }
            | Self::MissingDynamicSymbol { .. }
            | Self::MissingGotDynamicSymbol { .. }
            | Self::MissingGotEntry { .. }
            | Self::MissingCopyMetadata { .. }
            | Self::UnexpectedCopyMetadata { .. }
            | Self::InvalidCopySize { .. }
            | Self::CopyRelocationMixedReference { .. }
            | Self::MissingCopyRelocationTarget { .. }
            | Self::MissingPltGotEntry { .. }
            | Self::MissingTlsGdEntry { .. }
            | Self::MissingTlsDynamicSymbol { .. }
            | Self::TlsGdTargetNotExecutable { .. }
            | Self::TlsIeUnsupported { .. }
            | Self::TlsIeTargetNotExecutable { .. }
            | Self::MissingTlsIeEntry { .. }
            | Self::TlsDescUnsupported { .. }
            | Self::TlsDescTargetNotExecutable { .. }
            | Self::IncompleteTlsDescSequence
            | Self::MissingTlsDescEntry { .. }
            | Self::TlsLdUnsupported { .. }
            | Self::TlsLdTargetNotExecutable { .. }
            | Self::IncompleteTlsLdSequence
            | Self::MissingTlsLdEntry
            | Self::MissingTlsLdRelocationTarget { .. }
            | Self::TlsLdSymbolOutsideImage { .. }
            | Self::ExternalPltUnsupportedType { .. }
            | Self::ExternalPltTargetNotExecutable { .. }
            | Self::TlsRelocationUnsupported { .. }
            | Self::DynamicExecutableTlsModelUnsupported { .. }
            | Self::TlsImportUnsupported { .. }
            | Self::TlsSymbolOutsideImage { .. }
            | Self::DynamicLifecycleSectionName { .. }
            | Self::DynamicLifecycleSectionFlags { .. }
            | Self::DynamicLifecycleSectionSize { .. }
            | Self::DynamicLifecycleMissingRelocatedSection { .. }
            | Self::DynamicLifecycleNonContiguous { .. }
            | Self::SharedPreinitUnsupported { .. }
            | Self::DynamicLifecycleHookMissing { .. }
            | Self::DynamicLifecycleHookType { .. }
            | Self::DynamicLifecycleHookNotImageBacked { .. }
            | Self::DynamicLifecycleHookNotExecutable { .. }
            | Self::EmptyNeededName { .. }
            | Self::NeededNameContainsNul { .. }
            | Self::EmptySoname
            | Self::SonameContainsNul
            | Self::EmptyRunpath
            | Self::RunpathContainsNul
            | Self::DynamicExecutableMissingEntry { .. }
            | Self::EmptyInterpreter
            | Self::InterpreterContainsNul
            | Self::InterpreterNotAbsolute
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
    linker_name: Vec<u8>,
    dynamic_name: Vec<u8>,
    version: Option<Vec<u8>>,
    is_default_version: bool,
    info: u8,
    other: u8,
    section_index: u16,
    value: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct ExportIdentity {
    dynamic_name: Vec<u8>,
    version: Option<Vec<u8>>,
    is_default_version: bool,
}

fn parse_export_identity(name: &[u8]) -> Result<ExportIdentity, SharedObjectError> {
    let Some(first_at) = name.iter().position(|byte| *byte == b'@') else {
        return Ok(ExportIdentity {
            dynamic_name: name.to_vec(),
            version: None,
            is_default_version: true,
        });
    };
    let base = &name[..first_at];
    let suffix = &name[first_at..];
    let (version, is_default_version) = if let Some(version) = suffix.strip_prefix(b"@@") {
        (version, true)
    } else if let Some(version) = suffix.strip_prefix(b"@") {
        (version, false)
    } else {
        unreachable!("suffix starts at an @ byte");
    };
    if base.is_empty() || version.is_empty() || version.contains(&b'@') {
        return Err(SharedObjectError::MalformedVersionedExportName {
            name: name.to_vec(),
        });
    }
    Ok(ExportIdentity {
        dynamic_name: base.to_vec(),
        version: Some(version.to_vec()),
        is_default_version,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedImportRequirement {
    pub linker_name: Vec<u8>,
    pub name: Vec<u8>,
    pub symbol_type: u8,
    pub version: Option<Vec<u8>>,
    pub requires_copy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedVersionRequirement {
    pub linker_name: Vec<u8>,
    pub provider: Vec<u8>,
    pub version: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicPieCopyRelocation {
    pub linker_name: Vec<u8>,
    pub size: u64,
}

#[derive(Debug, Clone)]
struct ImportSymbol {
    name: Vec<u8>,
    dynamic_name: Vec<u8>,
    version: Option<Vec<u8>>,
    info: u8,
    size: u64,
}

fn parse_import_identity(name: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), SharedObjectError> {
    let Some(separator) = name.iter().position(|byte| *byte == b'@') else {
        return Ok((name.to_vec(), None));
    };
    let base = &name[..separator];
    let version = &name[separator + 1..];
    if base.is_empty()
        || version.is_empty()
        || version.contains(&b'@')
        || name[separator..].starts_with(b"@@")
    {
        return Err(SharedObjectError::MalformedVersionedImportName {
            name: name.to_vec(),
        });
    }
    Ok((base.to_vec(), Some(version.to_vec())))
}

fn record_import_symbol(
    imports: &mut BTreeMap<Vec<u8>, ImportSymbol>,
    name: &[u8],
    info: u8,
    size: u64,
) -> Result<(), SharedObjectError> {
    let symbol_type = info & 0x0f;
    let binding = info >> 4;
    let (dynamic_name, version) = parse_import_identity(name)?;
    if version.is_some() && !matches!(symbol_type, STT_OBJECT | STT_FUNC | STT_TLS) {
        return Err(SharedObjectError::UnsupportedVersionedImportType {
            name: name.to_vec(),
            symbol_type,
        });
    }

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
                    dynamic_name,
                    version,
                    info,
                    size,
                },
            );
        }
    }

    Ok(())
}

fn is_supported_dynamic_tls_definition(definition: &SymbolDefinition) -> bool {
    let binding = definition.symbol.info >> 4;
    let symbol_type = definition.symbol.info & 0x0f;
    if symbol_type != STT_TLS {
        return false;
    }
    match definition.symbol.other {
        0 => matches!(binding, STB_GLOBAL | STB_WEAK),
        STV_PROTECTED => binding == STB_GLOBAL,
        _ => false,
    }
}

fn is_supported_dynamic_tls_reference(
    info: u8,
    other: u8,
    name: &[u8],
    unresolved: bool,
    definition: Option<&SymbolDefinition>,
) -> bool {
    let binding = info >> 4;
    let symbol_type = info & 0x0f;
    if symbol_type != STT_TLS || !matches!(binding, STB_GLOBAL | STB_WEAK) || name.is_empty() {
        return false;
    }
    if unresolved {
        return other == 0;
    }
    let Some(definition) = definition else {
        return false;
    };
    if !is_supported_dynamic_tls_definition(definition) {
        return false;
    }
    other == 0 || (other == STV_PROTECTED && definition.symbol.other == STV_PROTECTED)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DynamicSymbolRelocationSite {
    object_index: usize,
    rela_section_index: u16,
    relocation_index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoaderTlsPolicy {
    SharedObject,
    DynamicPieGdIeDescLd,
}

impl LoaderTlsPolicy {
    fn allows(self, relocation_type: u32) -> bool {
        match self {
            Self::SharedObject => true,
            Self::DynamicPieGdIeDescLd => matches!(
                relocation_type,
                R_X86_64_TLSGD
                    | R_X86_64_GOTTPOFF
                    | R_X86_64_GOTPC32_TLSDESC
                    | R_X86_64_TLSDESC_CALL
                    | R_X86_64_TLSLD
                    | R_X86_64_DTPOFF32
            ),
        }
    }
}

fn dynamic_pie_tls_reference_supported(symbol_info: u8, symbol_other: u8, symbol_type: u8) -> bool {
    let binding = symbol_info >> 4;
    matches!(binding, STB_GLOBAL | STB_WEAK) && symbol_other == 0 && symbol_type == STT_TLS
}

fn is_loader_gotpcrel_type(relocation_type: u32) -> bool {
    matches!(
        relocation_type,
        R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX
    )
}

#[derive(Debug, Clone, Copy)]
struct InputValidationOptions {
    allow_copy_relocations: bool,
    allow_explicit_ifunc_imports: bool,
    allow_defined_pc32: bool,
    allow_plt_notype_function_imports: bool,
    tls_policy: LoaderTlsPolicy,
}

#[derive(Debug)]
struct ImportPlan {
    symbols: BTreeMap<Vec<u8>, ImportSymbol>,
    symbol_relocation_sites: BTreeSet<DynamicSymbolRelocationSite>,
    got_symbols: BTreeSet<Vec<u8>>,
    relative_got_symbols: BTreeSet<Vec<u8>>,
    copy_symbols: BTreeSet<Vec<u8>>,
    copy_relocation_sites: BTreeSet<DynamicSymbolRelocationSite>,
    plt_symbols: BTreeSet<Vec<u8>>,
    tls_gd_symbols: BTreeSet<Vec<u8>>,
    tls_ie_symbols: BTreeSet<Vec<u8>>,
    tls_desc_symbols: BTreeSet<Vec<u8>>,
    tls_desc_call_sites: BTreeSet<DynamicSymbolRelocationSite>,
    tls_ld_dtpoff_sites: BTreeSet<DynamicSymbolRelocationSite>,
    uses_tls_ld: bool,
}

#[derive(Debug, Clone, Copy)]
struct DynamicNames<'a> {
    needed: &'a [Vec<u8>],
    soname: Option<&'a [u8]>,
    runpath: Option<&'a [u8]>,
    version_requirements: &'a [SharedVersionRequirement],
    version_script: Option<&'a VersionScript>,
}

#[derive(Debug, Clone, Copy)]
struct DynamicRelocations<'a> {
    rela: &'a [u8],
    relative_count: usize,
    relr: &'a [u8],
    jmprel: &'a [u8],
    plt_got_address: Option<u64>,
    flags: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DynamicLifecycleArray {
    address: u64,
    size: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DynamicLifecycle {
    preinit: Option<DynamicLifecycleArray>,
    init: Option<DynamicLifecycleArray>,
    fini: Option<DynamicLifecycleArray>,
    init_hook: Option<u64>,
    fini_hook: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecyclePriority {
    Suffixed {
        numeric: Option<u32>,
        suffix: Vec<u8>,
    },
    Base,
}

#[derive(Debug)]
struct DynamicMetadata {
    bytes: Vec<u8>,
    dynamic_offset: u64,
    dynamic_size: u64,
}

pub fn shared_import_requirements(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<SharedImportRequirement>, SharedObjectError> {
    import_requirements(
        inputs,
        InputValidationOptions {
            allow_copy_relocations: false,
            allow_explicit_ifunc_imports: false,
            allow_defined_pc32: false,
            allow_plt_notype_function_imports: false,
            tls_policy: LoaderTlsPolicy::SharedObject,
        },
    )
}

pub fn dynamic_pie_import_requirements(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<SharedImportRequirement>, SharedObjectError> {
    import_requirements(
        inputs,
        InputValidationOptions {
            allow_copy_relocations: true,
            allow_explicit_ifunc_imports: true,
            allow_defined_pc32: true,
            allow_plt_notype_function_imports: true,
            tls_policy: LoaderTlsPolicy::DynamicPieGdIeDescLd,
        },
    )
}

fn import_requirements(
    inputs: &[LinkerInputObject<'_>],
    options: InputValidationOptions,
) -> Result<Vec<SharedImportRequirement>, SharedObjectError> {
    let validated = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let resolved =
        resolve_validated_objects_with_common(&validated).map_err(SharedObjectError::Symbols)?;
    let plan = validate_inputs(inputs, &resolved.definitions, options)?;
    let ImportPlan {
        symbols,
        copy_symbols,
        ..
    } = plan;
    Ok(symbols
        .into_values()
        .map(|symbol| SharedImportRequirement {
            requires_copy: copy_symbols.contains(&symbol.name),
            linker_name: symbol.name,
            name: symbol.dynamic_name,
            symbol_type: symbol.info & 0x0f,
            version: symbol.version,
        })
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
    link_shared_object_with_needed_soname_runpath_and_versions(
        inputs,
        page_alignment,
        needed,
        soname,
        runpath,
        &[],
    )
}

pub fn link_shared_object_with_needed_soname_runpath_and_versions(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    needed: &[Vec<u8>],
    soname: Option<&[u8]>,
    runpath: Option<&[u8]>,
    version_requirements: &[SharedVersionRequirement],
) -> Result<ExecutableImage, SharedObjectError> {
    link_shared_object_with_needed_soname_runpath_versions_and_checked_providers(
        inputs,
        page_alignment,
        needed,
        soname,
        runpath,
        version_requirements,
        needed,
    )
}

pub fn link_shared_object_with_needed_soname_runpath_versions_and_checked_providers(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    needed: &[Vec<u8>],
    soname: Option<&[u8]>,
    runpath: Option<&[u8]>,
    version_requirements: &[SharedVersionRequirement],
    checked_version_providers: &[Vec<u8>],
) -> Result<ExecutableImage, SharedObjectError> {
    link_shared_object_with_version_script_and_checked_providers(
        inputs,
        page_alignment,
        SharedObjectLinkOptions {
            needed,
            soname,
            runpath,
            version_requirements,
            checked_version_providers,
            version_script: None,
            symbolic: false,
            ibt_plt: false,
            gnu_property_ibt: false,
            bind_now: false,
            pack_relative_relocs: false,
            init_symbol: None,
            fini_symbol: None,
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub struct SharedObjectLinkOptions<'a> {
    pub needed: &'a [Vec<u8>],
    pub soname: Option<&'a [u8]>,
    pub runpath: Option<&'a [u8]>,
    pub version_requirements: &'a [SharedVersionRequirement],
    pub checked_version_providers: &'a [Vec<u8>],
    pub version_script: Option<&'a VersionScript>,
    pub symbolic: bool,
    pub ibt_plt: bool,
    pub gnu_property_ibt: bool,
    pub bind_now: bool,
    pub pack_relative_relocs: bool,
    pub init_symbol: Option<&'a [u8]>,
    pub fini_symbol: Option<&'a [u8]>,
}

pub fn link_shared_object_with_version_script_and_checked_providers(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    options: SharedObjectLinkOptions<'_>,
) -> Result<ExecutableImage, SharedObjectError> {
    link_loader_image(
        inputs,
        page_alignment,
        LoaderImageLinkOptions {
            shared: options,
            entry_symbol: None,
            interpreter: None,
            init_symbol: options.init_symbol,
            fini_symbol: options.fini_symbol,
            copy_relocations: None,
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicPieLinkOptions<'a> {
    pub needed: &'a [Vec<u8>],
    pub runpath: Option<&'a [u8]>,
    pub version_requirements: &'a [SharedVersionRequirement],
    pub checked_version_providers: &'a [Vec<u8>],
    pub entry_symbol: &'a [u8],
    pub interpreter: &'a [u8],
    pub init_symbol: Option<&'a [u8]>,
    pub fini_symbol: Option<&'a [u8]>,
    pub ibt_plt: bool,
    pub gnu_property_ibt: bool,
    pub bind_now: bool,
    pub pack_relative_relocs: bool,
    pub copy_relocations: &'a [DynamicPieCopyRelocation],
}

pub fn link_dynamic_pie_with_checked_providers(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    options: DynamicPieLinkOptions<'_>,
) -> Result<ExecutableImage, SharedObjectError> {
    link_loader_image(
        inputs,
        page_alignment,
        LoaderImageLinkOptions {
            shared: SharedObjectLinkOptions {
                needed: options.needed,
                soname: None,
                runpath: options.runpath,
                version_requirements: options.version_requirements,
                checked_version_providers: options.checked_version_providers,
                version_script: None,
                symbolic: false,
                ibt_plt: options.ibt_plt,
                gnu_property_ibt: options.gnu_property_ibt,
                bind_now: options.bind_now,
                pack_relative_relocs: options.pack_relative_relocs,
                init_symbol: None,
                fini_symbol: None,
            },
            entry_symbol: Some(options.entry_symbol),
            interpreter: Some(options.interpreter),
            init_symbol: options.init_symbol,
            fini_symbol: options.fini_symbol,
            copy_relocations: Some(options.copy_relocations),
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct LoaderImageLinkOptions<'a> {
    shared: SharedObjectLinkOptions<'a>,
    entry_symbol: Option<&'a [u8]>,
    interpreter: Option<&'a [u8]>,
    init_symbol: Option<&'a [u8]>,
    fini_symbol: Option<&'a [u8]>,
    copy_relocations: Option<&'a [DynamicPieCopyRelocation]>,
}

fn link_loader_image(
    inputs: &[LinkerInputObject<'_>],
    page_alignment: u64,
    options: LoaderImageLinkOptions<'_>,
) -> Result<ExecutableImage, SharedObjectError> {
    let LoaderImageLinkOptions {
        shared,
        entry_symbol,
        interpreter,
        init_symbol,
        fini_symbol,
        copy_relocations,
    } = options;
    let SharedObjectLinkOptions {
        needed,
        soname,
        runpath,
        version_requirements,
        checked_version_providers,
        version_script,
        symbolic,
        ibt_plt,
        gnu_property_ibt,
        bind_now,
        pack_relative_relocs,
        init_symbol: _,
        fini_symbol: _,
    } = shared;
    let ibt_plt = ibt_plt || gnu_property_ibt;
    validate_needed_names(needed)?;
    validate_needed_names(checked_version_providers)?;
    validate_soname(soname)?;
    validate_runpath(runpath)?;
    if let Some(path) = interpreter {
        if path.is_empty() {
            return Err(SharedObjectError::EmptyInterpreter);
        }
        if path.contains(&0) {
            return Err(SharedObjectError::InterpreterContainsNul);
        }
        if path.first() != Some(&b'/') {
            return Err(SharedObjectError::InterpreterNotAbsolute);
        }
    }

    let validated = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let resolved =
        resolve_validated_objects_with_common(&validated).map_err(SharedObjectError::Symbols)?;
    let dynamic_pie = copy_relocations.is_some();
    let imports = validate_inputs(
        inputs,
        &resolved.definitions,
        InputValidationOptions {
            allow_copy_relocations: dynamic_pie,
            allow_explicit_ifunc_imports: dynamic_pie,
            allow_defined_pc32: dynamic_pie,
            allow_plt_notype_function_imports: dynamic_pie,
            tls_policy: if dynamic_pie {
                LoaderTlsPolicy::DynamicPieGdIeDescLd
            } else {
                LoaderTlsPolicy::SharedObject
            },
        },
    )?;
    let copy_sizes = validate_dynamic_pie_copy_metadata(&imports.copy_symbols, copy_relocations)?;
    validate_version_requirements(
        checked_version_providers,
        &imports.symbols,
        version_requirements,
    )?;
    let tls_ie_import_symbols = imports
        .tls_ie_symbols
        .iter()
        .filter(|name| imports.symbols.contains_key(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut masked_sites = imports.symbol_relocation_sites.clone();
    masked_sites.extend(imports.copy_relocation_sites.iter().copied());
    masked_sites.extend(imports.tls_ld_dtpoff_sites.iter().copied());
    masked_sites.extend(imports.tls_desc_call_sites.iter().copied());
    let relocation_inputs = mask_deferred_relocations(inputs, &masked_sites);
    if !dynamic_pie {
        reject_shared_preinit_arrays(inputs)?;
    }
    let lifecycle_layout_tail_order = loader_lifecycle_layout_tail_order(inputs)?;

    // Dynamic-executable partial RELRO: isolate the synthetic GOT whenever
    // it carries ordinary or TLS loader state. The loader applies GLOB_DAT,
    // TLSGD/TLSLD, TPOFF64, and TLSDESC relocations before sealing RELRO,
    // while GOTPLT stays on its separate writable page so lazy JUMP_SLOT
    // binding continues to work.
    let dynamic_pie_got_relro = dynamic_pie
        && (!imports.got_symbols.is_empty()
            || !imports.tls_gd_symbols.is_empty()
            || !imports.tls_ie_symbols.is_empty()
            || !imports.tls_desc_symbols.is_empty()
            || imports.uses_tls_ld);
    let tls_requests = TlsSyntheticRequests {
        tls_gd_symbols: &imports.tls_gd_symbols,
        tls_ld_enabled: imports.uses_tls_ld,
        tls_desc_symbols: &imports.tls_desc_symbols,
        external_tls_got_symbols: &tls_ie_import_symbols,
    };
    let relocated_output = if bind_now {
        relocate_allocatable_sections_with_external_got_plt_and_tls_requests_bind_now(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            tls_requests,
            BindNowRelocationLayout {
                tail_order: &lifecycle_layout_tail_order,
                ibt_plt,
            },
        )
    } else if dynamic_pie_got_relro {
        relocate_allocatable_sections_with_external_got_plt_and_tls_requests_isolated_got(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            tls_requests,
            &lifecycle_layout_tail_order,
        )
    } else if ibt_plt {
        relocate_allocatable_sections_with_external_got_plt_and_tls_requests_with_layout_tail_order_and_ibt_plt(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            tls_requests,
            &lifecycle_layout_tail_order,
        )
    } else if dynamic_pie || !lifecycle_layout_tail_order.is_empty() {
        relocate_allocatable_sections_with_external_got_plt_and_tls_requests_with_layout_tail_order(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            tls_requests,
            &lifecycle_layout_tail_order,
        )
    } else {
        relocate_allocatable_sections_with_external_got_plt_and_tls_requests(
            &relocation_inputs,
            page_alignment,
            page_alignment,
            &imports.got_symbols,
            &imports.plt_symbols,
            tls_requests,
        )
    }
    .map_err(SharedObjectError::Relocation)?;
    let got_relro = if dynamic_pie_got_relro || bind_now {
        relocated_output.got_region
    } else {
        None
    };
    let plt_got_relro = if bind_now {
        relocated_output.plt_got_region
    } else {
        None
    };
    let mut relocated = relocated_output.sections;
    let got_entries = relocated_output.got_entries;
    let relative_got_entries = imports
        .relative_got_symbols
        .iter()
        .map(|name| {
            got_entries
                .get(name)
                .copied()
                .map(|address| (name.clone(), address))
                .ok_or_else(|| SharedObjectError::MissingGotEntry { name: name.clone() })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let tls_got_entries = relocated_output.tls_got_entries;
    let tls_gd_entries = relocated_output.tls_gd_entries;
    let tls_ld_entry = relocated_output.tls_ld_entry;
    let tls_desc_entries = relocated_output.tls_desc_entries;
    let plt_got_entries = relocated_output.plt_got_entries;
    let plt_got_base = relocated_output.plt_got_base;
    let copy_addresses = allocate_dynamic_pie_copy_storage(&mut relocated, &copy_sizes)?;
    apply_dynamic_pie_copy_relocations(
        inputs,
        &mut relocated,
        &imports.copy_relocation_sites,
        &copy_addresses,
    )?;
    let layout = relocated
        .iter()
        .map(|section| LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address: section.address,
            size: section.size,
        })
        .collect::<Vec<_>>();

    let entry_address = if let Some(name) = entry_symbol {
        let definition = resolved.definitions.get(name).ok_or_else(|| {
            SharedObjectError::DynamicExecutableMissingEntry {
                name: name.to_vec(),
            }
        })?;
        Some(final_symbol_address(definition, &layout).map_err(SharedObjectError::SymbolAddress)?)
    } else {
        None
    };

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
    let init_hook = resolve_dynamic_lifecycle_hook(
        "DT_INIT",
        init_symbol,
        &resolved.definitions,
        &relocated,
        &layout,
    )?;
    let fini_hook = resolve_dynamic_lifecycle_hook(
        "DT_FINI",
        fini_symbol,
        &resolved.definitions,
        &relocated,
        &layout,
    )?;
    let lifecycle = if dynamic_pie {
        collect_dynamic_pie_lifecycle(inputs, &relocated, init_hook, fini_hook)?
    } else {
        collect_shared_object_lifecycle(inputs, &relocated, init_hook, fini_hook)?
    };

    let mut matched_script_symbols = BTreeSet::new();
    let mut exports = Vec::new();
    for definition in resolved.definitions.values() {
        let identity = if let Some(script) = version_script {
            if definition.name.contains(&b'@') {
                return Err(SharedObjectError::VersionScriptExplicitAliasUnsupported {
                    name: definition.name.clone(),
                });
            }
            let version =
                script
                    .resolve_version(&definition.name)
                    .map_err(|source| match source {
                        VersionScriptMatchError::MultiplePrefixVersions {
                            symbol,
                            first_version,
                            second_version,
                        } => SharedObjectError::VersionScriptPatternConflict {
                            name: symbol,
                            first_version,
                            second_version,
                        },
                    })?;
            if let Some(version) = version {
                if script.version_for(&definition.name).is_some() {
                    matched_script_symbols.insert(definition.name.clone());
                }
                ExportIdentity {
                    dynamic_name: definition.name.clone(),
                    version: Some(version.to_vec()),
                    is_default_version: true,
                }
            } else if script.localize_unlisted() {
                continue;
            } else {
                parse_export_identity(&definition.name)?
            }
        } else {
            parse_export_identity(&definition.name)?
        };

        let absolute_value =
            final_symbol_address(definition, &layout).map_err(SharedObjectError::SymbolAddress)?;
        let symbol_type = definition.symbol.info & 0x0f;
        let value = if symbol_type == STT_TLS {
            tls_export_value(definition, absolute_value, tls_layout)?
        } else {
            absolute_value
        };
        exports.push(ExportSymbol {
            linker_name: definition.name.clone(),
            dynamic_name: identity.dynamic_name,
            version: identity.version,
            is_default_version: identity.is_default_version,
            info: definition.symbol.info,
            other: definition.symbol.other,
            section_index: if definition.symbol.section_index == SHN_ABS {
                SHN_ABS
            } else {
                1
            },
            value,
            size: definition.symbol.size,
        });
    }

    for name in &imports.copy_symbols {
        let import = imports
            .symbols
            .get(name)
            .ok_or_else(|| SharedObjectError::MissingCopyMetadata { name: name.clone() })?;
        let value = copy_addresses
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingCopyMetadata { name: name.clone() })?;
        let size = copy_sizes
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingCopyMetadata { name: name.clone() })?;
        exports.push(ExportSymbol {
            linker_name: import.name.clone(),
            dynamic_name: import.dynamic_name.clone(),
            version: None,
            is_default_version: true,
            info: (STB_GLOBAL << 4) | STT_OBJECT,
            other: 0,
            section_index: 1,
            value,
            size,
        });
    }

    if let Some(script) = version_script {
        for (name, version) in script.assignments() {
            if !matched_script_symbols.contains(name) {
                return Err(SharedObjectError::VersionScriptUnknownSymbol {
                    name: name.to_vec(),
                    version: version.to_vec(),
                });
            }
        }
    }
    if exports.is_empty() {
        return Err(SharedObjectError::NoExports);
    }
    let mut dynamic_export_identities = BTreeSet::new();
    let mut default_dynamic_names = BTreeSet::new();
    for export in &exports {
        if !dynamic_export_identities.insert((export.dynamic_name.clone(), export.version.clone()))
        {
            return Err(SharedObjectError::ConflictingDynamicExportName {
                name: export.dynamic_name.clone(),
            });
        }
        if export.is_default_version && !default_dynamic_names.insert(export.dynamic_name.clone()) {
            return Err(SharedObjectError::MultipleDefaultVersionAliases {
                name: export.dynamic_name.clone(),
            });
        }
    }

    let export_dynamic_indices = export_dynamic_symbol_indices(&exports)?;
    let mut dynamic_imports = imports.symbols.clone();
    for name in &imports.copy_symbols {
        dynamic_imports.remove(name);
    }
    let import_dynamic_indices = import_dynamic_symbol_indices(exports.len(), &dynamic_imports)?;
    let (mut rela_bytes, relative_relocation_count, relr_bytes) = if pack_relative_relocs {
        let relr = build_relr_relocation_table(
            &relocation_inputs,
            &mut relocated,
            &resolved.definitions,
            &relative_got_entries,
        )
        .map_err(SharedObjectError::RuntimeRelative)?;
        (Vec::new(), 0, relr)
    } else {
        let (rela, relative_count) = build_relative_relocation_table(
            &relocation_inputs,
            &relocated,
            &resolved.definitions,
            &relative_got_entries,
        )
        .map_err(SharedObjectError::RuntimeRelative)?;
        (rela, relative_count, Vec::new())
    };
    let copy_rela_bytes = build_copy_relocation_table(
        &imports.copy_symbols,
        &copy_addresses,
        &export_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&copy_rela_bytes);
    let symbol_rela_bytes = build_dynamic_symbol_relocation_table(
        inputs,
        &relocated,
        &imports.symbol_relocation_sites,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&symbol_rela_bytes);
    let got_rela_bytes = build_got_relocation_table(
        &imports.got_symbols,
        &got_entries,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&got_rela_bytes);
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
    let tls_desc_rela_bytes = build_tls_desc_relocation_table(
        &imports.tls_desc_symbols,
        &tls_desc_entries,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;
    rela_bytes.extend_from_slice(&tls_desc_rela_bytes);
    let jmprel_bytes = build_plt_relocation_table(
        &imports.plt_symbols,
        &plt_got_entries,
        &export_dynamic_indices,
        &import_dynamic_indices,
    )?;

    let relocated_end = relocated
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
        .unwrap_or(0);
    let bind_now_relro_tail_start = if dynamic_pie && bind_now {
        let mut protected_start = None;
        let mut protected_end = None;
        for region in [plt_got_relro, got_relro].into_iter().flatten() {
            let end = region
                .address
                .checked_add(region.size)
                .ok_or(SharedObjectError::AddressOverflow)?;
            protected_start = Some(
                protected_start.map_or(region.address, |start: u64| start.min(region.address)),
            );
            protected_end = Some(protected_end.map_or(end, |current: u64| current.max(end)));
        }
        match (protected_start, protected_end) {
            (Some(start), Some(end)) if end == relocated_end => Some(start),
            _ => None,
        }
    } else {
        None
    };
    let coalesced_relro_start = bind_now_relro_tail_start.or_else(|| {
        if bind_now {
            return None;
        }
        got_relro.and_then(|region| {
            region
                .address
                .checked_add(region.size)
                .filter(|end| dynamic_pie && *end == relocated_end)
                .map(|_| region.address)
        })
    });
    let interpreter_payload = interpreter.map(|path| {
        let mut bytes = path.to_vec();
        bytes.push(0);
        bytes
    });

    // Keep loader-mutated dynamic-PIE state contiguous before protection.
    // Partial RELRO coalesces a tail-isolated ordinary/TLS GOT with metadata.
    // Bind-now also admits a GOTPLT-only tail or the ordered GOTPLT+GOT tail,
    // keeping PT_INTERP after the protected RW interval.
    let interpreter_before_metadata = if coalesced_relro_start.is_none()
        && interpreter_payload.is_some()
    {
        Some(align_up(relocated_end, page_alignment).ok_or(SharedObjectError::AddressOverflow)?)
    } else {
        None
    };
    let metadata_floor = match (interpreter_before_metadata, interpreter_payload.as_ref()) {
        (Some(address), Some(bytes)) => address
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?,
            )
            .ok_or(SharedObjectError::AddressOverflow)?,
        _ => relocated_end,
    };
    let metadata_address =
        align_up(metadata_floor, page_alignment).ok_or(SharedObjectError::AddressOverflow)?;
    let metadata_relro =
        bind_now || (dynamic_pie && (got_relro.is_none() || coalesced_relro_start.is_some()));
    let mut metadata = build_dynamic_metadata(
        metadata_address,
        &exports,
        &dynamic_imports,
        DynamicNames {
            needed,
            soname,
            runpath,
            version_requirements,
            version_script,
        },
        DynamicRelocations {
            rela: &rela_bytes,
            relative_count: relative_relocation_count,
            relr: &relr_bytes,
            jmprel: &jmprel_bytes,
            plt_got_address: plt_got_base,
            flags: (if !dynamic_pie && !imports.tls_ie_symbols.is_empty() {
                DF_STATIC_TLS
            } else {
                0
            }) | if symbolic { DF_SYMBOLIC } else { 0 }
                | if bind_now { DF_BIND_NOW } else { 0 },
        },
        lifecycle,
        dynamic_pie,
    )?;
    let dynamic_address = metadata_address
        .checked_add(metadata.dynamic_offset)
        .ok_or(SharedObjectError::AddressOverflow)?;
    let unpadded_metadata_size =
        u64::try_from(metadata.bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
    let metadata_size = if metadata_relro {
        let padded = align_up(unpadded_metadata_size, page_alignment)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let padded_len =
            usize::try_from(padded).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        metadata.bytes.resize(padded_len, 0);
        padded
    } else {
        unpadded_metadata_size
    };
    let interpreter_after_metadata =
        if coalesced_relro_start.is_some() && interpreter_payload.is_some() {
            let metadata_end = metadata_address
                .checked_add(metadata_size)
                .ok_or(SharedObjectError::AddressOverflow)?;
            Some(align_up(metadata_end, page_alignment).ok_or(SharedObjectError::AddressOverflow)?)
        } else {
            None
        };
    let interpreter_address = interpreter_before_metadata.or(interpreter_after_metadata);
    let gnu_property_payload = gnu_property_ibt.then(build_ibt_gnu_property_note);
    let gnu_property_address = if let Some(payload) = gnu_property_payload.as_ref() {
        let metadata_end = metadata_address
            .checked_add(metadata_size)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let mut floor = metadata_end;
        if let (Some(address), Some(bytes)) = (interpreter_address, interpreter_payload.as_ref()) {
            let interpreter_end = address
                .checked_add(
                    u64::try_from(bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?,
                )
                .ok_or(SharedObjectError::AddressOverflow)?;
            floor = floor.max(interpreter_end);
        }
        let _ = payload;
        Some(align_up(floor, page_alignment).ok_or(SharedObjectError::AddressOverflow)?)
    } else {
        None
    };

    let mut sections = relocated;
    if coalesced_relro_start.is_some() {
        sections.push(RelocatedSectionImage {
            object_index: SHARED_METADATA_OBJECT_INDEX,
            section_index: SHARED_METADATA_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: metadata_address,
            size: metadata_size,
            alignment: 8,
            bytes: metadata.bytes,
        });
        if let (Some(address), Some(bytes)) = (interpreter_address, interpreter_payload) {
            sections.push(RelocatedSectionImage {
                object_index: DYNAMIC_INTERP_OBJECT_INDEX,
                section_index: DYNAMIC_INTERP_SECTION_INDEX,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC,
                address,
                size: u64::try_from(bytes.len())
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?,
                alignment: 1,
                bytes,
            });
        }
    } else {
        if let (Some(address), Some(bytes)) = (interpreter_address, interpreter_payload) {
            sections.push(RelocatedSectionImage {
                object_index: DYNAMIC_INTERP_OBJECT_INDEX,
                section_index: DYNAMIC_INTERP_SECTION_INDEX,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC,
                address,
                size: u64::try_from(bytes.len())
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?,
                alignment: 1,
                bytes,
            });
        }
        sections.push(RelocatedSectionImage {
            object_index: SHARED_METADATA_OBJECT_INDEX,
            section_index: SHARED_METADATA_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: metadata_address,
            size: metadata_size,
            alignment: 8,
            bytes: metadata.bytes,
        });
    }
    if let (Some(address), Some(bytes)) = (gnu_property_address, gnu_property_payload) {
        sections.push(RelocatedSectionImage {
            object_index: GNU_PROPERTY_OBJECT_INDEX,
            section_index: GNU_PROPERTY_SECTION_INDEX,
            section_type: SHT_NOTE,
            flags: SHF_ALLOC,
            address,
            size: GNU_PROPERTY_NOTE_SIZE,
            alignment: 8,
            bytes,
        });
    }

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

    let image = if let Some(entry_address) = entry_address {
        write_elf64_x86_64_position_independent_segments(
            &writer_segments,
            entry_address,
            page_alignment,
        )
    } else {
        write_elf64_x86_64_shared_segments(&writer_segments, page_alignment)
    }
    .map_err(SharedObjectError::Write)?;
    let image = if let Some(tls) = tls_layout {
        inject_static_tls_program_header(image, tls, page_alignment)
            .map_err(SharedObjectError::TlsProgramHeader)?
    } else {
        image
    };
    let dynamic = RuntimeDynamicProgramHeader {
        address: dynamic_address,
        size: metadata.dynamic_size,
    };
    let mut relro = Vec::new();
    if bind_now {
        let protected_start = match (plt_got_relro, got_relro) {
            (Some(plt_got), Some(got)) => plt_got.address.min(got.address),
            (Some(plt_got), None) => plt_got.address,
            (None, Some(got)) => got.address,
            (None, None) => metadata_address,
        };
        let metadata_end = metadata_address
            .checked_add(metadata_size)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let protected_size = metadata_end
            .checked_sub(protected_start)
            .ok_or(SharedObjectError::AddressOverflow)?;

        // GNU/Linux exposes one effective RELRO interval per loaded object.
        // Bind-now therefore places the page-isolated GOTPLT/GOT after TLS and
        // immediately before the padded loader metadata, so one contiguous
        // PT_GNU_RELRO covers every table the loader finishes mutating before
        // control reaches user code.
        relro.push(RuntimeRelroProgramHeader {
            address: protected_start,
            size: protected_size,
        });
    } else if let Some(address) = coalesced_relro_start {
        let metadata_end = metadata_address
            .checked_add(metadata_size)
            .ok_or(SharedObjectError::AddressOverflow)?;
        let size = metadata_end
            .checked_sub(address)
            .ok_or(SharedObjectError::AddressOverflow)?;
        // Coalesced dynamic-PIE RELRO: the tail-isolated ordinary/TLS GOT and
        // the padded loader metadata now share one contiguous RW PT_LOAD.
        // GOTPLT stays earlier in the image and remains writable for lazy
        // JUMP_SLOT binding.
        relro.push(RuntimeRelroProgramHeader { address, size });
    } else if let Some(region) = got_relro {
        // If later image state prevents a contiguous interval, retain the
        // already-qualified GOT/TLS-GOT protection rather than stretching
        // RELRO across unrelated or non-contiguous runtime state.
        relro.push(RuntimeRelroProgramHeader {
            address: region.address,
            size: region.size,
        });
    } else if metadata_relro {
        // When no loader-bound GOT state exists, the page-aligned synthetic
        // loader metadata block remains the object's single RELRO interval.
        relro.push(RuntimeRelroProgramHeader {
            address: metadata_address,
            size: metadata_size,
        });
    }

    if let Some(address) = gnu_property_address {
        let property = RuntimeGnuPropertyProgramHeader {
            address,
            size: GNU_PROPERTY_NOTE_SIZE,
        };
        return match (interpreter_address, interpreter) {
            (Some(interp_address), Some(path)) if !relro.is_empty() => {
                map_runtime_program_headers_with_dynamic_interp_relros_and_gnu_property(
                    image,
                    dynamic,
                    RuntimeInterpProgramHeader {
                        address: interp_address,
                        size: u64::try_from(path.len() + 1)
                            .map_err(|_| SharedObjectError::MetadataTooLarge)?,
                    },
                    &relro,
                    property,
                )
                .map_err(SharedObjectError::Write)
            }
            (Some(interp_address), Some(path)) => {
                map_runtime_program_headers_with_dynamic_interp_and_gnu_property(
                    image,
                    dynamic,
                    RuntimeInterpProgramHeader {
                        address: interp_address,
                        size: u64::try_from(path.len() + 1)
                            .map_err(|_| SharedObjectError::MetadataTooLarge)?,
                    },
                    property,
                )
                .map_err(SharedObjectError::Write)
            }
            (None, None) if relro.is_empty() => {
                map_runtime_program_headers_with_dynamic_and_gnu_property(image, dynamic, property)
                    .map_err(SharedObjectError::Write)
            }
            (None, None) => map_runtime_program_headers_with_dynamic_relros_and_gnu_property(
                image, dynamic, &relro, property,
            )
            .map_err(SharedObjectError::Write),
            _ => unreachable!("interpreter payload and path are constructed together"),
        };
    }

    match (interpreter_address, interpreter) {
        (Some(address), Some(path)) if !relro.is_empty() => {
            map_runtime_program_headers_with_dynamic_interp_and_relros(
                image,
                dynamic,
                RuntimeInterpProgramHeader {
                    address,
                    size: u64::try_from(path.len() + 1)
                        .map_err(|_| SharedObjectError::MetadataTooLarge)?,
                },
                &relro,
            )
            .map_err(SharedObjectError::Write)
        }
        (Some(address), Some(path)) => map_runtime_program_headers_with_dynamic_and_interp(
            image,
            dynamic,
            RuntimeInterpProgramHeader {
                address,
                size: u64::try_from(path.len() + 1)
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?,
            },
        )
        .map_err(SharedObjectError::Write),
        (None, None) if !relro.is_empty() => {
            map_runtime_program_headers_with_dynamic_and_relros(image, dynamic, &relro)
                .map_err(SharedObjectError::Write)
        }
        (None, None) => map_runtime_program_headers_with_dynamic(image, dynamic)
            .map_err(SharedObjectError::Write),
        _ => unreachable!("interpreter payload and path are constructed together"),
    }
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

fn validate_version_requirements(
    checked_providers: &[Vec<u8>],
    imports: &BTreeMap<Vec<u8>, ImportSymbol>,
    requirements: &[SharedVersionRequirement],
) -> Result<(), SharedObjectError> {
    let mut requirement_names = BTreeSet::new();
    for requirement in requirements {
        if !checked_providers
            .iter()
            .any(|name| name == &requirement.provider)
        {
            return Err(SharedObjectError::VersionRequirementProviderMissing {
                provider: requirement.provider.clone(),
            });
        }
        let valid = imports.get(&requirement.linker_name).is_some_and(|import| {
            import.version.as_deref() == Some(requirement.version.as_slice())
        });
        if !valid || !requirement_names.insert(requirement.linker_name.as_slice()) {
            let name = imports
                .get(&requirement.linker_name)
                .map(|import| import.dynamic_name.clone())
                .unwrap_or_else(|| requirement.linker_name.clone());
            return Err(SharedObjectError::InvalidVersionRequirement {
                name,
                version: requirement.version.clone(),
            });
        }
    }

    for (linker_name, import) in imports {
        let Some(version) = import.version.as_ref() else {
            continue;
        };
        if !requirement_names.contains(linker_name.as_slice()) {
            return Err(SharedObjectError::InvalidVersionRequirement {
                name: import.dynamic_name.clone(),
                version: version.clone(),
            });
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
    options: InputValidationOptions,
) -> Result<ImportPlan, SharedObjectError> {
    let mut import_symbols = BTreeMap::<Vec<u8>, ImportSymbol>::new();
    let mut symbol_relocation_sites = BTreeSet::<DynamicSymbolRelocationSite>::new();
    let mut got_symbols = BTreeSet::<Vec<u8>>::new();
    let mut relative_got_symbols = BTreeSet::<Vec<u8>>::new();
    let mut copy_symbols = BTreeSet::<Vec<u8>>::new();
    let mut copy_relocation_sites = BTreeSet::<DynamicSymbolRelocationSite>::new();
    let mut noncopy_import_symbols = BTreeSet::<Vec<u8>>::new();
    let mut plt_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_gd_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_ie_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_desc_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_desc_call_symbols = BTreeSet::<Vec<u8>>::new();
    let mut tls_desc_call_sites = BTreeSet::<DynamicSymbolRelocationSite>::new();
    let mut tls_ld_dtpoff_sites = BTreeSet::<DynamicSymbolRelocationSite>::new();
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
                if matches!(
                    relocation.relocation_type,
                    R_X86_64_GOTPC32_TLSDESC
                        | R_X86_64_TLSDESC_CALL
                        | R_X86_64_TLSGD
                        | R_X86_64_GOTTPOFF
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
                ) && !options.tls_policy.allows(relocation.relocation_type)
                {
                    return Err(SharedObjectError::DynamicExecutableTlsModelUnsupported {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        relocation_type: relocation.relocation_type,
                        name: symbol.name.to_vec(),
                    });
                }
                if relocation.relocation_type == R_X86_64_GOTPC32_TLSDESC
                    || relocation.relocation_type == R_X86_64_TLSDESC_CALL
                {
                    let unresolved = symbol.symbol.section_index == SHN_UNDEF
                        && !definitions.contains_key(symbol.name);
                    if options.tls_policy == LoaderTlsPolicy::DynamicPieGdIeDescLd
                        && !dynamic_pie_tls_reference_supported(
                            symbol.symbol.info,
                            symbol.symbol.other,
                            symbol_type,
                        )
                    {
                        return Err(SharedObjectError::DynamicExecutableTlsModelUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            relocation_type: relocation.relocation_type,
                            name: symbol.name.to_vec(),
                        });
                    }
                    let definition = definitions.get(symbol.name);
                    if !is_supported_dynamic_tls_reference(
                        symbol.symbol.info,
                        symbol.symbol.other,
                        symbol.name,
                        unresolved,
                        definition,
                    ) {
                        return Err(SharedObjectError::TlsDescUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            symbol_index: relocation.symbol_index,
                            name: symbol.name.to_vec(),
                        });
                    }
                    if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                        return Err(SharedObjectError::TlsDescTargetNotExecutable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        });
                    }
                    if unresolved {
                        if copy_symbols.contains(symbol.name) {
                            return Err(SharedObjectError::CopyRelocationMixedReference {
                                name: symbol.name.to_vec(),
                            });
                        }
                        noncopy_import_symbols.insert(symbol.name.to_vec());
                        record_import_symbol(
                            &mut import_symbols,
                            symbol.name,
                            symbol.symbol.info,
                            symbol.symbol.size,
                        )?;
                    }
                    if relocation.relocation_type == R_X86_64_GOTPC32_TLSDESC {
                        tls_desc_symbols.insert(symbol.name.to_vec());
                    } else {
                        tls_desc_call_symbols.insert(symbol.name.to_vec());
                        tls_desc_call_sites.insert(DynamicSymbolRelocationSite {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                        });
                    }
                    continue;
                }
                if relocation.relocation_type == R_X86_64_TLSGD {
                    let unresolved = symbol.symbol.section_index == SHN_UNDEF
                        && !definitions.contains_key(symbol.name);
                    if options.tls_policy == LoaderTlsPolicy::DynamicPieGdIeDescLd
                        && !dynamic_pie_tls_reference_supported(
                            symbol.symbol.info,
                            symbol.symbol.other,
                            symbol_type,
                        )
                    {
                        return Err(SharedObjectError::DynamicExecutableTlsModelUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            relocation_type: relocation.relocation_type,
                            name: symbol.name.to_vec(),
                        });
                    }
                    let definition = definitions.get(symbol.name);
                    if !is_supported_dynamic_tls_reference(
                        symbol.symbol.info,
                        symbol.symbol.other,
                        symbol.name,
                        unresolved,
                        definition,
                    ) {
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

                    if unresolved {
                        if copy_symbols.contains(symbol.name) {
                            return Err(SharedObjectError::CopyRelocationMixedReference {
                                name: symbol.name.to_vec(),
                            });
                        }
                        noncopy_import_symbols.insert(symbol.name.to_vec());
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
                    let unresolved = symbol.symbol.section_index == SHN_UNDEF
                        && !definitions.contains_key(symbol.name);
                    if options.tls_policy == LoaderTlsPolicy::DynamicPieGdIeDescLd
                        && !dynamic_pie_tls_reference_supported(
                            symbol.symbol.info,
                            symbol.symbol.other,
                            symbol_type,
                        )
                    {
                        return Err(SharedObjectError::DynamicExecutableTlsModelUnsupported {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            relocation_type: relocation.relocation_type,
                            name: symbol.name.to_vec(),
                        });
                    }
                    let definition = definitions.get(symbol.name);
                    if !is_supported_dynamic_tls_reference(
                        symbol.symbol.info,
                        symbol.symbol.other,
                        symbol.name,
                        unresolved,
                        definition,
                    ) {
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
                        if copy_symbols.contains(symbol.name) {
                            return Err(SharedObjectError::CopyRelocationMixedReference {
                                name: symbol.name.to_vec(),
                            });
                        }
                        noncopy_import_symbols.insert(symbol.name.to_vec());
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
                        tls_ld_dtpoff_sites.insert(DynamicSymbolRelocationSite {
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
                let supported = matches!(
                    relocation.relocation_type,
                    R_X86_64_64
                        | R_X86_64_PLT32
                        | R_X86_64_TLSGD
                        | R_X86_64_GOTPC32_TLSDESC
                        | R_X86_64_TLSDESC_CALL
                        | R_X86_64_GOTTPOFF
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
                ) || is_loader_gotpcrel_type(relocation.relocation_type);
                !supported
                    && !(options.allow_copy_relocations
                        && relocation.relocation_type == R_X86_64_PC32)
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
                let is_got_import = is_loader_gotpcrel_type(relocation.relocation_type);
                let is_plt_import = relocation.relocation_type == R_X86_64_PLT32;
                let is_copy_import =
                    options.allow_copy_relocations && relocation.relocation_type == R_X86_64_PC32;
                if matches!(
                    relocation.relocation_type,
                    R_X86_64_TLSGD
                        | R_X86_64_GOTPC32_TLSDESC
                        | R_X86_64_TLSDESC_CALL
                        | R_X86_64_GOTTPOFF
                        | R_X86_64_TLSLD
                        | R_X86_64_DTPOFF32
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
                    let supported_definition = !symbol.name.is_empty()
                        && definitions.get(symbol.name).is_some_and(|definition| {
                            let definition_binding = definition.symbol.info >> 4;
                            let definition_type = definition.symbol.info & 0x0f;
                            definition_binding == STB_GLOBAL
                                && matches!(definition_type, STT_OBJECT | STT_FUNC)
                                && definition.symbol.other == 0
                        });
                    let protected_definition = !symbol.name.is_empty()
                        && definitions.get(symbol.name).is_some_and(|definition| {
                            let definition_binding = definition.symbol.info >> 4;
                            let definition_type = definition.symbol.info & 0x0f;
                            definition_binding == STB_GLOBAL
                                && matches!(definition_type, STT_OBJECT | STT_FUNC)
                                && definition.symbol.other == STV_PROTECTED
                                && definition.symbol.section_index != SHN_ABS
                        });
                    if is_got_import && supported_definition {
                        got_symbols.insert(symbol.name.to_vec());
                        continue;
                    }
                    if is_got_import && protected_definition {
                        relative_got_symbols.insert(symbol.name.to_vec());
                        continue;
                    }
                    let supported_plt_definition = is_plt_import
                        && definitions.get(symbol.name).is_some_and(|definition| {
                            let definition_binding = definition.symbol.info >> 4;
                            let definition_type = definition.symbol.info & 0x0f;
                            definition_binding == STB_GLOBAL
                                && definition_type == STT_FUNC
                                && definition.symbol.other == 0
                        });
                    if supported_plt_definition {
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
                    let protected_plt_definition = is_plt_import
                        && definitions.get(symbol.name).is_some_and(|definition| {
                            let definition_binding = definition.symbol.info >> 4;
                            let definition_type = definition.symbol.info & 0x0f;
                            definition_binding == STB_GLOBAL
                                && definition_type == STT_FUNC
                                && definition.symbol.other == STV_PROTECTED
                                && definition.symbol.section_index != SHN_ABS
                        });
                    if protected_plt_definition {
                        if target.flags & SHF_ALLOC == 0 || target.flags & SHF_EXECINSTR == 0 {
                            return Err(SharedObjectError::ExternalPltTargetNotExecutable {
                                object_index: input.object_index,
                                rela_section_index: table.section_index,
                                relocation_index,
                                target_section_index: table.target_section_index,
                                flags: target.flags,
                            });
                        }
                        continue;
                    }
                    let image_backed_definition = definitions
                        .get(symbol.name)
                        .is_some_and(|definition| definition.symbol.section_index != SHN_ABS);
                    if options.allow_defined_pc32
                        && relocation.relocation_type == R_X86_64_PC32
                        && target.flags & SHF_ALLOC != 0
                        && image_backed_definition
                        && (supported_definition || protected_definition)
                    {
                        // Definitions in the main executable are locally bound
                        // for its own direct PC-relative references. Keep shared
                        // objects on the existing interposition-aware path.
                        continue;
                    }
                    if relocation.relocation_type == R_X86_64_64
                        && (supported_definition || protected_definition)
                    {
                        if target.flags & SHF_ALLOC == 0 || target.flags & SHF_WRITE == 0 {
                            return Err(
                                SharedObjectError::DynamicSymbolRelocationTargetNotWritable {
                                    object_index: input.object_index,
                                    rela_section_index: table.section_index,
                                    relocation_index,
                                    target_section_index: table.target_section_index,
                                    flags: target.flags,
                                },
                            );
                        }
                        if supported_definition {
                            symbol_relocation_sites.insert(DynamicSymbolRelocationSite {
                                object_index: input.object_index,
                                rela_section_index: table.section_index,
                                relocation_index,
                            });
                        }
                        continue;
                    }
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
                    || (binding == STB_WEAK
                        && matches!(symbol_type, STT_OBJECT | STT_FUNC)
                        && (!is_plt_import || symbol_type == STT_FUNC));
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

                if is_copy_import {
                    if binding != STB_GLOBAL || symbol_type != STT_OBJECT {
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
                    let (_, version) = parse_import_identity(symbol.name)?;
                    if version.is_some() {
                        return Err(SharedObjectError::UnsupportedVersionedImportType {
                            name: symbol.name.to_vec(),
                            symbol_type,
                        });
                    }
                    if noncopy_import_symbols.contains(symbol.name)
                        && !got_symbols.contains(symbol.name)
                    {
                        return Err(SharedObjectError::CopyRelocationMixedReference {
                            name: symbol.name.to_vec(),
                        });
                    }
                    record_import_symbol(
                        &mut import_symbols,
                        symbol.name,
                        symbol.symbol.info,
                        symbol.symbol.size,
                    )?;
                    copy_symbols.insert(symbol.name.to_vec());
                    copy_relocation_sites.insert(DynamicSymbolRelocationSite {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                    });
                    continue;
                }

                let tls_get_addr_notype =
                    is_plt_import && symbol.name == b"__tls_get_addr" && symbol_type == STT_NOTYPE;
                let plt_notype_function = is_plt_import
                    && options.allow_plt_notype_function_imports
                    && symbol_type == STT_NOTYPE;
                if is_plt_import
                    && symbol_type != STT_FUNC
                    && !tls_get_addr_notype
                    && !plt_notype_function
                {
                    return Err(SharedObjectError::ExternalPltUnsupportedType {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        symbol_index: relocation.symbol_index,
                        name: symbol.name.to_vec(),
                        symbol_type,
                    });
                }
                let supported_nonplt_import_type = matches!(symbol_type, STT_OBJECT | STT_FUNC)
                    || (options.allow_explicit_ifunc_imports && symbol_type == STT_GNU_IFUNC);
                if !is_plt_import && !supported_nonplt_import_type {
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

                if copy_symbols.contains(symbol.name) && !is_got_import {
                    return Err(SharedObjectError::CopyRelocationMixedReference {
                        name: symbol.name.to_vec(),
                    });
                }
                noncopy_import_symbols.insert(symbol.name.to_vec());
                let import_info = if plt_notype_function {
                    (binding << 4) | STT_FUNC
                } else {
                    symbol.symbol.info
                };
                record_import_symbol(
                    &mut import_symbols,
                    symbol.name,
                    import_info,
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
                    return Err(
                        SharedObjectError::DynamicSymbolRelocationTargetNotWritable {
                            object_index: input.object_index,
                            rela_section_index: table.section_index,
                            relocation_index,
                            target_section_index: table.target_section_index,
                            flags: target.flags,
                        },
                    );
                }
                symbol_relocation_sites.insert(DynamicSymbolRelocationSite {
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
                let symbol_type = symbol.symbol.info & 0x0f;
                let protected_definition = symbol.symbol.other == STV_PROTECTED
                    && binding == STB_GLOBAL
                    && matches!(symbol_type, STT_OBJECT | STT_FUNC | STT_TLS)
                    && symbol.symbol.section_index != SHN_UNDEF
                    && symbol.symbol.section_index != SHN_ABS;
                if symbol.symbol.other != 0 && !protected_definition {
                    return Err(SharedObjectError::NondefaultVisibility {
                        object_index: input.object_index,
                        symbol_index: symbol.symbol_index,
                        name: symbol.name.to_vec(),
                        other: symbol.symbol.other,
                    });
                }
                if symbol.symbol.section_index == SHN_UNDEF && !symbol.name.is_empty() {
                    if definitions.contains_key(symbol.name) {
                        continue;
                    }
                    if symbol_type == STT_TLS {
                        let supported_tls_model = (binding == STB_GLOBAL
                            && (tls_gd_symbols.contains(symbol.name)
                                || tls_ie_symbols.contains(symbol.name)
                                || tls_desc_symbols.contains(symbol.name)))
                            || (binding == STB_WEAK
                                && (tls_gd_symbols.contains(symbol.name)
                                    || tls_ie_symbols.contains(symbol.name)
                                    || tls_desc_symbols.contains(symbol.name)));
                        let supported_tls_import =
                            import_symbols.contains_key(symbol.name) && supported_tls_model;
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
                        || !relative_got_symbols.is_empty()
                        || !tls_gd_symbols.is_empty()
                        || !tls_ie_symbols.is_empty()
                        || !tls_desc_symbols.is_empty()
                        || uses_tls_ld)
                        && symbol.name == GLOBAL_OFFSET_TABLE_SYMBOL
                        && binding == STB_GLOBAL
                        && symbol_type == STT_NOTYPE;
                    if linker_owned_got_symbol {
                        continue;
                    }
                    let tls_get_addr_notype =
                        symbol.name == b"__tls_get_addr" && symbol_type == STT_NOTYPE;
                    let explicit_ifunc_import =
                        options.allow_explicit_ifunc_imports && symbol_type == STT_GNU_IFUNC;
                    let normalized_plt_notype = symbol_type == STT_NOTYPE
                        && import_symbols
                            .get(symbol.name)
                            .is_some_and(|import| import.info & 0x0f == STT_FUNC);
                    let supported_import = import_symbols.contains_key(symbol.name)
                        && (binding == STB_GLOBAL
                            || (binding == STB_WEAK
                                && (matches!(symbol_type, STT_OBJECT | STT_FUNC)
                                    || normalized_plt_notype)))
                        && (matches!(symbol_type, STT_OBJECT | STT_FUNC)
                            || explicit_ifunc_import
                            || tls_get_addr_notype
                            || normalized_plt_notype);
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
    if tls_desc_symbols != tls_desc_call_symbols {
        return Err(SharedObjectError::IncompleteTlsDescSequence);
    }

    Ok(ImportPlan {
        symbols: import_symbols,
        symbol_relocation_sites,
        got_symbols,
        relative_got_symbols,
        copy_symbols,
        copy_relocation_sites,
        plt_symbols,
        tls_gd_symbols,
        tls_ie_symbols,
        tls_desc_symbols,
        tls_desc_call_sites,
        tls_ld_dtpoff_sites,
        uses_tls_ld,
    })
}

fn validate_dynamic_pie_copy_metadata(
    planned: &BTreeSet<Vec<u8>>,
    metadata: Option<&[DynamicPieCopyRelocation]>,
) -> Result<BTreeMap<Vec<u8>, u64>, SharedObjectError> {
    let Some(metadata) = metadata else {
        debug_assert!(planned.is_empty());
        return Ok(BTreeMap::new());
    };

    let mut sizes = BTreeMap::new();
    for copy in metadata {
        if !planned.contains(&copy.linker_name) {
            return Err(SharedObjectError::UnexpectedCopyMetadata {
                name: copy.linker_name.clone(),
            });
        }
        if copy.size == 0 {
            return Err(SharedObjectError::InvalidCopySize {
                name: copy.linker_name.clone(),
                size: copy.size,
            });
        }
        if sizes.insert(copy.linker_name.clone(), copy.size).is_some() {
            return Err(SharedObjectError::UnexpectedCopyMetadata {
                name: copy.linker_name.clone(),
            });
        }
    }
    for name in planned {
        if !sizes.contains_key(name) {
            return Err(SharedObjectError::MissingCopyMetadata { name: name.clone() });
        }
    }
    Ok(sizes)
}

fn allocate_dynamic_pie_copy_storage(
    sections: &mut Vec<RelocatedSectionImage>,
    sizes: &BTreeMap<Vec<u8>, u64>,
) -> Result<BTreeMap<Vec<u8>, u64>, SharedObjectError> {
    if sizes.is_empty() {
        return Ok(BTreeMap::new());
    }

    let mut cursor = sections
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
        .unwrap_or(0);
    cursor = align_up(cursor, DYNAMIC_COPY_ALIGNMENT).ok_or(SharedObjectError::AddressOverflow)?;
    let base = cursor;
    let mut addresses = BTreeMap::new();
    for (name, size) in sizes {
        cursor =
            align_up(cursor, DYNAMIC_COPY_ALIGNMENT).ok_or(SharedObjectError::AddressOverflow)?;
        addresses.insert(name.clone(), cursor);
        cursor = cursor
            .checked_add(*size)
            .ok_or(SharedObjectError::AddressOverflow)?;
    }
    let total_size = cursor
        .checked_sub(base)
        .ok_or(SharedObjectError::AddressOverflow)?;
    sections.push(RelocatedSectionImage {
        object_index: DYNAMIC_COPY_OBJECT_INDEX,
        section_index: DYNAMIC_COPY_SECTION_INDEX,
        section_type: SHT_NOBITS,
        flags: SHF_ALLOC | SHF_WRITE,
        address: base,
        size: total_size,
        alignment: DYNAMIC_COPY_ALIGNMENT,
        bytes: Vec::new(),
    });
    Ok(addresses)
}

fn apply_dynamic_pie_copy_relocations(
    inputs: &[LinkerInputObject<'_>],
    sections: &mut [RelocatedSectionImage],
    sites: &BTreeSet<DynamicSymbolRelocationSite>,
    addresses: &BTreeMap<Vec<u8>, u64>,
) -> Result<(), SharedObjectError> {
    for site in sites {
        let input = inputs
            .iter()
            .find(|input| input.object_index == site.object_index)
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
        debug_assert_eq!(relocation.relocation_type, R_X86_64_PC32);
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
        let symbol = &symbols[relocation.symbol_index as usize];
        let copy_address = addresses.get(symbol.name).copied().ok_or_else(|| {
            SharedObjectError::MissingCopyMetadata {
                name: symbol.name.to_vec(),
            }
        })?;
        let target = sections
            .iter_mut()
            .find(|section| {
                section.object_index == input.object_index
                    && section.section_index == table.target_section_index
            })
            .ok_or(SharedObjectError::MissingCopyRelocationTarget {
                object_index: input.object_index,
                target_section_index: table.target_section_index,
            })?;
        let place = target
            .address
            .checked_add(relocation.offset)
            .ok_or(SharedObjectError::AddressOverflow)?;
        apply_relocation(&mut target.bytes, relocation, copy_address, place).map_err(|source| {
            SharedObjectError::CopyRelocationApply {
                object_index: input.object_index,
                rela_section_index: table.section_index,
                relocation_index: site.relocation_index,
                source,
            }
        })?;
    }
    Ok(())
}

fn mask_deferred_relocations<'a>(
    inputs: &[LinkerInputObject<'a>],
    sites: &BTreeSet<DynamicSymbolRelocationSite>,
) -> Vec<LinkerInputObject<'a>> {
    inputs
        .iter()
        .map(|input| {
            let mut object = input.object.clone();
            for table in &mut object.rela_tables {
                for (relocation_index, relocation) in table.relocations.iter_mut().enumerate() {
                    if sites.contains(&DynamicSymbolRelocationSite {
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
            Ok((export.linker_name.clone(), index))
        })
        .collect()
}

fn apply_tls_ld_dtpoff32_relocations(
    inputs: &[LinkerInputObject<'_>],
    sections: &mut [RelocatedSectionImage],
    sites: &BTreeSet<DynamicSymbolRelocationSite>,
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

fn build_tls_desc_relocation_table(
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
        let descriptor = entries
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsDescEntry { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .or_else(|| import_dynamic_indices.get(name))
            .copied()
            .ok_or_else(|| SharedObjectError::MissingTlsDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_TLSDESC);
        bytes.extend_from_slice(&descriptor.to_le_bytes());
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

fn build_dynamic_symbol_relocation_table(
    inputs: &[LinkerInputObject<'_>],
    sections: &[RelocatedSectionImage],
    sites: &BTreeSet<DynamicSymbolRelocationSite>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
    import_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let mut bytes = Vec::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .enumerate()
                .any(|(relocation_index, _)| {
                    sites.contains(&DynamicSymbolRelocationSite {
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
                .ok_or(SharedObjectError::MissingDynamicSymbolRelocationTarget {
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
                let site = DynamicSymbolRelocationSite {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    relocation_index,
                };
                if !sites.contains(&site) {
                    continue;
                }

                let end = relocation.offset.checked_add(8).ok_or(
                    SharedObjectError::DynamicSymbolRelocationOutOfBounds {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        target_section_index: table.target_section_index,
                        offset: relocation.offset,
                        target_size: target.size,
                    },
                )?;
                if end > target.size {
                    return Err(SharedObjectError::DynamicSymbolRelocationOutOfBounds {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        relocation_index,
                        target_section_index: table.target_section_index,
                        offset: relocation.offset,
                        target_size: target.size,
                    });
                }

                let symbol = &symbols[relocation.symbol_index as usize];
                let dynamic_index = export_dynamic_indices
                    .get(symbol.name)
                    .or_else(|| import_dynamic_indices.get(symbol.name))
                    .copied()
                    .ok_or_else(|| SharedObjectError::MissingDynamicSymbol {
                        name: symbol.name.to_vec(),
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

fn build_copy_relocation_table(
    copy_symbols: &BTreeSet<Vec<u8>>,
    copy_addresses: &BTreeMap<Vec<u8>, u64>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
) -> Result<Vec<u8>, SharedObjectError> {
    let capacity = copy_symbols
        .len()
        .checked_mul(ELF64_RELA_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity);
    for name in copy_symbols {
        let offset = copy_addresses
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingCopyMetadata { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .copied()
            .ok_or_else(|| SharedObjectError::MissingDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_COPY);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }
    Ok(bytes)
}

fn build_got_relocation_table(
    got_symbols: &BTreeSet<Vec<u8>>,
    got_entries: &BTreeMap<Vec<u8>, u64>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
    import_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
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
            .ok_or_else(|| SharedObjectError::MissingGotEntry { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .or_else(|| import_dynamic_indices.get(name))
            .copied()
            .ok_or_else(|| SharedObjectError::MissingGotDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_GLOB_DAT);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
}

fn build_plt_relocation_table(
    plt_symbols: &BTreeSet<Vec<u8>>,
    plt_got_entries: &BTreeMap<Vec<u8>, u64>,
    export_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
    import_dynamic_indices: &BTreeMap<Vec<u8>, u32>,
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
            .ok_or_else(|| SharedObjectError::MissingPltGotEntry { name: name.clone() })?;
        let dynamic_index = export_dynamic_indices
            .get(name)
            .or_else(|| import_dynamic_indices.get(name))
            .copied()
            .ok_or_else(|| SharedObjectError::MissingDynamicSymbol { name: name.clone() })?;
        let info = (u64::from(dynamic_index) << 32) | u64::from(R_X86_64_JUMP_SLOT);
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&info.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
    }

    Ok(bytes)
}

#[derive(Debug)]
struct VersionMetadata {
    versym: Vec<u8>,
    verdef: Vec<u8>,
    definition_count: usize,
    verneed: Vec<u8>,
    provider_count: usize,
}

fn append_dynamic_string(table: &mut Vec<u8>, value: &[u8]) -> Result<u32, SharedObjectError> {
    let offset = u32::try_from(table.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
    table.extend_from_slice(value);
    table.push(0);
    Ok(offset)
}

fn build_version_metadata(
    exports: &[ExportSymbol],
    imports: &BTreeMap<Vec<u8>, ImportSymbol>,
    requirements: &[SharedVersionRequirement],
    version_script: Option<&VersionScript>,
    dynstr: &mut Vec<u8>,
) -> Result<VersionMetadata, SharedObjectError> {
    let mut local_versions = exports
        .iter()
        .filter_map(|export| export.version.clone())
        .collect::<BTreeSet<_>>();
    if let Some(script) = version_script {
        local_versions.extend(script.versions().map(ToOwned::to_owned));
    }

    let mut group_keys = BTreeSet::<(Vec<u8>, Vec<u8>)>::new();
    let mut requirement_by_linker = BTreeMap::<Vec<u8>, (Vec<u8>, Vec<u8>)>::new();
    for requirement in requirements {
        let key = (requirement.provider.clone(), requirement.version.clone());
        group_keys.insert(key.clone());
        match requirement_by_linker.get(&requirement.linker_name) {
            Some(existing) if existing != &key => {
                return Err(SharedObjectError::InvalidVersionRequirement {
                    name: requirement.linker_name.clone(),
                    version: requirement.version.clone(),
                });
            }
            Some(_) => {}
            None => {
                requirement_by_linker.insert(requirement.linker_name.clone(), key);
            }
        }
    }

    if local_versions.is_empty() && group_keys.is_empty() {
        return Ok(VersionMetadata {
            versym: Vec::new(),
            verdef: Vec::new(),
            definition_count: 0,
            verneed: Vec::new(),
            provider_count: 0,
        });
    }

    let mut next_index = usize::from(VERSYM_FIRST_VERSION);
    let mut local_indices = BTreeMap::<Vec<u8>, u16>::new();
    for version in &local_versions {
        let index = u16::try_from(next_index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        if index > VERSYM_INDEX_MASK {
            return Err(SharedObjectError::MetadataTooLarge);
        }
        local_indices.insert(version.clone(), index);
        next_index = next_index
            .checked_add(1)
            .ok_or(SharedObjectError::MetadataTooLarge)?;
    }

    let mut group_indices = BTreeMap::<(Vec<u8>, Vec<u8>), u16>::new();
    for key in group_keys {
        let index = u16::try_from(next_index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        if index > VERSYM_INDEX_MASK {
            return Err(SharedObjectError::MetadataTooLarge);
        }
        group_indices.insert(key, index);
        next_index = next_index
            .checked_add(1)
            .ok_or(SharedObjectError::MetadataTooLarge)?;
    }

    let symbol_count = exports
        .len()
        .checked_add(imports.len())
        .and_then(|count| count.checked_add(1))
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let versym_size = symbol_count
        .checked_mul(2)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let mut versym = vec![0_u8; versym_size];
    for symbol_index in 1..symbol_count {
        put_u16(&mut versym, symbol_index * 2, VERSYM_GLOBAL);
    }

    for (offset, export) in exports.iter().enumerate() {
        let Some(version) = export.version.as_ref() else {
            continue;
        };
        let mut index = local_indices
            .get(version)
            .copied()
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        if !export.is_default_version {
            index |= VERSYM_HIDDEN;
        }
        put_u16(&mut versym, (offset + 1) * 2, index);
    }

    for (offset, (linker_name, import)) in imports.iter().enumerate() {
        let Some(version) = import.version.as_ref() else {
            continue;
        };
        let key = requirement_by_linker.get(linker_name).ok_or_else(|| {
            SharedObjectError::InvalidVersionRequirement {
                name: import.dynamic_name.clone(),
                version: version.clone(),
            }
        })?;
        if &key.1 != version {
            return Err(SharedObjectError::InvalidVersionRequirement {
                name: import.dynamic_name.clone(),
                version: version.clone(),
            });
        }
        let version_index = group_indices
            .get(key)
            .copied()
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        let symbol_index = 1usize
            .checked_add(exports.len())
            .and_then(|index| index.checked_add(offset))
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        put_u16(&mut versym, symbol_index * 2, version_index);
    }

    let mut local_name_offsets = BTreeMap::<Vec<u8>, u32>::new();
    for version in &local_versions {
        local_name_offsets.insert(version.clone(), append_dynamic_string(dynstr, version)?);
    }

    let mut verdef = Vec::new();
    let definition_count = local_versions.len();
    for (definition_index, version) in local_versions.iter().enumerate() {
        let index = local_indices
            .get(version)
            .copied()
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        let parent = version_script.and_then(|script| script.parent_for(version));
        let aux_count = 1usize + usize::from(parent.is_some());
        let record_size = ELF64_VERDEF_SIZE
            .checked_add(
                aux_count
                    .checked_mul(ELF64_VERDAUX_SIZE)
                    .ok_or(SharedObjectError::MetadataTooLarge)?,
            )
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        let next = if definition_index + 1 == definition_count {
            0
        } else {
            u32::try_from(record_size).map_err(|_| SharedObjectError::MetadataTooLarge)?
        };

        verdef.extend_from_slice(&VER_DEF_CURRENT.to_le_bytes());
        verdef.extend_from_slice(&0_u16.to_le_bytes());
        verdef.extend_from_slice(&index.to_le_bytes());
        verdef.extend_from_slice(
            &u16::try_from(aux_count)
                .map_err(|_| SharedObjectError::MetadataTooLarge)?
                .to_le_bytes(),
        );
        verdef.extend_from_slice(&sysv_elf_hash(version).to_le_bytes());
        verdef.extend_from_slice(&(ELF64_VERDEF_SIZE as u32).to_le_bytes());
        verdef.extend_from_slice(&next.to_le_bytes());
        verdef.extend_from_slice(
            &local_name_offsets
                .get(version)
                .copied()
                .ok_or(SharedObjectError::MetadataTooLarge)?
                .to_le_bytes(),
        );
        verdef.extend_from_slice(
            &(if parent.is_some() {
                ELF64_VERDAUX_SIZE as u32
            } else {
                0
            })
            .to_le_bytes(),
        );
        if let Some(parent) = parent {
            verdef.extend_from_slice(
                &local_name_offsets
                    .get(parent)
                    .copied()
                    .ok_or(SharedObjectError::MetadataTooLarge)?
                    .to_le_bytes(),
            );
            verdef.extend_from_slice(&0_u32.to_le_bytes());
        }
    }

    let mut providers = BTreeMap::<Vec<u8>, Vec<(Vec<u8>, u16)>>::new();
    for ((provider, version), index) in &group_indices {
        providers
            .entry(provider.clone())
            .or_default()
            .push((version.clone(), *index));
    }

    let mut provider_offsets = BTreeMap::<Vec<u8>, u32>::new();
    let mut version_offsets = BTreeMap::<(Vec<u8>, Vec<u8>), u32>::new();
    for (provider, versions) in &providers {
        let provider_offset = append_dynamic_string(dynstr, provider)?;
        provider_offsets.insert(provider.clone(), provider_offset);
        for (version, _) in versions {
            let offset = append_dynamic_string(dynstr, version)?;
            version_offsets.insert((provider.clone(), version.clone()), offset);
        }
    }

    let mut verneed = Vec::new();
    let provider_count = providers.len();
    for (provider_index, (provider, versions)) in providers.iter().enumerate() {
        let record_size = ELF64_VERNEED_SIZE
            .checked_add(
                versions
                    .len()
                    .checked_mul(ELF64_VERNAUX_SIZE)
                    .ok_or(SharedObjectError::MetadataTooLarge)?,
            )
            .ok_or(SharedObjectError::MetadataTooLarge)?;
        let next = if provider_index + 1 == provider_count {
            0
        } else {
            u32::try_from(record_size).map_err(|_| SharedObjectError::MetadataTooLarge)?
        };
        verneed.extend_from_slice(&VER_NEED_CURRENT.to_le_bytes());
        verneed.extend_from_slice(
            &u16::try_from(versions.len())
                .map_err(|_| SharedObjectError::MetadataTooLarge)?
                .to_le_bytes(),
        );
        verneed.extend_from_slice(
            &provider_offsets
                .get(provider)
                .copied()
                .ok_or(SharedObjectError::MetadataTooLarge)?
                .to_le_bytes(),
        );
        verneed.extend_from_slice(&(ELF64_VERNEED_SIZE as u32).to_le_bytes());
        verneed.extend_from_slice(&next.to_le_bytes());

        for (version_index, (version, index)) in versions.iter().enumerate() {
            verneed.extend_from_slice(&sysv_elf_hash(version).to_le_bytes());
            verneed.extend_from_slice(&0_u16.to_le_bytes());
            verneed.extend_from_slice(&index.to_le_bytes());
            verneed.extend_from_slice(
                &version_offsets
                    .get(&(provider.clone(), version.clone()))
                    .copied()
                    .ok_or(SharedObjectError::MetadataTooLarge)?
                    .to_le_bytes(),
            );
            let next = if version_index + 1 == versions.len() {
                0
            } else {
                ELF64_VERNAUX_SIZE as u32
            };
            verneed.extend_from_slice(&next.to_le_bytes());
        }
    }

    Ok(VersionMetadata {
        versym,
        verdef,
        definition_count,
        verneed,
        provider_count,
    })
}

fn reject_shared_preinit_arrays(inputs: &[LinkerInputObject<'_>]) -> Result<(), SharedObjectError> {
    for input in inputs {
        for (section_index, section) in input.object.sections.iter().enumerate() {
            if section.section_type != SHT_PREINIT_ARRAY {
                continue;
            }
            let section_index =
                u16::try_from(section_index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
            return Err(SharedObjectError::SharedPreinitUnsupported {
                object_index: input.object_index,
                section_index,
            });
        }
    }
    Ok(())
}

fn loader_lifecycle_layout_tail_order(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<(usize, u16)>, SharedObjectError> {
    let mut order = Vec::new();

    for (section_type, prefix) in [
        (SHT_INIT_ARRAY, b".init_array".as_slice()),
        (SHT_FINI_ARRAY, b".fini_array".as_slice()),
    ] {
        let mut entries = Vec::new();
        for input in inputs {
            for (section_index, section) in input.object.sections.iter().enumerate() {
                if section.section_type != section_type || section.size == 0 {
                    continue;
                }
                let section_index = u16::try_from(section_index)
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?;
                let name = section_name(input, section_index).map_err(|source| {
                    SharedObjectError::DynamicLifecycleSectionName {
                        object_index: input.object_index,
                        section_index,
                        reason: source.to_string(),
                    }
                })?;
                entries.push((
                    lifecycle_priority(name, prefix),
                    (input.object_index, section_index),
                ));
            }
        }
        entries.sort_by(|(left, _), (right, _)| compare_lifecycle_priority(left, right));
        order.extend(entries.into_iter().map(|(_, identity)| identity));
    }

    Ok(order)
}

fn lifecycle_priority(name: Option<&[u8]>, prefix: &[u8]) -> LifecyclePriority {
    let Some(name) = name else {
        return LifecyclePriority::Base;
    };
    if name == prefix {
        return LifecyclePriority::Base;
    }
    let Some(suffix) = name
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix(b"."))
    else {
        return LifecyclePriority::Base;
    };

    LifecyclePriority::Suffixed {
        numeric: parse_lifecycle_numeric_priority(suffix),
        suffix: suffix.to_vec(),
    }
}

fn parse_lifecycle_numeric_priority(suffix: &[u8]) -> Option<u32> {
    if suffix.is_empty() || !suffix.iter().all(u8::is_ascii_digit) {
        return None;
    }

    let mut value = 0u64;
    for byte in suffix {
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(*byte - b'0'))?;
        if value > i32::MAX as u64 {
            return None;
        }
    }
    Some(value as u32)
}

fn compare_lifecycle_priority(left: &LifecyclePriority, right: &LifecyclePriority) -> Ordering {
    match (left, right) {
        (
            LifecyclePriority::Suffixed {
                numeric: left_numeric,
                suffix: left_suffix,
            },
            LifecyclePriority::Suffixed {
                numeric: right_numeric,
                suffix: right_suffix,
            },
        ) => match (left_numeric, right_numeric) {
            (Some(left), Some(right)) => {
                left.cmp(right).then_with(|| left_suffix.cmp(right_suffix))
            }
            _ => left_suffix.cmp(right_suffix),
        },
        (LifecyclePriority::Suffixed { .. }, LifecyclePriority::Base) => Ordering::Less,
        (LifecyclePriority::Base, LifecyclePriority::Suffixed { .. }) => Ordering::Greater,
        (LifecyclePriority::Base, LifecyclePriority::Base) => Ordering::Equal,
    }
}

fn collect_shared_object_lifecycle(
    inputs: &[LinkerInputObject<'_>],
    relocated: &[RelocatedSectionImage],
    init_hook: Option<u64>,
    fini_hook: Option<u64>,
) -> Result<DynamicLifecycle, SharedObjectError> {
    let init = collect_lifecycle_kind(inputs, relocated, SHT_INIT_ARRAY)?;
    let fini = collect_lifecycle_kind(inputs, relocated, SHT_FINI_ARRAY)?;
    Ok(DynamicLifecycle {
        preinit: None,
        init,
        fini,
        init_hook,
        fini_hook,
    })
}

fn collect_dynamic_pie_lifecycle(
    inputs: &[LinkerInputObject<'_>],
    relocated: &[RelocatedSectionImage],
    init_hook: Option<u64>,
    fini_hook: Option<u64>,
) -> Result<DynamicLifecycle, SharedObjectError> {
    let preinit = collect_lifecycle_kind(inputs, relocated, SHT_PREINIT_ARRAY)?;
    let init = collect_lifecycle_kind(inputs, relocated, SHT_INIT_ARRAY)?;
    let fini = collect_lifecycle_kind(inputs, relocated, SHT_FINI_ARRAY)?;
    Ok(DynamicLifecycle {
        preinit,
        init,
        fini,
        init_hook,
        fini_hook,
    })
}

fn resolve_dynamic_lifecycle_hook(
    hook: &'static str,
    name: Option<&[u8]>,
    definitions: &BTreeMap<Vec<u8>, SymbolDefinition>,
    relocated: &[RelocatedSectionImage],
    layout: &[LaidOutSection],
) -> Result<Option<u64>, SharedObjectError> {
    let Some(name) = name else {
        return Ok(None);
    };
    let definition =
        definitions
            .get(name)
            .ok_or_else(|| SharedObjectError::DynamicLifecycleHookMissing {
                hook,
                name: name.to_vec(),
            })?;
    let symbol_type = definition.symbol.info & 0x0f;
    if symbol_type != STT_FUNC {
        return Err(SharedObjectError::DynamicLifecycleHookType {
            hook,
            name: name.to_vec(),
            symbol_type,
        });
    }
    if definition.symbol.section_index == SHN_ABS {
        return Err(SharedObjectError::DynamicLifecycleHookNotImageBacked {
            hook,
            name: name.to_vec(),
            object_index: definition.object_index,
            section_index: definition.symbol.section_index,
        });
    }
    let section = relocated
        .iter()
        .find(|section| {
            section.object_index == definition.object_index
                && section.section_index == definition.symbol.section_index
        })
        .ok_or_else(|| SharedObjectError::DynamicLifecycleHookNotImageBacked {
            hook,
            name: name.to_vec(),
            object_index: definition.object_index,
            section_index: definition.symbol.section_index,
        })?;
    if section.flags & SHF_ALLOC == 0 || section.flags & SHF_EXECINSTR == 0 {
        return Err(SharedObjectError::DynamicLifecycleHookNotExecutable {
            hook,
            name: name.to_vec(),
            object_index: definition.object_index,
            section_index: definition.symbol.section_index,
            flags: section.flags,
        });
    }
    let address =
        final_symbol_address(definition, layout).map_err(SharedObjectError::SymbolAddress)?;
    Ok(Some(address))
}

fn collect_lifecycle_kind(
    inputs: &[LinkerInputObject<'_>],
    relocated: &[RelocatedSectionImage],
    section_type: u32,
) -> Result<Option<DynamicLifecycleArray>, SharedObjectError> {
    let mut ranges = Vec::new();

    for input in inputs {
        for (section_index, section) in input.object.sections.iter().enumerate() {
            if section.section_type != section_type || section.size == 0 {
                continue;
            }
            let section_index =
                u16::try_from(section_index).map_err(|_| SharedObjectError::MetadataTooLarge)?;
            if section.flags & (SHF_ALLOC | SHF_WRITE) != (SHF_ALLOC | SHF_WRITE) {
                return Err(SharedObjectError::DynamicLifecycleSectionFlags {
                    object_index: input.object_index,
                    section_index,
                    section_type,
                    flags: section.flags,
                });
            }
            if section.size % 8 != 0 {
                return Err(SharedObjectError::DynamicLifecycleSectionSize {
                    object_index: input.object_index,
                    section_index,
                    section_type,
                    size: section.size,
                });
            }
            let output = relocated
                .iter()
                .find(|candidate| {
                    candidate.object_index == input.object_index
                        && candidate.section_index == section_index
                })
                .ok_or(SharedObjectError::DynamicLifecycleMissingRelocatedSection {
                    object_index: input.object_index,
                    section_index,
                    section_type,
                })?;
            ranges.push(DynamicLifecycleArray {
                address: output.address,
                size: output.size,
            });
        }
    }

    if ranges.is_empty() {
        return Ok(None);
    }
    ranges.sort_by_key(|range| range.address);
    let first = ranges[0];
    let mut end = first
        .address
        .checked_add(first.size)
        .ok_or(SharedObjectError::AddressOverflow)?;
    for range in ranges.iter().skip(1) {
        if range.address != end {
            return Err(SharedObjectError::DynamicLifecycleNonContiguous {
                section_type,
                previous_end: end,
                next_address: range.address,
            });
        }
        end = range
            .address
            .checked_add(range.size)
            .ok_or(SharedObjectError::AddressOverflow)?;
    }
    Ok(Some(DynamicLifecycleArray {
        address: first.address,
        size: end - first.address,
    }))
}

fn build_dynamic_metadata(
    base_address: u64,
    exports: &[ExportSymbol],
    imports: &BTreeMap<Vec<u8>, ImportSymbol>,
    names: DynamicNames<'_>,
    relocations: DynamicRelocations<'_>,
    lifecycle: DynamicLifecycle,
    dynamic_executable: bool,
) -> Result<DynamicMetadata, SharedObjectError> {
    let rela_bytes = relocations.rela;
    let relative_relocation_count = relocations.relative_count;
    let relr_bytes = relocations.relr;
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

    let gnu_hash_offset =
        align_up_usize(hash_size, 8).ok_or(SharedObjectError::MetadataTooLarge)?;
    let gnu_hash_chain_count = symbol_count.saturating_sub(1);
    let gnu_hash_size = 28usize
        .checked_add(
            gnu_hash_chain_count
                .checked_mul(4)
                .ok_or(SharedObjectError::MetadataTooLarge)?,
        )
        .ok_or(SharedObjectError::MetadataTooLarge)?;

    let dynsym_offset = align_up_usize(
        gnu_hash_offset
            .checked_add(gnu_hash_size)
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let dynsym_size = symbol_count
        .checked_mul(ELF64_SYMBOL_SIZE)
        .ok_or(SharedObjectError::MetadataTooLarge)?;

    let mut dynstr = vec![0_u8];
    let mut export_name_offsets = Vec::with_capacity(exports.len());
    for export in exports {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        export_name_offsets.push(offset);
        dynstr.extend_from_slice(&export.dynamic_name);
        dynstr.push(0);
    }
    let mut import_name_offsets = Vec::with_capacity(imports.len());
    for import in imports.values() {
        let offset =
            u32::try_from(dynstr.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        import_name_offsets.push(offset);
        dynstr.extend_from_slice(&import.dynamic_name);
        dynstr.push(0);
    }
    let gnu_hash = |name: &[u8]| {
        let mut hash = 5381u32;
        for byte in name {
            hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
        }
        hash
    };
    let mut gnu_hashes = Vec::with_capacity(gnu_hash_chain_count);
    let mut gnu_bloom = 0u64;
    for name in exports
        .iter()
        .map(|export| export.dynamic_name.as_slice())
        .chain(
            imports
                .values()
                .map(|import| import.dynamic_name.as_slice()),
        )
    {
        let hash = gnu_hash(name);
        gnu_bloom |= 1u64 << (hash % 64);
        gnu_bloom |= 1u64 << ((hash >> 5) % 64);
        gnu_hashes.push(hash);
    }
    debug_assert_eq!(gnu_hashes.len(), gnu_hash_chain_count);

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

    let version_metadata = build_version_metadata(
        exports,
        imports,
        names.version_requirements,
        names.version_script,
        &mut dynstr,
    )?;
    let dynstr_offset = dynsym_offset
        .checked_add(dynsym_size)
        .ok_or(SharedObjectError::MetadataTooLarge)?;
    let versym_offset = align_up_usize(
        dynstr_offset
            .checked_add(dynstr.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        2,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let verdef_offset = align_up_usize(
        versym_offset
            .checked_add(version_metadata.versym.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let verneed_offset = align_up_usize(
        verdef_offset
            .checked_add(version_metadata.verdef.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let relr_offset = align_up_usize(
        verneed_offset
            .checked_add(version_metadata.verneed.len())
            .ok_or(SharedObjectError::MetadataTooLarge)?,
        8,
    )
    .ok_or(SharedObjectError::MetadataTooLarge)?;
    let rela_offset = align_up_usize(
        relr_offset
            .checked_add(relr_bytes.len())
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
    let has_relr = !relr_bytes.is_empty();
    let has_plt_relocations = !jmprel_bytes.is_empty();
    let symbolic = dynamic_flags & DF_SYMBOLIC != 0;
    debug_assert_eq!(has_plt_relocations, plt_got_address.is_some());
    let dynamic_entry_count = 6usize
        .checked_add(names.needed.len())
        .and_then(|count| count.checked_add(usize::from(soname_offset.is_some())))
        .and_then(|count| count.checked_add(usize::from(runpath_offset.is_some())))
        .and_then(|count| count.checked_add(if has_relocations { 3 } else { 0 }))
        .and_then(|count| count.checked_add(usize::from(relative_relocation_count != 0)))
        .and_then(|count| count.checked_add(if has_relr { 3 } else { 0 }))
        .and_then(|count| count.checked_add(if has_plt_relocations { 4 } else { 0 }))
        .and_then(|count| {
            count.checked_add(usize::from(
                version_metadata.definition_count != 0 || version_metadata.provider_count != 0,
            ))
        })
        .and_then(|count| {
            count.checked_add(if version_metadata.definition_count != 0 {
                2
            } else {
                0
            })
        })
        .and_then(|count| {
            count.checked_add(if version_metadata.provider_count != 0 {
                2
            } else {
                0
            })
        })
        .and_then(|count| count.checked_add(usize::from(symbolic)))
        .and_then(|count| count.checked_add(usize::from(dynamic_flags != 0)))
        .and_then(|count| count.checked_add(2 * usize::from(dynamic_executable)))
        .and_then(|count| count.checked_add(usize::from(lifecycle.init_hook.is_some())))
        .and_then(|count| count.checked_add(usize::from(lifecycle.fini_hook.is_some())))
        .and_then(|count| count.checked_add(2 * usize::from(lifecycle.preinit.is_some())))
        .and_then(|count| count.checked_add(2 * usize::from(lifecycle.init.is_some())))
        .and_then(|count| count.checked_add(2 * usize::from(lifecycle.fini.is_some())))
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

    put_u32(&mut bytes, gnu_hash_offset, 1);
    put_u32(&mut bytes, gnu_hash_offset + 4, 1);
    put_u32(&mut bytes, gnu_hash_offset + 8, 1);
    put_u32(&mut bytes, gnu_hash_offset + 12, 5);
    put_u64(&mut bytes, gnu_hash_offset + 16, gnu_bloom);
    put_u32(
        &mut bytes,
        gnu_hash_offset + 24,
        if gnu_hashes.is_empty() { 0 } else { 1 },
    );
    for (index, hash) in gnu_hashes.iter().copied().enumerate() {
        let terminator = u32::from(index + 1 == gnu_hashes.len());
        put_u32(
            &mut bytes,
            gnu_hash_offset + 28 + index * 4,
            (hash & !1) | terminator,
        );
    }

    for (index, export) in exports.iter().enumerate() {
        let offset = dynsym_offset + (index + 1) * ELF64_SYMBOL_SIZE;
        put_u32(&mut bytes, offset, export_name_offsets[index]);
        bytes[offset + 4] = export.info;
        bytes[offset + 5] = export.other;
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
    bytes[versym_offset..versym_offset + version_metadata.versym.len()]
        .copy_from_slice(&version_metadata.versym);
    bytes[verdef_offset..verdef_offset + version_metadata.verdef.len()]
        .copy_from_slice(&version_metadata.verdef);
    bytes[verneed_offset..verneed_offset + version_metadata.verneed.len()]
        .copy_from_slice(&version_metadata.verneed);
    bytes[relr_offset..relr_offset + relr_bytes.len()].copy_from_slice(relr_bytes);
    bytes[rela_offset..rela_offset + rela_bytes.len()].copy_from_slice(rela_bytes);
    bytes[jmprel_offset..jmprel_offset + jmprel_bytes.len()].copy_from_slice(jmprel_bytes);

    let hash_address = checked_metadata_address(base_address, hash_offset)?;
    let gnu_hash_address = checked_metadata_address(base_address, gnu_hash_offset)?;
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
        (DT_GNU_HASH, gnu_hash_address),
        (DT_STRTAB, dynstr_address),
        (DT_SYMTAB, dynsym_address),
        (DT_STRSZ, dynstr.len() as u64),
        (DT_SYMENT, ELF64_SYMBOL_SIZE as u64),
    ]);
    if version_metadata.definition_count != 0 || version_metadata.provider_count != 0 {
        let versym_address = checked_metadata_address(base_address, versym_offset)?;
        entries.push((DT_VERSYM, versym_address));
    }
    if version_metadata.definition_count != 0 {
        let verdef_address = checked_metadata_address(base_address, verdef_offset)?;
        entries.extend_from_slice(&[
            (DT_VERDEF, verdef_address),
            (
                DT_VERDEFNUM,
                u64::try_from(version_metadata.definition_count)
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?,
            ),
        ]);
    }
    if version_metadata.provider_count != 0 {
        let verneed_address = checked_metadata_address(base_address, verneed_offset)?;
        entries.extend_from_slice(&[
            (DT_VERNEED, verneed_address),
            (
                DT_VERNEEDNUM,
                u64::try_from(version_metadata.provider_count)
                    .map_err(|_| SharedObjectError::MetadataTooLarge)?,
            ),
        ]);
    }
    if has_relr {
        debug_assert_eq!(relr_bytes.len() % ELF64_RELR_SIZE, 0);
        let relr_address = checked_metadata_address(base_address, relr_offset)?;
        let relr_size =
            u64::try_from(relr_bytes.len()).map_err(|_| SharedObjectError::MetadataTooLarge)?;
        entries.extend_from_slice(&[
            (DT_RELR, relr_address),
            (DT_RELRSZ, relr_size),
            (DT_RELRENT, ELF64_RELR_SIZE as u64),
        ]);
    }
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
    if symbolic {
        entries.push((DT_SYMBOLIC, 0));
    }
    if dynamic_flags != 0 {
        entries.push((DT_FLAGS, dynamic_flags));
    }
    if dynamic_executable {
        // GNU-compatible dynamic executables advertise their main-program
        // identity through DF_1_PIE and reserve DT_DEBUG for the runtime
        // loader to populate with the r_debug rendezvous pointer.
        entries.push((DT_DEBUG, 0));
        entries.push((DT_FLAGS_1, DF_1_PIE));
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
    if let Some(address) = lifecycle.init_hook {
        entries.push((DT_INIT, address));
    }
    if let Some(address) = lifecycle.fini_hook {
        entries.push((DT_FINI, address));
    }
    if let Some(array) = lifecycle.preinit {
        entries.extend_from_slice(&[
            (DT_PREINIT_ARRAY, array.address),
            (DT_PREINIT_ARRAYSZ, array.size),
        ]);
    }
    if let Some(array) = lifecycle.init {
        entries.extend_from_slice(&[
            (DT_INIT_ARRAY, array.address),
            (DT_INIT_ARRAYSZ, array.size),
        ]);
    }
    if let Some(array) = lifecycle.fini {
        entries.extend_from_slice(&[
            (DT_FINI_ARRAY, array.address),
            (DT_FINI_ARRAYSZ, array.size),
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

fn sysv_elf_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(u32::from(*byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

fn checked_metadata_address(base_address: u64, offset: usize) -> Result<u64, SharedObjectError> {
    base_address
        .checked_add(u64::try_from(offset).map_err(|_| SharedObjectError::MetadataTooLarge)?)
        .ok_or(SharedObjectError::AddressOverflow)
}

fn build_ibt_gnu_property_note() -> Vec<u8> {
    const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
    const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
    const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1;

    let mut bytes = Vec::with_capacity(GNU_PROPERTY_NOTE_SIZE as usize);
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
    bytes.extend_from_slice(b"GNU\0");
    bytes.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_IBT.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(bytes.len(), GNU_PROPERTY_NOTE_SIZE as usize);
    bytes
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

#[cfg(test)]
mod lifecycle_priority_tests {
    use super::*;

    fn key(name: &[u8]) -> LifecyclePriority {
        lifecycle_priority(Some(name), b".init_array")
    }

    fn sorted_names(names: &[&[u8]]) -> Vec<Vec<u8>> {
        let mut entries = names
            .iter()
            .map(|name| (key(name), name.to_vec()))
            .collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| compare_lifecycle_priority(left, right));
        entries.into_iter().map(|(_, name)| name).collect()
    }

    #[test]
    fn lifecycle_priority_matches_gnu_numeric_and_name_fallback_order() {
        assert_eq!(
            sorted_names(&[
                b".init_array",
                b".init_array.zed",
                b".init_array.99999",
                b".init_array.100",
                b".init_array.bar",
                b".init_array.099foo",
            ]),
            vec![
                b".init_array.099foo".to_vec(),
                b".init_array.100".to_vec(),
                b".init_array.99999".to_vec(),
                b".init_array.bar".to_vec(),
                b".init_array.zed".to_vec(),
                b".init_array".to_vec(),
            ]
        );
    }

    #[test]
    fn lifecycle_priority_equal_numeric_values_fall_back_to_section_name() {
        assert_eq!(
            sorted_names(&[
                b".init_array.100",
                b".init_array.0100",
                b".init_array.000100",
            ]),
            vec![
                b".init_array.000100".to_vec(),
                b".init_array.0100".to_vec(),
                b".init_array.100".to_vec(),
            ]
        );
    }

    #[test]
    fn lifecycle_priority_identical_names_preserve_link_order() {
        let mut priorities = vec![
            (key(b".init_array.100"), 0usize),
            (key(b".init_array.100"), 1usize),
            (key(b".init_array.100"), 2usize),
        ];
        priorities.sort_by(|(left, _), (right, _)| compare_lifecycle_priority(left, right));

        assert_eq!(
            priorities
                .into_iter()
                .map(|(_, link_order)| link_order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn lifecycle_priority_rejects_numeric_values_above_gnu_int_range() {
        assert_eq!(
            parse_lifecycle_numeric_priority(b"2147483647"),
            Some(2_147_483_647)
        );
        assert_eq!(parse_lifecycle_numeric_priority(b"2147483648"), None);
        assert_eq!(
            parse_lifecycle_numeric_priority(b"999999999999999999999999999999"),
            None
        );
    }
}
