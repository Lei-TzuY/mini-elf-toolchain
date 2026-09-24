use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::elf64::SHT_NOBITS;
use crate::executable_pipeline::ExecutableSectionInput;
use crate::layout::LaidOutSection;
use crate::link_context::{
    build_link_context_with_got_plt_maps_and_unresolved, LinkContextBuildError,
    LinkContextRelocationError, LinkSyntheticEntries,
};
use crate::link_symbols::{resolve_validated_objects_with_common, LinkSymbolError};
use crate::linker_input::{LinkerInputError, LinkerInputObject};
use crate::load_segments::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use crate::object_symbols::named_symbols_from_table;
use crate::permission_layout::{
    layout_sections_by_permissions, PermissionLayoutError, PermissionLayoutInput,
};
use crate::relocations::Elf64RelaTable;
use crate::resolve::{COMMON_OBJECT_INDEX, COMMON_SECTION_INDEX, STB_GLOBAL, STB_WEAK};
use crate::x86_64_relocations::{
    is_static_got_entry_type, is_static_tls_gotpcrel_type, is_tls_desc_address_relocation_type,
    is_tls_gd_relocation_type, is_tls_ld_relocation_type, R_X86_64_PLT32,
};

const SHT_PROGBITS: u32 = 1;
const GOT_OBJECT_INDEX: usize = usize::MAX - 1;
const GOT_SECTION_INDEX: u16 = 1;
const GOT_ENTRY_SIZE: u64 = 8;
const TLS_GD_ENTRY_SIZE: u64 = 16;
const TLS_LD_ENTRY_SIZE: u64 = 16;
const TLS_DESC_ENTRY_SIZE: u64 = 16;
const GOT_ALIGNMENT: u64 = 8;
const PLT_OBJECT_INDEX: usize = usize::MAX - 4;
const PLT_SECTION_INDEX: u16 = 1;
const PLT_GOT_OBJECT_INDEX: usize = usize::MAX - 5;
const PLT_GOT_SECTION_INDEX: u16 = 1;
const PLT0_SIZE: u64 = 16;
const PLT_ENTRY_SIZE: u64 = 16;
const PLT_ALIGNMENT: u64 = 16;
const PLT_GOT_RESERVED_SIZE: u64 = 24;
const PLT_GOT_ENTRY_SIZE: u64 = 8;
const PLT_GOT_ALIGNMENT: u64 = 8;
const STT_TLS: u8 = 6;

#[derive(Debug, Clone, Copy)]
pub struct TlsSyntheticRequests<'a> {
    pub tls_gd_symbols: &'a BTreeSet<Vec<u8>>,
    pub tls_ld_enabled: bool,
    pub tls_desc_symbols: &'a BTreeSet<Vec<u8>>,
    pub external_tls_got_symbols: &'a BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedSectionImage {
    pub object_index: usize,
    pub section_index: u16,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub size: u64,
    pub alignment: u64,
    pub bytes: Vec<u8>,
}

impl RelocatedSectionImage {
    pub fn executable_input(&self) -> ExecutableSectionInput<'_> {
        ExecutableSectionInput {
            object_index: self.object_index,
            section_index: self.section_index,
            section_type: self.section_type,
            flags: self.flags,
            size: self.size,
            alignment: self.alignment,
            bytes: &self.bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyntheticGotRegion {
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocatedSectionsOutput {
    pub sections: Vec<RelocatedSectionImage>,
    pub got_entries: BTreeMap<Vec<u8>, u64>,
    pub tls_got_entries: BTreeMap<Vec<u8>, u64>,
    pub tls_gd_entries: BTreeMap<Vec<u8>, u64>,
    pub tls_ld_entry: Option<u64>,
    pub tls_desc_entries: BTreeMap<Vec<u8>, u64>,
    pub plt_entries: BTreeMap<Vec<u8>, u64>,
    pub plt_got_entries: BTreeMap<Vec<u8>, u64>,
    pub plt_got_base: Option<u64>,
    pub(crate) got_region: Option<SyntheticGotRegion>,
}

#[derive(Debug)]
pub enum RelocatedSectionError {
    NonCanonicalObjectIndex {
        position: usize,
        object_index: usize,
    },
    Input(LinkerInputError),
    Symbols(LinkSymbolError),
    Layout(PermissionLayoutError),
    LinkContext(LinkContextBuildError),
    MissingLayout {
        object_index: usize,
        section_index: u16,
    },
    MissingGotSymbolMetadata {
        object_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
    },
    UnsupportedGotBinding {
        object_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
        binding: u8,
    },
    NonTlsGotSymbol {
        object_index: usize,
        rela_section_index: u16,
        symbol_index: u32,
        symbol_type: u8,
    },
    GotSizeOverflow {
        symbol_count: usize,
    },
    GotAddressOverflow {
        entry_index: usize,
    },
    MissingGotSymbolAddress {
        name: Vec<u8>,
    },
    MissingExternalGotSymbol {
        name: Vec<u8>,
    },
    MissingExternalTlsGotSymbol {
        name: Vec<u8>,
    },
    MissingExternalPltSymbol {
        name: Vec<u8>,
    },
    MissingTlsGdSymbol {
        name: Vec<u8>,
    },
    MissingTlsLdRelocation,
    PltSizeOverflow {
        symbol_count: usize,
    },
    PltDisplacementOutOfRange {
        name: Vec<u8>,
        stub_address: u64,
        slot_address: u64,
    },
    RelocationAgainstMemoryOnlySection {
        object_index: usize,
        section_index: u16,
        rela_section_index: u16,
    },
    Relocation {
        object_index: usize,
        section_index: u16,
        rela_section_index: u16,
        source: LinkContextRelocationError,
    },
}

impl fmt::Display for RelocatedSectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalObjectIndex {
                position,
                object_index,
            } => write!(
                f,
                "link input at position {position} has object index {object_index}; expected canonical index {position}"
            ),
            Self::Input(source) => write!(f, "cannot extract linker input sections: {source}"),
            Self::Symbols(source) => write!(f, "cannot resolve linker symbols: {source}"),
            Self::Layout(source) => write!(f, "cannot lay out linker input sections: {source}"),
            Self::LinkContext(source) => write!(f, "cannot build link context: {source}"),
            Self::MissingLayout {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} has no matching output layout"
            ),
            Self::MissingGotSymbolMetadata {
                object_index,
                rela_section_index,
                symbol_index,
            } => write!(
                f,
                "static GOT relocation in object {object_index} RELA section {rela_section_index} refers to missing symbol {symbol_index} metadata"
            ),
            Self::UnsupportedGotBinding {
                object_index,
                rela_section_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "static GOT relocation in object {object_index} RELA section {rela_section_index} symbol {symbol_index} uses unsupported binding {binding}; bounded static GOT entries require global/weak symbols"
            ),
            Self::NonTlsGotSymbol {
                object_index,
                rela_section_index,
                symbol_index,
                symbol_type,
            } => write!(
                f,
                "TLS GOT relocation in object {object_index} RELA section {rela_section_index} symbol {symbol_index} has ELF symbol type {symbol_type}, expected STT_TLS"
            ),
            Self::GotSizeOverflow { symbol_count } => write!(
                f,
                "synthetic GOT size overflows u64 for {symbol_count} unique symbols"
            ),
            Self::GotAddressOverflow { entry_index } => write!(
                f,
                "synthetic GOT entry address overflows u64 at entry {entry_index}"
            ),
            Self::MissingGotSymbolAddress { name } => write!(
                f,
                "synthetic GOT symbol {:?} has no resolved final address",
                String::from_utf8_lossy(name)
            ),
            Self::MissingExternalGotSymbol { name } => write!(
                f,
                "requested external GOT symbol {:?} has no synthetic GOT relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingExternalTlsGotSymbol { name } => write!(
                f,
                "requested external TLS GOT symbol {:?} has no GOTTPOFF relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingExternalPltSymbol { name } => write!(
                f,
                "requested external PLT symbol {:?} has no PLT32 relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingTlsGdSymbol { name } => write!(
                f,
                "requested TLSGD symbol {:?} has no TLSGD relocation",
                String::from_utf8_lossy(name)
            ),
            Self::MissingTlsLdRelocation => write!(
                f,
                "requested TLSLD module descriptor but no TLSLD relocation was observed"
            ),
            Self::PltSizeOverflow { symbol_count } => write!(
                f,
                "synthetic PLT/PLT-GOT size overflows u64 for {symbol_count} unique symbols"
            ),
            Self::PltDisplacementOutOfRange {
                name,
                stub_address,
                slot_address,
            } => write!(
                f,
                "synthetic PLT stub for {:?} at {stub_address:#x} cannot reach PLT-GOT slot {slot_address:#x} with signed disp32",
                String::from_utf8_lossy(name)
            ),
            Self::RelocationAgainstMemoryOnlySection {
                object_index,
                section_index,
                rela_section_index,
            } => write!(
                f,
                "RELA section {rela_section_index} targets memory-only object {object_index} section {section_index}; materializing relocated NOBITS contents is not supported"
            ),
            Self::Relocation {
                object_index,
                section_index,
                rela_section_index,
                source,
            } => write!(
                f,
                "cannot apply RELA section {rela_section_index} to object {object_index} section {section_index}: {source}"
            ),
        }
    }
}

impl std::error::Error for RelocatedSectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Input(source) => Some(source),
            Self::Symbols(source) => Some(source),
            Self::Layout(source) => Some(source),
            Self::LinkContext(source) => Some(source),
            Self::Relocation { source, .. } => Some(source),
            Self::NonCanonicalObjectIndex { .. }
            | Self::MissingLayout { .. }
            | Self::MissingGotSymbolMetadata { .. }
            | Self::UnsupportedGotBinding { .. }
            | Self::NonTlsGotSymbol { .. }
            | Self::GotSizeOverflow { .. }
            | Self::GotAddressOverflow { .. }
            | Self::MissingGotSymbolAddress { .. }
            | Self::MissingExternalGotSymbol { .. }
            | Self::MissingExternalTlsGotSymbol { .. }
            | Self::MissingExternalPltSymbol { .. }
            | Self::MissingTlsGdSymbol { .. }
            | Self::MissingTlsLdRelocation
            | Self::PltSizeOverflow { .. }
            | Self::PltDisplacementOutOfRange { .. }
            | Self::RelocationAgainstMemoryOnlySection { .. } => None,
        }
    }
}

pub fn relocate_allocatable_sections(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
) -> Result<Vec<RelocatedSectionImage>, RelocatedSectionError> {
    relocate_allocatable_sections_with_metadata(inputs, start_address, page_alignment)
        .map(|output| output.sections)
}

pub fn relocate_allocatable_sections_with_metadata(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got(
        inputs,
        start_address,
        page_alignment,
        &BTreeSet::new(),
    )
}

pub(crate) fn relocate_allocatable_sections_with_metadata_isolated_got(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_impl(
        inputs,
        start_address,
        page_alignment,
        &BTreeSet::new(),
        &BTreeSet::new(),
        TlsSyntheticRequests {
            tls_gd_symbols: &BTreeSet::new(),
            tls_ld_enabled: false,
            tls_desc_symbols: &BTreeSet::new(),
            external_tls_got_symbols: &BTreeSet::new(),
        },
        Some(page_alignment),
    )
}

pub fn relocate_allocatable_sections_with_external_got(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_and_plt(
        inputs,
        start_address,
        page_alignment,
        external_got_symbols,
        &BTreeSet::new(),
    )
}

pub fn relocate_allocatable_sections_with_external_got_and_plt(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
    external_plt_symbols: &BTreeSet<Vec<u8>>,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_plt_and_tls_gd(
        inputs,
        start_address,
        page_alignment,
        external_got_symbols,
        external_plt_symbols,
        &BTreeSet::new(),
    )
}

pub fn relocate_allocatable_sections_with_external_got_plt_and_tls_gd(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
    external_plt_symbols: &BTreeSet<Vec<u8>>,
    tls_gd_symbols: &BTreeSet<Vec<u8>>,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_plt_tls_gd_and_tls_ld(
        inputs,
        start_address,
        page_alignment,
        external_got_symbols,
        external_plt_symbols,
        tls_gd_symbols,
        false,
    )
}

pub fn relocate_allocatable_sections_with_external_got_plt_tls_gd_and_tls_ld(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
    external_plt_symbols: &BTreeSet<Vec<u8>>,
    tls_gd_symbols: &BTreeSet<Vec<u8>>,
    tls_ld_enabled: bool,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests(
        inputs,
        start_address,
        page_alignment,
        external_got_symbols,
        external_plt_symbols,
        TlsSyntheticRequests {
            tls_gd_symbols,
            tls_ld_enabled,
            tls_desc_symbols: &BTreeSet::new(),
            external_tls_got_symbols: &BTreeSet::new(),
        },
    )
}

pub fn relocate_allocatable_sections_with_external_got_plt_and_tls_requests(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
    external_plt_symbols: &BTreeSet<Vec<u8>>,
    tls: TlsSyntheticRequests<'_>,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    relocate_allocatable_sections_with_external_got_plt_and_tls_requests_impl(
        inputs,
        start_address,
        page_alignment,
        external_got_symbols,
        external_plt_symbols,
        tls,
        None,
    )
}

fn relocate_allocatable_sections_with_external_got_plt_and_tls_requests_impl(
    inputs: &[LinkerInputObject<'_>],
    start_address: u64,
    page_alignment: u64,
    external_got_symbols: &BTreeSet<Vec<u8>>,
    external_plt_symbols: &BTreeSet<Vec<u8>>,
    tls: TlsSyntheticRequests<'_>,
    isolated_got_page_alignment: Option<u64>,
) -> Result<RelocatedSectionsOutput, RelocatedSectionError> {
    let tls_gd_symbols = tls.tls_gd_symbols;
    let tls_ld_enabled = tls.tls_ld_enabled;
    let tls_desc_symbols = tls.tls_desc_symbols;
    let external_tls_got_symbols = tls.external_tls_got_symbols;
    for (position, input) in inputs.iter().enumerate() {
        if input.object_index != position {
            return Err(RelocatedSectionError::NonCanonicalObjectIndex {
                position,
                object_index: input.object_index,
            });
        }
    }

    let mut sections = Vec::new();
    for input in inputs {
        sections.extend(
            input
                .allocatable_sections()
                .map_err(RelocatedSectionError::Input)?,
        );
    }

    let validated_objects = inputs
        .iter()
        .map(LinkerInputObject::validated_object)
        .collect::<Vec<_>>();
    let common_section = resolve_validated_objects_with_common(&validated_objects)
        .map_err(RelocatedSectionError::Symbols)?
        .common_section;
    let got_symbols = collect_static_got_symbols(inputs)?;
    for name in external_got_symbols {
        if !got_symbols.iter().any(|candidate| candidate == name) {
            return Err(RelocatedSectionError::MissingExternalGotSymbol { name: name.clone() });
        }
    }
    let tls_got_symbols = collect_static_tls_got_symbols(inputs)?;
    for name in external_tls_got_symbols {
        if !tls_got_symbols.iter().any(|candidate| candidate == name) {
            return Err(RelocatedSectionError::MissingExternalTlsGotSymbol { name: name.clone() });
        }
    }
    if !tls_gd_symbols.is_empty() {
        let observed_tls_gd = collect_tls_gd_symbols(inputs)?;
        for name in tls_gd_symbols {
            if !observed_tls_gd.contains(name) {
                return Err(RelocatedSectionError::MissingTlsGdSymbol { name: name.clone() });
            }
        }
    }
    if tls_ld_enabled
        && !inputs.iter().any(|input| {
            input.object.rela_tables.iter().any(|table| {
                table
                    .relocations
                    .iter()
                    .any(|relocation| is_tls_ld_relocation_type(relocation.relocation_type))
            })
        })
    {
        return Err(RelocatedSectionError::MissingTlsLdRelocation);
    }
    if !tls_desc_symbols.is_empty() {
        let observed_tls_desc = collect_tls_desc_symbols(inputs)?;
        for name in tls_desc_symbols {
            if !observed_tls_desc.contains(name) {
                return Err(RelocatedSectionError::MissingTlsGdSymbol { name: name.clone() });
            }
        }
    }
    let got_symbol_count = got_symbols.len().checked_add(tls_got_symbols.len()).ok_or(
        RelocatedSectionError::GotSizeOverflow {
            symbol_count: usize::MAX,
        },
    )?;
    let fixed_got_size = got_size(got_symbol_count)?;
    let tls_gd_size = u64::try_from(tls_gd_symbols.len())
        .ok()
        .and_then(|count| count.checked_mul(TLS_GD_ENTRY_SIZE))
        .ok_or(RelocatedSectionError::GotSizeOverflow {
            symbol_count: tls_gd_symbols.len(),
        })?;
    let tls_ld_size = if tls_ld_enabled { TLS_LD_ENTRY_SIZE } else { 0 };
    let tls_desc_size = u64::try_from(tls_desc_symbols.len())
        .ok()
        .and_then(|count| count.checked_mul(TLS_DESC_ENTRY_SIZE))
        .ok_or(RelocatedSectionError::GotSizeOverflow {
            symbol_count: tls_desc_symbols.len(),
        })?;
    let got_size = fixed_got_size
        .checked_add(tls_gd_size)
        .and_then(|size| size.checked_add(tls_ld_size))
        .and_then(|size| size.checked_add(tls_desc_size))
        .ok_or(RelocatedSectionError::GotSizeOverflow {
            symbol_count: got_symbol_count
                .saturating_add(tls_gd_symbols.len().saturating_mul(2))
                .saturating_add(if tls_ld_enabled { 2 } else { 0 })
                .saturating_add(tls_desc_symbols.len().saturating_mul(2)),
        })?;

    let (got_layout_size, got_layout_alignment) =
        if got_size != 0 && isolated_got_page_alignment.is_some() {
            let alignment = isolated_got_page_alignment.unwrap();
            if alignment == 0 || !alignment.is_power_of_two() {
                return Err(RelocatedSectionError::Layout(
                    PermissionLayoutError::InvalidPageAlignment { alignment },
                ));
            }
            let mask = alignment - 1;
            let size = got_size.checked_add(mask).map(|sum| sum & !mask).ok_or(
                RelocatedSectionError::GotSizeOverflow {
                    symbol_count: got_symbol_count,
                },
            )?;
            (size, alignment)
        } else {
            (got_size, GOT_ALIGNMENT)
        };

    validate_external_plt_symbols(inputs, external_plt_symbols)?;
    let plt_size =
        synthetic_table_size_with_prefix(external_plt_symbols.len(), PLT_ENTRY_SIZE, PLT0_SIZE)?;
    let plt_got_size = synthetic_table_size_with_prefix(
        external_plt_symbols.len(),
        PLT_GOT_ENTRY_SIZE,
        PLT_GOT_RESERVED_SIZE,
    )?;

    let mut layout_inputs = sections
        .iter()
        .map(|section| section.permission_layout_input())
        .collect::<Vec<_>>();
    if let Some(common) = common_section {
        layout_inputs.push(PermissionLayoutInput {
            object_index: COMMON_OBJECT_INDEX,
            section_index: COMMON_SECTION_INDEX,
            size: common.size,
            alignment: common.alignment,
            flags: SHF_ALLOC | SHF_WRITE,
        });
    }
    if got_size != 0 {
        layout_inputs.push(PermissionLayoutInput {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
            size: got_layout_size,
            alignment: got_layout_alignment,
            flags: SHF_ALLOC | SHF_WRITE,
        });
    }
    if plt_size != 0 {
        layout_inputs.push(PermissionLayoutInput {
            object_index: PLT_OBJECT_INDEX,
            section_index: PLT_SECTION_INDEX,
            size: plt_size,
            alignment: PLT_ALIGNMENT,
            flags: SHF_ALLOC | SHF_EXECINSTR,
        });
        layout_inputs.push(PermissionLayoutInput {
            object_index: PLT_GOT_OBJECT_INDEX,
            section_index: PLT_GOT_SECTION_INDEX,
            size: plt_got_size,
            alignment: PLT_GOT_ALIGNMENT,
            flags: SHF_ALLOC | SHF_WRITE,
        });
    }

    let layout = layout_sections_by_permissions(start_address, page_alignment, layout_inputs)
        .map_err(RelocatedSectionError::Layout)?;
    let got_region = if got_size != 0 && isolated_got_page_alignment.is_some() {
        let got_layout = matching_layout(&layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
            RelocatedSectionError::MissingLayout {
                object_index: GOT_OBJECT_INDEX,
                section_index: GOT_SECTION_INDEX,
            },
        )?;
        Some(SyntheticGotRegion {
            address: got_layout.address,
            size: got_layout.size,
        })
    } else {
        None
    };
    let got_entries = got_entry_addresses(&layout, &got_symbols, 0)?;
    let tls_got_entries = got_entry_addresses(&layout, &tls_got_symbols, got_symbols.len())?;
    let tls_gd_entries = tls_gd_entry_addresses(&layout, tls_gd_symbols, got_symbol_count)?;
    let tls_ld_entry = if tls_ld_enabled {
        let got_layout = matching_layout(&layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
            RelocatedSectionError::MissingLayout {
                object_index: GOT_OBJECT_INDEX,
                section_index: GOT_SECTION_INDEX,
            },
        )?;
        Some(
            got_layout
                .address
                .checked_add(fixed_got_size)
                .and_then(|address| address.checked_add(tls_gd_size))
                .ok_or(RelocatedSectionError::GotAddressOverflow {
                    entry_index: got_symbol_count
                        .saturating_add(tls_gd_symbols.len().saturating_mul(2)),
                })?,
        )
    } else {
        None
    };
    let tls_desc_entries = tls_desc_entry_addresses(
        &layout,
        tls_desc_symbols,
        fixed_got_size
            .checked_add(tls_gd_size)
            .and_then(|offset| offset.checked_add(tls_ld_size))
            .ok_or(RelocatedSectionError::GotSizeOverflow {
                symbol_count: tls_desc_symbols.len(),
            })?,
    )?;
    let plt_entries = synthetic_entry_addresses(
        &layout,
        PLT_OBJECT_INDEX,
        PLT_SECTION_INDEX,
        external_plt_symbols,
        PLT_ENTRY_SIZE,
        PLT0_SIZE,
    )?;
    let plt_got_entries = synthetic_entry_addresses(
        &layout,
        PLT_GOT_OBJECT_INDEX,
        PLT_GOT_SECTION_INDEX,
        external_plt_symbols,
        PLT_GOT_ENTRY_SIZE,
        PLT_GOT_RESERVED_SIZE,
    )?;
    let got_entries_output = got_entries.clone();
    let tls_got_entries_output = tls_got_entries.clone();
    let tls_gd_entries_output = tls_gd_entries.clone();
    let tls_ld_entry_output = tls_ld_entry;
    let tls_desc_entries_output = tls_desc_entries.clone();
    let plt_entries_output = plt_entries.clone();
    let plt_got_entries_output = plt_got_entries.clone();

    let context = build_link_context_with_got_plt_maps_and_unresolved(
        &validated_objects,
        &layout,
        LinkSyntheticEntries {
            got_entries,
            tls_got_entries,
            tls_gd_entries,
            tls_desc_entries,
            tls_ld_entry,
            unresolved_tls_got_symbols: external_tls_got_symbols.clone(),
            unresolved_got_symbols: external_got_symbols.clone(),
            plt_entries,
            unresolved_plt_symbols: external_plt_symbols.clone(),
        },
    )
    .map_err(RelocatedSectionError::LinkContext)?;

    let mut relocated = sections
        .into_iter()
        .map(|section| {
            let section_layout =
                matching_layout(&layout, section.object_index, section.section_index).ok_or(
                    RelocatedSectionError::MissingLayout {
                        object_index: section.object_index,
                        section_index: section.section_index,
                    },
                )?;
            let mut bytes = section.bytes.to_vec();

            for table in &section.rela_tables {
                reject_memory_only_relocation(&section, table)?;
                context
                    .apply_rela_table(
                        &mut bytes,
                        section_layout.address,
                        table,
                        section.object_index,
                    )
                    .map_err(|source| RelocatedSectionError::Relocation {
                        object_index: section.object_index,
                        section_index: section.section_index,
                        rela_section_index: table.section_index,
                        source,
                    })?;
            }

            Ok(RelocatedSectionImage {
                object_index: section.object_index,
                section_index: section.section_index,
                section_type: section.section_type,
                flags: section.flags,
                address: section_layout.address,
                size: section.size,
                alignment: section.alignment,
                bytes,
            })
        })
        .collect::<Result<Vec<_>, RelocatedSectionError>>()?;

    if let Some(common) = common_section {
        let common_layout = matching_layout(&layout, COMMON_OBJECT_INDEX, COMMON_SECTION_INDEX)
            .ok_or(RelocatedSectionError::MissingLayout {
                object_index: COMMON_OBJECT_INDEX,
                section_index: COMMON_SECTION_INDEX,
            })?;
        relocated.push(RelocatedSectionImage {
            object_index: COMMON_OBJECT_INDEX,
            section_index: COMMON_SECTION_INDEX,
            section_type: SHT_NOBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: common_layout.address,
            size: common.size,
            alignment: common.alignment,
            bytes: Vec::new(),
        });
    }

    if got_size != 0 {
        let got_layout = matching_layout(&layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
            RelocatedSectionError::MissingLayout {
                object_index: GOT_OBJECT_INDEX,
                section_index: GOT_SECTION_INDEX,
            },
        )?;
        let got_capacity = usize::try_from(got_layout_size).map_err(|_| {
            RelocatedSectionError::GotSizeOverflow {
                symbol_count: got_symbol_count,
            }
        })?;
        let mut bytes = Vec::with_capacity(got_capacity);
        for name in &got_symbols {
            if external_got_symbols.contains(name) {
                bytes.extend_from_slice(&0_u64.to_le_bytes());
                continue;
            }
            let address = context
                .global_addresses()
                .get(name)
                .copied()
                .ok_or_else(|| RelocatedSectionError::MissingGotSymbolAddress {
                    name: name.clone(),
                })?;
            bytes.extend_from_slice(&address.to_le_bytes());
        }
        for _ in &tls_got_symbols {
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        for _ in tls_gd_symbols {
            bytes.extend_from_slice(&0_u64.to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        if tls_ld_enabled {
            bytes.extend_from_slice(&0_u64.to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        for _ in tls_desc_symbols {
            bytes.extend_from_slice(&0_u64.to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        bytes.resize(got_capacity, 0);
        relocated.push(RelocatedSectionImage {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: got_layout.address,
            size: got_layout_size,
            alignment: got_layout_alignment,
            bytes,
        });
    }

    let plt_got_base = if plt_size != 0 {
        let plt_layout = matching_layout(&layout, PLT_OBJECT_INDEX, PLT_SECTION_INDEX).ok_or(
            RelocatedSectionError::MissingLayout {
                object_index: PLT_OBJECT_INDEX,
                section_index: PLT_SECTION_INDEX,
            },
        )?;
        let plt_got_layout = matching_layout(&layout, PLT_GOT_OBJECT_INDEX, PLT_GOT_SECTION_INDEX)
            .ok_or(RelocatedSectionError::MissingLayout {
                object_index: PLT_GOT_OBJECT_INDEX,
                section_index: PLT_GOT_SECTION_INDEX,
            })?;

        let got_link_map = plt_got_layout.address.checked_add(8).ok_or(
            RelocatedSectionError::PltSizeOverflow {
                symbol_count: external_plt_symbols.len(),
            },
        )?;
        let got_resolver = plt_got_layout.address.checked_add(16).ok_or(
            RelocatedSectionError::PltSizeOverflow {
                symbol_count: external_plt_symbols.len(),
            },
        )?;
        let mut plt_bytes = Vec::with_capacity(plt_size as usize);
        append_rip_indirect(
            &mut plt_bytes,
            [0xff, 0x35],
            plt_layout.address,
            got_link_map,
            b"<plt0-link-map>",
        )?;
        let plt0_second =
            plt_layout
                .address
                .checked_add(6)
                .ok_or(RelocatedSectionError::PltSizeOverflow {
                    symbol_count: external_plt_symbols.len(),
                })?;
        append_rip_indirect(
            &mut plt_bytes,
            [0xff, 0x25],
            plt0_second,
            got_resolver,
            b"<plt0-resolver>",
        )?;
        plt_bytes.extend_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);

        let mut plt_got_bytes = vec![0_u8; PLT_GOT_RESERVED_SIZE as usize];
        for (relocation_index, name) in external_plt_symbols.iter().enumerate() {
            let stub_address = plt_entries_output[name];
            let slot_address = plt_got_entries_output[name];
            append_rip_indirect(
                &mut plt_bytes,
                [0xff, 0x25],
                stub_address,
                slot_address,
                name,
            )?;

            let relocation_index = u32::try_from(relocation_index).map_err(|_| {
                RelocatedSectionError::PltSizeOverflow {
                    symbol_count: external_plt_symbols.len(),
                }
            })?;
            plt_bytes.push(0x68);
            plt_bytes.extend_from_slice(&relocation_index.to_le_bytes());

            let jump_next_ip = stub_address.checked_add(PLT_ENTRY_SIZE).ok_or(
                RelocatedSectionError::PltDisplacementOutOfRange {
                    name: name.clone(),
                    stub_address,
                    slot_address: plt_layout.address,
                },
            )?;
            let displacement = i128::from(plt_layout.address) - i128::from(jump_next_ip);
            let displacement = i32::try_from(displacement).map_err(|_| {
                RelocatedSectionError::PltDisplacementOutOfRange {
                    name: name.clone(),
                    stub_address,
                    slot_address: plt_layout.address,
                }
            })?;
            plt_bytes.push(0xe9);
            plt_bytes.extend_from_slice(&displacement.to_le_bytes());

            let lazy_target =
                stub_address
                    .checked_add(6)
                    .ok_or(RelocatedSectionError::PltSizeOverflow {
                        symbol_count: external_plt_symbols.len(),
                    })?;
            plt_got_bytes.extend_from_slice(&lazy_target.to_le_bytes());
        }

        debug_assert_eq!(plt_bytes.len(), plt_size as usize);
        debug_assert_eq!(plt_got_bytes.len(), plt_got_size as usize);
        relocated.push(RelocatedSectionImage {
            object_index: PLT_OBJECT_INDEX,
            section_index: PLT_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            address: plt_layout.address,
            size: plt_size,
            alignment: PLT_ALIGNMENT,
            bytes: plt_bytes,
        });
        relocated.push(RelocatedSectionImage {
            object_index: PLT_GOT_OBJECT_INDEX,
            section_index: PLT_GOT_SECTION_INDEX,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            address: plt_got_layout.address,
            size: plt_got_size,
            alignment: PLT_GOT_ALIGNMENT,
            bytes: plt_got_bytes,
        });
        Some(plt_got_layout.address)
    } else {
        None
    };

    Ok(RelocatedSectionsOutput {
        sections: relocated,
        got_entries: got_entries_output,
        tls_got_entries: tls_got_entries_output,
        tls_gd_entries: tls_gd_entries_output,
        tls_ld_entry: tls_ld_entry_output,
        tls_desc_entries: tls_desc_entries_output,
        plt_entries: plt_entries_output,
        plt_got_entries: plt_got_entries_output,
        plt_got_base,
        got_region,
    })
}

fn validate_external_plt_symbols(
    inputs: &[LinkerInputObject<'_>],
    external_plt_symbols: &BTreeSet<Vec<u8>>,
) -> Result<(), RelocatedSectionError> {
    if external_plt_symbols.is_empty() {
        return Ok(());
    }

    let mut observed = BTreeSet::new();
    for input in inputs {
        for table in &input.object.rela_tables {
            let plt_relocations = table
                .relocations
                .iter()
                .filter(|relocation| relocation.relocation_type == R_X86_64_PLT32)
                .collect::<Vec<_>>();
            if plt_relocations.is_empty() {
                continue;
            }
            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: plt_relocations[0].symbol_index,
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;
            for relocation in plt_relocations {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                if external_plt_symbols.contains(symbol.name) {
                    observed.insert(symbol.name.to_vec());
                }
            }
        }
    }

    for name in external_plt_symbols {
        if !observed.contains(name) {
            return Err(RelocatedSectionError::MissingExternalPltSymbol { name: name.clone() });
        }
    }
    Ok(())
}

fn synthetic_table_size(
    symbol_count: usize,
    entry_size: u64,
) -> Result<u64, RelocatedSectionError> {
    u64::try_from(symbol_count)
        .ok()
        .and_then(|count| count.checked_mul(entry_size))
        .ok_or(RelocatedSectionError::PltSizeOverflow { symbol_count })
}

fn synthetic_table_size_with_prefix(
    symbol_count: usize,
    entry_size: u64,
    prefix_size: u64,
) -> Result<u64, RelocatedSectionError> {
    if symbol_count == 0 {
        return Ok(0);
    }
    synthetic_table_size(symbol_count, entry_size)?
        .checked_add(prefix_size)
        .ok_or(RelocatedSectionError::PltSizeOverflow { symbol_count })
}

fn synthetic_entry_addresses(
    layout: &[LaidOutSection],
    object_index: usize,
    section_index: u16,
    symbols: &BTreeSet<Vec<u8>>,
    entry_size: u64,
    prefix_size: u64,
) -> Result<BTreeMap<Vec<u8>, u64>, RelocatedSectionError> {
    if symbols.is_empty() {
        return Ok(BTreeMap::new());
    }
    let section = matching_layout(layout, object_index, section_index).ok_or(
        RelocatedSectionError::MissingLayout {
            object_index,
            section_index,
        },
    )?;
    let mut entries = BTreeMap::new();
    for (entry_index, name) in symbols.iter().enumerate() {
        let offset = u64::try_from(entry_index)
            .ok()
            .and_then(|index| index.checked_mul(entry_size))
            .ok_or(RelocatedSectionError::PltSizeOverflow {
                symbol_count: symbols.len(),
            })?;
        let offset =
            prefix_size
                .checked_add(offset)
                .ok_or(RelocatedSectionError::PltSizeOverflow {
                    symbol_count: symbols.len(),
                })?;
        let address = section
            .address
            .checked_add(offset)
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        entries.insert(name.clone(), address);
    }
    Ok(entries)
}

fn append_rip_indirect(
    bytes: &mut Vec<u8>,
    opcode: [u8; 2],
    instruction_address: u64,
    target_address: u64,
    name: &[u8],
) -> Result<(), RelocatedSectionError> {
    let next_ip = instruction_address.checked_add(6).ok_or_else(|| {
        RelocatedSectionError::PltDisplacementOutOfRange {
            name: name.to_vec(),
            stub_address: instruction_address,
            slot_address: target_address,
        }
    })?;
    let displacement = i128::from(target_address) - i128::from(next_ip);
    let displacement = i32::try_from(displacement).map_err(|_| {
        RelocatedSectionError::PltDisplacementOutOfRange {
            name: name.to_vec(),
            stub_address: instruction_address,
            slot_address: target_address,
        }
    })?;
    bytes.extend_from_slice(&opcode);
    bytes.extend_from_slice(&displacement.to_le_bytes());
    Ok(())
}

fn collect_static_got_symbols(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<Vec<u8>>, RelocatedSectionError> {
    let mut names = BTreeSet::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .any(|relocation| is_static_got_entry_type(relocation.relocation_type))
            {
                continue;
            }

            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: table
                        .relocations
                        .iter()
                        .find(|relocation| is_static_got_entry_type(relocation.relocation_type))
                        .map(|relocation| relocation.symbol_index)
                        .unwrap_or(0),
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;

            for relocation in table
                .relocations
                .iter()
                .filter(|relocation| is_static_got_entry_type(relocation.relocation_type))
            {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(RelocatedSectionError::UnsupportedGotBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        binding,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                names.insert(symbol.name.to_vec());
            }
        }
    }

    Ok(names.into_iter().collect())
}

fn collect_static_tls_got_symbols(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Vec<Vec<u8>>, RelocatedSectionError> {
    let mut names = BTreeSet::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            if !table
                .relocations
                .iter()
                .any(|relocation| is_static_tls_gotpcrel_type(relocation.relocation_type))
            {
                continue;
            }

            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: table
                        .relocations
                        .iter()
                        .find(|relocation| is_static_tls_gotpcrel_type(relocation.relocation_type))
                        .map(|relocation| relocation.symbol_index)
                        .unwrap_or(0),
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;

            for relocation in table
                .relocations
                .iter()
                .filter(|relocation| is_static_tls_gotpcrel_type(relocation.relocation_type))
            {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(RelocatedSectionError::UnsupportedGotBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        binding,
                    });
                }
                let symbol_type = symbol.symbol.info & 0x0f;
                if symbol_type != STT_TLS {
                    return Err(RelocatedSectionError::NonTlsGotSymbol {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        symbol_type,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                names.insert(symbol.name.to_vec());
            }
        }
    }

    Ok(names.into_iter().collect())
}

fn collect_tls_gd_symbols(
    inputs: &[LinkerInputObject<'_>],
) -> Result<BTreeSet<Vec<u8>>, RelocatedSectionError> {
    let mut names = BTreeSet::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            let tls_gd_relocations = table
                .relocations
                .iter()
                .filter(|relocation| is_tls_gd_relocation_type(relocation.relocation_type))
                .collect::<Vec<_>>();
            if tls_gd_relocations.is_empty() {
                continue;
            }
            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: tls_gd_relocations[0].symbol_index,
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;
            for relocation in tls_gd_relocations {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(RelocatedSectionError::UnsupportedGotBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        binding,
                    });
                }
                let symbol_type = symbol.symbol.info & 0x0f;
                if symbol_type != STT_TLS {
                    return Err(RelocatedSectionError::NonTlsGotSymbol {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        symbol_type,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                names.insert(symbol.name.to_vec());
            }
        }
    }

    Ok(names)
}

fn collect_tls_desc_symbols(
    inputs: &[LinkerInputObject<'_>],
) -> Result<BTreeSet<Vec<u8>>, RelocatedSectionError> {
    let mut names = BTreeSet::new();

    for input in inputs {
        for table in &input.object.rela_tables {
            let relocations = table
                .relocations
                .iter()
                .filter(|relocation| {
                    is_tls_desc_address_relocation_type(relocation.relocation_type)
                })
                .collect::<Vec<_>>();
            if relocations.is_empty() {
                continue;
            }
            let symbol_table = input
                .object
                .symbol_tables
                .iter()
                .find(|candidate| candidate.section_index == table.symbol_table_index)
                .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                    object_index: input.object_index,
                    rela_section_index: table.section_index,
                    symbol_index: relocations[0].symbol_index,
                })?;
            let symbols = named_symbols_from_table(
                input.file,
                &input.object.sections,
                symbol_table,
                input.object_index,
            )
            .map_err(|source| {
                RelocatedSectionError::Symbols(LinkSymbolError::ObjectSymbols {
                    object_index: input.object_index,
                    source,
                })
            })?;
            for relocation in relocations {
                let symbol = symbols
                    .iter()
                    .find(|symbol| symbol.symbol_index == relocation.symbol_index as usize)
                    .ok_or(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    })?;
                let binding = symbol.symbol.info >> 4;
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(RelocatedSectionError::UnsupportedGotBinding {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        binding,
                    });
                }
                let symbol_type = symbol.symbol.info & 0x0f;
                if symbol_type != STT_TLS {
                    return Err(RelocatedSectionError::NonTlsGotSymbol {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                        symbol_type,
                    });
                }
                if symbol.name.is_empty() {
                    return Err(RelocatedSectionError::MissingGotSymbolMetadata {
                        object_index: input.object_index,
                        rela_section_index: table.section_index,
                        symbol_index: relocation.symbol_index,
                    });
                }
                names.insert(symbol.name.to_vec());
            }
        }
    }

    Ok(names)
}

fn tls_desc_entry_addresses(
    layout: &[LaidOutSection],
    symbols: &BTreeSet<Vec<u8>>,
    base_offset: u64,
) -> Result<BTreeMap<Vec<u8>, u64>, RelocatedSectionError> {
    if symbols.is_empty() {
        return Ok(BTreeMap::new());
    }
    let got_layout = matching_layout(layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
        RelocatedSectionError::MissingLayout {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
        },
    )?;
    let mut entries = BTreeMap::new();
    for (entry_index, name) in symbols.iter().enumerate() {
        let descriptor_offset = u64::try_from(entry_index)
            .ok()
            .and_then(|index| index.checked_mul(TLS_DESC_ENTRY_SIZE))
            .and_then(|offset| base_offset.checked_add(offset))
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        let address = got_layout
            .address
            .checked_add(descriptor_offset)
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        entries.insert(name.clone(), address);
    }
    Ok(entries)
}

fn tls_gd_entry_addresses(
    layout: &[LaidOutSection],
    symbols: &BTreeSet<Vec<u8>>,
    preceding_got_slots: usize,
) -> Result<BTreeMap<Vec<u8>, u64>, RelocatedSectionError> {
    if symbols.is_empty() {
        return Ok(BTreeMap::new());
    }
    let got_layout = matching_layout(layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
        RelocatedSectionError::MissingLayout {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
        },
    )?;
    let base_offset = u64::try_from(preceding_got_slots)
        .ok()
        .and_then(|count| count.checked_mul(GOT_ENTRY_SIZE))
        .ok_or(RelocatedSectionError::GotAddressOverflow {
            entry_index: preceding_got_slots,
        })?;
    let mut entries = BTreeMap::new();
    for (entry_index, name) in symbols.iter().enumerate() {
        let descriptor_offset = u64::try_from(entry_index)
            .ok()
            .and_then(|index| index.checked_mul(TLS_GD_ENTRY_SIZE))
            .and_then(|offset| base_offset.checked_add(offset))
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        let address = got_layout
            .address
            .checked_add(descriptor_offset)
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        entries.insert(name.clone(), address);
    }
    Ok(entries)
}

fn got_size(symbol_count: usize) -> Result<u64, RelocatedSectionError> {
    u64::try_from(symbol_count)
        .ok()
        .and_then(|count| count.checked_mul(GOT_ENTRY_SIZE))
        .ok_or(RelocatedSectionError::GotSizeOverflow { symbol_count })
}

fn got_entry_addresses(
    layout: &[LaidOutSection],
    symbols: &[Vec<u8>],
    start_index: usize,
) -> Result<BTreeMap<Vec<u8>, u64>, RelocatedSectionError> {
    if symbols.is_empty() {
        return Ok(BTreeMap::new());
    }
    let got_layout = matching_layout(layout, GOT_OBJECT_INDEX, GOT_SECTION_INDEX).ok_or(
        RelocatedSectionError::MissingLayout {
            object_index: GOT_OBJECT_INDEX,
            section_index: GOT_SECTION_INDEX,
        },
    )?;
    let mut entries = BTreeMap::new();
    for (local_index, name) in symbols.iter().enumerate() {
        let entry_index = start_index.checked_add(local_index).ok_or(
            RelocatedSectionError::GotAddressOverflow {
                entry_index: usize::MAX,
            },
        )?;
        let offset = u64::try_from(entry_index)
            .ok()
            .and_then(|index| index.checked_mul(GOT_ENTRY_SIZE))
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        let address = got_layout
            .address
            .checked_add(offset)
            .ok_or(RelocatedSectionError::GotAddressOverflow { entry_index })?;
        entries.insert(name.clone(), address);
    }
    Ok(entries)
}

fn matching_layout(
    layout: &[LaidOutSection],
    object_index: usize,
    section_index: u16,
) -> Option<LaidOutSection> {
    layout
        .iter()
        .copied()
        .find(|entry| entry.object_index == object_index && entry.section_index == section_index)
}

fn reject_memory_only_relocation(
    section: &crate::linker_input::LinkerInputSection<'_>,
    table: &Elf64RelaTable,
) -> Result<(), RelocatedSectionError> {
    if section.bytes.is_empty() && section.size != 0 && !table.relocations.is_empty() {
        return Err(RelocatedSectionError::RelocationAgainstMemoryOnlySection {
            object_index: section.object_index,
            section_index: section.section_index,
            rela_section_index: table.section_index,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf64::{
        Elf64Header, Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, EM_X86_64, SHT_STRTAB,
        SHT_SYMTAB,
    };
    use crate::input_object::{RelocatableObject, ET_REL};
    use crate::load_segments::{SHF_EXECINSTR, SHF_WRITE};
    use crate::relocations::{Elf64Rela, Elf64RelaTable};
    use crate::x86_64_relocations::R_X86_64_64;

    fn header(section_count: u16) -> Elf64Header {
        Elf64Header {
            elf_type: ET_REL,
            machine: EM_X86_64,
            entry: 0,
            program_header_offset: 0,
            section_header_offset: 0,
            flags: 0,
            header_size: 64,
            program_header_entry_size: 0,
            program_header_count: 0,
            section_header_entry_size: 64,
            section_header_count: section_count,
            section_name_string_table_index: 0,
        }
    }

    fn section(
        section_type: u32,
        flags: u64,
        offset: u64,
        size: u64,
        alignment: u64,
    ) -> Elf64SectionHeader {
        Elf64SectionHeader {
            name_offset: 0,
            section_type,
            flags,
            address: 0,
            offset,
            size,
            link: 0,
            info: 0,
            address_alignment: alignment,
            entry_size: 0,
        }
    }

    #[test]
    fn lays_out_and_applies_local_absolute_relocation() {
        let file = [0_u8; 9];
        let sections = vec![
            section(0, 0, 0, 0, 0),
            section(SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 8, 16),
            section(SHT_STRTAB, 0, 8, 1, 1),
            section(SHT_SYMTAB, 0, 9, 0, 8),
        ];
        let symbol_tables = vec![Elf64SymbolTable {
            section_index: 3,
            string_table_index: 2,
            symbols: vec![Elf64Symbol {
                name_offset: 0,
                info: 0,
                other: 0,
                section_index: 1,
                value: 4,
                size: 0,
            }],
        }];
        let rela_tables = vec![Elf64RelaTable {
            section_index: 4,
            symbol_table_index: 3,
            target_section_index: 1,
            relocations: vec![Elf64Rela {
                offset: 0,
                symbol_index: 0,
                relocation_type: R_X86_64_64,
                addend: 0,
            }],
        }];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(4),
                sections,
                symbol_tables,
                rela_tables,
            },
        };

        let relocated = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap();

        assert_eq!(relocated.len(), 1);
        assert_eq!(relocated[0].address, 0x400000);
        assert_eq!(
            u64::from_le_bytes(relocated[0].bytes[..8].try_into().unwrap()),
            0x400004
        );
        let executable = relocated[0].executable_input();
        assert_eq!(executable.bytes, relocated[0].bytes.as_slice());
        assert_eq!(executable.flags, SHF_ALLOC | SHF_EXECINSTR);
    }

    #[test]
    fn separates_permission_classes_across_pages() {
        let file = [1_u8, 2, 3];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(4),
                sections: vec![
                    section(0, 0, 0, 0, 0),
                    section(SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 1, 1),
                    section(SHT_PROGBITS, SHF_ALLOC, 1, 1, 1),
                    section(SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 2, 1, 1),
                ],
                symbol_tables: Vec::new(),
                rela_tables: Vec::new(),
            },
        };

        let relocated = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap();

        assert_eq!(
            relocated
                .iter()
                .map(|section| section.address)
                .collect::<Vec<_>>(),
            vec![0x400000, 0x401000, 0x402000]
        );
        assert_eq!(relocated[0].bytes, vec![1]);
        assert_eq!(relocated[1].bytes, vec![2]);
        assert_eq!(relocated[2].bytes, vec![3]);
    }

    #[test]
    fn rejects_noncanonical_object_indices_before_symbol_resolution() {
        let file = [0_u8; 1];
        let input = LinkerInputObject {
            object_index: 3,
            file: &file,
            object: RelocatableObject {
                header: header(1),
                sections: vec![section(0, 0, 0, 0, 0)],
                symbol_tables: Vec::new(),
                rela_tables: Vec::new(),
            },
        };

        let error = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap_err();
        assert!(matches!(
            error,
            RelocatedSectionError::NonCanonicalObjectIndex {
                position: 0,
                object_index: 3
            }
        ));
    }

    #[test]
    fn rejects_relocations_against_nobits_sections() {
        let file = [0_u8; 1];
        let input = LinkerInputObject {
            object_index: 0,
            file: &file,
            object: RelocatableObject {
                header: header(2),
                sections: vec![
                    section(0, 0, 0, 0, 0),
                    section(SHT_NOBITS, SHF_ALLOC | SHF_WRITE, 0, 8, 8),
                ],
                symbol_tables: Vec::new(),
                rela_tables: vec![Elf64RelaTable {
                    section_index: 2,
                    symbol_table_index: 3,
                    target_section_index: 1,
                    relocations: vec![Elf64Rela {
                        offset: 0,
                        symbol_index: 0,
                        relocation_type: R_X86_64_64,
                        addend: 0,
                    }],
                }],
            },
        };

        let error = relocate_allocatable_sections(&[input], 0x400000, 0x1000).unwrap_err();
        assert!(matches!(
            error,
            RelocatedSectionError::RelocationAgainstMemoryOnlySection {
                object_index: 0,
                section_index: 1,
                rela_section_index: 2
            }
        ));
    }
}
