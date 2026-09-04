use core::fmt;
use std::collections::BTreeSet;

use crate::archive::{Archive, ArchiveError, ArchiveMemberKind};
use crate::archive_index::{parse_archive_symbol_index, ArchiveSymbolIndexError};
use crate::archive_lazy::{extract_indexed_archive_members, ArchiveExtractionError};
use crate::input_object::RelocatableObjectError;
use crate::linker_input::LinkerInputObject;
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::resolve::{SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};

#[derive(Debug, Clone, Copy)]
pub enum OrderedLinkInput<'a> {
    Object(&'a [u8]),
    Archive(&'a [u8]),
    WholeArchive(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkObjectOrigin {
    Regular { input_index: usize },
    ArchiveMember { input_index: usize, archive_member_index: usize, member_name: Vec<u8> },
}

#[derive(Debug)]
pub struct OrderedLinkObjects<'a> {
    pub objects: Vec<LinkerInputObject<'a>>,
    pub origins: Vec<LinkObjectOrigin>,
    pub unresolved: BTreeSet<Vec<u8>>,
}

#[derive(Debug)]
pub enum OrderedLinkInputError {
    InvalidObject { input_index: usize, source: RelocatableObjectError },
    ObjectSymbols { input_index: usize, object_index: usize, source: ObjectSymbolError },
    UnsupportedBinding { input_index: usize, object_index: usize, table_section_index: u16, symbol_index: usize, binding: u8 },
    InvalidArchive { input_index: usize, source: ArchiveError },
    InvalidArchiveIndex { input_index: usize, source: ArchiveSymbolIndexError },
    MissingArchiveIndex { input_index: usize },
    InvalidArchiveMember { input_index: usize, archive_member_index: usize, member_name: Vec<u8>, source: RelocatableObjectError },
    ArchiveExtraction { input_index: usize, source: ArchiveExtractionError },
}

impl fmt::Display for OrderedLinkInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidObject { input_index, source } => write!(f, "input {input_index} is not a valid ET_REL object: {source}"),
            Self::ObjectSymbols { input_index, object_index, source } => write!(f, "cannot read symbols from input {input_index} object {object_index}: {source}"),
            Self::UnsupportedBinding { input_index, object_index, table_section_index, symbol_index, binding } => write!(f, "input {input_index} object {object_index} symbol {symbol_index} in table section {table_section_index} uses unsupported binding {binding}"),
            Self::InvalidArchive { input_index, source } => write!(f, "input {input_index} is not a valid archive: {source}"),
            Self::InvalidArchiveIndex { input_index, source } => write!(f, "input {input_index} has an invalid archive index: {source}"),
            Self::MissingArchiveIndex { input_index } => write!(f, "input {input_index} archive has no System V/GNU symbol index"),
            Self::InvalidArchiveMember { input_index, archive_member_index, member_name, source } => write!(f, "input {input_index} archive member {archive_member_index} '{}' is not a valid ET_REL object: {source}", String::from_utf8_lossy(member_name)),
            Self::ArchiveExtraction { input_index, source } => write!(f, "cannot lazily extract archive input {input_index}: {source}"),
        }
    }
}

impl std::error::Error for OrderedLinkInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidObject { source, .. } => Some(source),
            Self::ObjectSymbols { source, .. } => Some(source),
            Self::InvalidArchive { source, .. } => Some(source),
            Self::InvalidArchiveIndex { source, .. } => Some(source),
            Self::InvalidArchiveMember { source, .. } => Some(source),
            Self::ArchiveExtraction { source, .. } => Some(source),
            Self::UnsupportedBinding { .. } | Self::MissingArchiveIndex { .. } => None,
        }
    }
}

pub fn prepare_ordered_link_inputs<'a>(inputs: &[OrderedLinkInput<'a>]) -> Result<OrderedLinkObjects<'a>, OrderedLinkInputError> {
    prepare_ordered_link_inputs_with_forced_undefined(inputs, &[])
}

pub fn prepare_ordered_link_inputs_with_forced_undefined<'a>(
    inputs: &[OrderedLinkInput<'a>],
    forced_undefined: &[Vec<u8>],
) -> Result<OrderedLinkObjects<'a>, OrderedLinkInputError> {
    let mut objects = Vec::new();
    let mut origins = Vec::new();
    let mut defined = BTreeSet::new();
    let mut unresolved = forced_undefined.iter().cloned().collect::<BTreeSet<_>>();

    for (input_index, input) in inputs.iter().copied().enumerate() {
        match input {
            OrderedLinkInput::Object(file) => {
                let object_index = objects.len();
                let object = LinkerInputObject::parse(object_index, file).map_err(|source| OrderedLinkInputError::InvalidObject { input_index, source })?;
                update_symbol_state(input_index, object_index, file, &object, &mut defined, &mut unresolved)?;
                objects.push(object);
                origins.push(LinkObjectOrigin::Regular { input_index });
            }
            OrderedLinkInput::Archive(file) => {
                let archive = Archive::parse(file).map_err(|source| OrderedLinkInputError::InvalidArchive { input_index, source })?;
                let index = parse_archive_symbol_index(&archive)
                    .map_err(|source| OrderedLinkInputError::InvalidArchiveIndex { input_index, source })?
                    .ok_or(OrderedLinkInputError::MissingArchiveIndex { input_index })?;
                let extraction = extract_indexed_archive_members(
                    &archive,
                    &index,
                    unresolved.iter().map(Vec::as_slice),
                    defined.iter().map(Vec::as_slice),
                )
                .map_err(|source| OrderedLinkInputError::ArchiveExtraction { input_index, source })?;

                for extracted in extraction.members {
                    let object_index = objects.len();
                    let archive_member_index = extracted.archive_member_index;
                    let member_file = archive.members[archive_member_index].data;
                    let object = LinkerInputObject { object_index, file: member_file, object: extracted.object };
                    update_symbol_state(input_index, object_index, member_file, &object, &mut defined, &mut unresolved)?;
                    objects.push(object);
                    origins.push(LinkObjectOrigin::ArchiveMember { input_index, archive_member_index, member_name: extracted.name });
                }
            }
            OrderedLinkInput::WholeArchive(file) => {
                let archive = Archive::parse(file).map_err(|source| OrderedLinkInputError::InvalidArchive { input_index, source })?;
                for (archive_member_index, member) in archive.members.iter().enumerate() {
                    if member.kind != ArchiveMemberKind::Ordinary { continue; }
                    let object_index = objects.len();
                    let object = LinkerInputObject::parse(object_index, member.data).map_err(|source| OrderedLinkInputError::InvalidArchiveMember {
                        input_index,
                        archive_member_index,
                        member_name: member.name.clone(),
                        source,
                    })?;
                    update_symbol_state(input_index, object_index, member.data, &object, &mut defined, &mut unresolved)?;
                    objects.push(object);
                    origins.push(LinkObjectOrigin::ArchiveMember { input_index, archive_member_index, member_name: member.name.clone() });
                }
            }
        }
    }

    Ok(OrderedLinkObjects { objects, origins, unresolved })
}

fn update_symbol_state(
    input_index: usize,
    object_index: usize,
    file: &[u8],
    object: &LinkerInputObject<'_>,
    defined: &mut BTreeSet<Vec<u8>>,
    unresolved: &mut BTreeSet<Vec<u8>>,
) -> Result<(), OrderedLinkInputError> {
    let mut tables = object.object.symbol_tables.iter().collect::<Vec<_>>();
    tables.sort_by_key(|table| table.section_index);

    for table in tables {
        let named = named_symbols_from_table(file, &object.object.sections, table, object_index)
            .map_err(|source| OrderedLinkInputError::ObjectSymbols { input_index, object_index, source })?;
        for candidate in named {
            let binding = candidate.symbol.info >> 4;
            if binding == STB_LOCAL || candidate.name.is_empty() { continue; }
            if binding != STB_GLOBAL && binding != STB_WEAK {
                return Err(OrderedLinkInputError::UnsupportedBinding {
                    input_index,
                    object_index,
                    table_section_index: candidate.table_section_index,
                    symbol_index: candidate.symbol_index,
                    binding,
                });
            }

            let name = candidate.name.to_vec();
            if candidate.symbol.section_index == SHN_UNDEF {
                if binding == STB_GLOBAL && !defined.contains(&name) { unresolved.insert(name); }
            } else {
                defined.insert(name.clone());
                unresolved.remove(&name);
            }
        }
    }

    Ok(())
}
