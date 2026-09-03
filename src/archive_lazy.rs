use core::fmt;
use std::collections::BTreeSet;

use crate::archive::{Archive, ArchiveMemberKind};
use crate::archive_index::ArchiveSymbolIndex;
use crate::input_object::{RelocatableObject, RelocatableObjectError};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::resolve::{SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedArchiveMember {
    pub archive_member_index: usize,
    pub name: Vec<u8>,
    pub object: RelocatableObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveExtraction {
    pub members: Vec<ExtractedArchiveMember>,
    pub unresolved: BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveExtractionError {
    IndexMemberMismatch {
        member_index: usize,
        expected_header_offset: usize,
    },
    InvalidObject {
        member_index: usize,
        member_name: Vec<u8>,
        source: RelocatableObjectError,
    },
    ObjectSymbols {
        member_index: usize,
        member_name: Vec<u8>,
        source: ObjectSymbolError,
    },
    UnsupportedBinding {
        member_index: usize,
        table_section_index: u16,
        symbol_index: usize,
        binding: u8,
    },
    StaleIndexEntry {
        symbol: Vec<u8>,
        member_index: usize,
    },
}

impl fmt::Display for ArchiveExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IndexMemberMismatch {
                member_index,
                expected_header_offset,
            } => write!(
                f,
                "archive symbol index member {member_index} does not match ordinary member at header offset {expected_header_offset}"
            ),
            Self::InvalidObject {
                member_index,
                member_name,
                source,
            } => write!(
                f,
                "cannot parse archive member {member_index} ({}) as ET_REL object: {source}",
                String::from_utf8_lossy(member_name)
            ),
            Self::ObjectSymbols {
                member_index,
                member_name,
                source,
            } => write!(
                f,
                "cannot read symbols from archive member {member_index} ({}): {source}",
                String::from_utf8_lossy(member_name)
            ),
            Self::UnsupportedBinding {
                member_index,
                table_section_index,
                symbol_index,
                binding,
            } => write!(
                f,
                "archive member {member_index} symbol {symbol_index} in table section {table_section_index} uses unsupported binding {binding}"
            ),
            Self::StaleIndexEntry {
                symbol,
                member_index,
            } => write!(
                f,
                "archive symbol index maps {} to member {member_index}, but that member does not define the symbol",
                String::from_utf8_lossy(symbol)
            ),
        }
    }
}

impl std::error::Error for ArchiveExtractionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidObject { source, .. } => Some(source),
            Self::ObjectSymbols { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn extract_indexed_archive_members<I, S, D, T>(
    archive: &Archive<'_>,
    index: &ArchiveSymbolIndex<'_>,
    initial_unresolved: I,
    initial_defined: D,
) -> Result<ArchiveExtraction, ArchiveExtractionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
    D: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut defined = initial_defined
        .into_iter()
        .map(|name| name.as_ref().to_vec())
        .filter(|name| !name.is_empty())
        .collect::<BTreeSet<_>>();
    let mut unresolved = initial_unresolved
        .into_iter()
        .map(|name| name.as_ref().to_vec())
        .filter(|name| !name.is_empty() && !defined.contains(name))
        .collect::<BTreeSet<_>>();
    let mut extracted_indices = BTreeSet::new();
    let mut extracted = Vec::new();

    while let Some(entry) = index.entries.iter().find(|entry| {
        unresolved.contains(entry.name) && !extracted_indices.contains(&entry.member_index)
    }) {
        let member = archive.members.get(entry.member_index).ok_or(
            ArchiveExtractionError::IndexMemberMismatch {
                member_index: entry.member_index,
                expected_header_offset: entry.member_header_offset,
            },
        )?;
        if member.kind != ArchiveMemberKind::Ordinary
            || member.header_offset != entry.member_header_offset
        {
            return Err(ArchiveExtractionError::IndexMemberMismatch {
                member_index: entry.member_index,
                expected_header_offset: entry.member_header_offset,
            });
        }

        let object = RelocatableObject::parse(member.data).map_err(|source| {
            ArchiveExtractionError::InvalidObject {
                member_index: entry.member_index,
                member_name: member.name.clone(),
                source,
            }
        })?;

        let mut member_definitions = BTreeSet::new();
        let mut member_undefined = BTreeSet::new();
        let mut tables = object.symbol_tables.iter().collect::<Vec<_>>();
        tables.sort_by_key(|table| table.section_index);
        for table in tables {
            let named = named_symbols_from_table(member.data, &object.sections, table, 0).map_err(
                |source| ArchiveExtractionError::ObjectSymbols {
                    member_index: entry.member_index,
                    member_name: member.name.clone(),
                    source,
                },
            )?;
            for candidate in named {
                let binding = candidate.symbol.info >> 4;
                if binding == STB_LOCAL {
                    continue;
                }
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(ArchiveExtractionError::UnsupportedBinding {
                        member_index: entry.member_index,
                        table_section_index: candidate.table_section_index,
                        symbol_index: candidate.symbol_index,
                        binding,
                    });
                }
                if candidate.name.is_empty() {
                    continue;
                }

                if candidate.symbol.section_index == SHN_UNDEF {
                    if binding == STB_GLOBAL {
                        member_undefined.insert(candidate.name.to_vec());
                    }
                } else {
                    member_definitions.insert(candidate.name.to_vec());
                }
            }
        }

        if !member_definitions.contains(entry.name) {
            return Err(ArchiveExtractionError::StaleIndexEntry {
                symbol: entry.name.to_vec(),
                member_index: entry.member_index,
            });
        }

        for symbol in &member_definitions {
            defined.insert(symbol.clone());
            unresolved.remove(symbol);
        }
        for symbol in member_undefined {
            if !defined.contains(&symbol) {
                unresolved.insert(symbol);
            }
        }

        extracted_indices.insert(entry.member_index);
        extracted.push(ExtractedArchiveMember {
            archive_member_index: entry.member_index,
            name: member.name.clone(),
            object,
        });
    }

    Ok(ArchiveExtraction {
        members: extracted,
        unresolved,
    })
}
