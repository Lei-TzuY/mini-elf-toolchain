use crate::archive::{Archive, ArchiveMemberKind};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveSymbolIndexKind {
    SysV32,
    SysV64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSymbolIndexEntry<'a> {
    pub name: &'a [u8],
    pub member_index: usize,
    pub member_header_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveSymbolIndex<'a> {
    pub kind: ArchiveSymbolIndexKind,
    pub entries: Vec<ArchiveSymbolIndexEntry<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveSymbolIndexError {
    MultipleSymbolTables {
        first_offset: usize,
        second_offset: usize,
    },
    TruncatedCount {
        offset: usize,
        width: usize,
        available: usize,
    },
    CountOverflow {
        offset: usize,
    },
    TableSizeOverflow {
        offset: usize,
        count: usize,
        width: usize,
    },
    TruncatedOffsets {
        offset: usize,
        count: usize,
        width: usize,
        available: usize,
    },
    MemberOffsetOverflow {
        offset: usize,
        raw_offset: u64,
    },
    UnknownMemberOffset {
        offset: usize,
        member_offset: usize,
    },
    SpecialMemberReference {
        offset: usize,
        member_offset: usize,
    },
    MissingSymbolName {
        offset: usize,
        symbol_index: usize,
    },
    UnterminatedSymbolName {
        offset: usize,
        symbol_index: usize,
    },
    EmptySymbolName {
        offset: usize,
        symbol_index: usize,
    },
    TrailingData {
        offset: usize,
        trailing_bytes: usize,
    },
}

impl fmt::Display for ArchiveSymbolIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultipleSymbolTables {
                first_offset,
                second_offset,
            } => write!(
                f,
                "multiple archive symbol tables at offsets {first_offset} and {second_offset}"
            ),
            Self::TruncatedCount {
                offset,
                width,
                available,
            } => write!(
                f,
                "truncated archive symbol count at member offset {offset}: need {width} bytes, only {available} available"
            ),
            Self::CountOverflow { offset } => write!(
                f,
                "archive symbol count does not fit usize at member offset {offset}"
            ),
            Self::TableSizeOverflow {
                offset,
                count,
                width,
            } => write!(
                f,
                "archive symbol offset table size overflows at member offset {offset}: count {count}, width {width}"
            ),
            Self::TruncatedOffsets {
                offset,
                count,
                width,
                available,
            } => write!(
                f,
                "truncated archive symbol offsets at member offset {offset}: {count} entries of {width} bytes exceed {available} available bytes"
            ),
            Self::MemberOffsetOverflow { offset, raw_offset } => write!(
                f,
                "archive symbol member offset {raw_offset} does not fit usize in symbol table at offset {offset}"
            ),
            Self::UnknownMemberOffset {
                offset,
                member_offset,
            } => write!(
                f,
                "archive symbol table at offset {offset} references unknown member header offset {member_offset}"
            ),
            Self::SpecialMemberReference {
                offset,
                member_offset,
            } => write!(
                f,
                "archive symbol table at offset {offset} references special member at header offset {member_offset}"
            ),
            Self::MissingSymbolName {
                offset,
                symbol_index,
            } => write!(
                f,
                "archive symbol table at offset {offset} has no bytes left for symbol {symbol_index}"
            ),
            Self::UnterminatedSymbolName {
                offset,
                symbol_index,
            } => write!(
                f,
                "archive symbol table at offset {offset} has unterminated name for symbol {symbol_index}"
            ),
            Self::EmptySymbolName {
                offset,
                symbol_index,
            } => write!(
                f,
                "archive symbol table at offset {offset} has an empty name for symbol {symbol_index}"
            ),
            Self::TrailingData {
                offset,
                trailing_bytes,
            } => write!(
                f,
                "archive symbol table at offset {offset} has {trailing_bytes} unexpected trailing bytes"
            ),
        }
    }
}

impl std::error::Error for ArchiveSymbolIndexError {}

pub fn parse_archive_symbol_index<'a>(
    archive: &'a Archive<'a>,
) -> Result<Option<ArchiveSymbolIndex<'a>>, ArchiveSymbolIndexError> {
    let mut selected = None;
    for member in &archive.members {
        let kind = match member.kind {
            ArchiveMemberKind::SymbolTable => ArchiveSymbolIndexKind::SysV32,
            ArchiveMemberKind::SymbolTable64 => ArchiveSymbolIndexKind::SysV64,
            _ => continue,
        };
        if let Some((first_offset, _, _)) = selected {
            return Err(ArchiveSymbolIndexError::MultipleSymbolTables {
                first_offset,
                second_offset: member.header_offset,
            });
        }
        selected = Some((member.header_offset, kind, member.data));
    }

    let Some((table_offset, kind, data)) = selected else {
        return Ok(None);
    };
    let width = match kind {
        ArchiveSymbolIndexKind::SysV32 => 4,
        ArchiveSymbolIndexKind::SysV64 => 8,
    };

    if data.len() < width {
        return Err(ArchiveSymbolIndexError::TruncatedCount {
            offset: table_offset,
            width,
            available: data.len(),
        });
    }

    let count_raw = read_be(data, 0, width);
    let count = usize::try_from(count_raw).map_err(|_| ArchiveSymbolIndexError::CountOverflow {
        offset: table_offset,
    })?;
    let offsets_size =
        count
            .checked_mul(width)
            .ok_or(ArchiveSymbolIndexError::TableSizeOverflow {
                offset: table_offset,
                count,
                width,
            })?;
    let names_start =
        width
            .checked_add(offsets_size)
            .ok_or(ArchiveSymbolIndexError::TableSizeOverflow {
                offset: table_offset,
                count,
                width,
            })?;
    if names_start > data.len() {
        return Err(ArchiveSymbolIndexError::TruncatedOffsets {
            offset: table_offset,
            count,
            width,
            available: data.len().saturating_sub(width),
        });
    }

    let mut member_indices = Vec::with_capacity(count);
    for index in 0..count {
        let entry_offset = width + index * width;
        let raw_offset = read_be(data, entry_offset, width);
        let member_offset = usize::try_from(raw_offset).map_err(|_| {
            ArchiveSymbolIndexError::MemberOffsetOverflow {
                offset: table_offset,
                raw_offset,
            }
        })?;
        let Some((member_index, member)) = archive
            .members
            .iter()
            .enumerate()
            .find(|(_, member)| member.header_offset == member_offset)
        else {
            return Err(ArchiveSymbolIndexError::UnknownMemberOffset {
                offset: table_offset,
                member_offset,
            });
        };
        if member.kind != ArchiveMemberKind::Ordinary {
            return Err(ArchiveSymbolIndexError::SpecialMemberReference {
                offset: table_offset,
                member_offset,
            });
        }
        member_indices.push((member_index, member_offset));
    }

    let mut entries = Vec::with_capacity(count);
    let mut cursor = names_start;
    for (symbol_index, (member_index, member_header_offset)) in
        member_indices.into_iter().enumerate()
    {
        if cursor == data.len() {
            return Err(ArchiveSymbolIndexError::MissingSymbolName {
                offset: table_offset,
                symbol_index,
            });
        }
        let tail = &data[cursor..];
        let Some(name_len) = tail.iter().position(|byte| *byte == 0) else {
            return Err(ArchiveSymbolIndexError::UnterminatedSymbolName {
                offset: table_offset,
                symbol_index,
            });
        };
        if name_len == 0 {
            return Err(ArchiveSymbolIndexError::EmptySymbolName {
                offset: table_offset,
                symbol_index,
            });
        }
        let name = &tail[..name_len];
        cursor =
            cursor
                .checked_add(name_len + 1)
                .ok_or(ArchiveSymbolIndexError::TableSizeOverflow {
                    offset: table_offset,
                    count,
                    width,
                })?;
        entries.push(ArchiveSymbolIndexEntry {
            name,
            member_index,
            member_header_offset,
        });
    }

    if data[cursor..].iter().any(|byte| *byte != 0) {
        return Err(ArchiveSymbolIndexError::TrailingData {
            offset: table_offset,
            trailing_bytes: data.len() - cursor,
        });
    }

    Ok(Some(ArchiveSymbolIndex { kind, entries }))
}

fn read_be(data: &[u8], start: usize, width: usize) -> u64 {
    data[start..start + width]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}
