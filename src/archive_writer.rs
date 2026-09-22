use crate::input_object::{RelocatableObject, RelocatableObjectError};
use crate::object_symbols::{named_symbols_from_table, ObjectSymbolError};
use crate::resolve::{SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use core::fmt;

const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";
const MEMBER_HEADER_SIZE: usize = 60;
const SHORT_NAME_LIMIT: usize = 15;

#[derive(Debug, Clone, Copy)]
pub struct ArchiveWriterMember<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveWriteError {
    EmptyMemberName {
        member_index: usize,
    },
    UnsafeMemberName {
        member_index: usize,
        name: Vec<u8>,
    },
    InvalidObject {
        member_index: usize,
        name: Vec<u8>,
        source: RelocatableObjectError,
    },
    ObjectSymbols {
        member_index: usize,
        name: Vec<u8>,
        source: ObjectSymbolError,
    },
    UnsupportedBinding {
        member_index: usize,
        table_section_index: u16,
        symbol_index: usize,
        binding: u8,
    },
    SymbolCountOverflow {
        count: usize,
    },
    ArchiveSizeOverflow,
    MemberOffsetOverflow {
        member_index: usize,
        offset: usize,
    },
    HeaderFieldOverflow {
        field: &'static str,
        value: usize,
        width: usize,
    },
    LongNameOffsetOverflow {
        member_index: usize,
        offset: usize,
    },
}

impl fmt::Display for ArchiveWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyMemberName { member_index } => {
                write!(f, "archive member {member_index} has an empty name")
            }
            Self::UnsafeMemberName { member_index, name } => write!(
                f,
                "archive member {member_index} has unsupported name '{}'; member names must be single safe file names",
                String::from_utf8_lossy(name)
            ),
            Self::InvalidObject {
                member_index,
                name,
                source,
            } => write!(
                f,
                "archive member {member_index} ({}) is not a valid ELF64 x86-64 ET_REL object: {source}",
                String::from_utf8_lossy(name)
            ),
            Self::ObjectSymbols {
                member_index,
                name,
                source,
            } => write!(
                f,
                "cannot read symbols from archive member {member_index} ({}): {source}",
                String::from_utf8_lossy(name)
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
            Self::SymbolCountOverflow { count } => {
                write!(f, "archive symbol count {count} exceeds the SysV32 index limit")
            }
            Self::ArchiveSizeOverflow => write!(f, "archive size arithmetic overflow"),
            Self::MemberOffsetOverflow {
                member_index,
                offset,
            } => write!(
                f,
                "archive member {member_index} header offset {offset} exceeds the SysV32 index limit"
            ),
            Self::HeaderFieldOverflow {
                field,
                value,
                width,
            } => write!(
                f,
                "archive {field} value {value} does not fit the {width}-byte header field"
            ),
            Self::LongNameOffsetOverflow {
                member_index,
                offset,
            } => write!(
                f,
                "archive member {member_index} long-name offset {offset} does not fit the 16-byte name field"
            ),
        }
    }
}

impl std::error::Error for ArchiveWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidObject { source, .. } => Some(source),
            Self::ObjectSymbols { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn write_indexed_archive(
    members: &[ArchiveWriterMember<'_>],
) -> Result<Vec<u8>, ArchiveWriteError> {
    let mut symbols = Vec::<(Vec<u8>, usize)>::new();
    let mut long_name_table = Vec::new();
    let mut long_name_offsets = Vec::with_capacity(members.len());

    for (member_index, member) in members.iter().enumerate() {
        validate_member_name(member_index, member.name)?;

        if needs_long_name(member.name) {
            let offset = long_name_table.len();
            long_name_table.extend_from_slice(member.name);
            long_name_table.extend_from_slice(b"/\n");
            long_name_offsets.push(Some(offset));
        } else {
            long_name_offsets.push(None);
        }

        let object = RelocatableObject::parse(member.data).map_err(|source| {
            ArchiveWriteError::InvalidObject {
                member_index,
                name: member.name.to_vec(),
                source,
            }
        })?;
        let mut tables = object.symbol_tables.iter().collect::<Vec<_>>();
        tables.sort_by_key(|table| table.section_index);
        for table in tables {
            let named = named_symbols_from_table(member.data, &object.sections, table, member_index)
                .map_err(|source| ArchiveWriteError::ObjectSymbols {
                    member_index,
                    name: member.name.to_vec(),
                    source,
                })?;
            for candidate in named {
                let binding = candidate.symbol.info >> 4;
                if binding == STB_LOCAL {
                    continue;
                }
                if binding != STB_GLOBAL && binding != STB_WEAK {
                    return Err(ArchiveWriteError::UnsupportedBinding {
                        member_index,
                        table_section_index: candidate.table_section_index,
                        symbol_index: candidate.symbol_index,
                        binding,
                    });
                }
                if candidate.name.is_empty() || candidate.symbol.section_index == SHN_UNDEF {
                    continue;
                }
                symbols.push((candidate.name.to_vec(), member_index));
            }
        }
    }

    let symbol_count =
        u32::try_from(symbols.len()).map_err(|_| ArchiveWriteError::SymbolCountOverflow {
            count: symbols.len(),
        })?;
    let index_size = 4usize
        .checked_add(
            symbols
                .len()
                .checked_mul(4)
                .ok_or(ArchiveWriteError::ArchiveSizeOverflow)?,
        )
        .and_then(|size| {
            symbols.iter().try_fold(size, |size, (name, _)| {
                size.checked_add(name.len().checked_add(1)?)
            })
        })
        .ok_or(ArchiveWriteError::ArchiveSizeOverflow)?;

    let mut cursor = GLOBAL_HEADER
        .len()
        .checked_add(MEMBER_HEADER_SIZE)
        .and_then(|value| value.checked_add(index_size))
        .and_then(|value| value.checked_add(index_size % 2))
        .ok_or(ArchiveWriteError::ArchiveSizeOverflow)?;

    if !long_name_table.is_empty() {
        cursor = cursor
            .checked_add(MEMBER_HEADER_SIZE)
            .and_then(|value| value.checked_add(long_name_table.len()))
            .and_then(|value| value.checked_add(long_name_table.len() % 2))
            .ok_or(ArchiveWriteError::ArchiveSizeOverflow)?;
    }

    let mut member_offsets = Vec::with_capacity(members.len());
    for (member_index, member) in members.iter().enumerate() {
        let raw_offset =
            u32::try_from(cursor).map_err(|_| ArchiveWriteError::MemberOffsetOverflow {
                member_index,
                offset: cursor,
            })?;
        member_offsets.push(raw_offset);
        cursor = cursor
            .checked_add(MEMBER_HEADER_SIZE)
            .and_then(|value| value.checked_add(member.data.len()))
            .and_then(|value| value.checked_add(member.data.len() % 2))
            .ok_or(ArchiveWriteError::ArchiveSizeOverflow)?;
    }

    let mut index = Vec::with_capacity(index_size);
    index.extend_from_slice(&symbol_count.to_be_bytes());
    for (_, member_index) in &symbols {
        index.extend_from_slice(&member_offsets[*member_index].to_be_bytes());
    }
    for (name, _) in &symbols {
        index.extend_from_slice(name);
        index.push(0);
    }
    debug_assert_eq!(index.len(), index_size);

    let mut archive = Vec::with_capacity(cursor);
    archive.extend_from_slice(GLOBAL_HEADER);
    append_member(&mut archive, b"/", &index, 0)?;

    if !long_name_table.is_empty() {
        append_member(&mut archive, b"//", &long_name_table, 0)?;
    }

    for (member_index, member) in members.iter().enumerate() {
        let name_field = if let Some(offset) = long_name_offsets[member_index] {
            let token = format!("/{offset}");
            if token.len() > 16 {
                return Err(ArchiveWriteError::LongNameOffsetOverflow {
                    member_index,
                    offset,
                });
            }
            token.into_bytes()
        } else {
            let mut token = member.name.to_vec();
            token.push(b'/');
            token
        };
        append_member(&mut archive, &name_field, member.data, 0o100644)?;
    }

    Ok(archive)
}

fn validate_member_name(member_index: usize, name: &[u8]) -> Result<(), ArchiveWriteError> {
    if name.is_empty() {
        return Err(ArchiveWriteError::EmptyMemberName { member_index });
    }
    if name == b"."
        || name == b".."
        || name.contains(&b'/')
        || name.contains(&b'\\')
        || name.contains(&0)
        || name.contains(&b'\n')
        || name.contains(&b'\r')
    {
        return Err(ArchiveWriteError::UnsafeMemberName {
            member_index,
            name: name.to_vec(),
        });
    }
    Ok(())
}

fn needs_long_name(name: &[u8]) -> bool {
    name.len() > SHORT_NAME_LIMIT || name.contains(&b' ')
}

fn append_member(
    archive: &mut Vec<u8>,
    name_field: &[u8],
    data: &[u8],
    mode: usize,
) -> Result<(), ArchiveWriteError> {
    let mut header = [b' '; MEMBER_HEADER_SIZE];
    write_bytes(&mut header[0..16], name_field, "member-name")?;
    write_decimal(&mut header[16..28], 0, "timestamp")?;
    write_decimal(&mut header[28..34], 0, "uid")?;
    write_decimal(&mut header[34..40], 0, "gid")?;
    write_octal(&mut header[40..48], mode, "mode")?;
    write_decimal(&mut header[48..58], data.len(), "member-size")?;
    header[58] = b'`';
    header[59] = b'\n';

    archive.extend_from_slice(&header);
    archive.extend_from_slice(data);
    if data.len() % 2 != 0 {
        archive.push(b'\n');
    }
    Ok(())
}

fn write_bytes(
    field: &mut [u8],
    value: &[u8],
    label: &'static str,
) -> Result<(), ArchiveWriteError> {
    if value.len() > field.len() {
        return Err(ArchiveWriteError::HeaderFieldOverflow {
            field: label,
            value: value.len(),
            width: field.len(),
        });
    }
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

fn write_decimal(
    field: &mut [u8],
    value: usize,
    label: &'static str,
) -> Result<(), ArchiveWriteError> {
    let text = value.to_string();
    write_bytes(field, text.as_bytes(), label).map_err(|_| ArchiveWriteError::HeaderFieldOverflow {
        field: label,
        value,
        width: field.len(),
    })
}

fn write_octal(
    field: &mut [u8],
    value: usize,
    label: &'static str,
) -> Result<(), ArchiveWriteError> {
    let text = format!("{value:o}");
    write_bytes(field, text.as_bytes(), label).map_err(|_| ArchiveWriteError::HeaderFieldOverflow {
        field: label,
        value,
        width: field.len(),
    })
}
