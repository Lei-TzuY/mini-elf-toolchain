use core::fmt;

const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";
const MEMBER_HEADER_SIZE: usize = 60;
const NAME_END: usize = 16;
const SIZE_START: usize = 48;
const SIZE_END: usize = 58;
const TRAILER_START: usize = 58;
const TRAILER_END: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveMemberKind {
    Ordinary,
    SymbolTable,
    SymbolTable64,
    StringTable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember<'a> {
    pub name: Vec<u8>,
    pub kind: ArchiveMemberKind,
    pub header_offset: usize,
    pub data_offset: usize,
    pub declared_size: usize,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive<'a> {
    pub members: Vec<ArchiveMember<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveError {
    BadMagic,
    TruncatedHeader {
        offset: usize,
        available: usize,
    },
    InvalidHeaderTrailer {
        offset: usize,
    },
    InvalidSize {
        offset: usize,
    },
    SizeOverflow {
        offset: usize,
    },
    MemberRangeOverflow {
        offset: usize,
    },
    TruncatedMember {
        offset: usize,
        size: usize,
        available: usize,
    },
    MissingPadding {
        offset: usize,
    },
    EmptyMemberName {
        offset: usize,
    },
    InvalidBsdExtendedNameLength {
        offset: usize,
    },
    BsdExtendedNameLengthOverflow {
        offset: usize,
    },
    BsdExtendedNameOutOfBounds {
        offset: usize,
        name_len: usize,
        member_size: usize,
    },
    InvalidLongNameOffset {
        offset: usize,
    },
    LongNameOffsetOverflow {
        offset: usize,
    },
    MissingStringTable {
        offset: usize,
    },
    LongNameOutOfBounds {
        offset: usize,
        string_offset: usize,
        string_table_len: usize,
    },
    UnterminatedLongName {
        offset: usize,
        string_offset: usize,
    },
    DuplicateStringTable {
        offset: usize,
    },
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(
                f,
                "invalid archive magic; expected System V/GNU or BSD ar archive"
            ),
            Self::TruncatedHeader { offset, available } => write!(
                f,
                "truncated archive member header at offset {offset}: only {available} bytes remain"
            ),
            Self::InvalidHeaderTrailer { offset } => {
                write!(f, "invalid archive member header trailer at offset {offset}")
            }
            Self::InvalidSize { offset } => {
                write!(f, "invalid archive member size field at offset {offset}")
            }
            Self::SizeOverflow { offset } => {
                write!(f, "archive member size overflows usize at offset {offset}")
            }
            Self::MemberRangeOverflow { offset } => {
                write!(f, "archive member byte range overflows usize at offset {offset}")
            }
            Self::TruncatedMember {
                offset,
                size,
                available,
            } => write!(
                f,
                "truncated archive member at offset {offset}: declared {size} bytes, only {available} available"
            ),
            Self::MissingPadding { offset } => {
                write!(f, "missing archive alignment padding after member at offset {offset}")
            }
            Self::EmptyMemberName { offset } => {
                write!(f, "empty archive member name at offset {offset}")
            }
            Self::InvalidBsdExtendedNameLength { offset } => write!(
                f,
                "invalid BSD extended archive member name length at offset {offset}"
            ),
            Self::BsdExtendedNameLengthOverflow { offset } => write!(
                f,
                "BSD extended archive member name length overflows usize at offset {offset}"
            ),
            Self::BsdExtendedNameOutOfBounds {
                offset,
                name_len,
                member_size,
            } => write!(
                f,
                "BSD extended archive member name length {name_len} at offset {offset} exceeds member size {member_size}"
            ),
            Self::InvalidLongNameOffset { offset } => write!(
                f,
                "invalid GNU archive long-name offset in member at offset {offset}"
            ),
            Self::LongNameOffsetOverflow { offset } => write!(
                f,
                "GNU archive long-name offset overflows usize in member at offset {offset}"
            ),
            Self::MissingStringTable { offset } => write!(
                f,
                "GNU archive long-name reference at offset {offset} has no string table"
            ),
            Self::LongNameOutOfBounds {
                offset,
                string_offset,
                string_table_len,
            } => write!(
                f,
                "GNU archive long-name offset {string_offset} in member at offset {offset} is outside string table of {string_table_len} bytes"
            ),
            Self::UnterminatedLongName {
                offset,
                string_offset,
            } => write!(
                f,
                "unterminated GNU archive long name at string-table offset {string_offset} referenced by member at offset {offset}"
            ),
            Self::DuplicateStringTable { offset } => {
                write!(f, "duplicate GNU archive string table at offset {offset}")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

#[derive(Debug, Clone, Copy)]
struct RawMember<'a> {
    name_field: &'a [u8],
    header_offset: usize,
    data_offset: usize,
    declared_size: usize,
    data: &'a [u8],
}

impl<'a> Archive<'a> {
    pub fn parse(file: &'a [u8]) -> Result<Self, ArchiveError> {
        if file.get(..GLOBAL_HEADER.len()) != Some(&GLOBAL_HEADER[..]) {
            return Err(ArchiveError::BadMagic);
        }

        let mut raw_members = Vec::new();
        let mut cursor = GLOBAL_HEADER.len();
        while cursor < file.len() {
            let remaining = file.len() - cursor;
            if remaining < MEMBER_HEADER_SIZE {
                return Err(ArchiveError::TruncatedHeader {
                    offset: cursor,
                    available: remaining,
                });
            }

            let header_end = cursor
                .checked_add(MEMBER_HEADER_SIZE)
                .ok_or(ArchiveError::MemberRangeOverflow { offset: cursor })?;
            let header = &file[cursor..header_end];
            if &header[TRAILER_START..TRAILER_END] != b"`\n" {
                return Err(ArchiveError::InvalidHeaderTrailer { offset: cursor });
            }

            let declared_size = parse_decimal_size(&header[SIZE_START..SIZE_END], cursor)?;
            let data_offset = header_end;
            let data_end = data_offset
                .checked_add(declared_size)
                .ok_or(ArchiveError::MemberRangeOverflow { offset: cursor })?;
            if data_end > file.len() {
                return Err(ArchiveError::TruncatedMember {
                    offset: cursor,
                    size: declared_size,
                    available: file.len() - data_offset,
                });
            }

            raw_members.push(RawMember {
                name_field: &header[..NAME_END],
                header_offset: cursor,
                data_offset,
                declared_size,
                data: &file[data_offset..data_end],
            });

            cursor = data_end;
            if declared_size % 2 != 0 {
                if cursor == file.len() {
                    return Err(ArchiveError::MissingPadding { offset: cursor });
                }
                cursor = cursor
                    .checked_add(1)
                    .ok_or(ArchiveError::MemberRangeOverflow { offset: cursor })?;
            }
        }

        let mut string_table = None;
        for raw in &raw_members {
            if trimmed_name_field(raw.name_field) == b"//"
                && string_table.replace(raw.data).is_some()
            {
                return Err(ArchiveError::DuplicateStringTable {
                    offset: raw.header_offset,
                });
            }
        }

        let mut members = Vec::with_capacity(raw_members.len());
        for raw in raw_members {
            let token = trimmed_name_field(raw.name_field);
            let mut data_offset = raw.data_offset;
            let mut data = raw.data;
            let (kind, name) = if token == b"/" {
                (ArchiveMemberKind::SymbolTable, token.to_vec())
            } else if token == b"/SYM64/" {
                (ArchiveMemberKind::SymbolTable64, token.to_vec())
            } else if token == b"//" {
                (ArchiveMemberKind::StringTable, token.to_vec())
            } else if let Some(length_field) = token.strip_prefix(b"#1/") {
                let name_len = parse_bsd_extended_name_length(length_field, raw.header_offset)?;
                if name_len > raw.data.len() {
                    return Err(ArchiveError::BsdExtendedNameOutOfBounds {
                        offset: raw.header_offset,
                        name_len,
                        member_size: raw.data.len(),
                    });
                }
                let name_bytes = &raw.data[..name_len];
                let name_end = name_bytes
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |index| index + 1);
                if name_end == 0 {
                    return Err(ArchiveError::EmptyMemberName {
                        offset: raw.header_offset,
                    });
                }
                data_offset = raw
                    .data_offset
                    .checked_add(name_len)
                    .ok_or(ArchiveError::MemberRangeOverflow {
                        offset: raw.header_offset,
                    })?;
                data = &raw.data[name_len..];
                (ArchiveMemberKind::Ordinary, name_bytes[..name_end].to_vec())
            } else if token.starts_with(b"/") {
                let string_offset = parse_long_name_offset(&token[1..], raw.header_offset)?;
                let table = string_table.ok_or(ArchiveError::MissingStringTable {
                    offset: raw.header_offset,
                })?;
                let name = resolve_long_name(table, string_offset, raw.header_offset)?;
                (ArchiveMemberKind::Ordinary, name)
            } else {
                let name = short_member_name(token, raw.header_offset)?;
                (ArchiveMemberKind::Ordinary, name)
            };

            members.push(ArchiveMember {
                name,
                kind,
                header_offset: raw.header_offset,
                data_offset,
                declared_size: raw.declared_size,
                data,
            });
        }

        Ok(Self { members })
    }

    pub fn ordinary_members(&self) -> impl Iterator<Item = &ArchiveMember<'a>> {
        self.members
            .iter()
            .filter(|member| member.kind == ArchiveMemberKind::Ordinary)
    }
}

fn trimmed_name_field(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    &field[..end]
}

fn short_member_name(token: &[u8], offset: usize) -> Result<Vec<u8>, ArchiveError> {
    let name = token.strip_suffix(b"/").unwrap_or(token);
    if name.is_empty() {
        return Err(ArchiveError::EmptyMemberName { offset });
    }
    Ok(name.to_vec())
}

fn parse_decimal_size(field: &[u8], offset: usize) -> Result<usize, ArchiveError> {
    let trimmed = trim_ascii_spaces(field);
    if trimmed.is_empty() || !trimmed.iter().all(u8::is_ascii_digit) {
        return Err(ArchiveError::InvalidSize { offset });
    }
    parse_decimal_usize(trimmed).ok_or(ArchiveError::SizeOverflow { offset })
}

fn parse_bsd_extended_name_length(field: &[u8], offset: usize) -> Result<usize, ArchiveError> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(ArchiveError::InvalidBsdExtendedNameLength { offset });
    }
    parse_decimal_usize(field).ok_or(ArchiveError::BsdExtendedNameLengthOverflow { offset })
}

fn parse_long_name_offset(field: &[u8], offset: usize) -> Result<usize, ArchiveError> {
    if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
        return Err(ArchiveError::InvalidLongNameOffset { offset });
    }
    parse_decimal_usize(field).ok_or(ArchiveError::LongNameOffsetOverflow { offset })
}

fn parse_decimal_usize(bytes: &[u8]) -> Option<usize> {
    bytes.iter().try_fold(0usize, |value, byte| {
        value.checked_mul(10)?.checked_add(usize::from(byte - b'0'))
    })
}

fn trim_ascii_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn resolve_long_name(
    table: &[u8],
    string_offset: usize,
    member_offset: usize,
) -> Result<Vec<u8>, ArchiveError> {
    if string_offset >= table.len() {
        return Err(ArchiveError::LongNameOutOfBounds {
            offset: member_offset,
            string_offset,
            string_table_len: table.len(),
        });
    }

    let tail = &table[string_offset..];
    let newline =
        tail.iter()
            .position(|byte| *byte == b'\n')
            .ok_or(ArchiveError::UnterminatedLongName {
                offset: member_offset,
                string_offset,
            })?;
    let entry = &tail[..newline];
    let name = entry.strip_suffix(b"/").unwrap_or(entry);
    if name.is_empty() {
        return Err(ArchiveError::EmptyMemberName {
            offset: member_offset,
        });
    }
    Ok(name.to_vec())
}
