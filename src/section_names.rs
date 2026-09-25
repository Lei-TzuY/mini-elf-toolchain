use core::fmt;

use crate::elf64::SHT_STRTAB;
use crate::linker_input::LinkerInputObject;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionNameError {
    MissingSectionNameStringTable {
        object_index: usize,
        section_index: u16,
    },
    SectionNameStringTableNotStringTable {
        object_index: usize,
        section_index: u16,
        section_type: u32,
    },
    SectionNameStringTableRangeOverflow {
        object_index: usize,
        section_index: u16,
    },
    SectionNameStringTableOutOfBounds {
        object_index: usize,
        section_index: u16,
        end: u64,
        file_len: usize,
    },
    SectionNameOffsetOutOfBounds {
        object_index: usize,
        section_index: u16,
        name_offset: u32,
        string_table_size: usize,
    },
    UnterminatedSectionName {
        object_index: usize,
        section_index: u16,
        name_offset: u32,
    },
}

impl fmt::Display for SectionNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSectionNameStringTable {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section-name string-table index {section_index} is missing"
            ),
            Self::SectionNameStringTableNotStringTable {
                object_index,
                section_index,
                section_type,
            } => write!(
                f,
                "object {object_index} section-name table {section_index} has type {section_type}, expected SHT_STRTAB"
            ),
            Self::SectionNameStringTableRangeOverflow {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section-name table {section_index} file range overflows u64"
            ),
            Self::SectionNameStringTableOutOfBounds {
                object_index,
                section_index,
                end,
                file_len,
            } => write!(
                f,
                "object {object_index} section-name table {section_index} ends at file offset {end}, beyond file length {file_len}"
            ),
            Self::SectionNameOffsetOutOfBounds {
                object_index,
                section_index,
                name_offset,
                string_table_size,
            } => write!(
                f,
                "object {object_index} section {section_index} has name offset {name_offset}, outside section-name table size {string_table_size}"
            ),
            Self::UnterminatedSectionName {
                object_index,
                section_index,
                name_offset,
            } => write!(
                f,
                "object {object_index} section {section_index} name at offset {name_offset} is not NUL-terminated"
            ),
        }
    }
}

impl std::error::Error for SectionNameError {}

pub(crate) fn section_name<'file>(
    input: &LinkerInputObject<'file>,
    section_index: u16,
) -> Result<Option<&'file [u8]>, SectionNameError> {
    let string_table_index = input.object.header.section_name_string_table_index;
    if string_table_index == 0 {
        return Ok(None);
    }
    let string_table = input
        .object
        .sections
        .get(usize::from(string_table_index))
        .ok_or(SectionNameError::MissingSectionNameStringTable {
            object_index: input.object_index,
            section_index: string_table_index,
        })?;
    if string_table.section_type != SHT_STRTAB {
        return Err(SectionNameError::SectionNameStringTableNotStringTable {
            object_index: input.object_index,
            section_index: string_table_index,
            section_type: string_table.section_type,
        });
    }
    let table_end = string_table.offset.checked_add(string_table.size).ok_or(
        SectionNameError::SectionNameStringTableRangeOverflow {
            object_index: input.object_index,
            section_index: string_table_index,
        },
    )?;
    if table_end > input.file.len() as u64 {
        return Err(SectionNameError::SectionNameStringTableOutOfBounds {
            object_index: input.object_index,
            section_index: string_table_index,
            end: table_end,
            file_len: input.file.len(),
        });
    }
    let table_start = usize::try_from(string_table.offset).map_err(|_| {
        SectionNameError::SectionNameStringTableOutOfBounds {
            object_index: input.object_index,
            section_index: string_table_index,
            end: table_end,
            file_len: input.file.len(),
        }
    })?;
    let table_end = usize::try_from(table_end).map_err(|_| {
        SectionNameError::SectionNameStringTableOutOfBounds {
            object_index: input.object_index,
            section_index: string_table_index,
            end: u64::MAX,
            file_len: input.file.len(),
        }
    })?;
    let names = &input.file[table_start..table_end];
    let section = &input.object.sections[usize::from(section_index)];
    let name_offset = section.name_offset;
    let offset = usize::try_from(name_offset).map_err(|_| {
        SectionNameError::SectionNameOffsetOutOfBounds {
            object_index: input.object_index,
            section_index,
            name_offset,
            string_table_size: names.len(),
        }
    })?;
    if offset >= names.len() {
        return Err(SectionNameError::SectionNameOffsetOutOfBounds {
            object_index: input.object_index,
            section_index,
            name_offset,
            string_table_size: names.len(),
        });
    }
    let tail = &names[offset..];
    let end = tail.iter().position(|byte| *byte == 0).ok_or(
        SectionNameError::UnterminatedSectionName {
            object_index: input.object_index,
            section_index,
            name_offset,
        },
    )?;
    Ok(Some(&tail[..end]))
}
