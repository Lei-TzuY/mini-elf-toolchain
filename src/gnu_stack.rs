use core::fmt;

use crate::linker_input::LinkerInputObject;
use crate::load_segments::SHF_EXECINSTR;
use crate::section_names::{section_name, SectionNameError};

const GNU_STACK_SECTION_NAME: &[u8] = b".note.GNU-stack";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GnuStackPolicy {
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnuStackPolicyError {
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

impl fmt::Display for GnuStackPolicyError {
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

impl std::error::Error for GnuStackPolicyError {}

impl From<SectionNameError> for GnuStackPolicyError {
    fn from(error: SectionNameError) -> Self {
        match error {
            SectionNameError::MissingSectionNameStringTable {
                object_index,
                section_index,
            } => Self::MissingSectionNameStringTable {
                object_index,
                section_index,
            },
            SectionNameError::SectionNameStringTableNotStringTable {
                object_index,
                section_index,
                section_type,
            } => Self::SectionNameStringTableNotStringTable {
                object_index,
                section_index,
                section_type,
            },
            SectionNameError::SectionNameStringTableRangeOverflow {
                object_index,
                section_index,
            } => Self::SectionNameStringTableRangeOverflow {
                object_index,
                section_index,
            },
            SectionNameError::SectionNameStringTableOutOfBounds {
                object_index,
                section_index,
                end,
                file_len,
            } => Self::SectionNameStringTableOutOfBounds {
                object_index,
                section_index,
                end,
                file_len,
            },
            SectionNameError::SectionNameOffsetOutOfBounds {
                object_index,
                section_index,
                name_offset,
                string_table_size,
            } => Self::SectionNameOffsetOutOfBounds {
                object_index,
                section_index,
                name_offset,
                string_table_size,
            },
            SectionNameError::UnterminatedSectionName {
                object_index,
                section_index,
                name_offset,
            } => Self::UnterminatedSectionName {
                object_index,
                section_index,
                name_offset,
            },
        }
    }
}

pub(crate) fn gnu_stack_policy(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Option<GnuStackPolicy>, GnuStackPolicyError> {
    let mut saw_stack_note = false;
    let mut executable = false;

    for input in inputs {
        for (section_index, section) in input.object.sections.iter().enumerate() {
            let section_index = u16::try_from(section_index).map_err(|_| {
                GnuStackPolicyError::SectionNameOffsetOutOfBounds {
                    object_index: input.object_index,
                    section_index: u16::MAX,
                    name_offset: section.name_offset,
                    string_table_size: 0,
                }
            })?;
            if section_name(input, section_index)? == Some(GNU_STACK_SECTION_NAME) {
                saw_stack_note = true;
                executable |= section.flags & SHF_EXECINSTR != 0;
            }
        }
    }

    Ok(saw_stack_note.then_some(GnuStackPolicy { executable }))
}
