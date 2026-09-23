use core::fmt;

use crate::elf64::SHT_STRTAB;
use crate::linker_input::LinkerInputObject;
use crate::load_segments::SHF_EXECINSTR;

const GNU_STACK_SECTION_NAME: &[u8] = b".note.GNU-stack";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GnuStackPolicy {
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GnuStackPolicyError {
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

pub(crate) fn gnu_stack_policy(
    inputs: &[LinkerInputObject<'_>],
) -> Result<Option<GnuStackPolicy>, GnuStackPolicyError> {
    let mut saw_stack_note = false;
    let mut executable = false;

    for input in inputs {
        let string_table_index = input.object.header.section_name_string_table_index;
        if string_table_index == 0 {
            continue;
        }
        let string_table = input
            .object
            .sections
            .get(usize::from(string_table_index))
            .ok_or(GnuStackPolicyError::MissingSectionNameStringTable {
                object_index: input.object_index,
                section_index: string_table_index,
            })?;
        if string_table.section_type != SHT_STRTAB {
            return Err(GnuStackPolicyError::SectionNameStringTableNotStringTable {
                object_index: input.object_index,
                section_index: string_table_index,
                section_type: string_table.section_type,
            });
        }
        let table_end = string_table.offset.checked_add(string_table.size).ok_or(
            GnuStackPolicyError::SectionNameStringTableRangeOverflow {
                object_index: input.object_index,
                section_index: string_table_index,
            },
        )?;
        if table_end > input.file.len() as u64 {
            return Err(GnuStackPolicyError::SectionNameStringTableOutOfBounds {
                object_index: input.object_index,
                section_index: string_table_index,
                end: table_end,
                file_len: input.file.len(),
            });
        }
        let table_start = usize::try_from(string_table.offset).map_err(|_| {
            GnuStackPolicyError::SectionNameStringTableOutOfBounds {
                object_index: input.object_index,
                section_index: string_table_index,
                end: table_end,
                file_len: input.file.len(),
            }
        })?;
        let table_end = usize::try_from(table_end).map_err(|_| {
            GnuStackPolicyError::SectionNameStringTableOutOfBounds {
                object_index: input.object_index,
                section_index: string_table_index,
                end: u64::MAX,
                file_len: input.file.len(),
            }
        })?;
        let names = &input.file[table_start..table_end];

        for (section_index, section) in input.object.sections.iter().enumerate() {
            let section_index = u16::try_from(section_index).map_err(|_| {
                GnuStackPolicyError::SectionNameOffsetOutOfBounds {
                    object_index: input.object_index,
                    section_index: u16::MAX,
                    name_offset: section.name_offset,
                    string_table_size: names.len(),
                }
            })?;
            let name = section_name(
                names,
                input.object_index,
                section_index,
                section.name_offset,
            )?;
            if name == GNU_STACK_SECTION_NAME {
                saw_stack_note = true;
                executable |= section.flags & SHF_EXECINSTR != 0;
            }
        }
    }

    Ok(saw_stack_note.then_some(GnuStackPolicy { executable }))
}

fn section_name<'a>(
    names: &'a [u8],
    object_index: usize,
    section_index: u16,
    name_offset: u32,
) -> Result<&'a [u8], GnuStackPolicyError> {
    let offset = usize::try_from(name_offset).map_err(|_| {
        GnuStackPolicyError::SectionNameOffsetOutOfBounds {
            object_index,
            section_index,
            name_offset,
            string_table_size: names.len(),
        }
    })?;
    if offset >= names.len() {
        return Err(GnuStackPolicyError::SectionNameOffsetOutOfBounds {
            object_index,
            section_index,
            name_offset,
            string_table_size: names.len(),
        });
    }
    let tail = &names[offset..];
    let end = tail.iter().position(|byte| *byte == 0).ok_or(
        GnuStackPolicyError::UnterminatedSectionName {
            object_index,
            section_index,
            name_offset,
        },
    )?;
    Ok(&tail[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nul_terminated_section_names() {
        let names = b"\0.text\0.note.GNU-stack\0";
        assert_eq!(section_name(names, 0, 3, 7).unwrap(), b".note.GNU-stack");
    }

    #[test]
    fn rejects_out_of_range_section_name_offsets() {
        let error = section_name(b"\0.text\0", 2, 4, 99).unwrap_err();
        assert!(matches!(
            error,
            GnuStackPolicyError::SectionNameOffsetOutOfBounds {
                object_index: 2,
                section_index: 4,
                ..
            }
        ));
    }

    #[test]
    fn rejects_unterminated_section_names() {
        let error = section_name(b"\0.text", 1, 2, 1).unwrap_err();
        assert!(matches!(
            error,
            GnuStackPolicyError::UnterminatedSectionName {
                object_index: 1,
                section_index: 2,
                ..
            }
        ));
    }
}
