use crate::executable_writer::LoadSegmentPermissions;
use crate::layout::LaidOutSection;
use crate::output_image::{MaterializedSection, OutputSectionImage};
use core::fmt;
use std::collections::BTreeSet;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHT_NOBITS: u32 = 8;

#[derive(Debug, Clone, Copy)]
pub struct LoadableSectionInput<'a> {
    pub layout: LaidOutSection,
    pub section_type: u32,
    pub flags: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltLoadSegment {
    pub image: OutputSectionImage,
    pub memory_size: u64,
    pub permissions: LoadSegmentPermissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSegmentBuildError {
    DuplicateSection {
        object_index: usize,
        section_index: u16,
    },
    UnsupportedReadOnlySection {
        object_index: usize,
        section_index: u16,
    },
    WritableExecutableSection {
        object_index: usize,
        section_index: u16,
    },
    NobitsHasFileData {
        object_index: usize,
        section_index: u16,
        byte_size: usize,
    },
    SectionSizeMismatch {
        object_index: usize,
        section_index: u16,
        layout_size: u64,
        byte_size: u64,
    },
    SectionEndOverflow {
        object_index: usize,
        section_index: u16,
        address: u64,
        size: u64,
    },
    OverlappingSections {
        first_object_index: usize,
        first_section_index: u16,
        second_object_index: usize,
        second_section_index: u16,
    },
    SegmentTooLarge {
        base_address: u64,
        end_address: u64,
    },
}

impl fmt::Display for LoadSegmentBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSection {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} appears more than once"
            ),
            Self::UnsupportedReadOnlySection {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} is allocatable but neither executable nor writable; read-only PT_LOAD construction is not supported yet"
            ),
            Self::WritableExecutableSection {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} requests both SHF_WRITE and SHF_EXECINSTR"
            ),
            Self::NobitsHasFileData {
                object_index,
                section_index,
                byte_size,
            } => write!(
                f,
                "object {object_index} SHT_NOBITS section {section_index} unexpectedly has {byte_size} file bytes"
            ),
            Self::SectionSizeMismatch {
                object_index,
                section_index,
                layout_size,
                byte_size,
            } => write!(
                f,
                "object {object_index} section {section_index} has layout size {layout_size} but {byte_size} bytes were provided"
            ),
            Self::SectionEndOverflow {
                object_index,
                section_index,
                address,
                size,
            } => write!(
                f,
                "object {object_index} section {section_index} at {address:#x} with size {size} overflows u64"
            ),
            Self::OverlappingSections {
                first_object_index,
                first_section_index,
                second_object_index,
                second_section_index,
            } => write!(
                f,
                "object {first_object_index} section {first_section_index} overlaps object {second_object_index} section {second_section_index}"
            ),
            Self::SegmentTooLarge {
                base_address,
                end_address,
            } => write!(
                f,
                "load segment from {base_address:#x} through {end_address:#x} cannot be represented in memory"
            ),
        }
    }
}

impl std::error::Error for LoadSegmentBuildError {}

pub fn build_load_segments<'a, I>(
    sections: I,
) -> Result<Vec<BuiltLoadSegment>, LoadSegmentBuildError>
where
    I: IntoIterator<Item = LoadableSectionInput<'a>>,
{
    let mut ordered = Vec::new();
    let mut identities = BTreeSet::new();

    for input in sections {
        if input.flags & SHF_ALLOC == 0 {
            continue;
        }
        if !identities.insert((input.layout.object_index, input.layout.section_index)) {
            return Err(LoadSegmentBuildError::DuplicateSection {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
            });
        }
        let writable = input.flags & SHF_WRITE != 0;
        let executable = input.flags & SHF_EXECINSTR != 0;
        let permissions = match (writable, executable) {
            (true, true) => {
                return Err(LoadSegmentBuildError::WritableExecutableSection {
                    object_index: input.layout.object_index,
                    section_index: input.layout.section_index,
                })
            }
            (false, true) => LoadSegmentPermissions::ReadExecute,
            (true, false) => LoadSegmentPermissions::ReadWrite,
            (false, false) => {
                return Err(LoadSegmentBuildError::UnsupportedReadOnlySection {
                    object_index: input.layout.object_index,
                    section_index: input.layout.section_index,
                })
            }
        };
        if input.section_type == SHT_NOBITS {
            if !input.bytes.is_empty() {
                return Err(LoadSegmentBuildError::NobitsHasFileData {
                    object_index: input.layout.object_index,
                    section_index: input.layout.section_index,
                    byte_size: input.bytes.len(),
                });
            }
        } else {
            let byte_size = u64::try_from(input.bytes.len()).unwrap_or(u64::MAX);
            if byte_size != input.layout.size {
                return Err(LoadSegmentBuildError::SectionSizeMismatch {
                    object_index: input.layout.object_index,
                    section_index: input.layout.section_index,
                    layout_size: input.layout.size,
                    byte_size,
                });
            }
        }
        let end = input.layout.address.checked_add(input.layout.size).ok_or(
            LoadSegmentBuildError::SectionEndOverflow {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
                address: input.layout.address,
                size: input.layout.size,
            },
        )?;
        ordered.push((input, permissions, end));
    }

    ordered.sort_by_key(|(input, _, _)| {
        (
            input.layout.address,
            input.layout.object_index,
            input.layout.section_index,
        )
    });
    for pair in ordered.windows(2) {
        let (first, _, first_end) = &pair[0];
        let (second, _, _) = &pair[1];
        if second.layout.address < *first_end {
            return Err(LoadSegmentBuildError::OverlappingSections {
                first_object_index: first.layout.object_index,
                first_section_index: first.layout.section_index,
                second_object_index: second.layout.object_index,
                second_section_index: second.layout.section_index,
            });
        }
    }

    let mut groups: Vec<Vec<(LoadableSectionInput<'a>, LoadSegmentPermissions, u64)>> = Vec::new();
    for item in ordered {
        let starts_new = groups.last().and_then(|group| group.last()).is_some_and(
            |(previous, permissions, _)| {
                *permissions != item.1
                    || (previous.section_type == SHT_NOBITS && item.0.section_type != SHT_NOBITS)
            },
        );
        if groups.is_empty() || starts_new {
            groups.push(Vec::new());
        }
        groups.last_mut().expect("group exists").push(item);
    }

    groups.into_iter().map(build_group).collect()
}

fn build_group(
    group: Vec<(LoadableSectionInput<'_>, LoadSegmentPermissions, u64)>,
) -> Result<BuiltLoadSegment, LoadSegmentBuildError> {
    let base_address = group[0].0.layout.address;
    let permissions = group[0].1;
    let memory_end = group
        .iter()
        .map(|(_, _, end)| *end)
        .max()
        .unwrap_or(base_address);
    let file_end = group
        .iter()
        .filter(|(input, _, _)| input.section_type != SHT_NOBITS)
        .map(|(_, _, end)| *end)
        .max()
        .unwrap_or(base_address);
    let file_len_u64 = file_end - base_address;
    let file_len =
        usize::try_from(file_len_u64).map_err(|_| LoadSegmentBuildError::SegmentTooLarge {
            base_address,
            end_address: file_end,
        })?;
    let memory_size = memory_end - base_address;
    let mut bytes = vec![0; file_len];
    let mut materialized = Vec::new();

    for (input, _, _) in group {
        if input.section_type == SHT_NOBITS {
            continue;
        }
        let image_offset = input.layout.address - base_address;
        let start =
            usize::try_from(image_offset).map_err(|_| LoadSegmentBuildError::SegmentTooLarge {
                base_address,
                end_address: file_end,
            })?;
        let end =
            start
                .checked_add(input.bytes.len())
                .ok_or(LoadSegmentBuildError::SegmentTooLarge {
                    base_address,
                    end_address: file_end,
                })?;
        bytes[start..end].copy_from_slice(input.bytes);
        materialized.push(MaterializedSection {
            object_index: input.layout.object_index,
            section_index: input.layout.section_index,
            address: input.layout.address,
            image_offset,
            size: input.layout.size,
        });
    }

    Ok(BuiltLoadSegment {
        image: OutputSectionImage {
            base_address,
            bytes,
            sections: materialized,
        },
        memory_size,
        permissions,
    })
}
