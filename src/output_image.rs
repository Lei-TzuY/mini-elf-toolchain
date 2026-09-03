use crate::layout::LaidOutSection;
use core::fmt;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct SectionImageInput<'a> {
    pub layout: LaidOutSection,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedSection {
    pub object_index: usize,
    pub section_index: u16,
    pub address: u64,
    pub image_offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSectionImage {
    pub base_address: u64,
    pub bytes: Vec<u8>,
    pub sections: Vec<MaterializedSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputImageError {
    InputSizeTooLarge {
        object_index: usize,
        section_index: u16,
    },
    SizeMismatch {
        object_index: usize,
        section_index: u16,
        layout_size: u64,
        byte_size: u64,
    },
    DuplicateSection {
        object_index: usize,
        section_index: u16,
    },
    SectionBeforeBase {
        object_index: usize,
        section_index: u16,
        address: u64,
        base_address: u64,
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
    ImageTooLarge {
        base_address: u64,
        end_address: u64,
    },
}

impl fmt::Display for OutputImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputSizeTooLarge {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} byte length cannot be represented as u64"
            ),
            Self::SizeMismatch {
                object_index,
                section_index,
                layout_size,
                byte_size,
            } => write!(
                f,
                "object {object_index} section {section_index} has layout size {layout_size} but {byte_size} bytes were provided"
            ),
            Self::DuplicateSection {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} appears more than once in the output image"
            ),
            Self::SectionBeforeBase {
                object_index,
                section_index,
                address,
                base_address,
            } => write!(
                f,
                "object {object_index} section {section_index} at address {address} is below image base address {base_address}"
            ),
            Self::SectionEndOverflow {
                object_index,
                section_index,
                address,
                size,
            } => write!(
                f,
                "object {object_index} section {section_index} at address {address} with size {size} overflows u64"
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
            Self::ImageTooLarge {
                base_address,
                end_address,
            } => write!(
                f,
                "output image from address {base_address} through {end_address} cannot be represented in memory"
            ),
        }
    }
}

impl std::error::Error for OutputImageError {}

pub fn materialize_section_image<'a, I>(
    base_address: u64,
    sections: I,
) -> Result<OutputSectionImage, OutputImageError>
where
    I: IntoIterator<Item = SectionImageInput<'a>>,
{
    let mut inputs = Vec::new();
    let mut identities = BTreeSet::new();

    for input in sections {
        let byte_size = u64::try_from(input.bytes.len()).map_err(|_| {
            OutputImageError::InputSizeTooLarge {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
            }
        })?;
        if byte_size != input.layout.size {
            return Err(OutputImageError::SizeMismatch {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
                layout_size: input.layout.size,
                byte_size,
            });
        }
        if !identities.insert((input.layout.object_index, input.layout.section_index)) {
            return Err(OutputImageError::DuplicateSection {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
            });
        }
        if input.layout.address < base_address {
            return Err(OutputImageError::SectionBeforeBase {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
                address: input.layout.address,
                base_address,
            });
        }
        let end = input.layout.address.checked_add(input.layout.size).ok_or(
            OutputImageError::SectionEndOverflow {
                object_index: input.layout.object_index,
                section_index: input.layout.section_index,
                address: input.layout.address,
                size: input.layout.size,
            },
        )?;
        inputs.push((input, end));
    }

    inputs.sort_by_key(|(input, _)| {
        (
            input.layout.address,
            input.layout.object_index,
            input.layout.section_index,
        )
    });

    for pair in inputs.windows(2) {
        let (first, first_end) = &pair[0];
        let (second, _) = &pair[1];
        if second.layout.address < *first_end {
            return Err(OutputImageError::OverlappingSections {
                first_object_index: first.layout.object_index,
                first_section_index: first.layout.section_index,
                second_object_index: second.layout.object_index,
                second_section_index: second.layout.section_index,
            });
        }
    }

    let end_address = inputs
        .iter()
        .map(|(_, end)| *end)
        .max()
        .unwrap_or(base_address);
    let image_len_u64 = end_address.checked_sub(base_address).ok_or(
        OutputImageError::ImageTooLarge {
            base_address,
            end_address,
        },
    )?;
    let image_len = usize::try_from(image_len_u64).map_err(|_| OutputImageError::ImageTooLarge {
        base_address,
        end_address,
    })?;

    let mut bytes = vec![0; image_len];
    let mut materialized = Vec::with_capacity(inputs.len());

    for (input, _) in inputs {
        let image_offset = input.layout.address - base_address;
        let start = usize::try_from(image_offset).map_err(|_| OutputImageError::ImageTooLarge {
            base_address,
            end_address,
        })?;
        let end = start
            .checked_add(input.bytes.len())
            .ok_or(OutputImageError::ImageTooLarge {
                base_address,
                end_address,
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

    Ok(OutputSectionImage {
        base_address,
        bytes,
        sections: materialized,
    })
}
