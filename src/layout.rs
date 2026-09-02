use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionLayoutInput {
    pub object_index: usize,
    pub section_index: u16,
    pub size: u64,
    pub alignment: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaidOutSection {
    pub object_index: usize,
    pub section_index: u16,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionLayoutError {
    InvalidAlignment {
        object_index: usize,
        section_index: u16,
        alignment: u64,
    },
    AlignmentOverflow {
        object_index: usize,
        section_index: u16,
        address: u64,
        alignment: u64,
    },
    SectionEndOverflow {
        object_index: usize,
        section_index: u16,
        address: u64,
        size: u64,
    },
}

impl fmt::Display for SectionLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlignment {
                object_index,
                section_index,
                alignment,
            } => write!(
                f,
                "object {object_index} section {section_index} has invalid alignment {alignment}; expected zero or a power of two"
            ),
            Self::AlignmentOverflow {
                object_index,
                section_index,
                address,
                alignment,
            } => write!(
                f,
                "aligning object {object_index} section {section_index} from address {address} to alignment {alignment} overflows u64"
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
        }
    }
}

impl std::error::Error for SectionLayoutError {}

pub fn layout_sections<I>(
    start_address: u64,
    sections: I,
) -> Result<Vec<LaidOutSection>, SectionLayoutError>
where
    I: IntoIterator<Item = SectionLayoutInput>,
{
    let mut cursor = start_address;
    let mut laid_out = Vec::new();

    for section in sections {
        if section.alignment != 0 && !section.alignment.is_power_of_two() {
            return Err(SectionLayoutError::InvalidAlignment {
                object_index: section.object_index,
                section_index: section.section_index,
                alignment: section.alignment,
            });
        }

        let address =
            align_up(cursor, section.alignment).ok_or(SectionLayoutError::AlignmentOverflow {
                object_index: section.object_index,
                section_index: section.section_index,
                address: cursor,
                alignment: section.alignment,
            })?;
        cursor =
            address
                .checked_add(section.size)
                .ok_or(SectionLayoutError::SectionEndOverflow {
                    object_index: section.object_index,
                    section_index: section.section_index,
                    address,
                    size: section.size,
                })?;

        laid_out.push(LaidOutSection {
            object_index: section.object_index,
            section_index: section.section_index,
            address,
            size: section.size,
        });
    }

    Ok(laid_out)
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}
