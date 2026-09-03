use crate::layout::LaidOutSection;
use crate::load_segments::{SHF_EXECINSTR, SHF_WRITE};
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionLayoutInput {
    pub object_index: usize,
    pub section_index: u16,
    pub size: u64,
    pub alignment: u64,
    pub flags: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionLayoutError {
    InvalidPageAlignment {
        alignment: u64,
    },
    InvalidSectionAlignment {
        object_index: usize,
        section_index: u16,
        alignment: u64,
    },
    WritableExecutableSection {
        object_index: usize,
        section_index: u16,
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

impl fmt::Display for PermissionLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPageAlignment { alignment } => write!(
                f,
                "invalid page alignment {alignment}; expected a non-zero power of two"
            ),
            Self::InvalidSectionAlignment {
                object_index,
                section_index,
                alignment,
            } => write!(
                f,
                "object {object_index} section {section_index} has invalid alignment {alignment}; expected zero or a power of two"
            ),
            Self::WritableExecutableSection {
                object_index,
                section_index,
            } => write!(
                f,
                "object {object_index} section {section_index} requests both SHF_WRITE and SHF_EXECINSTR"
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

impl std::error::Error for PermissionLayoutError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionClass {
    ReadOnly,
    ReadExecute,
    ReadWrite,
}

pub fn layout_sections_by_permissions<I>(
    start_address: u64,
    page_alignment: u64,
    sections: I,
) -> Result<Vec<LaidOutSection>, PermissionLayoutError>
where
    I: IntoIterator<Item = PermissionLayoutInput>,
{
    if page_alignment == 0 || !page_alignment.is_power_of_two() {
        return Err(PermissionLayoutError::InvalidPageAlignment {
            alignment: page_alignment,
        });
    }

    let mut cursor = start_address;
    let mut previous_permissions = None;
    let mut laid_out = Vec::new();

    for section in sections {
        if section.alignment != 0 && !section.alignment.is_power_of_two() {
            return Err(PermissionLayoutError::InvalidSectionAlignment {
                object_index: section.object_index,
                section_index: section.section_index,
                alignment: section.alignment,
            });
        }

        let permissions = permission_class(section)?;
        let mut required_alignment = section.alignment.max(1);
        if previous_permissions.is_some_and(|previous| previous != permissions) {
            required_alignment = required_alignment.max(page_alignment);
        }

        let address = align_up(cursor, required_alignment).ok_or(
            PermissionLayoutError::AlignmentOverflow {
                object_index: section.object_index,
                section_index: section.section_index,
                address: cursor,
                alignment: required_alignment,
            },
        )?;
        cursor =
            address
                .checked_add(section.size)
                .ok_or(PermissionLayoutError::SectionEndOverflow {
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
        previous_permissions = Some(permissions);
    }

    Ok(laid_out)
}

fn permission_class(
    section: PermissionLayoutInput,
) -> Result<PermissionClass, PermissionLayoutError> {
    let writable = section.flags & SHF_WRITE != 0;
    let executable = section.flags & SHF_EXECINSTR != 0;
    match (writable, executable) {
        (true, true) => Err(PermissionLayoutError::WritableExecutableSection {
            object_index: section.object_index,
            section_index: section.section_index,
        }),
        (false, true) => Ok(PermissionClass::ReadExecute),
        (true, false) => Ok(PermissionClass::ReadWrite),
        (false, false) => Ok(PermissionClass::ReadOnly),
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}
