use crate::archive::{Archive, ArchiveMemberKind};
use core::fmt;
use std::collections::BTreeSet;
use std::path::{Component, Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedArchiveExtraction<'a> {
    pub name: String,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveExtractionPlanError {
    NonUtf8MemberName { offset: usize },
    UnsafeMemberName { offset: usize, name: String },
    DuplicateOutputName { name: String },
}

impl fmt::Display for ArchiveExtractionPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonUtf8MemberName { offset } => {
                write!(f, "archive member name at offset {offset} is not UTF-8")
            }
            Self::UnsafeMemberName { offset, name } => write!(
                f,
                "unsafe archive member name '{name}' at offset {offset}; extraction targets must be single file names"
            ),
            Self::DuplicateOutputName { name } => {
                write!(f, "duplicate extraction output '{name}'")
            }
        }
    }
}

impl std::error::Error for ArchiveExtractionPlanError {}

pub fn plan_archive_extraction<'a>(
    archive: &Archive<'a>,
    selectors: &[String],
) -> Result<Vec<PlannedArchiveExtraction<'a>>, ArchiveExtractionPlanError> {
    let mut planned = Vec::new();
    let mut output_names = BTreeSet::new();

    for member in &archive.members {
        if member.kind != ArchiveMemberKind::Ordinary {
            continue;
        }
        if !selectors.is_empty()
            && !selectors
                .iter()
                .any(|selector| selector.as_bytes() == member.name.as_slice())
        {
            continue;
        }

        let name = std::str::from_utf8(&member.name)
            .map_err(|_| ArchiveExtractionPlanError::NonUtf8MemberName {
                offset: member.header_offset,
            })?
            .to_owned();

        if !is_safe_output_name(&name) {
            return Err(ArchiveExtractionPlanError::UnsafeMemberName {
                offset: member.header_offset,
                name,
            });
        }

        if !output_names.insert(name.clone()) {
            return Err(ArchiveExtractionPlanError::DuplicateOutputName { name });
        }

        planned.push(PlannedArchiveExtraction {
            name,
            data: member.data,
        });
    }

    Ok(planned)
}

fn is_safe_output_name(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&b'\\')
        || name.as_bytes().contains(&0)
    {
        return false;
    }

    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    )
}
