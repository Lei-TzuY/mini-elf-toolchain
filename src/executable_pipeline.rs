use crate::executable_writer::{
    write_elf64_x86_64_executable_segments, ExecutableImage, ExecutableWriteError, LoadSegmentInput,
};
use crate::load_segments::{
    build_load_segments, LoadSegmentBuildError, LoadableSectionInput, SHF_ALLOC,
};
use crate::permission_layout::{
    layout_sections_by_permissions, PermissionLayoutError, PermissionLayoutInput,
};
use core::fmt;

#[derive(Debug, Clone, Copy)]
pub struct ExecutableSectionInput<'a> {
    pub object_index: usize,
    pub section_index: u16,
    pub section_type: u32,
    pub flags: u64,
    pub size: u64,
    pub alignment: u64,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutablePipelineError {
    Layout(PermissionLayoutError),
    LoadSegments(LoadSegmentBuildError),
    Write(ExecutableWriteError),
}

impl fmt::Display for ExecutablePipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layout(error) => write!(f, "section layout failed: {error}"),
            Self::LoadSegments(error) => write!(f, "load-segment construction failed: {error}"),
            Self::Write(error) => write!(f, "executable emission failed: {error}"),
        }
    }
}

impl std::error::Error for ExecutablePipelineError {}

impl From<PermissionLayoutError> for ExecutablePipelineError {
    fn from(error: PermissionLayoutError) -> Self {
        Self::Layout(error)
    }
}

impl From<LoadSegmentBuildError> for ExecutablePipelineError {
    fn from(error: LoadSegmentBuildError) -> Self {
        Self::LoadSegments(error)
    }
}

impl From<ExecutableWriteError> for ExecutablePipelineError {
    fn from(error: ExecutableWriteError) -> Self {
        Self::Write(error)
    }
}

pub fn write_executable_from_sections<'a, I>(
    start_address: u64,
    page_alignment: u64,
    entry_address: u64,
    sections: I,
) -> Result<ExecutableImage, ExecutablePipelineError>
where
    I: IntoIterator<Item = ExecutableSectionInput<'a>>,
{
    let alloc_sections = sections
        .into_iter()
        .filter(|section| section.flags & SHF_ALLOC != 0)
        .collect::<Vec<_>>();

    let layout = layout_sections_by_permissions(
        start_address,
        page_alignment,
        alloc_sections.iter().map(|section| PermissionLayoutInput {
            object_index: section.object_index,
            section_index: section.section_index,
            size: section.size,
            alignment: section.alignment,
            flags: section.flags,
        }),
    )?;

    let load_segments =
        build_load_segments(alloc_sections.iter().zip(layout).map(|(section, layout)| {
            LoadableSectionInput {
                layout,
                section_type: section.section_type,
                flags: section.flags,
                bytes: section.bytes,
            }
        }))?;

    let writer_segments = load_segments
        .iter()
        .map(|segment| LoadSegmentInput {
            image: &segment.image,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        })
        .collect::<Vec<_>>();

    Ok(write_elf64_x86_64_executable_segments(
        &writer_segments,
        entry_address,
        page_alignment,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executable_writer::LoadSegmentPermissions;
    use crate::load_segments::{SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

    const SHT_PROGBITS: u32 = 1;

    #[test]
    fn builds_page_separated_rx_r_rw_executable() {
        let text = [0x90, 0xc3];
        let rodata = *b"ELF!";
        let data = [1, 2, 3, 4];
        let sections = [
            ExecutableSectionInput {
                object_index: 0,
                section_index: 1,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                size: text.len() as u64,
                alignment: 16,
                bytes: &text,
            },
            ExecutableSectionInput {
                object_index: 0,
                section_index: 2,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC,
                size: rodata.len() as u64,
                alignment: 4,
                bytes: &rodata,
            },
            ExecutableSectionInput {
                object_index: 0,
                section_index: 3,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC | SHF_WRITE,
                size: data.len() as u64,
                alignment: 8,
                bytes: &data,
            },
            ExecutableSectionInput {
                object_index: 0,
                section_index: 4,
                section_type: SHT_NOBITS,
                flags: SHF_ALLOC | SHF_WRITE,
                size: 32,
                alignment: 16,
                bytes: &[],
            },
        ];

        let image = write_executable_from_sections(0x400000, 0x1000, 0x400000, sections)
            .expect("pipeline succeeds");

        assert_eq!(image.load_segments.len(), 3);
        assert_eq!(
            image.load_segments[0].permissions,
            LoadSegmentPermissions::ReadExecute
        );
        assert_eq!(
            image.load_segments[1].permissions,
            LoadSegmentPermissions::ReadOnly
        );
        assert_eq!(
            image.load_segments[2].permissions,
            LoadSegmentPermissions::ReadWrite
        );
        assert_eq!(image.load_segments[0].virtual_address, 0x400000);
        assert_eq!(image.load_segments[1].virtual_address, 0x401000);
        assert_eq!(image.load_segments[2].virtual_address, 0x402000);
        assert_eq!(image.load_segments[2].file_size, 4);
        assert_eq!(image.load_segments[2].memory_size, 48);

        for segment in &image.load_segments {
            assert_eq!(
                segment.file_offset % 0x1000,
                segment.virtual_address % 0x1000
            );
        }
    }

    #[test]
    fn ignores_non_alloc_sections_before_layout() {
        let debug = [7, 7, 7, 7];
        let text = [0xc3];
        let sections = [
            ExecutableSectionInput {
                object_index: 0,
                section_index: 9,
                section_type: SHT_PROGBITS,
                flags: 0,
                size: debug.len() as u64,
                alignment: 0x1000,
                bytes: &debug,
            },
            ExecutableSectionInput {
                object_index: 0,
                section_index: 1,
                section_type: SHT_PROGBITS,
                flags: SHF_ALLOC | SHF_EXECINSTR,
                size: text.len() as u64,
                alignment: 16,
                bytes: &text,
            },
        ];

        let image = write_executable_from_sections(0x401000, 0x1000, 0x401000, sections)
            .expect("pipeline succeeds");

        assert_eq!(image.load_segments.len(), 1);
        assert_eq!(image.load_segments[0].virtual_address, 0x401000);
        assert_eq!(image.load_segments[0].file_size, 1);
    }

    #[test]
    fn propagates_layout_validation_before_emission() {
        let bytes = [0x90];
        let sections = [ExecutableSectionInput {
            object_index: 3,
            section_index: 7,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR,
            size: 1,
            alignment: 1,
            bytes: &bytes,
        }];

        let error = write_executable_from_sections(0x400000, 0x1000, 0x400000, sections)
            .expect_err("W+X section must fail");

        assert_eq!(
            error,
            ExecutablePipelineError::Layout(PermissionLayoutError::WritableExecutableSection {
                object_index: 3,
                section_index: 7,
            })
        );
    }

    #[test]
    fn propagates_file_size_validation_after_layout() {
        let bytes = [0x90];
        let sections = [ExecutableSectionInput {
            object_index: 1,
            section_index: 2,
            section_type: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            size: 2,
            alignment: 1,
            bytes: &bytes,
        }];

        let error = write_executable_from_sections(0x400000, 0x1000, 0x400000, sections)
            .expect_err("size mismatch must fail");

        assert_eq!(
            error,
            ExecutablePipelineError::LoadSegments(LoadSegmentBuildError::SectionSizeMismatch {
                object_index: 1,
                section_index: 2,
                layout_size: 2,
                byte_size: 1,
            })
        );
    }
}
