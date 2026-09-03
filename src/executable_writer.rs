use crate::output_image::OutputSectionImage;
use core::fmt;

const ELF64_EHDR_SIZE: u64 = 64;
const ELF64_PHDR_SIZE: u64 = 56;
const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_PROGRAM_HEADER_OFFSET: u64 = ELF64_EHDR_SIZE;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const EV_CURRENT: u32 = 1;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSegmentPermissions {
    ReadOnly,
    ReadExecute,
    ReadWrite,
}

impl LoadSegmentPermissions {
    fn elf_flags(self) -> u32 {
        match self {
            Self::ReadOnly => PF_R,
            Self::ReadExecute => PF_R | PF_X,
            Self::ReadWrite => PF_R | PF_W,
        }
    }

    fn is_executable(self) -> bool {
        matches!(self, Self::ReadExecute)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LoadSegmentInput<'a> {
    pub image: &'a OutputSectionImage,
    pub memory_size: u64,
    pub permissions: LoadSegmentPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableLoadSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub permissions: LoadSegmentPermissions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableImage {
    pub bytes: Vec<u8>,
    pub load_file_offset: u64,
    pub load_virtual_address: u64,
    pub load_memory_size: u64,
    pub entry_address: u64,
    pub load_segments: Vec<ExecutableLoadSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableWriteError {
    NoLoadSegments,
    TooManyLoadSegments { count: usize },
    InvalidSegmentAlignment { alignment: u64 },
    ImageEndOverflow { base_address: u64, image_size: u64 },
    MemorySizeSmallerThanFile { file_size: u64, memory_size: u64 },
    MemoryEndOverflow { base_address: u64, memory_size: u64 },
    SegmentAddressOverlap {
        previous_base: u64,
        previous_memory_size: u64,
        next_base: u64,
    },
    EntryOutsideImage {
        entry_address: u64,
        base_address: u64,
        image_size: u64,
    },
    EntryOutsideExecutableSegment { entry_address: u64 },
    FileOffsetOverflow { metadata_end: u64, alignment: u64 },
    FileEndOverflow { load_file_offset: u64, image_size: u64 },
    FileTooLarge { file_size: u64 },
}

impl fmt::Display for ExecutableWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLoadSegments => write!(f, "ELF executable requires at least one PT_LOAD segment"),
            Self::TooManyLoadSegments { count } => write!(f, "ELF executable has {count} PT_LOAD segments, exceeding the ELF64 program-header count limit"),
            Self::InvalidSegmentAlignment { alignment } => write!(f, "ELF load-segment alignment {alignment} must be a non-zero power of two"),
            Self::ImageEndOverflow { base_address, image_size } => write!(f, "output image at virtual address {base_address:#x} with size {image_size} overflows u64"),
            Self::MemorySizeSmallerThanFile { file_size, memory_size } => write!(f, "PT_LOAD memory size {memory_size} is smaller than file-backed size {file_size}"),
            Self::MemoryEndOverflow { base_address, memory_size } => write!(f, "PT_LOAD at virtual address {base_address:#x} with memory size {memory_size} overflows u64"),
            Self::SegmentAddressOverlap { previous_base, previous_memory_size, next_base } => write!(f, "PT_LOAD at {next_base:#x} overlaps previous PT_LOAD at {previous_base:#x} with memory size {previous_memory_size}"),
            Self::EntryOutsideImage { entry_address, base_address, image_size } => write!(f, "entry address {entry_address:#x} is outside output image at {base_address:#x} with size {image_size}"),
            Self::EntryOutsideExecutableSegment { entry_address } => write!(f, "entry address {entry_address:#x} is outside every file-backed executable PT_LOAD segment"),
            Self::FileOffsetOverflow { metadata_end, alignment } => write!(f, "cannot place PT_LOAD at or after file offset {metadata_end} with alignment {alignment} without overflowing u64"),
            Self::FileEndOverflow { load_file_offset, image_size } => write!(f, "PT_LOAD at file offset {load_file_offset} with size {image_size} overflows u64"),
            Self::FileTooLarge { file_size } => write!(f, "ELF executable file size {file_size} cannot be represented in memory"),
        }
    }
}

impl std::error::Error for ExecutableWriteError {}

pub fn write_elf64_x86_64_executable(
    image: &OutputSectionImage,
    entry_address: u64,
    segment_alignment: u64,
) -> Result<ExecutableImage, ExecutableWriteError> {
    let file_size = image_size(image)?;
    write_elf64_x86_64_executable_with_memory_size(image, entry_address, segment_alignment, file_size)
}

pub fn write_elf64_x86_64_executable_with_memory_size(
    image: &OutputSectionImage,
    entry_address: u64,
    segment_alignment: u64,
    memory_size: u64,
) -> Result<ExecutableImage, ExecutableWriteError> {
    let image_size = image_size(image)?;
    let image_end = checked_image_end(image, image_size)?;
    if entry_address < image.base_address || entry_address >= image_end {
        return Err(ExecutableWriteError::EntryOutsideImage {
            entry_address,
            base_address: image.base_address,
            image_size,
        });
    }

    let input = [LoadSegmentInput {
        image,
        memory_size,
        permissions: LoadSegmentPermissions::ReadExecute,
    }];
    write_elf64_x86_64_executable_segments(&input, entry_address, segment_alignment)
}

pub fn write_elf64_x86_64_executable_segments(
    segments: &[LoadSegmentInput<'_>],
    entry_address: u64,
    segment_alignment: u64,
) -> Result<ExecutableImage, ExecutableWriteError> {
    if segments.is_empty() {
        return Err(ExecutableWriteError::NoLoadSegments);
    }
    let program_header_count = u16::try_from(segments.len())
        .map_err(|_| ExecutableWriteError::TooManyLoadSegments { count: segments.len() })?;
    if segment_alignment == 0 || !segment_alignment.is_power_of_two() {
        return Err(ExecutableWriteError::InvalidSegmentAlignment {
            alignment: segment_alignment,
        });
    }

    let mut ordered = segments.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|segment| segment.image.base_address);

    let mut validated = Vec::with_capacity(ordered.len());
    let mut previous_memory_range: Option<(u64, u64)> = None;
    let mut entry_is_executable = false;

    for segment in ordered {
        let file_size = image_size(segment.image)?;
        let image_end = checked_image_end(segment.image, file_size)?;
        if segment.memory_size < file_size {
            return Err(ExecutableWriteError::MemorySizeSmallerThanFile {
                file_size,
                memory_size: segment.memory_size,
            });
        }
        let memory_end = segment
            .image
            .base_address
            .checked_add(segment.memory_size)
            .ok_or(ExecutableWriteError::MemoryEndOverflow {
                base_address: segment.image.base_address,
                memory_size: segment.memory_size,
            })?;

        if let Some((previous_base, previous_end)) = previous_memory_range {
            if segment.memory_size != 0 && segment.image.base_address < previous_end {
                return Err(ExecutableWriteError::SegmentAddressOverlap {
                    previous_base,
                    previous_memory_size: previous_end - previous_base,
                    next_base: segment.image.base_address,
                });
            }
        }
        if segment.memory_size != 0 {
            previous_memory_range = Some((segment.image.base_address, memory_end));
        }

        if segment.permissions.is_executable()
            && entry_address >= segment.image.base_address
            && entry_address < image_end
        {
            entry_is_executable = true;
        }

        validated.push((segment, file_size));
    }

    if !entry_is_executable {
        return Err(ExecutableWriteError::EntryOutsideExecutableSegment { entry_address });
    }

    let program_headers_size = ELF64_PHDR_SIZE
        .checked_mul(u64::from(program_header_count))
        .ok_or(ExecutableWriteError::FileTooLarge { file_size: u64::MAX })?;
    let metadata_end = ELF64_EHDR_SIZE
        .checked_add(program_headers_size)
        .ok_or(ExecutableWriteError::FileTooLarge { file_size: u64::MAX })?;

    let mut emitted_segments = Vec::with_capacity(validated.len());
    let mut next_file_offset = metadata_end;
    for (segment, file_size) in &validated {
        let file_offset = first_congruent_offset_at_or_after(
            next_file_offset,
            segment.image.base_address,
            segment_alignment,
        )?;
        let file_end =
            file_offset
                .checked_add(*file_size)
                .ok_or(ExecutableWriteError::FileEndOverflow {
                    load_file_offset: file_offset,
                    image_size: *file_size,
                })?;
        emitted_segments.push(ExecutableLoadSegment {
            file_offset,
            virtual_address: segment.image.base_address,
            file_size: *file_size,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        });
        next_file_offset = file_end;
    }

    let file_size = next_file_offset;
    let file_size_usize =
        usize::try_from(file_size).map_err(|_| ExecutableWriteError::FileTooLarge { file_size })?;
    let mut bytes = vec![0; file_size_usize];
    write_elf_header(
        &mut bytes[..ELF64_HEADER_BYTES],
        entry_address,
        program_header_count,
    );

    for (index, emitted) in emitted_segments.iter().enumerate() {
        let header_start = ELF64_HEADER_BYTES + index * ELF64_PROGRAM_HEADER_BYTES;
        write_program_header(
            &mut bytes[header_start..header_start + ELF64_PROGRAM_HEADER_BYTES],
            emitted,
            segment_alignment,
        );
    }

    for ((segment, _), emitted) in validated.iter().zip(&emitted_segments) {
        let start = usize::try_from(emitted.file_offset)
            .map_err(|_| ExecutableWriteError::FileTooLarge { file_size })?;
        let end = start + segment.image.bytes.len();
        bytes[start..end].copy_from_slice(&segment.image.bytes);
    }

    let first = &emitted_segments[0];
    Ok(ExecutableImage {
        bytes,
        load_file_offset: first.file_offset,
        load_virtual_address: first.virtual_address,
        load_memory_size: first.memory_size,
        entry_address,
        load_segments: emitted_segments,
    })
}

fn image_size(image: &OutputSectionImage) -> Result<u64, ExecutableWriteError> {
    u64::try_from(image.bytes.len())
        .map_err(|_| ExecutableWriteError::FileTooLarge { file_size: u64::MAX })
}

fn checked_image_end(
    image: &OutputSectionImage,
    image_size: u64,
) -> Result<u64, ExecutableWriteError> {
    image
        .base_address
        .checked_add(image_size)
        .ok_or(ExecutableWriteError::ImageEndOverflow {
            base_address: image.base_address,
            image_size,
        })
}

fn first_congruent_offset_at_or_after(
    minimum: u64,
    virtual_address: u64,
    alignment: u64,
) -> Result<u64, ExecutableWriteError> {
    let mask = alignment - 1;
    let residue = virtual_address & mask;
    let minimum_residue = minimum & mask;
    let delta = residue.wrapping_sub(minimum_residue) & mask;
    minimum
        .checked_add(delta)
        .ok_or(ExecutableWriteError::FileOffsetOverflow {
            metadata_end: minimum,
            alignment,
        })
}

fn write_elf_header(out: &mut [u8], entry_address: u64, program_header_count: u16) {
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2;
    out[5] = 1;
    out[6] = 1;
    out[7] = 0;
    put_u16(out, 16, ET_EXEC);
    put_u16(out, 18, EM_X86_64);
    put_u32(out, 20, EV_CURRENT);
    put_u64(out, 24, entry_address);
    put_u64(out, 32, ELF64_PROGRAM_HEADER_OFFSET);
    put_u64(out, 40, 0);
    put_u32(out, 48, 0);
    put_u16(out, 52, ELF64_EHDR_SIZE as u16);
    put_u16(out, 54, ELF64_PHDR_SIZE as u16);
    put_u16(out, 56, program_header_count);
    put_u16(out, 58, 0);
    put_u16(out, 60, 0);
    put_u16(out, 62, 0);
}

fn write_program_header(out: &mut [u8], segment: &ExecutableLoadSegment, alignment: u64) {
    put_u32(out, 0, PT_LOAD);
    put_u32(out, 4, segment.permissions.elf_flags());
    put_u64(out, 8, segment.file_offset);
    put_u64(out, 16, segment.virtual_address);
    put_u64(out, 24, segment.virtual_address);
    put_u64(out, 32, segment.file_size);
    put_u64(out, 40, segment.memory_size);
    put_u64(out, 48, alignment);
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
