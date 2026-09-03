use crate::output_image::OutputSectionImage;
use core::fmt;

const ELF64_EHDR_SIZE: u64 = 64;
const ELF64_PHDR_SIZE: u64 = 56;
const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_PROGRAM_HEADER_OFFSET: u64 = ELF64_EHDR_SIZE;
const ELF64_METADATA_END: u64 = ELF64_EHDR_SIZE + ELF64_PHDR_SIZE;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const EV_CURRENT: u32 = 1;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableImage {
    pub bytes: Vec<u8>,
    pub load_file_offset: u64,
    pub load_virtual_address: u64,
    pub load_memory_size: u64,
    pub entry_address: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableWriteError {
    InvalidSegmentAlignment {
        alignment: u64,
    },
    ImageEndOverflow {
        base_address: u64,
        image_size: u64,
    },
    MemorySizeSmallerThanFile {
        file_size: u64,
        memory_size: u64,
    },
    MemoryEndOverflow {
        base_address: u64,
        memory_size: u64,
    },
    EntryOutsideImage {
        entry_address: u64,
        base_address: u64,
        image_size: u64,
    },
    FileOffsetOverflow {
        metadata_end: u64,
        alignment: u64,
    },
    FileEndOverflow {
        load_file_offset: u64,
        image_size: u64,
    },
    FileTooLarge {
        file_size: u64,
    },
}

impl fmt::Display for ExecutableWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSegmentAlignment { alignment } => write!(
                f,
                "ELF load-segment alignment {alignment} must be a non-zero power of two"
            ),
            Self::ImageEndOverflow {
                base_address,
                image_size,
            } => write!(
                f,
                "output image at virtual address {base_address:#x} with size {image_size} overflows u64"
            ),
            Self::MemorySizeSmallerThanFile {
                file_size,
                memory_size,
            } => write!(
                f,
                "PT_LOAD memory size {memory_size} is smaller than file-backed size {file_size}"
            ),
            Self::MemoryEndOverflow {
                base_address,
                memory_size,
            } => write!(
                f,
                "PT_LOAD at virtual address {base_address:#x} with memory size {memory_size} overflows u64"
            ),
            Self::EntryOutsideImage {
                entry_address,
                base_address,
                image_size,
            } => write!(
                f,
                "entry address {entry_address:#x} is outside output image at {base_address:#x} with size {image_size}"
            ),
            Self::FileOffsetOverflow {
                metadata_end,
                alignment,
            } => write!(
                f,
                "cannot place PT_LOAD after file offset {metadata_end} with alignment {alignment} without overflowing u64"
            ),
            Self::FileEndOverflow {
                load_file_offset,
                image_size,
            } => write!(
                f,
                "PT_LOAD at file offset {load_file_offset} with size {image_size} overflows u64"
            ),
            Self::FileTooLarge { file_size } => write!(
                f,
                "ELF executable file size {file_size} cannot be represented in memory"
            ),
        }
    }
}

impl std::error::Error for ExecutableWriteError {}

pub fn write_elf64_x86_64_executable(
    image: &OutputSectionImage,
    entry_address: u64,
    segment_alignment: u64,
) -> Result<ExecutableImage, ExecutableWriteError> {
    let file_size =
        u64::try_from(image.bytes.len()).map_err(|_| ExecutableWriteError::FileTooLarge {
            file_size: u64::MAX,
        })?;
    write_elf64_x86_64_executable_with_memory_size(
        image,
        entry_address,
        segment_alignment,
        file_size,
    )
}

pub fn write_elf64_x86_64_executable_with_memory_size(
    image: &OutputSectionImage,
    entry_address: u64,
    segment_alignment: u64,
    memory_size: u64,
) -> Result<ExecutableImage, ExecutableWriteError> {
    if segment_alignment == 0 || !segment_alignment.is_power_of_two() {
        return Err(ExecutableWriteError::InvalidSegmentAlignment {
            alignment: segment_alignment,
        });
    }

    let image_size =
        u64::try_from(image.bytes.len()).map_err(|_| ExecutableWriteError::FileTooLarge {
            file_size: u64::MAX,
        })?;
    let image_end = image.base_address.checked_add(image_size).ok_or(
        ExecutableWriteError::ImageEndOverflow {
            base_address: image.base_address,
            image_size,
        },
    )?;
    if memory_size < image_size {
        return Err(ExecutableWriteError::MemorySizeSmallerThanFile {
            file_size: image_size,
            memory_size,
        });
    }
    image
        .base_address
        .checked_add(memory_size)
        .ok_or(ExecutableWriteError::MemoryEndOverflow {
            base_address: image.base_address,
            memory_size,
        })?;
    if entry_address < image.base_address || entry_address >= image_end {
        return Err(ExecutableWriteError::EntryOutsideImage {
            entry_address,
            base_address: image.base_address,
            image_size,
        });
    }

    let load_file_offset = first_congruent_offset_at_or_after(
        ELF64_METADATA_END,
        image.base_address,
        segment_alignment,
    )?;
    let file_size =
        load_file_offset
            .checked_add(image_size)
            .ok_or(ExecutableWriteError::FileEndOverflow {
                load_file_offset,
                image_size,
            })?;
    let file_size_usize =
        usize::try_from(file_size).map_err(|_| ExecutableWriteError::FileTooLarge { file_size })?;
    let load_file_offset_usize = usize::try_from(load_file_offset)
        .map_err(|_| ExecutableWriteError::FileTooLarge { file_size })?;

    let mut bytes = vec![0; file_size_usize];
    write_elf_header(&mut bytes[..ELF64_HEADER_BYTES], entry_address);
    write_program_header(
        &mut bytes[ELF64_HEADER_BYTES..ELF64_HEADER_BYTES + ELF64_PROGRAM_HEADER_BYTES],
        load_file_offset,
        image.base_address,
        image_size,
        memory_size,
        segment_alignment,
    );
    bytes[load_file_offset_usize..].copy_from_slice(&image.bytes);

    Ok(ExecutableImage {
        bytes,
        load_file_offset,
        load_virtual_address: image.base_address,
        load_memory_size: memory_size,
        entry_address,
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

fn write_elf_header(out: &mut [u8], entry_address: u64) {
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
    put_u16(out, 56, 1);
    put_u16(out, 58, 0);
    put_u16(out, 60, 0);
    put_u16(out, 62, 0);
}

fn write_program_header(
    out: &mut [u8],
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
) {
    put_u32(out, 0, PT_LOAD);
    put_u32(out, 4, PF_R | PF_X);
    put_u64(out, 8, file_offset);
    put_u64(out, 16, virtual_address);
    put_u64(out, 24, virtual_address);
    put_u64(out, 32, file_size);
    put_u64(out, 40, memory_size);
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
