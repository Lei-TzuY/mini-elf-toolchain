use crate::executable_writer::{ExecutableImage, ExecutableWriteError};

const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PF_R: u32 = 4;

pub(crate) fn map_runtime_program_headers(
    mut image: ExecutableImage,
) -> Result<ExecutableImage, ExecutableWriteError> {
    if image.load_segments.is_empty() {
        return Err(ExecutableWriteError::NoLoadSegments);
    }
    if image.bytes.len() < ELF64_EHDR_SIZE {
        return Err(ExecutableWriteError::FileTooLarge {
            file_size: image.bytes.len() as u64,
        });
    }

    let old_phoff = read_u64(&image.bytes, 32) as usize;
    let old_phentsize = read_u16(&image.bytes, 54) as usize;
    let old_phnum = read_u16(&image.bytes, 56) as usize;
    if old_phentsize != ELF64_PHDR_SIZE || old_phnum == 0 {
        return Err(ExecutableWriteError::NoLoadSegments);
    }
    let old_table_size =
        old_phnum
            .checked_mul(ELF64_PHDR_SIZE)
            .ok_or(ExecutableWriteError::FileTooLarge {
                file_size: u64::MAX,
            })?;
    let old_table_end =
        old_phoff
            .checked_add(old_table_size)
            .ok_or(ExecutableWriteError::FileTooLarge {
                file_size: u64::MAX,
            })?;
    if old_table_end > image.bytes.len() {
        return Err(ExecutableWriteError::FileTooLarge {
            file_size: image.bytes.len() as u64,
        });
    }
    if old_phnum == u16::MAX as usize {
        return Err(ExecutableWriteError::TooManyLoadSegments {
            count: old_phnum + 1,
        });
    }

    let last_index = image
        .load_segments
        .iter()
        .enumerate()
        .max_by_key(|(_, segment)| segment.virtual_address)
        .map(|(index, _)| index)
        .ok_or(ExecutableWriteError::NoLoadSegments)?;
    let last = image.load_segments[last_index].clone();
    let old_memory_file_end = last.file_offset.checked_add(last.memory_size).ok_or(
        ExecutableWriteError::FileEndOverflow {
            load_file_offset: last.file_offset,
            image_size: last.memory_size,
        },
    )?;
    let minimum_offset = (image.bytes.len() as u64).max(old_memory_file_end);
    let phdr_file_offset =
        align_up(minimum_offset, 8).ok_or(ExecutableWriteError::FileOffsetOverflow {
            metadata_end: minimum_offset,
            alignment: 8,
        })?;
    if phdr_file_offset < last.file_offset {
        return Err(ExecutableWriteError::FileOffsetOverflow {
            metadata_end: phdr_file_offset,
            alignment: 8,
        });
    }
    let delta = phdr_file_offset - last.file_offset;
    let phdr_virtual_address =
        last.virtual_address
            .checked_add(delta)
            .ok_or(ExecutableWriteError::MemoryEndOverflow {
                base_address: last.virtual_address,
                memory_size: delta,
            })?;
    let new_phnum = old_phnum + 1;
    let new_table_size =
        new_phnum
            .checked_mul(ELF64_PHDR_SIZE)
            .ok_or(ExecutableWriteError::FileTooLarge {
                file_size: u64::MAX,
            })?;
    let new_table_size_u64 = new_table_size as u64;
    let new_last_size =
        delta
            .checked_add(new_table_size_u64)
            .ok_or(ExecutableWriteError::FileEndOverflow {
                load_file_offset: last.file_offset,
                image_size: new_table_size_u64,
            })?;
    let new_file_end = phdr_file_offset.checked_add(new_table_size_u64).ok_or(
        ExecutableWriteError::FileEndOverflow {
            load_file_offset: phdr_file_offset,
            image_size: new_table_size_u64,
        },
    )?;
    let new_file_len =
        usize::try_from(new_file_end).map_err(|_| ExecutableWriteError::FileTooLarge {
            file_size: new_file_end,
        })?;

    let mut last_header_index = None;
    for index in 0..old_phnum {
        let start = old_phoff + index * ELF64_PHDR_SIZE;
        if read_u32(&image.bytes, start) == PT_LOAD
            && read_u64(&image.bytes, start + 8) == last.file_offset
            && read_u64(&image.bytes, start + 16) == last.virtual_address
        {
            last_header_index = Some(index);
            break;
        }
    }
    let last_header_index = last_header_index.ok_or(ExecutableWriteError::NoLoadSegments)?;

    let mut table = vec![0_u8; new_table_size];
    write_phdr_program_header(
        &mut table[..ELF64_PHDR_SIZE],
        phdr_file_offset,
        phdr_virtual_address,
        new_table_size_u64,
    );
    for index in 0..old_phnum {
        let old_start = old_phoff + index * ELF64_PHDR_SIZE;
        let new_start = (index + 1) * ELF64_PHDR_SIZE;
        table[new_start..new_start + ELF64_PHDR_SIZE]
            .copy_from_slice(&image.bytes[old_start..old_start + ELF64_PHDR_SIZE]);
        if index == last_header_index {
            put_u64(&mut table, new_start + 32, new_last_size);
            put_u64(&mut table, new_start + 40, new_last_size);
        }
    }

    image.bytes.resize(new_file_len, 0);
    put_u64(&mut image.bytes, 32, phdr_file_offset);
    put_u16(&mut image.bytes, 56, new_phnum as u16);
    let table_start = phdr_file_offset as usize;
    image.bytes[table_start..table_start + new_table_size].copy_from_slice(&table);

    image.load_segments[last_index].file_size = new_last_size;
    image.load_segments[last_index].memory_size = new_last_size;
    if image.load_segments.len() == 1 {
        image.load_memory_size = new_last_size;
    }
    Ok(image)
}

fn write_phdr_program_header(out: &mut [u8], file_offset: u64, vaddr: u64, size: u64) {
    put_u32(out, 0, PT_PHDR);
    put_u32(out, 4, PF_R);
    put_u64(out, 8, file_offset);
    put_u64(out, 16, vaddr);
    put_u64(out, 24, vaddr);
    put_u64(out, 32, size);
    put_u64(out, 40, size);
    put_u64(out, 48, 8);
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executable_writer::write_elf64_x86_64_executable;
    use crate::output_image::OutputSectionImage;

    #[test]
    fn appends_mapped_program_header_table_without_moving_payload() {
        let source = OutputSectionImage {
            base_address: 0x401000,
            bytes: vec![0xc3],
            sections: Vec::new(),
        };
        let original = write_elf64_x86_64_executable(&source, 0x401000, 0x1000).unwrap();
        let old_offset = original.load_segments[0].file_offset;
        let old_address = original.load_segments[0].virtual_address;
        let finalized = map_runtime_program_headers(original).unwrap();
        let phoff = read_u64(&finalized.bytes, 32) as usize;

        assert_eq!(read_u16(&finalized.bytes, 56), 2);
        assert_eq!(read_u32(&finalized.bytes, phoff), PT_PHDR);
        assert_eq!(
            read_u64(&finalized.bytes, phoff + 16),
            finalized.load_segments[0].virtual_address + (phoff as u64 - old_offset)
        );
        assert_eq!(read_u32(&finalized.bytes, phoff + ELF64_PHDR_SIZE), PT_LOAD);
        assert_eq!(
            read_u64(&finalized.bytes, phoff + ELF64_PHDR_SIZE + 8),
            old_offset
        );
        assert_eq!(
            read_u64(&finalized.bytes, phoff + ELF64_PHDR_SIZE + 16),
            old_address
        );
        assert_eq!(finalized.bytes[old_offset as usize], 0xc3);
    }
}
