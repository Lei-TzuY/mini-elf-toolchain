use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::executable_writer::{
    write_elf64_x86_64_executable, write_elf64_x86_64_executable_segments,
    write_elf64_x86_64_executable_with_memory_size, ExecutableWriteError, LoadSegmentInput,
    LoadSegmentPermissions,
};
use mini_elf_toolchain::output_image::OutputSectionImage;
use std::fs;
use std::process::Command;

fn image(base_address: u64, bytes: &[u8]) -> OutputSectionImage {
    OutputSectionImage {
        base_address,
        bytes: bytes.to_vec(),
        sections: Vec::new(),
    }
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

#[test]
fn emits_elf64_x86_64_header_and_single_load_segment() {
    let input = image(0x401000, &[0x90, 0x90, 0xc3]);
    let executable = write_elf64_x86_64_executable(&input, 0x401000, 0x1000).unwrap();

    assert_eq!(&executable.bytes[0..4], b"\x7fELF");
    assert_eq!(executable.bytes[4], 2);
    assert_eq!(executable.bytes[5], 1);
    assert_eq!(read_u16(&executable.bytes, 16), 2);
    assert_eq!(read_u16(&executable.bytes, 18), 62);
    assert_eq!(read_u32(&executable.bytes, 20), 1);
    assert_eq!(read_u64(&executable.bytes, 24), 0x401000);
    assert_eq!(read_u64(&executable.bytes, 32), 64);
    assert_eq!(read_u16(&executable.bytes, 52), 64);
    assert_eq!(read_u16(&executable.bytes, 54), 56);
    assert_eq!(read_u16(&executable.bytes, 56), 1);

    let ph = 64;
    assert_eq!(read_u32(&executable.bytes, ph), 1);
    assert_eq!(read_u32(&executable.bytes, ph + 4), 5);
    assert_eq!(read_u64(&executable.bytes, ph + 8), 0x1000);
    assert_eq!(read_u64(&executable.bytes, ph + 16), 0x401000);
    assert_eq!(read_u64(&executable.bytes, ph + 24), 0x401000);
    assert_eq!(read_u64(&executable.bytes, ph + 32), 3);
    assert_eq!(read_u64(&executable.bytes, ph + 40), 3);
    assert_eq!(read_u64(&executable.bytes, ph + 48), 0x1000);
    assert_eq!(executable.load_memory_size, 3);
    assert_eq!(executable.load_segments.len(), 1);
    assert_eq!(&executable.bytes[0x1000..], &[0x90, 0x90, 0xc3]);

    let parsed = Elf64Header::parse(&executable.bytes).unwrap();
    assert_eq!(parsed.elf_type, 2);
    assert_eq!(parsed.entry, 0x401000);
    assert_eq!(parsed.program_header_count, 1);
    assert_eq!(parsed.section_header_count, 0);
}

#[test]
fn emits_load_segment_with_zero_fill_memory_tail() {
    let input = image(0x401000, &[0x90, 0xc3]);
    let executable =
        write_elf64_x86_64_executable_with_memory_size(&input, 0x401000, 0x1000, 0x102).unwrap();

    let ph = 64;
    assert_eq!(read_u64(&executable.bytes, ph + 32), 2);
    assert_eq!(read_u64(&executable.bytes, ph + 40), 0x102);
    assert_eq!(executable.load_memory_size, 0x102);
    assert_eq!(executable.bytes.len(), 0x1002);
    assert_eq!(&executable.bytes[0x1000..], &[0x90, 0xc3]);
}

#[test]
fn emits_checked_rx_and_rw_load_segments_in_virtual_address_order() {
    let text = image(0x401000, &[0x90, 0xc3]);
    let data = image(0x403000, &[1, 2, 3, 4]);
    let inputs = [
        LoadSegmentInput {
            image: &data,
            memory_size: 0x104,
            permissions: LoadSegmentPermissions::ReadWrite,
        },
        LoadSegmentInput {
            image: &text,
            memory_size: 2,
            permissions: LoadSegmentPermissions::ReadExecute,
        },
    ];

    let executable = write_elf64_x86_64_executable_segments(&inputs, 0x401000, 0x1000).unwrap();

    assert_eq!(read_u16(&executable.bytes, 56), 2);
    assert_eq!(executable.load_segments.len(), 2);

    let text_ph = 64;
    let data_ph = 64 + 56;
    assert_eq!(read_u32(&executable.bytes, text_ph + 4), 5);
    assert_eq!(read_u64(&executable.bytes, text_ph + 16), 0x401000);
    assert_eq!(read_u64(&executable.bytes, text_ph + 32), 2);
    assert_eq!(read_u64(&executable.bytes, text_ph + 40), 2);

    assert_eq!(read_u32(&executable.bytes, data_ph + 4), 6);
    assert_eq!(read_u64(&executable.bytes, data_ph + 16), 0x403000);
    assert_eq!(read_u64(&executable.bytes, data_ph + 32), 4);
    assert_eq!(read_u64(&executable.bytes, data_ph + 40), 0x104);

    let text_offset = read_u64(&executable.bytes, text_ph + 8) as usize;
    let data_offset = read_u64(&executable.bytes, data_ph + 8) as usize;
    assert_eq!(text_offset as u64 % 0x1000, 0x401000 % 0x1000);
    assert_eq!(data_offset as u64 % 0x1000, 0x403000 % 0x1000);
    assert!(data_offset >= text_offset + 2);
    assert_eq!(
        &executable.bytes[text_offset..text_offset + 2],
        &[0x90, 0xc3]
    );
    assert_eq!(
        &executable.bytes[data_offset..data_offset + 4],
        &[1, 2, 3, 4]
    );
}

#[test]
fn rejects_overlapping_load_segment_memory_ranges() {
    let text = image(0x401000, &[0x90, 0xc3]);
    let data = image(0x401100, &[1, 2]);
    let inputs = [
        LoadSegmentInput {
            image: &text,
            memory_size: 0x200,
            permissions: LoadSegmentPermissions::ReadExecute,
        },
        LoadSegmentInput {
            image: &data,
            memory_size: 2,
            permissions: LoadSegmentPermissions::ReadWrite,
        },
    ];

    assert_eq!(
        write_elf64_x86_64_executable_segments(&inputs, 0x401000, 0x1000),
        Err(ExecutableWriteError::SegmentAddressOverlap {
            previous_base: 0x401000,
            previous_memory_size: 0x200,
            next_base: 0x401100,
        })
    );
}

#[test]
fn rejects_entry_point_in_non_executable_load_segment() {
    let text = image(0x401000, &[0x90, 0xc3]);
    let data = image(0x403000, &[1, 2]);
    let inputs = [
        LoadSegmentInput {
            image: &text,
            memory_size: 2,
            permissions: LoadSegmentPermissions::ReadExecute,
        },
        LoadSegmentInput {
            image: &data,
            memory_size: 2,
            permissions: LoadSegmentPermissions::ReadWrite,
        },
    ];

    assert_eq!(
        write_elf64_x86_64_executable_segments(&inputs, 0x403000, 0x1000),
        Err(ExecutableWriteError::EntryOutsideExecutableSegment {
            entry_address: 0x403000,
        })
    );
}

#[test]
fn chooses_file_offset_congruent_with_nonzero_virtual_address_residue() {
    let input = image(0x400123, &[0xc3]);
    let executable = write_elf64_x86_64_executable(&input, 0x400123, 0x1000).unwrap();

    assert_eq!(executable.load_file_offset, 0x123);
    assert_eq!(executable.load_file_offset % 0x1000, 0x400123 % 0x1000);
    assert_eq!(read_u64(&executable.bytes, 64 + 8), 0x123);
    assert_eq!(executable.bytes[0x123], 0xc3);
}

#[test]
fn rejects_invalid_segment_alignment() {
    let input = image(0x400000, &[0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable(&input, 0x400000, 0),
        Err(ExecutableWriteError::InvalidSegmentAlignment { alignment: 0 })
    );
    assert_eq!(
        write_elf64_x86_64_executable(&input, 0x400000, 24),
        Err(ExecutableWriteError::InvalidSegmentAlignment { alignment: 24 })
    );
}

#[test]
fn rejects_memory_size_smaller_than_file_backing() {
    let input = image(0x400000, &[0x90, 0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable_with_memory_size(&input, 0x400000, 0x1000, 1),
        Err(ExecutableWriteError::MemorySizeSmallerThanFile {
            file_size: 2,
            memory_size: 1,
        })
    );
}

#[test]
fn rejects_memory_range_overflow() {
    let input = image(u64::MAX - 1, &[0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable_with_memory_size(&input, u64::MAX - 1, 1, 2),
        Err(ExecutableWriteError::MemoryEndOverflow {
            base_address: u64::MAX - 1,
            memory_size: 2,
        })
    );
}

#[test]
fn rejects_entry_outside_file_backed_image() {
    let input = image(0x400000, &[0x90, 0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable(&input, 0x3fffff, 0x1000),
        Err(ExecutableWriteError::EntryOutsideImage {
            entry_address: 0x3fffff,
            base_address: 0x400000,
            image_size: 2,
        })
    );
    assert_eq!(
        write_elf64_x86_64_executable(&input, 0x400002, 0x1000),
        Err(ExecutableWriteError::EntryOutsideImage {
            entry_address: 0x400002,
            base_address: 0x400000,
            image_size: 2,
        })
    );
}

#[test]
fn rejects_entry_in_memory_only_tail() {
    let input = image(0x400000, &[0x90, 0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable_with_memory_size(&input, 0x400002, 0x1000, 0x100),
        Err(ExecutableWriteError::EntryOutsideImage {
            entry_address: 0x400002,
            base_address: 0x400000,
            image_size: 2,
        })
    );
}

#[test]
fn rejects_virtual_image_end_overflow() {
    let input = image(u64::MAX, &[0xc3]);

    assert_eq!(
        write_elf64_x86_64_executable(&input, u64::MAX, 1),
        Err(ExecutableWriteError::ImageEndOverflow {
            base_address: u64::MAX,
            image_size: 1,
        })
    );
}

#[test]
fn gnu_readelf_accepts_emitted_header_and_program_header() {
    if Command::new("readelf").arg("--version").output().is_err() {
        return;
    }

    let text = image(0x401000, &[0x90, 0xc3]);
    let data = image(0x403000, &[1, 2]);
    let inputs = [
        LoadSegmentInput {
            image: &text,
            memory_size: 2,
            permissions: LoadSegmentPermissions::ReadExecute,
        },
        LoadSegmentInput {
            image: &data,
            memory_size: 0x102,
            permissions: LoadSegmentPermissions::ReadWrite,
        },
    ];
    let executable = write_elf64_x86_64_executable_segments(&inputs, 0x401000, 0x1000).unwrap();
    let path = std::env::temp_dir().join(format!(
        "mini-elf-toolchain-{}-writer-test.elf",
        std::process::id()
    ));
    fs::write(&path, &executable.bytes).unwrap();

    let output = Command::new("readelf")
        .args(["-h", "-l"])
        .arg(&path)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let _ = fs::remove_file(&path);

    assert!(
        output.status.success(),
        "readelf failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ELF64"));
    assert!(stdout.contains("EXEC"));
    assert!(stdout.contains("Advanced Micro Devices X86-64"));
    assert_eq!(stdout.matches("LOAD").count(), 2);
    assert!(stdout.contains("0x0000000000401000"));
    assert!(stdout.contains("0x0000000000403000"));
    assert!(stdout.contains("R E"));
    assert!(stdout.contains("RW"));
    assert!(stdout.contains("0x0000000000000002 0x0000000000000102"));
}
