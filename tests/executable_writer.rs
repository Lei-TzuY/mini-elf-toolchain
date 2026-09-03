use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::executable_writer::{
    write_elf64_x86_64_executable, ExecutableWriteError,
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
    assert_eq!(&executable.bytes[0x1000..], &[0x90, 0x90, 0xc3]);

    let parsed = Elf64Header::parse(&executable.bytes).unwrap();
    assert_eq!(parsed.elf_type, 2);
    assert_eq!(parsed.entry, 0x401000);
    assert_eq!(parsed.program_header_count, 1);
    assert_eq!(parsed.section_header_count, 0);
}

#[test]
fn chooses_file_offset_congruent_with_nonzero_virtual_address_residue() {
    let input = image(0x400123, &[0xc3]);
    let executable = write_elf64_x86_64_executable(&input, 0x400123, 0x1000).unwrap();

    assert_eq!(executable.load_file_offset, 0x123);
    assert_eq!(
        executable.load_file_offset % 0x1000,
        0x400123 % 0x1000
    );
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

    let input = image(0x401000, &[0x90, 0xc3]);
    let executable = write_elf64_x86_64_executable(&input, 0x401000, 0x1000).unwrap();
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
    assert!(stdout.contains("LOAD"));
    assert!(stdout.contains("0x0000000000401000"));
}
