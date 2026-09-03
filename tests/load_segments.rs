use mini_elf_toolchain::executable_writer::{
    write_elf64_x86_64_executable_segments, LoadSegmentInput, LoadSegmentPermissions,
};
use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::load_segments::{
    build_load_segments, LoadSegmentBuildError, LoadableSectionInput, SHF_ALLOC, SHF_EXECINSTR,
    SHF_WRITE, SHT_NOBITS,
};
use std::process::Command;

fn section<'a>(
    object_index: usize,
    section_index: u16,
    address: u64,
    size: u64,
    section_type: u32,
    flags: u64,
    bytes: &'a [u8],
) -> LoadableSectionInput<'a> {
    LoadableSectionInput {
        layout: LaidOutSection {
            object_index,
            section_index,
            address,
            size,
        },
        section_type,
        flags,
        bytes,
    }
}

#[test]
fn builds_deterministic_rx_r_and_rw_segments_with_trailing_bss() {
    let text = [0x90, 0xc3];
    let rodata = [b'o', b'k'];
    let data = [1, 2, 3, 4];
    let inputs = [
        section(1, 4, 0x403004, 0x20, SHT_NOBITS, SHF_ALLOC | SHF_WRITE, &[]),
        section(0, 1, 0x401000, 2, 1, SHF_ALLOC | SHF_EXECINSTR, &text),
        section(0, 2, 0x402000, 2, 1, SHF_ALLOC, &rodata),
        section(1, 3, 0x403000, 4, 1, SHF_ALLOC | SHF_WRITE, &data),
    ];

    let segments = build_load_segments(inputs).unwrap();
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].permissions, LoadSegmentPermissions::ReadExecute);
    assert_eq!(segments[0].image.base_address, 0x401000);
    assert_eq!(segments[0].image.bytes, text);
    assert_eq!(segments[0].memory_size, 2);
    assert_eq!(segments[1].permissions, LoadSegmentPermissions::ReadOnly);
    assert_eq!(segments[1].image.base_address, 0x402000);
    assert_eq!(segments[1].image.bytes, rodata);
    assert_eq!(segments[1].memory_size, 2);
    assert_eq!(segments[2].permissions, LoadSegmentPermissions::ReadWrite);
    assert_eq!(segments[2].image.base_address, 0x403000);
    assert_eq!(segments[2].image.bytes, data);
    assert_eq!(segments[2].memory_size, 0x24);
}

#[test]
fn ignores_non_alloc_sections() {
    let debug = [7, 8, 9];
    let text = [0xc3];
    let segments = build_load_segments([
        section(0, 5, 0x100, 3, 1, 0, &debug),
        section(0, 1, 0x401000, 1, 1, SHF_ALLOC | SHF_EXECINSTR, &text),
    ])
    .unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].image.sections.len(), 1);
    assert_eq!(segments[0].image.sections[0].section_index, 1);
}

#[test]
fn rejects_writable_executable_sections() {
    let bytes = [0u8; 1];
    let error = build_load_segments([section(
        0,
        1,
        0x401000,
        1,
        1,
        SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR,
        &bytes,
    )])
    .unwrap_err();
    assert_eq!(
        error,
        LoadSegmentBuildError::WritableExecutableSection {
            object_index: 0,
            section_index: 1,
        }
    );
}

#[test]
fn groups_adjacent_read_only_sections_into_one_segment() {
    let first = [1u8, 2];
    let second = [3u8, 4];
    let segments = build_load_segments([
        section(0, 4, 0x402000, 2, 1, SHF_ALLOC, &first),
        section(0, 5, 0x402002, 2, 1, SHF_ALLOC, &second),
    ])
    .unwrap();

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].permissions, LoadSegmentPermissions::ReadOnly);
    assert_eq!(segments[0].image.base_address, 0x402000);
    assert_eq!(segments[0].image.bytes, [1, 2, 3, 4]);
    assert_eq!(segments[0].memory_size, 4);
}

#[test]
fn rejects_file_bytes_for_nobits() {
    let bytes = [0u8; 1];
    let error = build_load_segments([section(
        0,
        3,
        0x402000,
        8,
        SHT_NOBITS,
        SHF_ALLOC | SHF_WRITE,
        &bytes,
    )])
    .unwrap_err();
    assert_eq!(
        error,
        LoadSegmentBuildError::NobitsHasFileData {
            object_index: 0,
            section_index: 3,
            byte_size: 1,
        }
    );
}

#[test]
fn rejects_overlapping_alloc_sections() {
    let first = [0u8; 8];
    let second = [0u8; 4];
    let error = build_load_segments([
        section(0, 1, 0x401000, 8, 1, SHF_ALLOC | SHF_EXECINSTR, &first),
        section(0, 2, 0x401004, 4, 1, SHF_ALLOC | SHF_EXECINSTR, &second),
    ])
    .unwrap_err();
    assert_eq!(
        error,
        LoadSegmentBuildError::OverlappingSections {
            first_object_index: 0,
            first_section_index: 1,
            second_object_index: 0,
            second_section_index: 2,
        }
    );
}

#[test]
fn rejects_section_end_overflow() {
    let error = build_load_segments([section(
        0,
        1,
        u64::MAX,
        2,
        SHT_NOBITS,
        SHF_ALLOC | SHF_WRITE,
        &[],
    )])
    .unwrap_err();
    assert_eq!(
        error,
        LoadSegmentBuildError::SectionEndOverflow {
            object_index: 0,
            section_index: 1,
            address: u64::MAX,
            size: 2,
        }
    );
}

#[test]
fn built_segments_feed_writer_and_readelf_with_r_rx_rw_permissions() {
    if Command::new("readelf").arg("--version").output().is_err() {
        return;
    }

    let text = [0x90, 0xc3];
    let rodata = [b'o', b'k'];
    let data = [1, 2, 3, 4];
    let built = build_load_segments([
        section(0, 1, 0x401000, 2, 1, SHF_ALLOC | SHF_EXECINSTR, &text),
        section(0, 2, 0x402000, 2, 1, SHF_ALLOC, &rodata),
        section(0, 3, 0x403000, 4, 1, SHF_ALLOC | SHF_WRITE, &data),
        section(0, 4, 0x403004, 0x20, SHT_NOBITS, SHF_ALLOC | SHF_WRITE, &[]),
    ])
    .unwrap();
    let inputs = built
        .iter()
        .map(|segment| LoadSegmentInput {
            image: &segment.image,
            memory_size: segment.memory_size,
            permissions: segment.permissions,
        })
        .collect::<Vec<_>>();
    let executable = write_elf64_x86_64_executable_segments(&inputs, 0x401000, 0x1000).unwrap();

    let path =
        std::env::temp_dir().join(format!("mini-elf-load-segments-{}.elf", std::process::id()));
    std::fs::write(&path, &executable.bytes).unwrap();
    let output = Command::new("readelf")
        .args(["-lW"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let load_lines = stdout
        .lines()
        .filter(|line| line.contains(" LOAD "))
        .collect::<Vec<_>>();
    assert_eq!(load_lines.len(), 3);
    assert!(load_lines[0].contains("R E"));
    assert!(load_lines[1].contains(" R "));
    assert!(!load_lines[1].contains(" E "));
    assert!(!load_lines[1].contains(" W "));
    assert!(load_lines[2].contains("RW"));
}
