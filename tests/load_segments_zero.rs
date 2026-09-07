use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::load_segments::{
    build_load_segments, LoadSegmentBuildError, LoadableSectionInput, SHF_ALLOC,
    SHF_EXECINSTR,
};

fn section<'a>(
    object_index: usize,
    section_index: u16,
    address: u64,
    size: u64,
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
        section_type: 1,
        flags,
        bytes,
    }
}

#[test]
fn ignores_zero_sized_alloc_marker_inside_live_section() {
    let live = [0x90u8; 8];
    let segments = build_load_segments([
        section(0, 1, 0x401000, 8, SHF_ALLOC | SHF_EXECINSTR, &live),
        section(16, 3, 0x401004, 0, SHF_ALLOC, &[]),
    ])
    .unwrap();

    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0].image.base_address, 0x401000);
    assert_eq!(segments[0].image.bytes, live);
    assert_eq!(segments[0].memory_size, 8);
    assert_eq!(segments[0].image.sections.len(), 1);
    assert_eq!(segments[0].image.sections[0].object_index, 0);
    assert_eq!(segments[0].image.sections[0].section_index, 1);
}

#[test]
fn still_rejects_nonzero_overlap() {
    let first = [0u8; 8];
    let second = [0u8; 1];
    let error = build_load_segments([
        section(0, 1, 0x401000, 8, SHF_ALLOC | SHF_EXECINSTR, &first),
        section(16, 3, 0x401004, 1, SHF_ALLOC | SHF_EXECINSTR, &second),
    ])
    .unwrap_err();

    assert_eq!(
        error,
        LoadSegmentBuildError::OverlappingSections {
            first_object_index: 0,
            first_section_index: 1,
            second_object_index: 16,
            second_section_index: 3,
        }
    );
}
