use mini_elf_toolchain::load_segments::{SHF_EXECINSTR, SHF_WRITE};
use mini_elf_toolchain::permission_layout::{
    layout_sections_by_permissions, PermissionLayoutError, PermissionLayoutInput,
};

fn input(section_index: u16, size: u64, alignment: u64, flags: u64) -> PermissionLayoutInput {
    PermissionLayoutInput {
        object_index: 0,
        section_index,
        size,
        alignment,
        flags,
    }
}

#[test]
fn keeps_same_permission_sections_packed_by_section_alignment() {
    let laid_out = layout_sections_by_permissions(
        0x401000,
        0x1000,
        [
            input(1, 0x30, 16, SHF_EXECINSTR),
            input(2, 0x20, 32, SHF_EXECINSTR),
        ],
    )
    .unwrap();

    assert_eq!(laid_out[0].address, 0x401000);
    assert_eq!(laid_out[1].address, 0x401040);
}

#[test]
fn moves_permission_changes_to_page_boundaries() {
    let laid_out = layout_sections_by_permissions(
        0x401000,
        0x1000,
        [
            input(1, 0x123, 16, SHF_EXECINSTR),
            input(2, 0x80, 16, 0),
            input(3, 0x40, 16, SHF_WRITE),
        ],
    )
    .unwrap();

    assert_eq!(laid_out[0].address, 0x401000);
    assert_eq!(laid_out[1].address, 0x402000);
    assert_eq!(laid_out[2].address, 0x403000);
}

#[test]
fn honors_section_alignment_larger_than_page_alignment() {
    let laid_out = layout_sections_by_permissions(
        0x401000,
        0x1000,
        [input(1, 1, 1, SHF_EXECINSTR), input(2, 1, 0x4000, 0)],
    )
    .unwrap();

    assert_eq!(laid_out[1].address, 0x404000);
}

#[test]
fn rejects_invalid_page_alignment() {
    assert_eq!(
        layout_sections_by_permissions(0x400000, 24, [input(1, 1, 1, 0)]),
        Err(PermissionLayoutError::InvalidPageAlignment { alignment: 24 })
    );
}

#[test]
fn rejects_writable_executable_sections() {
    assert_eq!(
        layout_sections_by_permissions(
            0x400000,
            0x1000,
            [input(7, 1, 1, SHF_WRITE | SHF_EXECINSTR)],
        ),
        Err(PermissionLayoutError::WritableExecutableSection {
            object_index: 0,
            section_index: 7,
        })
    );
}

#[test]
fn reports_page_boundary_alignment_overflow() {
    let error = layout_sections_by_permissions(
        u64::MAX - 7,
        0x1000,
        [input(1, 1, 1, SHF_EXECINSTR), input(2, 1, 1, 0)],
    )
    .unwrap_err();

    assert_eq!(
        error,
        PermissionLayoutError::AlignmentOverflow {
            object_index: 0,
            section_index: 2,
            address: u64::MAX - 6,
            alignment: 0x1000,
        }
    );
}

#[test]
fn reports_section_end_overflow() {
    assert_eq!(
        layout_sections_by_permissions(
            u64::MAX - 3,
            0x1000,
            [input(9, 8, 1, SHF_EXECINSTR)],
        ),
        Err(PermissionLayoutError::SectionEndOverflow {
            object_index: 0,
            section_index: 9,
            address: u64::MAX - 3,
            size: 8,
        })
    );
}
