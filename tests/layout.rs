use mini_elf_toolchain::layout::{layout_sections, SectionLayoutError, SectionLayoutInput};

fn input(object_index: usize, section_index: u16, size: u64, alignment: u64) -> SectionLayoutInput {
    SectionLayoutInput {
        object_index,
        section_index,
        size,
        alignment,
    }
}

#[test]
fn lays_out_sections_in_input_order_with_alignment() {
    let layout = layout_sections(
        0x1003,
        [
            input(0, 1, 5, 16),
            input(0, 2, 8, 8),
            input(1, 1, 3, 1),
        ],
    )
    .unwrap();

    assert_eq!(layout[0].address, 0x1010);
    assert_eq!(layout[1].address, 0x1018);
    assert_eq!(layout[2].address, 0x1020);
    assert_eq!(layout[2].object_index, 1);
    assert_eq!(layout[2].section_index, 1);
}

#[test]
fn treats_zero_alignment_as_no_alignment_requirement() {
    let layout = layout_sections(7, [input(0, 1, 2, 0)]).unwrap();

    assert_eq!(layout[0].address, 7);
}

#[test]
fn rejects_non_power_of_two_alignment() {
    let error = layout_sections(0, [input(2, 7, 1, 3)]).unwrap_err();

    assert_eq!(
        error,
        SectionLayoutError::InvalidAlignment {
            object_index: 2,
            section_index: 7,
            alignment: 3,
        }
    );
}

#[test]
fn rejects_alignment_rounding_overflow() {
    let error = layout_sections(u64::MAX - 3, [input(0, 4, 0, 8)]).unwrap_err();

    assert_eq!(
        error,
        SectionLayoutError::AlignmentOverflow {
            object_index: 0,
            section_index: 4,
            address: u64::MAX - 3,
            alignment: 8,
        }
    );
}

#[test]
fn rejects_section_end_overflow() {
    let error = layout_sections(u64::MAX - 1, [input(3, 9, 2, 1)]).unwrap_err();

    assert_eq!(
        error,
        SectionLayoutError::SectionEndOverflow {
            object_index: 3,
            section_index: 9,
            address: u64::MAX - 1,
            size: 2,
        }
    );
}

#[test]
fn zero_sized_section_still_observes_alignment() {
    let layout = layout_sections(0x1001, [input(0, 5, 0, 0x1000)]).unwrap();

    assert_eq!(layout[0].address, 0x2000);
    assert_eq!(layout[0].size, 0);
}
