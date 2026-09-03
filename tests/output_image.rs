use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::output_image::{
    materialize_section_image, OutputImageError, SectionImageInput,
};

fn section(
    object_index: usize,
    section_index: u16,
    address: u64,
    bytes: &'static [u8],
) -> SectionImageInput<'static> {
    SectionImageInput {
        layout: LaidOutSection {
            object_index,
            section_index,
            address,
            size: bytes.len() as u64,
        },
        bytes,
    }
}

#[test]
fn materializes_sections_with_zero_filled_gaps_in_address_order() {
    let image = materialize_section_image(
        0x1000,
        [
            section(1, 3, 0x1008, &[0xaa, 0xbb]),
            section(0, 2, 0x1000, &[1, 2, 3]),
        ],
    )
    .unwrap();

    assert_eq!(image.base_address, 0x1000);
    assert_eq!(image.bytes, vec![1, 2, 3, 0, 0, 0, 0, 0, 0xaa, 0xbb]);
    assert_eq!(image.sections.len(), 2);
    assert_eq!(image.sections[0].object_index, 0);
    assert_eq!(image.sections[0].image_offset, 0);
    assert_eq!(image.sections[1].object_index, 1);
    assert_eq!(image.sections[1].image_offset, 8);
}

#[test]
fn output_is_deterministic_regardless_of_input_order() {
    let a = section(0, 1, 0x2000, &[1, 2]);
    let b = section(1, 4, 0x2004, &[3, 4]);

    let forward = materialize_section_image(0x2000, [a, b]).unwrap();
    let reverse = materialize_section_image(0x2000, [b, a]).unwrap();

    assert_eq!(forward, reverse);
}

#[test]
fn rejects_layout_and_byte_size_mismatch() {
    let input = SectionImageInput {
        layout: LaidOutSection {
            object_index: 2,
            section_index: 7,
            address: 0x3000,
            size: 4,
        },
        bytes: &[1, 2, 3],
    };

    assert_eq!(
        materialize_section_image(0x3000, [input]),
        Err(OutputImageError::SizeMismatch {
            object_index: 2,
            section_index: 7,
            layout_size: 4,
            byte_size: 3,
        })
    );
}

#[test]
fn rejects_duplicate_section_identity_even_when_zero_sized() {
    let first = section(0, 5, 0x4000, &[]);
    let second = section(0, 5, 0x4000, &[]);

    assert_eq!(
        materialize_section_image(0x4000, [first, second]),
        Err(OutputImageError::DuplicateSection {
            object_index: 0,
            section_index: 5,
        })
    );
}

#[test]
fn rejects_sections_before_base_and_overlapping_ranges() {
    assert_eq!(
        materialize_section_image(0x5000, [section(0, 1, 0x4fff, &[1])]),
        Err(OutputImageError::SectionBeforeBase {
            object_index: 0,
            section_index: 1,
            address: 0x4fff,
            base_address: 0x5000,
        })
    );

    assert_eq!(
        materialize_section_image(
            0x5000,
            [
                section(0, 1, 0x5000, &[1, 2, 3, 4]),
                section(1, 2, 0x5002, &[5, 6]),
            ],
        ),
        Err(OutputImageError::OverlappingSections {
            first_object_index: 0,
            first_section_index: 1,
            second_object_index: 1,
            second_section_index: 2,
        })
    );
}

#[test]
fn rejects_section_end_overflow_before_allocation() {
    let input = SectionImageInput {
        layout: LaidOutSection {
            object_index: 3,
            section_index: 9,
            address: u64::MAX,
            size: 1,
        },
        bytes: &[0],
    };

    assert_eq!(
        materialize_section_image(u64::MAX, [input]),
        Err(OutputImageError::SectionEndOverflow {
            object_index: 3,
            section_index: 9,
            address: u64::MAX,
            size: 1,
        })
    );
}
