use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationApplyError, RelocationEvaluationError,
    RelocationValue, R_X86_64_SIZE32, R_X86_64_SIZE64,
};

fn relocation(relocation_type: u32, offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type,
        addend,
    }
}

#[test]
fn evaluates_size32_and_size64_from_symbol_size_operand() {
    assert_eq!(
        evaluate_relocation(&relocation(R_X86_64_SIZE32, 0, -1), 0x101, 0).unwrap(),
        RelocationValue::U32(0x100)
    );
    assert_eq!(
        evaluate_relocation(&relocation(R_X86_64_SIZE64, 0, 7), 0x1000, u64::MAX).unwrap(),
        RelocationValue::U64(0x1007)
    );
}

#[test]
fn size32_checks_unsigned_range_and_size64_checks_underflow() {
    let too_large = evaluate_relocation(
        &relocation(R_X86_64_SIZE32, 0, 1),
        u64::from(u32::MAX),
        0,
    )
    .unwrap_err();
    assert_eq!(
        too_large,
        RelocationEvaluationError::Unsigned32OutOfRange {
            value: i128::from(u32::MAX) + 1,
        }
    );

    let underflow =
        evaluate_relocation(&relocation(R_X86_64_SIZE64, 0, -1), 0, 0).unwrap_err();
    assert_eq!(
        underflow,
        RelocationEvaluationError::Unsigned64OutOfRange { value: -1 }
    );
}

#[test]
fn applies_size_relocations_with_checked_target_widths() {
    let mut section = [0xa5; 12];
    apply_relocation(
        &mut section,
        &relocation(R_X86_64_SIZE32, 0, 1),
        4,
        0,
    )
    .unwrap();
    apply_relocation(
        &mut section,
        &relocation(R_X86_64_SIZE64, 4, -1),
        9,
        0,
    )
    .unwrap();
    assert_eq!(&section[..4], &5u32.to_le_bytes());
    assert_eq!(&section[4..], &8u64.to_le_bytes());

    let error = apply_relocation(
        &mut [0u8; 7],
        &relocation(R_X86_64_SIZE64, 0, 0),
        1,
        0,
    )
    .unwrap_err();
    assert_eq!(
        error,
        RelocationApplyError::TargetOutOfBounds {
            offset: 0,
            width: 8,
            end: 8,
            section_len: 7,
        }
    );
}
