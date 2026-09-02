use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, write_relocation_value, RelocationApplyError,
    RelocationEvaluationError, RelocationValue, R_X86_64_64, R_X86_64_PC32,
};

fn relocation(relocation_type: u32, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset: 0,
        symbol_index: 0,
        relocation_type,
        addend,
    }
}

#[test]
fn evaluates_absolute_64_relocation() {
    let value = evaluate_relocation(&relocation(R_X86_64_64, -0x20), 0x120, 0x8000).unwrap();

    assert_eq!(value, RelocationValue::U64(0x100));
}

#[test]
fn accepts_maximum_unsigned_64_absolute_result() {
    let value = evaluate_relocation(&relocation(R_X86_64_64, 0), u64::MAX, 0).unwrap();

    assert_eq!(value, RelocationValue::U64(u64::MAX));
}

#[test]
fn rejects_negative_absolute_result() {
    let error = evaluate_relocation(&relocation(R_X86_64_64, -2), 1, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Unsigned64OutOfRange { value: -1 }
    );
}

#[test]
fn rejects_absolute_result_above_u64() {
    let error = evaluate_relocation(&relocation(R_X86_64_64, 1), u64::MAX, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Unsigned64OutOfRange {
            value: i128::from(u64::MAX) + 1
        }
    );
}

#[test]
fn evaluates_positive_pc32_relocation() {
    let value = evaluate_relocation(&relocation(R_X86_64_PC32, -4), 0x2200, 0x2000).unwrap();

    assert_eq!(value, RelocationValue::I32(0x1fc));
}

#[test]
fn evaluates_negative_pc32_relocation() {
    let value = evaluate_relocation(&relocation(R_X86_64_PC32, 0), 0x1000, 0x1010).unwrap();

    assert_eq!(value, RelocationValue::I32(-0x10));
}

#[test]
fn accepts_signed_32_bit_boundaries() {
    let max = evaluate_relocation(&relocation(R_X86_64_PC32, i64::from(i32::MAX)), 0, 0).unwrap();
    let min = evaluate_relocation(&relocation(R_X86_64_PC32, i64::from(i32::MIN)), 0, 0).unwrap();

    assert_eq!(max, RelocationValue::I32(i32::MAX));
    assert_eq!(min, RelocationValue::I32(i32::MIN));
}

#[test]
fn rejects_pc32_positive_overflow() {
    let error =
        evaluate_relocation(&relocation(R_X86_64_PC32, i64::from(i32::MAX) + 1), 0, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Signed32OutOfRange {
            value: i128::from(i32::MAX) + 1
        }
    );
}

#[test]
fn rejects_pc32_negative_overflow() {
    let error =
        evaluate_relocation(&relocation(R_X86_64_PC32, i64::from(i32::MIN) - 1), 0, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Signed32OutOfRange {
            value: i128::from(i32::MIN) - 1
        }
    );
}

#[test]
fn rejects_unsupported_relocation_type() {
    let error = evaluate_relocation(&relocation(42, 0), 0, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::UnsupportedRelocationType {
            relocation_type: 42
        }
    );
}

#[test]
fn writes_absolute_64_relocation_little_endian() {
    let mut section = [0xaa; 12];
    let mut relocation = relocation(R_X86_64_64, 1);
    relocation.offset = 2;

    apply_relocation(&mut section, &relocation, 0x0102_0304_0506_0708, 0).unwrap();

    assert_eq!(&section[..2], &[0xaa, 0xaa]);
    assert_eq!(&section[2..10], &0x0102_0304_0506_0709_u64.to_le_bytes());
    assert_eq!(&section[10..], &[0xaa, 0xaa]);
}

#[test]
fn writes_pc32_relocation_little_endian() {
    let mut section = [0; 8];
    let mut relocation = relocation(R_X86_64_PC32, 0);
    relocation.offset = 4;

    apply_relocation(&mut section, &relocation, 0x1000, 0x1010).unwrap();

    assert_eq!(&section[4..8], &(-0x10_i32).to_le_bytes());
}

#[test]
fn rejects_relocation_target_range_overflow_without_mutation() {
    let mut section = [0x5a; 16];
    let before = section;

    let error = write_relocation_value(
        &mut section,
        u64::MAX - 3,
        RelocationValue::U64(0x1122_3344_5566_7788),
    )
    .unwrap_err();

    assert_eq!(
        error,
        RelocationApplyError::TargetRangeOverflow {
            offset: u64::MAX - 3,
            width: 8,
        }
    );
    assert_eq!(section, before);
}

#[test]
fn rejects_relocation_target_out_of_bounds_without_mutation() {
    let mut section = [0x5a; 8];
    let before = section;

    let error = write_relocation_value(&mut section, 5, RelocationValue::I32(7)).unwrap_err();

    assert_eq!(
        error,
        RelocationApplyError::TargetOutOfBounds {
            offset: 5,
            width: 4,
            end: 9,
            section_len: 8,
        }
    );
    assert_eq!(section, before);
}

#[test]
fn propagates_evaluation_error_without_mutation() {
    let mut section = [0x5a; 8];
    let before = section;
    let mut relocation = relocation(R_X86_64_64, 1);
    relocation.offset = 0;

    let error = apply_relocation(&mut section, &relocation, u64::MAX, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationApplyError::Evaluation(RelocationEvaluationError::Unsigned64OutOfRange {
            value: i128::from(u64::MAX) + 1,
        })
    );
    assert_eq!(section, before);
}
