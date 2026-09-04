use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationEvaluationError, RelocationValue,
    R_X86_64_PC64,
};

fn relocation(addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset: 0,
        symbol_index: 0,
        relocation_type: R_X86_64_PC64,
        addend,
    }
}

#[test]
fn evaluates_positive_and_negative_pc64_relocations() {
    let positive = evaluate_relocation(&relocation(-8), 0x5000, 0x4000).unwrap();
    let negative = evaluate_relocation(&relocation(0), 0x4000, 0x5000).unwrap();

    assert_eq!(positive, RelocationValue::I64(0xff8));
    assert_eq!(negative, RelocationValue::I64(-0x1000));
}

#[test]
fn accepts_signed_64_bit_boundaries() {
    let max = evaluate_relocation(&relocation(i64::MAX), 0, 0).unwrap();
    let min = evaluate_relocation(&relocation(i64::MIN), 0, 0).unwrap();

    assert_eq!(max, RelocationValue::I64(i64::MAX));
    assert_eq!(min, RelocationValue::I64(i64::MIN));
}

#[test]
fn rejects_pc64_positive_overflow() {
    let error = evaluate_relocation(&relocation(0), u64::MAX, 0).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Signed64OutOfRange {
            value: i128::from(u64::MAX),
        }
    );
}

#[test]
fn rejects_pc64_negative_overflow() {
    let error = evaluate_relocation(&relocation(i64::MIN), 0, 1).unwrap_err();

    assert_eq!(
        error,
        RelocationEvaluationError::Signed64OutOfRange {
            value: i128::from(i64::MIN) - 1,
        }
    );
}

#[test]
fn writes_pc64_relocation_little_endian() {
    let mut section = [0xaa; 12];
    let mut relocation = relocation(-8);
    relocation.offset = 2;

    apply_relocation(&mut section, &relocation, 0x5000, 0x4000).unwrap();

    assert_eq!(&section[..2], &[0xaa, 0xaa]);
    assert_eq!(&section[2..10], &0xff8_i64.to_le_bytes());
    assert_eq!(&section[10..], &[0xaa, 0xaa]);
}
