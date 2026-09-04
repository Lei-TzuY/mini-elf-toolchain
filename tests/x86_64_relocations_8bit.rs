use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationEvaluationError, RelocationValue, R_X86_64_8,
    R_X86_64_PC8,
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
fn evaluates_unsigned_8_absolute_relocation() {
    let value = evaluate_relocation(&relocation(R_X86_64_8, -1), 0x80, 0).unwrap();
    assert_eq!(value, RelocationValue::U8(0x7f));
}

#[test]
fn accepts_unsigned_8_boundaries() {
    let zero = evaluate_relocation(&relocation(R_X86_64_8, 0), 0, 0).unwrap();
    let max = evaluate_relocation(&relocation(R_X86_64_8, 0), u64::from(u8::MAX), 0).unwrap();
    assert_eq!(zero, RelocationValue::U8(0));
    assert_eq!(max, RelocationValue::U8(u8::MAX));
}

#[test]
fn rejects_unsigned_8_underflow_and_overflow() {
    let underflow = evaluate_relocation(&relocation(R_X86_64_8, -1), 0, 0).unwrap_err();
    let overflow = evaluate_relocation(&relocation(R_X86_64_8, 1), u64::from(u8::MAX), 0)
        .unwrap_err();
    assert_eq!(
        underflow,
        RelocationEvaluationError::Unsigned8OutOfRange { value: -1 }
    );
    assert_eq!(
        overflow,
        RelocationEvaluationError::Unsigned8OutOfRange {
            value: i128::from(u8::MAX) + 1
        }
    );
}

#[test]
fn evaluates_positive_and_negative_pc8_relocations() {
    let positive = evaluate_relocation(&relocation(R_X86_64_PC8, 0), 0x107f, 0x1000).unwrap();
    let negative = evaluate_relocation(&relocation(R_X86_64_PC8, 0), 0x1000, 0x1080).unwrap();
    assert_eq!(positive, RelocationValue::I8(i8::MAX));
    assert_eq!(negative, RelocationValue::I8(i8::MIN));
}

#[test]
fn rejects_pc8_positive_and_negative_overflow() {
    let positive = evaluate_relocation(&relocation(R_X86_64_PC8, i64::from(i8::MAX) + 1), 0, 0)
        .unwrap_err();
    let negative = evaluate_relocation(&relocation(R_X86_64_PC8, i64::from(i8::MIN) - 1), 0, 0)
        .unwrap_err();
    assert_eq!(
        positive,
        RelocationEvaluationError::Signed8OutOfRange {
            value: i128::from(i8::MAX) + 1
        }
    );
    assert_eq!(
        negative,
        RelocationEvaluationError::Signed8OutOfRange {
            value: i128::from(i8::MIN) - 1
        }
    );
}

#[test]
fn writes_unsigned_8_absolute_relocation() {
    let mut section = [0xaa; 3];
    let mut relocation = relocation(R_X86_64_8, 1);
    relocation.offset = 1;
    apply_relocation(&mut section, &relocation, 0x7e, 0).unwrap();
    assert_eq!(section, [0xaa, 0x7f, 0xaa]);
}

#[test]
fn writes_signed_pc8_relocation_twos_complement() {
    let mut section = [0xaa; 3];
    let mut relocation = relocation(R_X86_64_PC8, 0);
    relocation.offset = 1;
    apply_relocation(&mut section, &relocation, 0x1000, 0x1080).unwrap();
    assert_eq!(section, [0xaa, 0x80, 0xaa]);
}
