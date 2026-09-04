use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationEvaluationError, RelocationValue, R_X86_64_16,
    R_X86_64_PC16,
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
fn evaluates_unsigned_16_bit_absolute_relocation() {
    let value = evaluate_relocation(&relocation(R_X86_64_16, -1), 0x1234, 0).unwrap();

    assert_eq!(value, RelocationValue::U16(0x1233));
}

#[test]
fn accepts_unsigned_16_bit_boundaries() {
    let zero = evaluate_relocation(&relocation(R_X86_64_16, 0), 0, 0).unwrap();
    let max = evaluate_relocation(&relocation(R_X86_64_16, 0), u16::MAX.into(), 0).unwrap();

    assert_eq!(zero, RelocationValue::U16(0));
    assert_eq!(max, RelocationValue::U16(u16::MAX));
}

#[test]
fn rejects_unsigned_16_bit_underflow_and_overflow() {
    let underflow = evaluate_relocation(&relocation(R_X86_64_16, -1), 0, 0).unwrap_err();
    let overflow = evaluate_relocation(&relocation(R_X86_64_16, 0), u64::from(u16::MAX) + 1, 0)
        .unwrap_err();

    assert_eq!(
        underflow,
        RelocationEvaluationError::Unsigned16OutOfRange { value: -1 }
    );
    assert_eq!(
        overflow,
        RelocationEvaluationError::Unsigned16OutOfRange {
            value: i128::from(u16::MAX) + 1,
        }
    );
}

#[test]
fn evaluates_positive_and_negative_pc16_relocations() {
    let positive = evaluate_relocation(&relocation(R_X86_64_PC16, -2), 0x4100, 0x4000).unwrap();
    let negative = evaluate_relocation(&relocation(R_X86_64_PC16, 0), 0x4000, 0x4100).unwrap();

    assert_eq!(positive, RelocationValue::I16(0xfe));
    assert_eq!(negative, RelocationValue::I16(-0x100));
}

#[test]
fn accepts_signed_16_bit_boundaries() {
    let max = evaluate_relocation(
        &relocation(R_X86_64_PC16, i64::from(i16::MAX)),
        0,
        0,
    )
    .unwrap();
    let min = evaluate_relocation(
        &relocation(R_X86_64_PC16, i64::from(i16::MIN)),
        0,
        0,
    )
    .unwrap();

    assert_eq!(max, RelocationValue::I16(i16::MAX));
    assert_eq!(min, RelocationValue::I16(i16::MIN));
}

#[test]
fn rejects_pc16_positive_and_negative_overflow() {
    let positive = evaluate_relocation(
        &relocation(R_X86_64_PC16, 0),
        i16::MAX as u64 + 1,
        0,
    )
    .unwrap_err();
    let negative = evaluate_relocation(
        &relocation(R_X86_64_PC16, i64::from(i16::MIN)),
        0,
        1,
    )
    .unwrap_err();

    assert_eq!(
        positive,
        RelocationEvaluationError::Signed16OutOfRange {
            value: i128::from(i16::MAX) + 1,
        }
    );
    assert_eq!(
        negative,
        RelocationEvaluationError::Signed16OutOfRange {
            value: i128::from(i16::MIN) - 1,
        }
    );
}

#[test]
fn writes_16_bit_relocations_little_endian() {
    let mut absolute_section = [0xaa; 6];
    let mut absolute = relocation(R_X86_64_16, 0);
    absolute.offset = 2;
    apply_relocation(&mut absolute_section, &absolute, 0x1234, 0).unwrap();
    assert_eq!(absolute_section, [0xaa, 0xaa, 0x34, 0x12, 0xaa, 0xaa]);

    let mut pc_section = [0xaa; 6];
    let mut pc = relocation(R_X86_64_PC16, 0);
    pc.offset = 1;
    apply_relocation(&mut pc_section, &pc, 0x4000, 0x4100).unwrap();
    assert_eq!(&pc_section[1..3], &(-0x100_i16).to_le_bytes());
    assert_eq!(pc_section[0], 0xaa);
    assert_eq!(&pc_section[3..], &[0xaa, 0xaa, 0xaa]);
}
