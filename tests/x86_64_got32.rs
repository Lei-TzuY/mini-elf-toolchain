use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationApplyError, RelocationEvaluationError,
    RelocationValue, R_X86_64_GOT32,
};

fn relocation(offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type: R_X86_64_GOT32,
        addend,
    }
}

#[test]
fn got32_evaluates_g_plus_a_as_unsigned32() {
    let value = evaluate_relocation(&relocation(0, 4), 8, 0xdead_beef).unwrap();
    assert_eq!(value, RelocationValue::U32(12));
}

#[test]
fn got32_rejects_unsigned32_overflow_and_underflow() {
    let overflow_value = i128::from(u32::MAX) + 1;
    assert_eq!(
        evaluate_relocation(&relocation(0, 1), u32::MAX as u64, 0),
        Err(RelocationEvaluationError::Unsigned32OutOfRange {
            value: overflow_value,
        })
    );
    assert_eq!(
        evaluate_relocation(&relocation(0, -1), 0, 0),
        Err(RelocationEvaluationError::Unsigned32OutOfRange { value: -1 })
    );
}

#[test]
fn got32_checks_four_byte_target_bounds() {
    let mut section = [0_u8; 3];
    let error = apply_relocation(&mut section, &relocation(0, 0), 0, 0).unwrap_err();
    assert_eq!(
        error,
        RelocationApplyError::TargetOutOfBounds {
            offset: 0,
            width: 4,
            end: 4,
            section_len: 3,
        }
    );
}