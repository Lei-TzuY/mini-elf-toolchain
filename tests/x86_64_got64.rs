use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, RelocationApplyError, RelocationEvaluationError,
    RelocationValue, R_X86_64_GOT64,
};

fn relocation(offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type: R_X86_64_GOT64,
        addend,
    }
}

#[test]
fn got64_evaluates_g_plus_a_as_unsigned64() {
    let value = evaluate_relocation(&relocation(0, 4), 8, 0xdead_beef).unwrap();
    assert_eq!(value, RelocationValue::U64(12));
}

#[test]
fn got64_rejects_unsigned64_overflow_and_underflow() {
    let overflow_value = i128::from(u64::MAX) + 1;
    assert_eq!(
        evaluate_relocation(&relocation(0, 1), u64::MAX, 0),
        Err(RelocationEvaluationError::Unsigned64OutOfRange {
            value: overflow_value,
        })
    );
    assert_eq!(
        evaluate_relocation(&relocation(0, -1), 0, 0),
        Err(RelocationEvaluationError::Unsigned64OutOfRange { value: -1 })
    );
}

#[test]
fn got64_checks_eight_byte_target_bounds() {
    let mut section = [0_u8; 7];
    let error = apply_relocation(&mut section, &relocation(0, 0), 0, 0).unwrap_err();
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
