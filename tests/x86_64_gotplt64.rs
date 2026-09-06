use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, is_static_got_entry_address_type,
    is_static_got_entry_type, RelocationApplyError, RelocationEvaluationError, RelocationValue,
    R_X86_64_GOTPLT64,
};

fn relocation(offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type: R_X86_64_GOTPLT64,
        addend,
    }
}

#[test]
fn gotplt64_evaluates_absolute_got_entry_address_plus_addend() {
    let value = evaluate_relocation(&relocation(0, 8), 0x401000, 0xdead_beef).unwrap();
    assert_eq!(value, RelocationValue::U64(0x401008));
    assert!(is_static_got_entry_address_type(R_X86_64_GOTPLT64));
    assert!(is_static_got_entry_type(R_X86_64_GOTPLT64));
}

#[test]
fn gotplt64_rejects_unsigned64_overflow_and_underflow() {
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
fn gotplt64_checks_eight_byte_target_bounds() {
    let mut section = [0_u8; 7];
    let error = apply_relocation(&mut section, &relocation(0, 0), 0x401000, 0).unwrap_err();
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
