use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, is_static_got_base_type, is_static_got_entry_type,
    RelocationApplyError, RelocationEvaluationError, RelocationValue, R_X86_64_GOTPC32,
};

fn relocation(offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type: R_X86_64_GOTPC32,
        addend,
    }
}

#[test]
fn gotpc32_uses_got_base_plus_addend_minus_place() {
    let value = evaluate_relocation(&relocation(0, -4), 0x402000, 0x400003).unwrap();
    assert_eq!(value, RelocationValue::I32(0x1ff9));
    assert!(is_static_got_base_type(R_X86_64_GOTPC32));
    assert!(is_static_got_entry_type(R_X86_64_GOTPC32));
}

#[test]
fn gotpc32_rejects_signed_32_bit_overflow() {
    let error = evaluate_relocation(&relocation(0, 0), u64::MAX, 0).unwrap_err();
    assert!(matches!(
        error,
        RelocationEvaluationError::Signed32OutOfRange { .. }
    ));
}

#[test]
fn gotpc32_preserves_checked_target_bounds() {
    let mut section = [0_u8; 3];
    let error = apply_relocation(&mut section, &relocation(0, -4), 0x402000, 0x400003).unwrap_err();
    assert!(matches!(
        error,
        RelocationApplyError::TargetOutOfBounds {
            offset: 0,
            width: 4,
            section_len: 3,
            ..
        }
    ));
}
