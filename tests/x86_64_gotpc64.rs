use mini_elf_toolchain::relocations::Elf64Rela;
use mini_elf_toolchain::x86_64_relocations::{
    apply_relocation, evaluate_relocation, is_static_got_base_type, is_static_got_entry_type,
    RelocationApplyError, RelocationEvaluationError, RelocationValue, R_X86_64_GOTPC64,
};

fn relocation(offset: u64, addend: i64) -> Elf64Rela {
    Elf64Rela {
        offset,
        symbol_index: 1,
        relocation_type: R_X86_64_GOTPC64,
        addend,
    }
}

#[test]
fn gotpc64_uses_got_base_plus_addend_minus_place() {
    let value = evaluate_relocation(&relocation(0, -8), 0x402000, 0x400003).unwrap();
    assert_eq!(value, RelocationValue::I64(0x1ff5));
    assert!(is_static_got_base_type(R_X86_64_GOTPC64));
    assert!(is_static_got_entry_type(R_X86_64_GOTPC64));
}

#[test]
fn gotpc64_rejects_signed_64_bit_overflow() {
    let error = evaluate_relocation(&relocation(0, i64::MAX), u64::MAX, 0).unwrap_err();
    assert!(matches!(
        error,
        RelocationEvaluationError::Signed64OutOfRange { .. }
    ));
}

#[test]
fn gotpc64_preserves_checked_target_bounds() {
    let mut section = [0_u8; 7];
    let error = apply_relocation(&mut section, &relocation(0, -8), 0x402000, 0x400003).unwrap_err();
    assert!(matches!(
        error,
        RelocationApplyError::TargetOutOfBounds {
            offset: 0,
            width: 8,
            section_len: 7,
            ..
        }
    ));
}
