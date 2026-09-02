use mini_elf_toolchain::rela_apply::{apply_rela_table, RelaTableApplyError};
use mini_elf_toolchain::relocations::{Elf64Rela, Elf64RelaTable};
use mini_elf_toolchain::x86_64_relocations::{RelocationApplyError, R_X86_64_64, R_X86_64_PC32};

fn table(relocations: Vec<Elf64Rela>) -> Elf64RelaTable {
    Elf64RelaTable {
        section_index: 4,
        symbol_table_index: 2,
        target_section_index: 1,
        relocations,
    }
}

#[test]
fn applies_rela_table_using_section_address_and_symbol_lookup() {
    let mut section = [0u8; 16];
    let table = table(vec![
        Elf64Rela {
            offset: 0,
            symbol_index: 1,
            relocation_type: R_X86_64_64,
            addend: 4,
        },
        Elf64Rela {
            offset: 8,
            symbol_index: 2,
            relocation_type: R_X86_64_PC32,
            addend: -4,
        },
    ]);

    apply_rela_table(&mut section, 0x1000, &table, |index| match index {
        1 => Some(0x2000),
        2 => Some(0x1100),
        _ => None,
    })
    .unwrap();

    assert_eq!(&section[0..8], &0x2004u64.to_le_bytes());
    assert_eq!(&section[8..12], &(0xf4i32).to_le_bytes());
}

#[test]
fn rejects_place_address_overflow_without_modifying_section() {
    let original = [0xa5u8; 8];
    let mut section = original;
    let table = table(vec![Elf64Rela {
        offset: 1,
        symbol_index: 0,
        relocation_type: R_X86_64_64,
        addend: 0,
    }]);

    let error = apply_rela_table(&mut section, u64::MAX, &table, |_| Some(0)).unwrap_err();

    assert_eq!(
        error,
        RelaTableApplyError::PlaceOverflow {
            relocation_index: 0,
            section_address: u64::MAX,
            offset: 1,
        }
    );
    assert_eq!(section, original);
}

#[test]
fn rejects_missing_symbol_value_without_modifying_section() {
    let original = [0x5au8; 8];
    let mut section = original;
    let table = table(vec![Elf64Rela {
        offset: 0,
        symbol_index: 7,
        relocation_type: R_X86_64_64,
        addend: 0,
    }]);

    let error = apply_rela_table(&mut section, 0x1000, &table, |_| None).unwrap_err();

    assert_eq!(
        error,
        RelaTableApplyError::MissingSymbolValue {
            relocation_index: 0,
            symbol_index: 7,
        }
    );
    assert_eq!(section, original);
}

#[test]
fn later_failure_does_not_leave_partial_patches() {
    let original = [0x11u8; 12];
    let mut section = original;
    let table = table(vec![
        Elf64Rela {
            offset: 0,
            symbol_index: 1,
            relocation_type: R_X86_64_64,
            addend: 0,
        },
        Elf64Rela {
            offset: 10,
            symbol_index: 2,
            relocation_type: R_X86_64_PC32,
            addend: 0,
        },
    ]);

    let error = apply_rela_table(&mut section, 0x1000, &table, |_| Some(0x2000)).unwrap_err();

    assert!(matches!(
        error,
        RelaTableApplyError::Relocation {
            relocation_index: 1,
            error: RelocationApplyError::TargetOutOfBounds { .. }
        }
    ));
    assert_eq!(section, original);
}
