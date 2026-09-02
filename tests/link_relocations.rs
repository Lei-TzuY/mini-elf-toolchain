use std::collections::BTreeMap;

use mini_elf_toolchain::elf64::Elf64Symbol;
use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::link_relocations::{
    apply_rela_table_with_resolved_symbols, LinkRelocationError,
};
use mini_elf_toolchain::relocations::{Elf64Rela, Elf64RelaTable};
use mini_elf_toolchain::resolve::{NamedSymbol, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK};
use mini_elf_toolchain::x86_64_relocations::R_X86_64_64;

fn symbol(binding: u8, section_index: u16, value: u64) -> Elf64Symbol {
    Elf64Symbol {
        name_offset: 0,
        info: binding << 4,
        other: 0,
        section_index,
        value,
        size: 0,
    }
}

fn rela_table(symbol_index: u32) -> Elf64RelaTable {
    Elf64RelaTable {
        section_index: 4,
        symbol_table_index: 2,
        target_section_index: 1,
        relocations: vec![Elf64Rela {
            offset: 0,
            symbol_index,
            relocation_type: R_X86_64_64,
            addend: 0,
        }],
    }
}

#[test]
fn local_symbol_uses_its_object_section_layout() {
    let mut section = [0u8; 8];
    let symbols = [NamedSymbol {
        name: b"local",
        object_index: 3,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_LOCAL, 5, 0x28),
    }];
    let layout = [LaidOutSection {
        object_index: 3,
        section_index: 5,
        address: 0x4000,
        size: 0x100,
    }];

    apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        3,
        &symbols,
        &BTreeMap::new(),
        &layout,
    )
    .unwrap();

    assert_eq!(section, 0x4028u64.to_le_bytes());
}

#[test]
fn undefined_global_uses_cross_object_resolved_address() {
    let mut section = [0u8; 8];
    let symbols = [NamedSymbol {
        name: b"target",
        object_index: 0,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_GLOBAL, SHN_UNDEF, 0),
    }];
    let global_addresses = BTreeMap::from([(b"target".to_vec(), 0x9000)]);

    apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        0,
        &symbols,
        &global_addresses,
        &[],
    )
    .unwrap();

    assert_eq!(section, 0x9000u64.to_le_bytes());
}

#[test]
fn defined_weak_symbol_uses_winning_global_address() {
    let mut section = [0u8; 8];
    let symbols = [NamedSymbol {
        name: b"choice",
        object_index: 0,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_WEAK, 5, 0x10),
    }];
    let layout = [LaidOutSection {
        object_index: 0,
        section_index: 5,
        address: 0x2000,
        size: 0x100,
    }];
    let global_addresses = BTreeMap::from([(b"choice".to_vec(), 0x7000)]);

    apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        0,
        &symbols,
        &global_addresses,
        &layout,
    )
    .unwrap();

    assert_eq!(section, 0x7000u64.to_le_bytes());
}

#[test]
fn unresolved_undefined_weak_symbol_resolves_to_zero() {
    let mut section = [0xffu8; 8];
    let symbols = [NamedSymbol {
        name: b"optional",
        object_index: 0,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_WEAK, SHN_UNDEF, 0),
    }];

    apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        0,
        &symbols,
        &BTreeMap::new(),
        &[],
    )
    .unwrap();

    assert_eq!(section, 0u64.to_le_bytes());
}

#[test]
fn missing_strong_global_address_does_not_modify_section() {
    let original = [0xa5u8; 8];
    let mut section = original;
    let symbols = [NamedSymbol {
        name: b"missing",
        object_index: 0,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_GLOBAL, SHN_UNDEF, 0),
    }];

    let error = apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        0,
        &symbols,
        &BTreeMap::new(),
        &[],
    )
    .unwrap_err();

    assert_eq!(
        error,
        LinkRelocationError::MissingGlobalAddress {
            relocation_index: 0,
            symbol_index: 1,
            name: b"missing".to_vec(),
        }
    );
    assert_eq!(section, original);
}

#[test]
fn rejects_symbol_metadata_from_the_wrong_object() {
    let original = [0x33u8; 8];
    let mut section = original;
    let symbols = [NamedSymbol {
        name: b"target",
        object_index: 7,
        table_section_index: 2,
        symbol_index: 1,
        symbol: symbol(STB_GLOBAL, SHN_UNDEF, 0),
    }];

    let error = apply_rela_table_with_resolved_symbols(
        &mut section,
        0x1000,
        &rela_table(1),
        0,
        &symbols,
        &BTreeMap::from([(b"target".to_vec(), 0x9000)]),
        &[],
    )
    .unwrap_err();

    assert_eq!(
        error,
        LinkRelocationError::WrongObject {
            relocation_index: 0,
            symbol_index: 1,
            expected_object_index: 0,
            actual_object_index: 7,
        }
    );
    assert_eq!(section, original);
}
