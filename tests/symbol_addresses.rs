use std::collections::BTreeMap;

use mini_elf_toolchain::elf64::{Elf64Symbol, SHN_LORESERVE};
use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::resolve::{SymbolDefinition, SHN_UNDEF};
use mini_elf_toolchain::symbol_addresses::{
    final_symbol_address, final_symbol_addresses, FinalSymbolAddressError, SHN_ABS,
};

fn definition(
    name: &[u8],
    object_index: usize,
    symbol_index: usize,
    section_index: u16,
    value: u64,
) -> SymbolDefinition {
    SymbolDefinition {
        name: name.to_vec(),
        object_index,
        table_section_index: 4,
        symbol_index,
        symbol: Elf64Symbol {
            name_offset: 0,
            info: 0x10,
            other: 0,
            section_index,
            value,
            size: 0,
        },
    }
}

fn section(object_index: usize, section_index: u16, address: u64) -> LaidOutSection {
    LaidOutSection {
        object_index,
        section_index,
        address,
        size: 0x100,
    }
}

#[test]
fn resolves_section_relative_symbol_to_final_address() {
    let symbol = definition(b"answer", 2, 7, 3, 0x28);
    let layout = [section(1, 3, 0x1000), section(2, 3, 0x4000)];

    assert_eq!(final_symbol_address(&symbol, &layout).unwrap(), 0x4028);
}

#[test]
fn preserves_absolute_symbol_value_without_layout() {
    let symbol = definition(b"absolute", 0, 1, SHN_ABS, 0xfeed_beef);

    assert_eq!(final_symbol_address(&symbol, &[]).unwrap(), 0xfeed_beef);
}

#[test]
fn rejects_undefined_symbol() {
    let symbol = definition(b"missing", 4, 9, SHN_UNDEF, 0);

    assert_eq!(
        final_symbol_address(&symbol, &[]).unwrap_err(),
        FinalSymbolAddressError::UndefinedSymbol {
            name: b"missing".to_vec(),
            object_index: 4,
            symbol_index: 9,
        }
    );
}

#[test]
fn rejects_unsupported_reserved_section_index() {
    let symbol = definition(b"special", 1, 5, SHN_LORESERVE, 0);

    assert_eq!(
        final_symbol_address(&symbol, &[]).unwrap_err(),
        FinalSymbolAddressError::UnsupportedSpecialSectionIndex {
            name: b"special".to_vec(),
            object_index: 1,
            symbol_index: 5,
            section_index: SHN_LORESERVE,
        }
    );
}

#[test]
fn rejects_missing_section_layout_with_provenance() {
    let symbol = definition(b"lost", 3, 8, 6, 4);

    assert_eq!(
        final_symbol_address(&symbol, &[section(2, 6, 0x2000)]).unwrap_err(),
        FinalSymbolAddressError::MissingSectionLayout {
            name: b"lost".to_vec(),
            object_index: 3,
            symbol_index: 8,
            section_index: 6,
        }
    );
}

#[test]
fn rejects_final_address_overflow() {
    let symbol = definition(b"overflow", 0, 2, 1, 2);

    assert_eq!(
        final_symbol_address(&symbol, &[section(0, 1, u64::MAX - 1)]).unwrap_err(),
        FinalSymbolAddressError::AddressOverflow {
            name: b"overflow".to_vec(),
            object_index: 0,
            symbol_index: 2,
            section_index: 1,
            section_address: u64::MAX - 1,
            symbol_value: 2,
        }
    );
}

#[test]
fn resolves_definition_map_deterministically() {
    let mut definitions = BTreeMap::new();
    definitions.insert(b"zeta".to_vec(), definition(b"zeta", 1, 2, SHN_ABS, 9));
    definitions.insert(b"alpha".to_vec(), definition(b"alpha", 0, 1, 2, 3));

    let addresses = final_symbol_addresses(&definitions, &[section(0, 2, 0x5000)]).unwrap();
    let entries: Vec<_> = addresses.into_iter().collect();

    assert_eq!(
        entries,
        vec![(b"alpha".to_vec(), 0x5003), (b"zeta".to_vec(), 9)]
    );
}
