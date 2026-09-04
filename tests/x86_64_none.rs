use std::collections::BTreeMap;

use mini_elf_toolchain::link_relocations::apply_rela_table_with_resolved_symbols;
use mini_elf_toolchain::rela_apply::apply_rela_table;
use mini_elf_toolchain::relocations::{Elf64Rela, Elf64RelaTable};

const R_X86_64_NONE: u32 = 0;

fn none_table() -> Elf64RelaTable {
    Elf64RelaTable {
        section_index: 4,
        symbol_table_index: 2,
        target_section_index: 1,
        relocations: vec![Elf64Rela {
            offset: u64::MAX,
            symbol_index: 7,
            relocation_type: R_X86_64_NONE,
            addend: i64::MAX,
        }],
    }
}

#[test]
fn rela_none_does_not_touch_target_or_request_symbol_value() {
    let original = [0xa5u8; 8];
    let mut section = original;
    let mut lookups = 0;

    apply_rela_table(&mut section, u64::MAX, &none_table(), |_| {
        lookups += 1;
        None
    })
    .unwrap();

    assert_eq!(lookups, 0);
    assert_eq!(section, original);
}

#[test]
fn link_layer_none_does_not_require_symbol_metadata() {
    let original = [0x5au8; 8];
    let mut section = original;

    apply_rela_table_with_resolved_symbols(
        &mut section,
        u64::MAX,
        &none_table(),
        3,
        &[],
        &BTreeMap::new(),
        &[],
    )
    .unwrap();

    assert_eq!(section, original);
}
