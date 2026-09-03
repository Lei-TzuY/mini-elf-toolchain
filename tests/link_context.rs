use mini_elf_toolchain::elf64::{Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHT_STRTAB};
use mini_elf_toolchain::layout::LaidOutSection;
use mini_elf_toolchain::link_context::{
    build_link_context, LinkContextBuildError, LinkContextRelocationError,
};
use mini_elf_toolchain::link_symbols::ValidatedObject;
use mini_elf_toolchain::relocations::{Elf64Rela, Elf64RelaTable};
use mini_elf_toolchain::resolve::{SHN_UNDEF, STB_GLOBAL, STB_LOCAL};
use mini_elf_toolchain::symbol_addresses::FinalSymbolAddressError;
use mini_elf_toolchain::x86_64_relocations::R_X86_64_64;

fn string_table(offset: u64, size: u64) -> Elf64SectionHeader {
    Elf64SectionHeader {
        name_offset: 0,
        section_type: SHT_STRTAB,
        flags: 0,
        address: 0,
        offset,
        size,
        link: 0,
        info: 0,
        address_alignment: 1,
        entry_size: 0,
    }
}

fn symbol(name_offset: u32, binding: u8, section_index: u16, value: u64) -> Elf64Symbol {
    Elf64Symbol {
        name_offset,
        info: binding << 4,
        other: 0,
        section_index,
        value,
        size: 0,
    }
}

fn table(section_index: u16, symbols: Vec<Elf64Symbol>) -> Elf64SymbolTable {
    Elf64SymbolTable {
        section_index,
        string_table_index: 0,
        symbols,
    }
}

fn rela_table(symbol_table_index: u16, symbol_index: u32) -> Elf64RelaTable {
    Elf64RelaTable {
        section_index: 4,
        symbol_table_index,
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
fn resolves_cross_object_global_and_applies_relocation() {
    let reference_file = b"\0target\0";
    let definition_file = b"\0target\0";
    let reference_sections = [string_table(0, reference_file.len() as u64)];
    let definition_sections = [string_table(0, definition_file.len() as u64)];
    let reference_tables = [table(
        2,
        vec![symbol(1, STB_GLOBAL, SHN_UNDEF, 0)],
    )];
    let definition_tables = [table(3, vec![symbol(1, STB_GLOBAL, 1, 0x20)])];
    let objects = [
        ValidatedObject {
            file: reference_file,
            sections: &reference_sections,
            symbol_tables: &reference_tables,
        },
        ValidatedObject {
            file: definition_file,
            sections: &definition_sections,
            symbol_tables: &definition_tables,
        },
    ];
    let layout = [LaidOutSection {
        object_index: 1,
        section_index: 1,
        address: 0x8000,
        size: 0x100,
    }];

    let context = build_link_context(&objects, &layout).unwrap();
    assert_eq!(context.global_addresses().get(b"target".as_slice()), Some(&0x8020));
    assert_eq!(context.definitions()[b"target".as_slice()].object_index, 1);

    let mut section = [0u8; 8];
    context
        .apply_rela_table(&mut section, 0x4000, &rela_table(2, 0), 0)
        .unwrap();

    assert_eq!(section, 0x8020u64.to_le_bytes());
}

#[test]
fn keeps_local_symbols_available_for_relocation_application() {
    let file = b"\0local\0";
    let sections = [string_table(0, file.len() as u64)];
    let tables = [table(2, vec![symbol(1, STB_LOCAL, 1, 0x18)])];
    let objects = [ValidatedObject {
        file,
        sections: &sections,
        symbol_tables: &tables,
    }];
    let layout = [LaidOutSection {
        object_index: 0,
        section_index: 1,
        address: 0x5000,
        size: 0x100,
    }];

    let context = build_link_context(&objects, &layout).unwrap();
    assert!(context.global_addresses().is_empty());

    let mut section = [0u8; 8];
    context
        .apply_rela_table(&mut section, 0x4000, &rela_table(2, 0), 0)
        .unwrap();

    assert_eq!(section, 0x5018u64.to_le_bytes());
}

#[test]
fn rejects_context_when_winning_definition_has_no_layout() {
    let file = b"\0target\0";
    let sections = [string_table(0, file.len() as u64)];
    let tables = [table(2, vec![symbol(1, STB_GLOBAL, 1, 0x20)])];
    let objects = [ValidatedObject {
        file,
        sections: &sections,
        symbol_tables: &tables,
    }];

    assert_eq!(
        build_link_context(&objects, &[]).unwrap_err(),
        LinkContextBuildError::FinalAddress(FinalSymbolAddressError::MissingSectionLayout {
            name: b"target".to_vec(),
            object_index: 0,
            symbol_index: 0,
            section_index: 1,
        })
    );
}

#[test]
fn invalid_object_index_does_not_modify_target_section() {
    let objects = [ValidatedObject {
        file: b"",
        sections: &[],
        symbol_tables: &[],
    }];
    let context = build_link_context(&objects, &[]).unwrap();
    let original = [0xa5u8; 8];
    let mut section = original;

    let error = context
        .apply_rela_table(&mut section, 0x4000, &rela_table(2, 0), 1)
        .unwrap_err();

    assert_eq!(
        error,
        LinkContextRelocationError::ObjectIndexOutOfRange {
            object_index: 1,
            object_count: 1,
        }
    );
    assert_eq!(section, original);
}
