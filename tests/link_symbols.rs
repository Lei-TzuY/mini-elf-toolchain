use mini_elf_toolchain::elf64::{Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHT_STRTAB};
use mini_elf_toolchain::link_symbols::{
    resolve_validated_objects, LinkSymbolError, ValidatedObject,
};
use mini_elf_toolchain::object_symbols::ObjectSymbolError;
use mini_elf_toolchain::resolve::{ResolutionError, STB_GLOBAL, STB_WEAK};
use mini_elf_toolchain::symbol_names::SymbolNameError;

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

fn symbol(name_offset: u32, binding: u8, value: u64) -> Elf64Symbol {
    Elf64Symbol {
        name_offset,
        info: binding << 4,
        other: 0,
        section_index: 1,
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

#[test]
fn resolves_global_over_weak_across_objects() {
    let weak_file = b"\0target\0";
    let strong_file = b"\0target\0";
    let weak_sections = [string_table(0, weak_file.len() as u64)];
    let strong_sections = [string_table(0, strong_file.len() as u64)];
    let weak_tables = [table(3, vec![symbol(1, STB_WEAK, 11)])];
    let strong_tables = [table(4, vec![symbol(1, STB_GLOBAL, 22)])];
    let objects = [
        ValidatedObject {
            file: weak_file,
            sections: &weak_sections,
            symbol_tables: &weak_tables,
        },
        ValidatedObject {
            file: strong_file,
            sections: &strong_sections,
            symbol_tables: &strong_tables,
        },
    ];

    let resolved = resolve_validated_objects(&objects).unwrap();
    let definition = resolved.get(b"target".as_slice()).unwrap();

    assert_eq!(definition.object_index, 1);
    assert_eq!(definition.table_section_index, 4);
    assert_eq!(definition.symbol.value, 22);
}

#[test]
fn sorts_tables_by_section_index_before_resolution() {
    let file = b"\0target\0";
    let sections = [string_table(0, file.len() as u64)];
    let tables = [
        table(9, vec![symbol(1, STB_WEAK, 99)]),
        table(2, vec![symbol(1, STB_WEAK, 22)]),
    ];
    let objects = [ValidatedObject {
        file,
        sections: &sections,
        symbol_tables: &tables,
    }];

    let resolved = resolve_validated_objects(&objects).unwrap();
    let definition = resolved.get(b"target".as_slice()).unwrap();

    assert_eq!(definition.table_section_index, 2);
    assert_eq!(definition.symbol.value, 22);
}

#[test]
fn reports_duplicate_strong_definitions_with_object_provenance() {
    let file_a = b"\0dup\0";
    let file_b = b"\0dup\0";
    let sections_a = [string_table(0, file_a.len() as u64)];
    let sections_b = [string_table(0, file_b.len() as u64)];
    let tables_a = [table(1, vec![symbol(1, STB_GLOBAL, 1)])];
    let tables_b = [table(1, vec![symbol(1, STB_GLOBAL, 2)])];
    let objects = [
        ValidatedObject {
            file: file_a,
            sections: &sections_a,
            symbol_tables: &tables_a,
        },
        ValidatedObject {
            file: file_b,
            sections: &sections_b,
            symbol_tables: &tables_b,
        },
    ];

    assert_eq!(
        resolve_validated_objects(&objects),
        Err(LinkSymbolError::Resolution(
            ResolutionError::MultipleStrongDefinitions {
                name: b"dup".to_vec(),
                first_object_index: 0,
                second_object_index: 1,
            }
        ))
    );
}

#[test]
fn reports_invalid_name_with_object_provenance() {
    let file = b"\0unterminated";
    let sections = [string_table(0, file.len() as u64)];
    let tables = [table(7, vec![symbol(1, STB_GLOBAL, 1)])];
    let objects = [ValidatedObject {
        file,
        sections: &sections,
        symbol_tables: &tables,
    }];

    assert_eq!(
        resolve_validated_objects(&objects),
        Err(LinkSymbolError::ObjectSymbols {
            object_index: 0,
            source: ObjectSymbolError::InvalidName {
                table_section_index: 7,
                symbol_index: 0,
                source: SymbolNameError::UnterminatedName {
                    symbol_index: 0,
                    name_offset: 1,
                },
            },
        })
    );
}
