use mini_elf_toolchain::elf64::{Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHT_STRTAB};
use mini_elf_toolchain::object_symbols::{named_symbols_from_table, ObjectSymbolError};
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

fn symbol(name_offset: u32, value: u64) -> Elf64Symbol {
    Elf64Symbol {
        name_offset,
        info: 1 << 4,
        other: 0,
        section_index: 1,
        value,
        size: 0,
    }
}

#[test]
fn adapts_validated_table_into_named_symbols_with_provenance() {
    let file = b"\0alpha\0beta\0";
    let sections = [string_table(0, file.len() as u64)];
    let table = Elf64SymbolTable {
        section_index: 7,
        string_table_index: 0,
        symbols: vec![symbol(1, 11), symbol(7, 22)],
    };

    let named = named_symbols_from_table(file, &sections, &table, 3).unwrap();

    assert_eq!(named.len(), 2);
    assert_eq!(named[0].name, b"alpha");
    assert_eq!(named[0].object_index, 3);
    assert_eq!(named[0].table_section_index, 7);
    assert_eq!(named[0].symbol_index, 0);
    assert_eq!(named[0].symbol.value, 11);
    assert_eq!(named[1].name, b"beta");
    assert_eq!(named[1].symbol_index, 1);
    assert_eq!(named[1].symbol.value, 22);
}

#[test]
fn preserves_non_utf8_symbol_names_as_bytes() {
    let file = [0, 0xff, 0x80, 0];
    let sections = [string_table(0, file.len() as u64)];
    let table = Elf64SymbolTable {
        section_index: 4,
        string_table_index: 0,
        symbols: vec![symbol(1, 9)],
    };

    let named = named_symbols_from_table(&file, &sections, &table, 1).unwrap();

    assert_eq!(named[0].name, &[0xff, 0x80]);
}

#[test]
fn reports_name_validation_failure_with_table_and_symbol_provenance() {
    let file = b"\0unterminated";
    let sections = [string_table(0, file.len() as u64)];
    let table = Elf64SymbolTable {
        section_index: 9,
        string_table_index: 0,
        symbols: vec![symbol(1, 0)],
    };

    let result = named_symbols_from_table(file, &sections, &table, 5);

    assert_eq!(
        result,
        Err(ObjectSymbolError::InvalidName {
            table_section_index: 9,
            symbol_index: 0,
            source: SymbolNameError::UnterminatedName {
                symbol_index: 0,
                name_offset: 1,
            },
        })
    );
}
