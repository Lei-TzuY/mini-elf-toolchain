use mini_elf_toolchain::elf64::{Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHT_STRTAB};
use mini_elf_toolchain::symbol_names::{symbol_name, SymbolNameError};

fn section(section_type: u32, offset: u64, size: u64) -> Elf64SectionHeader {
    Elf64SectionHeader {
        name_offset: 0,
        section_type,
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

fn symbol(name_offset: u32) -> Elf64Symbol {
    Elf64Symbol {
        name_offset,
        info: 0x10,
        other: 0,
        section_index: 0,
        value: 0,
        size: 0,
    }
}

fn table(name_offsets: &[u32]) -> Elf64SymbolTable {
    Elf64SymbolTable {
        section_index: 2,
        string_table_index: 1,
        symbols: name_offsets.iter().copied().map(symbol).collect(),
    }
}

#[test]
fn extracts_nul_terminated_symbol_names() {
    let file = b"xxxx\0foo\0bar\0";
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 4, 9)];
    let table = table(&[1, 5, 0]);

    assert_eq!(symbol_name(file, &sections, &table, 0).unwrap(), b"foo");
    assert_eq!(symbol_name(file, &sections, &table, 1).unwrap(), b"bar");
    assert_eq!(symbol_name(file, &sections, &table, 2).unwrap(), b"");
}

#[test]
fn preserves_non_utf8_symbol_names_as_bytes() {
    let file = [0, 0xff, 0xfe, 0];
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 0, 4)];
    let table = table(&[1]);

    assert_eq!(
        symbol_name(&file, &sections, &table, 0).unwrap(),
        &[0xff, 0xfe]
    );
}

#[test]
fn rejects_unterminated_symbol_name() {
    let file = b"\0foo";
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 0, 4)];
    let table = table(&[1]);

    assert_eq!(
        symbol_name(file, &sections, &table, 0),
        Err(SymbolNameError::UnterminatedName {
            symbol_index: 0,
            name_offset: 1,
        })
    );
}

#[test]
fn rejects_name_offset_at_string_table_end() {
    let file = b"\0foo\0";
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 0, 5)];
    let table = table(&[5]);

    assert_eq!(
        symbol_name(file, &sections, &table, 0),
        Err(SymbolNameError::InvalidNameOffset {
            symbol_index: 0,
            name_offset: 5,
            string_table_size: 5,
        })
    );
}

#[test]
fn rejects_string_table_past_file_end() {
    let file = b"\0foo\0";
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 2, 8)];
    let table = table(&[0]);

    assert_eq!(
        symbol_name(file, &sections, &table, 0),
        Err(SymbolNameError::StringTableOutOfBounds {
            string_table_index: 1,
            end: 10,
            file_len: 5,
        })
    );
}

#[test]
fn rejects_out_of_range_symbol_index() {
    let file = b"\0";
    let sections = vec![section(0, 0, 0), section(SHT_STRTAB, 0, 1)];
    let table = table(&[0]);

    assert_eq!(
        symbol_name(file, &sections, &table, 1),
        Err(SymbolNameError::InvalidSymbolIndex {
            symbol_index: 1,
            symbol_count: 1,
        })
    );
}
