use mini_elf_toolchain::elf64::{Elf64SectionHeader, Elf64Symbol, Elf64SymbolTable, SHT_SYMTAB};
use mini_elf_toolchain::relocations::{
    rela_tables, Elf64Rela, RelaError, ELF64_RELA_SIZE, SHT_RELA,
};

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
        address_alignment: 8,
        entry_size: 0,
    }
}

fn fixture() -> (Vec<u8>, Vec<Elf64SectionHeader>, Vec<Elf64SymbolTable>) {
    let mut file = vec![0u8; 128];
    let info = (1u64 << 32) | 2;
    file[64..72].copy_from_slice(&0x1122_3344u64.to_le_bytes());
    file[72..80].copy_from_slice(&info.to_le_bytes());
    file[80..88].copy_from_slice(&(-7i64).to_le_bytes());

    let mut symtab = section(SHT_SYMTAB, 0, 0);
    symtab.entry_size = 24;
    let target = section(1, 0, 0);
    let mut rela = section(SHT_RELA, 64, ELF64_RELA_SIZE);
    rela.link = 1;
    rela.info = 2;
    rela.entry_size = ELF64_RELA_SIZE;

    let sections = vec![section(0, 0, 0), symtab, target, rela];
    let symbol_tables = vec![Elf64SymbolTable {
        section_index: 1,
        string_table_index: 0,
        symbols: vec![
            Elf64Symbol {
                name_offset: 0,
                info: 0,
                other: 0,
                section_index: 0,
                value: 0,
                size: 0,
            },
            Elf64Symbol {
                name_offset: 0,
                info: 0,
                other: 0,
                section_index: 2,
                value: 0,
                size: 0,
            },
        ],
    }];

    (file, sections, symbol_tables)
}

#[test]
fn parses_rela_and_splits_r_info() {
    let (file, sections, symbol_tables) = fixture();
    let tables = rela_tables(&file, &sections, &symbol_tables).unwrap();

    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].section_index, 3);
    assert_eq!(tables[0].symbol_table_index, 1);
    assert_eq!(tables[0].target_section_index, 2);
    assert_eq!(
        tables[0].relocations,
        vec![Elf64Rela {
            offset: 0x1122_3344,
            symbol_index: 1,
            relocation_type: 2,
            addend: -7,
        }]
    );
}

#[test]
fn rejects_wrong_rela_entry_size() {
    let (file, mut sections, symbol_tables) = fixture();
    sections[3].entry_size = 16;

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::InvalidEntrySize {
            section_index: 3,
            entry_size: 16,
        })
    );
}

#[test]
fn rejects_non_multiple_rela_table_size() {
    let (file, mut sections, symbol_tables) = fixture();
    sections[3].size = ELF64_RELA_SIZE + 1;

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::InvalidTableSize {
            section_index: 3,
            size: ELF64_RELA_SIZE + 1,
            entry_size: ELF64_RELA_SIZE,
        })
    );
}

#[test]
fn rejects_link_to_non_symbol_table_section() {
    let (file, mut sections, symbol_tables) = fixture();
    sections[1].section_type = 1;

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::LinkedSectionNotSymbolTable {
            section_index: 3,
            symbol_table_index: 1,
            section_type: 1,
        })
    );
}

#[test]
fn rejects_missing_validated_symbol_table() {
    let (file, sections, _) = fixture();

    assert_eq!(
        rela_tables(&file, &sections, &[]),
        Err(RelaError::MissingValidatedSymbolTable {
            section_index: 3,
            symbol_table_index: 1,
        })
    );
}

#[test]
fn rejects_target_section_out_of_bounds() {
    let (file, mut sections, symbol_tables) = fixture();
    sections[3].info = sections.len() as u32;

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::InvalidTargetSectionIndex {
            section_index: 3,
            target_section_index: 4,
            section_count: 4,
        })
    );
}

#[test]
fn rejects_relocation_symbol_out_of_bounds() {
    let (mut file, sections, symbol_tables) = fixture();
    let info = (2u64 << 32) | 2;
    file[72..80].copy_from_slice(&info.to_le_bytes());

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::InvalidRelocationSymbolIndex {
            section_index: 3,
            relocation_index: 0,
            symbol_index: 2,
            symbol_count: 2,
        })
    );
}

#[test]
fn rejects_rela_data_out_of_bounds() {
    let (file, mut sections, symbol_tables) = fixture();
    sections[3].offset = file.len() as u64 - 8;

    assert_eq!(
        rela_tables(&file, &sections, &symbol_tables),
        Err(RelaError::DataOutOfBounds {
            section_index: 3,
            end: file.len() as u64 - 8 + ELF64_RELA_SIZE,
            file_len: file.len(),
        })
    );
}
