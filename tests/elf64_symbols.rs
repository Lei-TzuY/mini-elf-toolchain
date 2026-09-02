use mini_elf_toolchain::elf64::{
    Elf64Header, Elf64Symbol, Elf64SymbolTable, ElfError, ELF64_HEADER_SIZE,
    ELF64_SECTION_HEADER_SIZE, ELF64_SYMBOL_SIZE, SHT_STRTAB, SHT_SYMTAB,
};

const SECTION_COUNT: u16 = 4;
const SECTION_TABLE_OFFSET: usize = ELF64_HEADER_SIZE;
const SECTION_TABLE_SIZE: usize = ELF64_SECTION_HEADER_SIZE as usize * SECTION_COUNT as usize;
const STRTAB_OFFSET: usize = SECTION_TABLE_OFFSET + SECTION_TABLE_SIZE;
const STRTAB: &[u8] = b"\0foo\0";
const SYMTAB_OFFSET: usize = STRTAB_OFFSET + STRTAB.len();

struct SectionSpec {
    section_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    alignment: u64,
    entry_size: u64,
}

fn write_section(bytes: &mut [u8], index: usize, spec: SectionSpec) {
    let base = SECTION_TABLE_OFFSET + index * ELF64_SECTION_HEADER_SIZE as usize;
    bytes[base + 4..base + 8].copy_from_slice(&spec.section_type.to_le_bytes());
    bytes[base + 24..base + 32].copy_from_slice(&spec.offset.to_le_bytes());
    bytes[base + 32..base + 40].copy_from_slice(&spec.size.to_le_bytes());
    bytes[base + 40..base + 44].copy_from_slice(&spec.link.to_le_bytes());
    bytes[base + 48..base + 56].copy_from_slice(&spec.alignment.to_le_bytes());
    bytes[base + 56..base + 64].copy_from_slice(&spec.entry_size.to_le_bytes());
}

fn valid_symbol_file() -> Vec<u8> {
    let mut bytes = vec![0u8; SYMTAB_OFFSET + ELF64_SYMBOL_SIZE as usize * 2];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&(SECTION_TABLE_OFFSET as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
    bytes[58..60].copy_from_slice(&ELF64_SECTION_HEADER_SIZE.to_le_bytes());
    bytes[60..62].copy_from_slice(&SECTION_COUNT.to_le_bytes());

    write_section(
        &mut bytes,
        1,
        SectionSpec {
            section_type: SHT_STRTAB,
            offset: STRTAB_OFFSET as u64,
            size: STRTAB.len() as u64,
            link: 0,
            alignment: 1,
            entry_size: 0,
        },
    );
    write_section(
        &mut bytes,
        2,
        SectionSpec {
            section_type: SHT_SYMTAB,
            offset: SYMTAB_OFFSET as u64,
            size: ELF64_SYMBOL_SIZE * 2,
            link: 1,
            alignment: 8,
            entry_size: ELF64_SYMBOL_SIZE,
        },
    );
    bytes[STRTAB_OFFSET..STRTAB_OFFSET + STRTAB.len()].copy_from_slice(STRTAB);

    let symbol = SYMTAB_OFFSET + ELF64_SYMBOL_SIZE as usize;
    bytes[symbol..symbol + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[symbol + 4] = 0x12;
    bytes[symbol + 5] = 0;
    bytes[symbol + 6..symbol + 8].copy_from_slice(&3u16.to_le_bytes());
    bytes[symbol + 8..symbol + 16].copy_from_slice(&0x401000u64.to_le_bytes());
    bytes[symbol + 16..symbol + 24].copy_from_slice(&7u64.to_le_bytes());
    bytes
}

fn parse_tables(bytes: &[u8]) -> Result<Vec<Elf64SymbolTable>, ElfError> {
    let header = Elf64Header::parse(bytes)?;
    let sections = header.section_headers(bytes)?;
    header.symbol_tables(bytes, &sections)
}

#[test]
fn parses_symbol_table_and_linked_string_table() {
    let tables = parse_tables(&valid_symbol_file()).unwrap();
    assert_eq!(
        tables,
        vec![Elf64SymbolTable {
            section_index: 2,
            string_table_index: 1,
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
                    name_offset: 1,
                    info: 0x12,
                    other: 0,
                    section_index: 3,
                    value: 0x401000,
                    size: 7,
                },
            ],
        }]
    );
}

#[test]
fn rejects_wrong_symbol_entry_size() {
    let mut bytes = valid_symbol_file();
    let base = SECTION_TABLE_OFFSET + 2 * ELF64_SECTION_HEADER_SIZE as usize;
    bytes[base + 56..base + 64].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::InvalidSymbolEntrySize {
            section_index: 2,
            entry_size: 16,
        })
    );
}

#[test]
fn rejects_symbol_table_size_not_multiple_of_entry_size() {
    let mut bytes = valid_symbol_file();
    let base = SECTION_TABLE_OFFSET + 2 * ELF64_SECTION_HEADER_SIZE as usize;
    bytes[base + 32..base + 40].copy_from_slice(&(ELF64_SYMBOL_SIZE + 1).to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::InvalidSymbolTableSize {
            section_index: 2,
            size: ELF64_SYMBOL_SIZE + 1,
            entry_size: ELF64_SYMBOL_SIZE,
        })
    );
}

#[test]
fn rejects_out_of_range_linked_string_table() {
    let mut bytes = valid_symbol_file();
    let base = SECTION_TABLE_OFFSET + 2 * ELF64_SECTION_HEADER_SIZE as usize;
    bytes[base + 40..base + 44].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::InvalidSymbolStringTableIndex {
            section_index: 2,
            string_table_index: 4,
            section_count: SECTION_COUNT,
        })
    );
}

#[test]
fn rejects_link_to_non_string_table_section() {
    let mut bytes = valid_symbol_file();
    let base = SECTION_TABLE_OFFSET + ELF64_SECTION_HEADER_SIZE as usize;
    bytes[base + 4..base + 8].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::SymbolStringTableNotStringTable {
            section_index: 2,
            string_table_index: 1,
            section_type: 1,
        })
    );
}

#[test]
fn rejects_symbol_name_outside_string_table() {
    let mut bytes = valid_symbol_file();
    let symbol = SYMTAB_OFFSET + ELF64_SYMBOL_SIZE as usize;
    bytes[symbol..symbol + 4].copy_from_slice(&(STRTAB.len() as u32).to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::InvalidSymbolNameOffset {
            section_index: 2,
            symbol_index: 1,
            name_offset: STRTAB.len() as u32,
            string_table_size: STRTAB.len() as u64,
        })
    );
}

#[test]
fn rejects_symbol_section_index_outside_section_table() {
    let mut bytes = valid_symbol_file();
    let symbol = SYMTAB_OFFSET + ELF64_SYMBOL_SIZE as usize;
    bytes[symbol + 6..symbol + 8].copy_from_slice(&4u16.to_le_bytes());
    assert_eq!(
        parse_tables(&bytes),
        Err(ElfError::InvalidSymbolSectionIndex {
            section_index: 2,
            symbol_index: 1,
            symbol_section_index: 4,
            section_count: SECTION_COUNT,
        })
    );
}
