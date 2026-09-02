use mini_elf_toolchain::elf64::{
    Elf64Header, Elf64SectionHeader, ElfError, ELF64_HEADER_SIZE, ELF64_SECTION_HEADER_SIZE,
    SHT_NOBITS,
};

fn file_with_one_section(section_type: u32, offset: u64, size: u64, alignment: u64) -> Vec<u8> {
    let section_table_offset = ELF64_HEADER_SIZE as u64;
    let mut bytes = vec![0u8; ELF64_HEADER_SIZE + ELF64_SECTION_HEADER_SIZE as usize];
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&section_table_offset.to_le_bytes());
    bytes[52..54].copy_from_slice(&(ELF64_HEADER_SIZE as u16).to_le_bytes());
    bytes[58..60].copy_from_slice(&ELF64_SECTION_HEADER_SIZE.to_le_bytes());
    bytes[60..62].copy_from_slice(&1u16.to_le_bytes());

    let base = ELF64_HEADER_SIZE;
    bytes[base + 4..base + 8].copy_from_slice(&section_type.to_le_bytes());
    bytes[base + 24..base + 32].copy_from_slice(&offset.to_le_bytes());
    bytes[base + 32..base + 40].copy_from_slice(&size.to_le_bytes());
    bytes[base + 48..base + 56].copy_from_slice(&alignment.to_le_bytes());
    bytes
}

#[test]
fn parses_validated_section_header() {
    let mut bytes = file_with_one_section(1, 128, 4, 16);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    let header = Elf64Header::parse(&bytes).unwrap();
    assert_eq!(
        header.section_headers(&bytes).unwrap(),
        vec![Elf64SectionHeader {
            name_offset: 0,
            section_type: 1,
            flags: 0,
            address: 0,
            offset: 128,
            size: 4,
            link: 0,
            info: 0,
            address_alignment: 16,
            entry_size: 0,
        }]
    );
}

#[test]
fn rejects_out_of_bounds_section_payload() {
    let bytes = file_with_one_section(1, 128, 1, 1);
    let header = Elf64Header::parse(&bytes).unwrap();
    assert_eq!(
        header.section_headers(&bytes),
        Err(ElfError::SectionDataOutOfBounds {
            section_index: 0,
            end: 129,
            file_len: 128,
        })
    );
}

#[test]
fn rejects_section_payload_range_overflow() {
    let bytes = file_with_one_section(1, u64::MAX, 2, 1);
    let header = Elf64Header::parse(&bytes).unwrap();
    assert_eq!(
        header.section_headers(&bytes),
        Err(ElfError::SectionDataRangeOverflow { section_index: 0 })
    );
}

#[test]
fn allows_nobits_section_without_file_backing() {
    let bytes = file_with_one_section(SHT_NOBITS, u64::MAX, 4096, 4096);
    let header = Elf64Header::parse(&bytes).unwrap();
    let sections = header.section_headers(&bytes).unwrap();
    assert_eq!(sections[0].section_type, SHT_NOBITS);
    assert_eq!(sections[0].size, 4096);
}

#[test]
fn rejects_non_power_of_two_section_alignment() {
    let bytes = file_with_one_section(SHT_NOBITS, 0, 0, 3);
    let header = Elf64Header::parse(&bytes).unwrap();
    assert_eq!(
        header.section_headers(&bytes),
        Err(ElfError::InvalidSectionAlignment {
            section_index: 0,
            alignment: 3,
        })
    );
}

#[test]
fn rejects_out_of_range_section_name_table_index() {
    let mut bytes = file_with_one_section(SHT_NOBITS, 0, 0, 1);
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        Elf64Header::parse(&bytes),
        Err(ElfError::InvalidSectionNameStringTableIndex { index: 1, count: 1 })
    );
}
