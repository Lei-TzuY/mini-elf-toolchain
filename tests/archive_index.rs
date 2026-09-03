use mini_elf_toolchain::archive::Archive;
use mini_elf_toolchain::archive_index::{
    parse_archive_symbol_index, ArchiveSymbolIndexError, ArchiveSymbolIndexKind,
};

fn append_member(bytes: &mut Vec<u8>, name: &str, data: &[u8]) -> usize {
    let header_offset = bytes.len();
    let mut header = [b' '; 60];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[16..28].copy_from_slice(b"0           ");
    header[28..34].copy_from_slice(b"0     ");
    header[34..40].copy_from_slice(b"0     ");
    header[40..48].copy_from_slice(b"100644  ");
    let size = format!("{:<10}", data.len());
    header[48..58].copy_from_slice(size.as_bytes());
    header[58..60].copy_from_slice(b"`\n");
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(data);
    if data.len() % 2 != 0 {
        bytes.push(b'\n');
    }
    header_offset
}

#[test]
fn parses_sysv32_symbol_index_and_maps_members() {
    let mut bytes = b"!<arch>\n".to_vec();
    let first_header = 88u32;
    let second_header = 152u32;
    let mut index = Vec::new();
    index.extend_from_slice(&2u32.to_be_bytes());
    index.extend_from_slice(&first_header.to_be_bytes());
    index.extend_from_slice(&second_header.to_be_bytes());
    index.extend_from_slice(b"foo\0bar\0");
    append_member(&mut bytes, "/", &index);
    assert_eq!(append_member(&mut bytes, "a.o/", b"AAAA"), 88);
    assert_eq!(append_member(&mut bytes, "b.o/", b"BBBB"), 152);

    let archive = Archive::parse(&bytes).expect("valid archive");
    let parsed = parse_archive_symbol_index(&archive)
        .expect("valid symbol index")
        .expect("symbol index present");

    assert_eq!(parsed.kind, ArchiveSymbolIndexKind::SysV32);
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries[0].name, b"foo");
    assert_eq!(archive.members[parsed.entries[0].member_index].name, b"a.o");
    assert_eq!(parsed.entries[1].name, b"bar");
    assert_eq!(archive.members[parsed.entries[1].member_index].name, b"b.o");
}

#[test]
fn parses_sysv64_symbol_index() {
    let mut bytes = b"!<arch>\n".to_vec();
    let member_header = 88u64;
    let mut index = Vec::new();
    index.extend_from_slice(&1u64.to_be_bytes());
    index.extend_from_slice(&member_header.to_be_bytes());
    index.extend_from_slice(b"wide\0");
    append_member(&mut bytes, "/SYM64/", &index);
    assert_eq!(append_member(&mut bytes, "wide.o/", b"ELF0"), 88);

    let archive = Archive::parse(&bytes).expect("valid archive");
    let parsed = parse_archive_symbol_index(&archive)
        .expect("valid symbol index")
        .expect("symbol index present");

    assert_eq!(parsed.kind, ArchiveSymbolIndexKind::SysV64);
    assert_eq!(parsed.entries[0].name, b"wide");
    assert_eq!(parsed.entries[0].member_header_offset, 88);
}

#[test]
fn returns_none_without_symbol_table() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "a.o/", b"AAAA");
    let archive = Archive::parse(&bytes).expect("valid archive");
    assert_eq!(parse_archive_symbol_index(&archive), Ok(None));
}

#[test]
fn rejects_duplicate_symbol_tables() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "/", &0u32.to_be_bytes());
    let second_offset = bytes.len();
    append_member(&mut bytes, "/SYM64/", &0u64.to_be_bytes());
    let archive = Archive::parse(&bytes).expect("valid archive");

    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::MultipleSymbolTables {
            first_offset: 8,
            second_offset,
        })
    );
}

#[test]
fn rejects_truncated_count_and_offset_table() {
    let mut truncated_count = b"!<arch>\n".to_vec();
    append_member(&mut truncated_count, "/", b"\0\0");
    let archive = Archive::parse(&truncated_count).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::TruncatedCount {
            offset: 8,
            width: 4,
            available: 2,
        })
    );

    let mut truncated_offsets = b"!<arch>\n".to_vec();
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_be_bytes());
    data.extend_from_slice(&80u32.to_be_bytes());
    append_member(&mut truncated_offsets, "/", &data);
    let archive = Archive::parse(&truncated_offsets).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::TruncatedOffsets {
            offset: 8,
            count: 2,
            width: 4,
            available: 4,
        })
    );
}

#[test]
fn rejects_unknown_and_special_member_offsets() {
    let mut unknown = b"!<arch>\n".to_vec();
    let mut index = Vec::new();
    index.extend_from_slice(&1u32.to_be_bytes());
    index.extend_from_slice(&999u32.to_be_bytes());
    index.extend_from_slice(b"foo\0");
    append_member(&mut unknown, "/", &index);
    let archive = Archive::parse(&unknown).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::UnknownMemberOffset {
            offset: 8,
            member_offset: 999,
        })
    );

    let mut special = b"!<arch>\n".to_vec();
    let mut index = Vec::new();
    index.extend_from_slice(&1u32.to_be_bytes());
    index.extend_from_slice(&8u32.to_be_bytes());
    index.extend_from_slice(b"foo\0");
    append_member(&mut special, "/", &index);
    let archive = Archive::parse(&special).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::SpecialMemberReference {
            offset: 8,
            member_offset: 8,
        })
    );
}

#[test]
fn rejects_missing_unterminated_empty_and_trailing_symbol_names() {
    let cases = [
        (
            vec![0, 0, 0, 1, 0, 0, 0, 76],
            ArchiveSymbolIndexError::MissingSymbolName {
                offset: 8,
                symbol_index: 0,
            },
        ),
        (
            {
                let mut data = vec![0, 0, 0, 1, 0, 0, 0, 79];
                data.extend_from_slice(b"foo");
                data
            },
            ArchiveSymbolIndexError::UnterminatedSymbolName {
                offset: 8,
                symbol_index: 0,
            },
        ),
    ];

    for (data, expected) in cases {
        let mut bytes = b"!<arch>\n".to_vec();
        append_member(&mut bytes, "/", &data);
        let target = bytes.len();
        append_member(&mut bytes, "a.o/", b"X");
        let mut patched = bytes;
        let table_data = 68;
        let raw = u32::try_from(target)
            .expect("test offset fits u32")
            .to_be_bytes();
        patched[table_data + 4..table_data + 8].copy_from_slice(&raw);
        let archive = Archive::parse(&patched).expect("archive framing valid");
        assert_eq!(parse_archive_symbol_index(&archive), Err(expected));
    }

    let mut empty = b"!<arch>\n".to_vec();
    let mut index = Vec::new();
    index.extend_from_slice(&1u32.to_be_bytes());
    index.extend_from_slice(&80u32.to_be_bytes());
    index.push(0);
    append_member(&mut empty, "/", &index);
    let target = empty.len();
    append_member(&mut empty, "a.o/", b"X");
    let raw = u32::try_from(target)
        .expect("test offset fits u32")
        .to_be_bytes();
    empty[72..76].copy_from_slice(&raw);
    let archive = Archive::parse(&empty).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::EmptySymbolName {
            offset: 8,
            symbol_index: 0,
        })
    );

    let mut trailing = b"!<arch>\n".to_vec();
    let mut index = Vec::new();
    index.extend_from_slice(&1u32.to_be_bytes());
    index.extend_from_slice(&84u32.to_be_bytes());
    index.extend_from_slice(b"foo\0x");
    append_member(&mut trailing, "/", &index);
    let target = trailing.len();
    append_member(&mut trailing, "a.o/", b"X");
    let raw = u32::try_from(target)
        .expect("test offset fits u32")
        .to_be_bytes();
    trailing[72..76].copy_from_slice(&raw);
    let archive = Archive::parse(&trailing).expect("archive framing valid");
    assert_eq!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::TrailingData {
            offset: 8,
            trailing_bytes: 1,
        })
    );
}

#[test]
fn rejects_64_bit_count_size_overflow() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "/SYM64/", &u64::MAX.to_be_bytes());
    let archive = Archive::parse(&bytes).expect("archive framing valid");
    assert!(matches!(
        parse_archive_symbol_index(&archive),
        Err(ArchiveSymbolIndexError::TableSizeOverflow { .. })
    ));
}
