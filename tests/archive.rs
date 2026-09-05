use mini_elf_toolchain::archive::{Archive, ArchiveError, ArchiveMemberKind};

fn append_member(bytes: &mut Vec<u8>, name: &str, data: &[u8]) {
    assert!(name.len() <= 16);

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
}

#[test]
fn parses_short_and_gnu_long_member_names() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "//", b"very-long-object-name.o/\n");
    append_member(&mut bytes, "short.o/", b"ELF0");
    append_member(&mut bytes, "/0", b"ELF1");

    let archive = Archive::parse(&bytes).expect("valid archive");
    let ordinary = archive.ordinary_members().collect::<Vec<_>>();

    assert_eq!(archive.members[0].kind, ArchiveMemberKind::StringTable);
    assert_eq!(ordinary.len(), 2);
    assert_eq!(ordinary[0].name, b"short.o");
    assert_eq!(ordinary[0].data, b"ELF0");
    assert_eq!(ordinary[1].name, b"very-long-object-name.o");
    assert_eq!(ordinary[1].data, b"ELF1");
}

#[test]
fn preserves_symbol_table_members_without_exposing_them_as_objects() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "/", b"index");
    append_member(&mut bytes, "/SYM64/", b"wide-index");
    append_member(&mut bytes, "object.o/", b"object");

    let archive = Archive::parse(&bytes).expect("valid archive");

    assert_eq!(archive.members[0].kind, ArchiveMemberKind::SymbolTable);
    assert_eq!(archive.members[1].kind, ArchiveMemberKind::SymbolTable64);
    assert_eq!(archive.ordinary_members().count(), 1);
}

#[test]
fn records_checked_member_offsets_and_sizes() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "x.o/", b"abcd");

    let archive = Archive::parse(&bytes).expect("valid archive");
    let member = &archive.members[0];

    assert_eq!(member.header_offset, 8);
    assert_eq!(member.data_offset, 68);
    assert_eq!(member.declared_size, 4);
    assert_eq!(member.data, b"abcd");
}

#[test]
fn rejects_bad_magic_and_truncated_headers() {
    assert_eq!(Archive::parse(b"not ar"), Err(ArchiveError::BadMagic));

    let mut bytes = b"!<arch>\n".to_vec();
    bytes.extend_from_slice(b"partial");
    assert_eq!(
        Archive::parse(&bytes),
        Err(ArchiveError::TruncatedHeader {
            offset: 8,
            available: 7,
        })
    );
}

#[test]
fn rejects_invalid_member_size_and_truncated_payload() {
    let mut invalid_size = b"!<arch>\n".to_vec();
    let mut header = [b' '; 60];
    header[..4].copy_from_slice(b"x.o/");
    header[48..58].copy_from_slice(b"xyz       ");
    header[58..60].copy_from_slice(b"`\n");
    invalid_size.extend_from_slice(&header);
    assert_eq!(
        Archive::parse(&invalid_size),
        Err(ArchiveError::InvalidSize { offset: 8 })
    );

    let mut truncated = b"!<arch>\n".to_vec();
    let mut header = [b' '; 60];
    header[..4].copy_from_slice(b"x.o/");
    header[48..58].copy_from_slice(b"4         ");
    header[58..60].copy_from_slice(b"`\n");
    truncated.extend_from_slice(&header);
    truncated.extend_from_slice(b"ab");
    assert_eq!(
        Archive::parse(&truncated),
        Err(ArchiveError::TruncatedMember {
            offset: 8,
            size: 4,
            available: 2,
        })
    );
}

#[test]
fn requires_alignment_padding_for_odd_members() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "x.o/", b"abc");
    bytes.pop();

    assert_eq!(
        Archive::parse(&bytes),
        Err(ArchiveError::MissingPadding { offset: 71 })
    );
}

#[test]
fn rejects_missing_or_out_of_bounds_gnu_string_table_references() {
    let mut missing = b"!<arch>\n".to_vec();
    append_member(&mut missing, "/0", b"x");
    assert_eq!(
        Archive::parse(&missing),
        Err(ArchiveError::MissingStringTable { offset: 8 })
    );

    let mut out_of_bounds = b"!<arch>\n".to_vec();
    append_member(&mut out_of_bounds, "//", b"name.o/\n");
    let member_offset = out_of_bounds.len();
    append_member(&mut out_of_bounds, "/999", b"x");
    assert_eq!(
        Archive::parse(&out_of_bounds),
        Err(ArchiveError::LongNameOutOfBounds {
            offset: member_offset,
            string_offset: 999,
            string_table_len: 8,
        })
    );
}

#[test]
fn rejects_unterminated_long_names_and_duplicate_string_tables() {
    let mut unterminated = b"!<arch>\n".to_vec();
    append_member(&mut unterminated, "//", b"long-name.o/");
    let member_offset = unterminated.len();
    append_member(&mut unterminated, "/0", b"x");
    assert_eq!(
        Archive::parse(&unterminated),
        Err(ArchiveError::UnterminatedLongName {
            offset: member_offset,
            string_offset: 0,
        })
    );

    let mut duplicate = b"!<arch>\n".to_vec();
    append_member(&mut duplicate, "//", b"one/\n");
    let duplicate_offset = duplicate.len();
    append_member(&mut duplicate, "//", b"two/\n");
    assert_eq!(
        Archive::parse(&duplicate),
        Err(ArchiveError::DuplicateStringTable {
            offset: duplicate_offset,
        })
    );
}

#[test]
fn parses_bsd_extended_name_and_exposes_object_payload() {
    let mut bytes = b"!<arch>\n".to_vec();
    append_member(&mut bytes, "#1/8", b"name.o\0\0payload");

    let archive = Archive::parse(&bytes).expect("valid BSD extended member");
    let member = &archive.members[0];
    assert_eq!(member.kind, ArchiveMemberKind::Ordinary);
    assert_eq!(member.name, b"name.o");
    assert_eq!(member.header_offset, 8);
    assert_eq!(member.data_offset, 76);
    assert_eq!(member.declared_size, 15);
    assert_eq!(member.data, b"payload");
}

#[test]
fn rejects_malformed_bsd_extended_name_lengths() {
    let mut invalid = b"!<arch>\n".to_vec();
    append_member(&mut invalid, "#1/x", b"payload");
    assert_eq!(
        Archive::parse(&invalid),
        Err(ArchiveError::InvalidBsdExtendedNameLength { offset: 8 })
    );

    let mut out_of_bounds = b"!<arch>\n".to_vec();
    append_member(&mut out_of_bounds, "#1/9", b"short");
    assert_eq!(
        Archive::parse(&out_of_bounds),
        Err(ArchiveError::BsdExtendedNameOutOfBounds {
            offset: 8,
            name_len: 9,
            member_size: 5,
        })
    );

    let mut empty = b"!<arch>\n".to_vec();
    append_member(&mut empty, "#1/2", b"\0\0payload");
    assert_eq!(
        Archive::parse(&empty),
        Err(ArchiveError::EmptyMemberName { offset: 8 })
    );
}
