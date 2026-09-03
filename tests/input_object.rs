use mini_elf_toolchain::input_object::{RelocatableObject, RelocatableObjectError, ET_REL};

fn minimal_elf64(elf_type: u16) -> Vec<u8> {
    let mut file = vec![0u8; 64];
    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    file[16..18].copy_from_slice(&elf_type.to_le_bytes());
    file[18..20].copy_from_slice(&62u16.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    file[52..54].copy_from_slice(&64u16.to_le_bytes());
    file
}

#[test]
fn accepts_minimal_et_rel_object() {
    let object = RelocatableObject::parse(&minimal_elf64(ET_REL)).expect("ET_REL should validate");

    assert_eq!(object.header.elf_type, ET_REL);
    assert!(object.sections.is_empty());
    assert!(object.symbol_tables.is_empty());
    assert!(object.rela_tables.is_empty());
}

#[test]
fn rejects_non_relocatable_elf_before_linking() {
    let error = RelocatableObject::parse(&minimal_elf64(2)).expect_err("ET_EXEC must be rejected");

    assert_eq!(error, RelocatableObjectError::UnsupportedElfType(2));
    assert_eq!(
        error.to_string(),
        "unsupported ELF type 2; expected relocatable object (ET_REL)"
    );
}

#[test]
fn preserves_header_parser_diagnostics() {
    let mut file = minimal_elf64(ET_REL);
    file[0] = 0;

    let error = RelocatableObject::parse(&file).expect_err("bad magic must fail");
    assert!(error.to_string().contains("invalid ELF magic"));
}
