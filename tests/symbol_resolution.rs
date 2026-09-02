use mini_elf_toolchain::elf64::Elf64Symbol;
use mini_elf_toolchain::resolve::{
    resolve_symbols, NamedSymbol, ResolutionError, SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK,
};

fn symbol(binding: u8, section_index: u16, value: u64) -> Elf64Symbol {
    Elf64Symbol {
        name_offset: 0,
        info: binding << 4,
        other: 0,
        section_index,
        value,
        size: 0,
    }
}

fn named<'a>(
    name: &'a [u8],
    object_index: usize,
    symbol_index: usize,
    binding: u8,
    section_index: u16,
    value: u64,
) -> NamedSymbol<'a> {
    NamedSymbol {
        name,
        object_index,
        table_section_index: 3,
        symbol_index,
        symbol: symbol(binding, section_index, value),
    }
}

#[test]
fn skips_local_undefined_and_empty_name_symbols() {
    let definitions = resolve_symbols([
        named(b"local", 0, 1, STB_LOCAL, 2, 10),
        named(b"missing", 0, 2, STB_GLOBAL, SHN_UNDEF, 0),
        named(b"", 0, 3, STB_GLOBAL, 2, 20),
        named(b"kept", 0, 4, STB_GLOBAL, 2, 30),
    ])
    .unwrap();

    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions[b"kept".as_slice()].symbol.value, 30);
}

#[test]
fn strong_definition_replaces_earlier_weak_definition() {
    let definitions = resolve_symbols([
        named(b"target", 0, 1, STB_WEAK, 2, 10),
        named(b"target", 1, 2, STB_GLOBAL, 4, 20),
    ])
    .unwrap();

    let definition = &definitions[b"target".as_slice()];
    assert_eq!(definition.object_index, 1);
    assert_eq!(definition.symbol.value, 20);
}

#[test]
fn weak_definition_does_not_replace_existing_strong_definition() {
    let definitions = resolve_symbols([
        named(b"target", 0, 1, STB_GLOBAL, 2, 10),
        named(b"target", 1, 2, STB_WEAK, 4, 20),
    ])
    .unwrap();

    let definition = &definitions[b"target".as_slice()];
    assert_eq!(definition.object_index, 0);
    assert_eq!(definition.symbol.value, 10);
}

#[test]
fn first_weak_definition_wins_deterministically() {
    let definitions = resolve_symbols([
        named(b"target", 0, 1, STB_WEAK, 2, 10),
        named(b"target", 1, 2, STB_WEAK, 4, 20),
    ])
    .unwrap();

    let definition = &definitions[b"target".as_slice()];
    assert_eq!(definition.object_index, 0);
    assert_eq!(definition.symbol.value, 10);
}

#[test]
fn rejects_multiple_strong_definitions() {
    let result = resolve_symbols([
        named(b"target", 2, 1, STB_GLOBAL, 2, 10),
        named(b"target", 7, 2, STB_GLOBAL, 4, 20),
    ]);

    assert_eq!(
        result,
        Err(ResolutionError::MultipleStrongDefinitions {
            name: b"target".to_vec(),
            first_object_index: 2,
            second_object_index: 7,
        })
    );
}

#[test]
fn rejects_unsupported_nonlocal_binding() {
    let result = resolve_symbols([named(b"odd", 4, 9, 3, 2, 10)]);

    assert_eq!(
        result,
        Err(ResolutionError::UnsupportedBinding {
            object_index: 4,
            table_section_index: 3,
            symbol_index: 9,
            binding: 3,
        })
    );
}
