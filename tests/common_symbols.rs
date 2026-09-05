use mini_elf_toolchain::elf64::Elf64Symbol;
use mini_elf_toolchain::resolve::{
    resolve_symbols_with_common, NamedSymbol, ResolutionError, COMMON_OBJECT_INDEX,
    COMMON_SECTION_INDEX, SHN_COMMON, STB_GLOBAL,
};

fn common<'a>(
    name: &'a [u8],
    object_index: usize,
    symbol_index: usize,
    size: u64,
    alignment: u64,
) -> NamedSymbol<'a> {
    NamedSymbol {
        name,
        object_index,
        table_section_index: 3,
        symbol_index,
        symbol: Elf64Symbol {
            name_offset: 0,
            info: STB_GLOBAL << 4,
            other: 0,
            section_index: SHN_COMMON,
            value: alignment,
            size,
        },
    }
}

fn defined<'a>(name: &'a [u8], object_index: usize, symbol_index: usize) -> NamedSymbol<'a> {
    NamedSymbol {
        name,
        object_index,
        table_section_index: 3,
        symbol_index,
        symbol: Elf64Symbol {
            name_offset: 0,
            info: STB_GLOBAL << 4,
            other: 0,
            section_index: 2,
            value: 7,
            size: 4,
        },
    }
}

#[test]
fn merges_common_size_and_alignment_then_allocates_by_name() {
    let resolved = resolve_symbols_with_common([
        common(b"beta", 0, 1, 4, 8),
        common(b"alpha", 1, 2, 8, 16),
        common(b"alpha", 2, 3, 32, 32),
    ])
    .unwrap();

    let common_section = resolved.common_section.unwrap();
    assert_eq!(common_section.alignment, 32);
    assert_eq!(common_section.size, 36);

    let alpha = &resolved.definitions[b"alpha".as_slice()];
    assert_eq!(alpha.object_index, COMMON_OBJECT_INDEX);
    assert_eq!(alpha.symbol.section_index, COMMON_SECTION_INDEX);
    assert_eq!(alpha.symbol.value, 0);
    assert_eq!(alpha.symbol.size, 32);

    let beta = &resolved.definitions[b"beta".as_slice()];
    assert_eq!(beta.object_index, COMMON_OBJECT_INDEX);
    assert_eq!(beta.symbol.section_index, COMMON_SECTION_INDEX);
    assert_eq!(beta.symbol.value, 32);
    assert_eq!(beta.symbol.size, 4);
}

#[test]
fn real_strong_definition_overrides_common_without_allocating_storage() {
    let resolved = resolve_symbols_with_common([
        common(b"target", 0, 1, 64, 64),
        defined(b"target", 1, 2),
    ])
    .unwrap();

    assert!(resolved.common_section.is_none());
    let target = &resolved.definitions[b"target".as_slice()];
    assert_eq!(target.object_index, 1);
    assert_eq!(target.symbol.section_index, 2);
    assert_eq!(target.symbol.value, 7);
}

#[test]
fn rejects_invalid_common_alignment() {
    let error = resolve_symbols_with_common([common(b"bad", 4, 9, 8, 3)]).unwrap_err();

    assert_eq!(
        error,
        ResolutionError::InvalidCommonAlignment {
            name: b"bad".to_vec(),
            object_index: 4,
            symbol_index: 9,
            alignment: 3,
        }
    );
}

#[test]
fn rejects_common_storage_size_overflow() {
    let error = resolve_symbols_with_common([
        common(b"a", 0, 1, u64::MAX, 1),
        common(b"b", 1, 2, 1, 1),
    ])
    .unwrap_err();

    assert_eq!(
        error,
        ResolutionError::CommonSizeOverflow {
            name: b"b".to_vec(),
            offset: u64::MAX,
            size: 1,
        }
    );
}
