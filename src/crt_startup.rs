const ELF64_HEADER_SIZE: usize = 64;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_RELA_SIZE: usize = 24;

const ET_REL: u16 = 1;
const EM_X86_64: u16 = 62;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const STB_GLOBAL: u8 = 1;
const STT_FUNC: u8 = 2;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;

const TEXT_SECTION_INDEX: u16 = 1;
const RELA_TEXT_SECTION_INDEX: u16 = 2;
const SYMTAB_SECTION_INDEX: u16 = 3;
const STRTAB_SECTION_INDEX: u16 = 4;
const SHSTRTAB_SECTION_INDEX: u16 = 5;
const GNU_STACK_SECTION_INDEX: u16 = 6;
const SECTION_COUNT: u16 = 7;

const START_SYMBOL_INDEX: u32 = 1;
const MAIN_SYMBOL_INDEX: u32 = 2;
const LIBC_START_MAIN_SYMBOL_INDEX: u32 = 3;

/// Build the bounded GNU/Linux x86-64 startup object used by the dynamic-PIE
/// CRT synthesis slice.
///
/// The generated ET_REL object defines _start, references main with a
/// PC-relative address relocation, and calls __libc_start_main through a
/// PLT32 relocation. Feeding this object through the ordinary linker pipeline
/// deliberately reuses normal symbol resolution, provider checking, PLT/GOTPLT
/// generation, dynamic-symbol emission, and GNU-stack policy.
pub fn build_dynamic_pie_crt_startup_object() -> Vec<u8> {
    // endbr64; xor %ebp,%ebp; mov %rdx,%r9; pop %rsi; mov %rsp,%rdx;
    // and $-16,%rsp; push %rax; push %rsp; xor %r8d,%r8d; xor %ecx,%ecx;
    // lea main(%rip),%rdi; call __libc_start_main@PLT; hlt
    let text: [u8; 37] = [
        0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2, 0x48,
        0x83, 0xe4, 0xf0, 0x50, 0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x48, 0x8d, 0x3d, 0x00,
        0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xf4,
    ];

    let mut strtab = vec![0];
    let start_name = push_string(&mut strtab, b"_start");
    let main_name = push_string(&mut strtab, b"main");
    let libc_start_main_name = push_string(&mut strtab, b"__libc_start_main");

    let mut shstrtab = vec![0];
    let text_name = push_string(&mut shstrtab, b".text");
    let rela_text_name = push_string(&mut shstrtab, b".rela.text");
    let symtab_name = push_string(&mut shstrtab, b".symtab");
    let strtab_name = push_string(&mut shstrtab, b".strtab");
    let shstrtab_name = push_string(&mut shstrtab, b".shstrtab");
    let gnu_stack_name = push_string(&mut shstrtab, b".note.GNU-stack");

    let text_offset = align_up(ELF64_HEADER_SIZE, 16);
    let rela_offset = align_up(text_offset + text.len(), 8);
    let rela_size = 2 * ELF64_RELA_SIZE;
    let symtab_offset = align_up(rela_offset + rela_size, 8);
    let symtab_size = 4 * ELF64_SYMBOL_SIZE;
    let strtab_offset = symtab_offset + symtab_size;
    let shstrtab_offset = strtab_offset + strtab.len();
    let gnu_stack_offset = shstrtab_offset + shstrtab.len();
    let section_header_offset = align_up(gnu_stack_offset, 8);
    let file_size =
        section_header_offset + usize::from(SECTION_COUNT) * ELF64_SECTION_HEADER_SIZE;
    let mut file = vec![0_u8; file_size];

    file[0..4].copy_from_slice(b"\x7fELF");
    file[4] = 2;
    file[5] = 1;
    file[6] = 1;
    put_u16(&mut file, 16, ET_REL);
    put_u16(&mut file, 18, EM_X86_64);
    put_u32(&mut file, 20, 1);
    put_u64(&mut file, 40, section_header_offset as u64);
    put_u16(&mut file, 52, ELF64_HEADER_SIZE as u16);
    put_u16(&mut file, 58, ELF64_SECTION_HEADER_SIZE as u16);
    put_u16(&mut file, 60, SECTION_COUNT);
    put_u16(&mut file, 62, SHSTRTAB_SECTION_INDEX);

    file[text_offset..text_offset + text.len()].copy_from_slice(&text);

    write_rela(
        &mut file[rela_offset..rela_offset + ELF64_RELA_SIZE],
        27,
        MAIN_SYMBOL_INDEX,
        R_X86_64_PC32,
        -4,
    );
    write_rela(
        &mut file[rela_offset + ELF64_RELA_SIZE..rela_offset + rela_size],
        32,
        LIBC_START_MAIN_SYMBOL_INDEX,
        R_X86_64_PLT32,
        -4,
    );

    write_symbol(
        &mut file[symtab_offset..symtab_offset + ELF64_SYMBOL_SIZE],
        0,
        0,
        0,
        0,
        0,
    );
    write_symbol(
        &mut file[symtab_offset + ELF64_SYMBOL_SIZE..symtab_offset + 2 * ELF64_SYMBOL_SIZE],
        start_name,
        (STB_GLOBAL << 4) | STT_FUNC,
        TEXT_SECTION_INDEX,
        0,
        text.len() as u64,
    );
    write_symbol(
        &mut file[symtab_offset + 2 * ELF64_SYMBOL_SIZE..symtab_offset + 3 * ELF64_SYMBOL_SIZE],
        main_name,
        (STB_GLOBAL << 4) | STT_FUNC,
        0,
        0,
        0,
    );
    write_symbol(
        &mut file[symtab_offset + 3 * ELF64_SYMBOL_SIZE..symtab_offset + 4 * ELF64_SYMBOL_SIZE],
        libc_start_main_name,
        (STB_GLOBAL << 4) | STT_FUNC,
        0,
        0,
        0,
    );

    file[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);
    file[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(&shstrtab);

    let sh = |index: u16| section_header_offset + usize::from(index) * ELF64_SECTION_HEADER_SIZE;
    write_section(
        &mut file,
        sh(TEXT_SECTION_INDEX),
        text_name,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        text_offset as u64,
        text.len() as u64,
        0,
        0,
        16,
        0,
    );
    write_section(
        &mut file,
        sh(RELA_TEXT_SECTION_INDEX),
        rela_text_name,
        SHT_RELA,
        0,
        rela_offset as u64,
        rela_size as u64,
        u32::from(SYMTAB_SECTION_INDEX),
        u32::from(TEXT_SECTION_INDEX),
        8,
        ELF64_RELA_SIZE as u64,
    );
    write_section(
        &mut file,
        sh(SYMTAB_SECTION_INDEX),
        symtab_name,
        SHT_SYMTAB,
        0,
        symtab_offset as u64,
        symtab_size as u64,
        u32::from(STRTAB_SECTION_INDEX),
        1,
        8,
        ELF64_SYMBOL_SIZE as u64,
    );
    write_section(
        &mut file,
        sh(STRTAB_SECTION_INDEX),
        strtab_name,
        SHT_STRTAB,
        0,
        strtab_offset as u64,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_section(
        &mut file,
        sh(SHSTRTAB_SECTION_INDEX),
        shstrtab_name,
        SHT_STRTAB,
        0,
        shstrtab_offset as u64,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    write_section(
        &mut file,
        sh(GNU_STACK_SECTION_INDEX),
        gnu_stack_name,
        SHT_PROGBITS,
        0,
        gnu_stack_offset as u64,
        0,
        0,
        0,
        1,
        0,
    );

    file
}

fn align_up(value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

fn push_string(table: &mut Vec<u8>, value: &[u8]) -> u32 {
    let offset = u32::try_from(table.len()).expect("bounded CRT string table fits u32");
    table.extend_from_slice(value);
    table.push(0);
    offset
}

fn write_rela(out: &mut [u8], offset: u64, symbol_index: u32, relocation_type: u32, addend: i64) {
    put_u64(out, 0, offset);
    put_u64(
        out,
        8,
        (u64::from(symbol_index) << 32) | u64::from(relocation_type),
    );
    out[16..24].copy_from_slice(&addend.to_le_bytes());
}

fn write_symbol(
    out: &mut [u8],
    name_offset: u32,
    info: u8,
    section_index: u16,
    value: u64,
    size: u64,
) {
    put_u32(out, 0, name_offset);
    out[4] = info;
    out[5] = 0;
    put_u16(out, 6, section_index);
    put_u64(out, 8, value);
    put_u64(out, 16, size);
}

#[allow(clippy::too_many_arguments)]
fn write_section(
    file: &mut [u8],
    offset: usize,
    name_offset: u32,
    section_type: u32,
    flags: u64,
    file_offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
) {
    put_u32(file, offset, name_offset);
    put_u32(file, offset + 4, section_type);
    put_u64(file, offset + 8, flags);
    put_u64(file, offset + 24, file_offset);
    put_u64(file, offset + 32, size);
    put_u32(file, offset + 40, link);
    put_u32(file, offset + 44, info);
    put_u64(file, offset + 48, alignment);
    put_u64(file, offset + 56, entry_size);
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input_object::RelocatableObject;
    use crate::symbol_names::symbol_name;

    #[test]
    fn startup_object_is_valid_et_rel_with_expected_symbols_and_relocations() {
        let file = build_dynamic_pie_crt_startup_object();
        let object = RelocatableObject::parse(&file).unwrap();

        assert_eq!(object.sections.len(), usize::from(SECTION_COUNT));
        assert_eq!(object.symbol_tables.len(), 1);
        let symbols = &object.symbol_tables[0];
        assert_eq!(symbols.symbols.len(), 4);
        assert_eq!(
            symbol_name(&file, &object.sections, symbols, START_SYMBOL_INDEX as usize).unwrap(),
            b"_start"
        );
        assert_eq!(
            symbol_name(&file, &object.sections, symbols, MAIN_SYMBOL_INDEX as usize).unwrap(),
            b"main"
        );
        assert_eq!(
            symbol_name(
                &file,
                &object.sections,
                symbols,
                LIBC_START_MAIN_SYMBOL_INDEX as usize
            )
            .unwrap(),
            b"__libc_start_main"
        );

        let start = symbols.symbols[START_SYMBOL_INDEX as usize];
        assert_eq!(start.section_index, TEXT_SECTION_INDEX);
        assert_eq!(start.info, (STB_GLOBAL << 4) | STT_FUNC);
        assert_eq!(start.size, 37);
        assert_eq!(symbols.symbols[MAIN_SYMBOL_INDEX as usize].section_index, 0);
        assert_eq!(
            symbols.symbols[LIBC_START_MAIN_SYMBOL_INDEX as usize].section_index,
            0
        );

        assert_eq!(object.rela_tables.len(), 1);
        let rela = &object.rela_tables[0];
        assert_eq!(rela.target_section_index, TEXT_SECTION_INDEX);
        assert_eq!(rela.relocations.len(), 2);
        assert_eq!(rela.relocations[0].offset, 27);
        assert_eq!(rela.relocations[0].symbol_index, MAIN_SYMBOL_INDEX);
        assert_eq!(rela.relocations[0].relocation_type, R_X86_64_PC32);
        assert_eq!(rela.relocations[0].addend, -4);
        assert_eq!(rela.relocations[1].offset, 32);
        assert_eq!(
            rela.relocations[1].symbol_index,
            LIBC_START_MAIN_SYMBOL_INDEX
        );
        assert_eq!(rela.relocations[1].relocation_type, R_X86_64_PLT32);
        assert_eq!(rela.relocations[1].addend, -4);
    }

    #[test]
    fn startup_entry_begins_with_endbr64_for_ibt_compatibility() {
        let file = build_dynamic_pie_crt_startup_object();
        let object = RelocatableObject::parse(&file).unwrap();
        let text = object.sections[usize::from(TEXT_SECTION_INDEX)];
        let start = usize::try_from(text.offset).unwrap();
        assert_eq!(&file[start..start + 4], &[0xf3, 0x0f, 0x1e, 0xfa]);
    }
}
