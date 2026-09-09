from pathlib import Path
import re

source = Path("src/bin/mini-elf-dynrela-abs64.rs").read_text()
source = source.replace("mini-elf-dynrela-abs64", "mini-elf-dynrela-u32")
source = source.replace("R_X86_64_64", "R_X86_64_32")
source = source.replace("const R_X86_64_32: u32 = 1;", "const R_X86_64_32: u32 = 10;")
source, count = re.subn(
    r'(offset,\n\s+)8,(\n\s+PF_W,\n\s+&format!\("R_X86_64_32 relocation \{index\} target"\),)',
    r'\g<1>4,\2',
    source,
    count=1,
)
if count != 1:
    raise SystemExit("target-width anchor not found")
old = '''        let relocated = add_signed(runtime_symbol, addend)
            .ok_or_else(|| format!("R_X86_64_32 relocation {index} S + A overflows u64"))?;
        output.push_str(&format!(
            "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_target:#018x} symbol-value=B+{value:#018x}=>{runtime_symbol:#018x} addend={addend} result={relocated:#018x}\\n"
        ));'''
new = '''        let relocated = add_signed(runtime_symbol, addend)
            .ok_or_else(|| format!("R_X86_64_32 relocation {index} S + A overflows u64"))?;
        let narrowed = u32::try_from(relocated).map_err(|_| {
            format!(
                "R_X86_64_32 relocation {index} result {relocated:#x} does not fit unsigned 32 bits"
            )
        })?;
        output.push_str(&format!(
            "  index={index} symbol={symbol_index}:{name} target=B+{offset:#018x}=>{runtime_target:#018x} symbol-value=B+{value:#018x}=>{runtime_symbol:#018x} addend={addend} result={narrowed:#010x}\\n"
        ));'''
if old not in source:
    raise SystemExit("result anchor not found")
source = source.replace(old, new, 1)
Path("src/bin/mini-elf-dynrela-u32.rs").write_text(source)

tests = Path("tests/dynamic_rela_abs64.rs").read_text()
tests = tests.replace("dynrela-abs64", "dynrela-u32")
tests = tests.replace("abs64", "u32")
tests = tests.replace("R_X86_64_64", "R_X86_64_32")
tests = tests.replace("const R_X86_64_32: u32 = 1;", "const R_X86_64_32: u32 = 10;")
marker = '''    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    image
}'''
replacement = '''    assert!(Command::new("ld")
        .args([
            "-shared",
            "--hash-style=sysv",
            "-o",
            image.to_str().unwrap(),
            obj.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    // GNU ld emits a same-image R_X86_64_64 here. Keep its ET_DYN, DT_RELA,
    // dynsym, and load layout, changing only the relocation type for this slice.
    let mut bytes = fs::read(&image).unwrap();
    let rela = dynamic_tag(&bytes, DT_RELA);
    let mut cursor = map_vaddr(&bytes, rela);
    loop {
        let info = read_u64(&bytes, cursor + 8);
        if info as u32 == 1 {
            let symbol = info >> 32;
            bytes[cursor + 8..cursor + 16]
                .copy_from_slice(&((symbol << 32) | u64::from(R_X86_64_32)).to_le_bytes());
            break;
        }
        cursor += 24;
    }
    fs::write(&image, bytes).unwrap();
    image
}'''
if marker not in tests:
    raise SystemExit("fixture anchor not found")
tests = tests.replace(marker, replacement, 1)
old_overflow = '''#[test]
fn rejects_s_plus_a_overflow() {
    let dir = temp_dir("u32-overflow");
    let image = build_fixture(&dir);
    let mut bytes = fs::read(&image).unwrap();
    let rela = u32_rela_offset(&bytes);
    bytes[rela + 16..rela + 24].copy_from_slice(&i64::MAX.to_le_bytes());
    let bad = dir.join("bad-overflow.so");
    fs::write(&bad, bytes).unwrap();
    let output = run_tool(&[&bad], "0xffffffffffff0000");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("overflows u64"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}'''
new_overflow = '''#[test]
fn rejects_result_outside_unsigned_32_bits() {
    let dir = temp_dir("u32-overflow");
    let image = build_fixture(&dir);
    let output = run_tool(&[&image], "0x100000000");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not fit unsigned 32 bits"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}'''
if old_overflow not in tests:
    raise SystemExit("overflow-test anchor not found")
tests = tests.replace(old_overflow, new_overflow, 1)
Path("tests/dynamic_rela_u32.rs").write_text(tests)

Path("docs/mini-elf-dynrela-u32.md").write_text('''# `mini-elf-dynrela-u32`

`mini-elf-dynrela-u32` validates one bounded ELF64 x86-64 dynamic-loader contract: same-image `R_X86_64_32` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-u32 --load-bias <address> <input>...
```

The validator reads a checked `PT_DYNAMIC`, requires the ELF64 `DT_RELA` tuple plus SysV `DT_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, and uses `DT_HASH.nchain` as the bounded dynamic-symbol count. For each `R_X86_64_32` entry it requires a nonzero in-range dynamic symbol index, a four-byte relocation destination fully contained in writable `PT_LOAD` memory, and a same-image defined non-absolute, non-TLS symbol whose value lies in loadable memory. Symbol names must terminate inside the declared dynamic string table.

With explicit load bias `B`, the slice checks `B + r_offset`, `B + S`, then evaluates the ABI value `S + A` using checked signed-addend arithmetic. The final value must fit unsigned 32 bits exactly before it could be written to the four-byte relocation field. Multi-input operation validates every file before emitting stdout, preserving atomic output on malformed later inputs.

Focused integration coverage builds the image with GNU `as` and `ld --hash-style=sysv`, preserves the GNU-produced ET_DYN/DT_RELA/dynsym/load layout, changes only the selected same-image data relocation type to `R_X86_64_32`, and confirms GNU `readelf -rW` recognizes it. Regressions cover invalid dynamic-symbol indices, non-writable targets, unsigned-32 overflow, signed addends, and multi-input stdout atomicity.

This is intentionally not a complete dynamic loader. External dependency lookup, symbol interposition/versioning, TLS, IFUNC execution, relocation ordering, and memory writes remain outside this bounded slice.
''')
