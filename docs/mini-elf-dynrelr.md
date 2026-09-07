# `mini-elf-dynrelr`

`mini-elf-dynrelr` is a checked ELF64 x86-64 inspector for packed relative relocations described by the runtime `PT_DYNAMIC` table.

## Supported slice

The tool reads `DT_RELR`, `DT_RELRSZ`, and `DT_RELRENT` without relying on section headers. The three tags must appear together, `DT_RELRENT` must be the ELF64 word size (8 bytes), and the encoded table must be fully backed by a file-backed `PT_LOAD` range.

Each even RELR word is decoded as an aligned direct relocation address. Each odd word is decoded as a 63-slot bitmap relative to the cursor established by a preceding direct entry. Decoded relocation targets must fit inside a `PT_LOAD` memory range. All table, cursor, bitmap-slot, virtual-address, and file-offset arithmetic is checked for overflow.

```text
mini-elf-dynrelr libsample.so
mini-elf-dynrelr first.so second.so
```

For multiple inputs, output is emitted only after every input has been validated, so a malformed later file cannot leave partial stdout.

## Differential coverage

Focused integration coverage builds a real GNU-linked shared object with `ld -shared -z pack-relative-relocs` when that linker feature is available. Decoded offsets are checked against GNU `readelf -rW`. Dedicated regressions cover malformed tag tuples, invalid `DT_RELRENT`, a bitmap before any direct address, packed-address overflow, `DT_RELR` virtual-range overflow, and multi-input stdout atomicity.

This slice is inspection-only. It does not apply relocations, synthesize RELR tables, implement a runtime loader, or change the static linker output format.
