# `mini-elf-dynrelr`

`mini-elf-dynrelr` is a checked ELF64 x86-64 inspector for packed relative relocations described by the runtime `PT_DYNAMIC` table.

## Supported slice

The tool reads `DT_RELR`, `DT_RELRSZ`, and `DT_RELRENT` without relying on section headers. The three tags must appear together, `DT_RELRENT` must be the ELF64 word size (8 bytes), and the encoded table must be fully backed by a file-backed `PT_LOAD` range.

Each even RELR word is decoded as an aligned direct relocation address. Each odd word is decoded as a 63-slot bitmap relative to the cursor established by a preceding direct entry. Decoded relocation targets must fit inside a `PT_LOAD` memory range. All table, cursor, bitmap-slot, virtual-address, and file-offset arithmetic is checked for overflow.

```text
mini-elf-dynrelr libsample.so
mini-elf-dynrelr first.so second.so
mini-elf-dynrelr --load-bias 0x7f0000000000 libsample.so
mini-elf-dynrelr --load-bias=1048576 libsample.so
```

The optional `--load-bias` mode is a bounded runtime-relocation simulation step. After normal RELR decoding, each relocation target must also be backed by file bytes so the pre-relocation 64-bit implicit addend can be read. The tool then evaluates the x86-64 relative-relocation formula `B + A` using checked unsigned 64-bit arithmetic, where `B` is the requested load bias and `A` is the word stored at the relocation target. It reports the relocation offset, implicit addend, and computed value without mutating the ELF file or synthesizing a memory image. A memory-only target remains valid for offset inspection but is rejected in load-bias mode because its pre-relocation addend cannot be recovered from the file.

For multiple inputs, output is emitted only after every input has been validated, so a malformed later file cannot leave partial stdout.

## Differential coverage

Focused integration coverage constructs a real GNU-linked shared object, converts three contiguous GNU `R_X86_64_RELATIVE` relocations into a valid direct-plus-bitmap `DT_RELR` table, and checks decoded offsets against GNU `readelf --use-dynamic -rW`. The load-bias coverage preserves the original RELA addends in the relocated words before conversion, then verifies the checked `B + A` result. Dedicated regressions cover malformed tag tuples, invalid `DT_RELRENT`, a bitmap before any direct address, packed-address overflow, `DT_RELR` virtual-range overflow, load-bias arithmetic overflow, file-backed-addend requirements, invalid load-bias syntax, and multi-input stdout atomicity.

This slice does not mutate or map an ELF image, load dependencies, resolve dynamic symbols, apply REL/RELA relocations, synthesize RELR tables, or implement a complete runtime loader.
