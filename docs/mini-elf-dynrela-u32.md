# `mini-elf-dynrela-u32`

`mini-elf-dynrela-u32` validates one bounded ELF64 x86-64 dynamic-loader contract: same-image `R_X86_64_32` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-u32 --load-bias <address> <input>...
```

The validator reads a checked `PT_DYNAMIC`, requires the ELF64 `DT_RELA` tuple plus SysV `DT_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, and uses `DT_HASH.nchain` as the bounded dynamic-symbol count. For each `R_X86_64_32` entry it requires a nonzero in-range dynamic symbol index, a four-byte relocation destination fully contained in writable `PT_LOAD` memory, and a same-image defined non-absolute, non-TLS symbol whose value lies in loadable memory. Symbol names must terminate inside the declared dynamic string table.

With explicit load bias `B`, the slice checks `B + r_offset`, `B + S`, then evaluates the ABI value `S + A` using checked signed-addend arithmetic. The final value must fit unsigned 32 bits exactly before it could be written to the four-byte relocation field. Multi-input operation validates every file before emitting stdout, preserving atomic output on malformed later inputs.

Focused integration coverage builds the image with GNU `as` and `ld --hash-style=sysv`, preserves the GNU-produced ET_DYN/DT_RELA/dynsym/load layout, changes only the selected same-image data relocation type to `R_X86_64_32`, and confirms GNU `readelf -rW` recognizes it. Regressions cover invalid dynamic-symbol indices, non-writable targets, unsigned-32 overflow, signed addends, and multi-input stdout atomicity.

This is intentionally not a complete dynamic loader. External dependency lookup, symbol interposition/versioning, TLS, IFUNC execution, relocation ordering, and memory writes remain outside this bounded slice.
