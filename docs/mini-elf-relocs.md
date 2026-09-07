# mini-elf-relocs

`mini-elf-relocs` is a checked ELF64 x86-64 relocation-table inspection companion.

```sh
mini-elf-relocs input.o
mini-elf-relocs first.o second.o
```

The command parses `SHT_RELA` and `SHT_REL` sections, validates relocation entry sizes and table sizing, validates linked symbol-table and target-section indices, checks entry offset/range arithmetic, validates relocation symbol indices, resolves names through the checked symbol-name path, and renders relocation offset, raw info, x86-64 relocation type, symbol name, and addend.

Multiple inputs are completely inspected before stdout is emitted, so a malformed later input cannot leave a partial report.

Regression coverage includes malformed relocation entry sizes, overflowing relocation section file ranges, and GNU `readelf -rW` differential checks on real GNU-assembled `ET_REL` inputs containing `R_X86_64_PLT32` and `R_X86_64_64` relocations.

Dynamic-loader relocation application, symbol-version decoding, and architecture support beyond ELF64 x86-64 remain outside this bounded inspection slice.
