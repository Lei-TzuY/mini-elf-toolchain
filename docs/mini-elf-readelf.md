# mini-elf-readelf

`mini-elf-readelf` is the checked ELF64 x86-64 inspection companion to the linker and `mini-elf-nm`.

The current bounded slice exposes only ELF file-header inspection:

```sh
mini-elf-readelf -h input.o
mini-elf-readelf --file-header input.o executable
```

The command reuses the repository's checked `Elf64Header` parser and validates the referenced section-header table before producing output. Multiple inputs are validated before any stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

The output reports ELF class/data encoding, file type, machine, entry point, program/section-header offsets and sizes, flags, counts, and the section-name string-table index. GNU `readelf -h` is used as a differential oracle for core header facts on real GNU-assembled `ET_REL` inputs.

Section dumps, program-header dumps, dynamic metadata, notes, relocations, and symbol-table rendering are intentionally outside this slice.
