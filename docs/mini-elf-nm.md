# `mini-elf-nm`

`mini-elf-nm` is a bounded ELF64 x86-64 symbol-table inspection tool built on the toolchain's existing checked ELF parser.

```sh
mini-elf-nm input.o
```

It prints named symbols in deterministic ELF symbol-table order using these columns:

```text
VALUE             SIZE BIND   TYPE    SHNDX NAME
```

`VALUE` is the hexadecimal `st_value`, `SIZE` is `st_size`, `BIND` and `TYPE` decode the ELF symbol info byte, and `SHNDX` prints ordinary section indices plus `UND`, `ABS`, and `COM` for the corresponding reserved indices.

Malformed or truncated ELF input, invalid section/symbol tables, invalid symbol names, unreadable files, missing input, and extra operands are rejected with a nonzero exit status.

This slice intentionally does not add archive traversal, symbol sorting, demangling, address rewriting, dynamic-loader semantics, or linker behavior changes. GNU `as`, `readelf -Ws`, and `nm` are used in integration testing as differential evidence for real `ET_REL` symbol facts when those tools are available.
