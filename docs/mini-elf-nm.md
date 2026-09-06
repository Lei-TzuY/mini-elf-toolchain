# `mini-elf-nm`

`mini-elf-nm` is a bounded ELF64 x86-64 symbol-table inspection tool built on the toolchain's existing checked ELF and archive parsers.

```sh
mini-elf-nm input.o
mini-elf-nm libsupport.a
```

For a single ELF input, it prints named symbols in deterministic ELF symbol-table order using these columns:

```text
VALUE             SIZE BIND   TYPE    SHNDX NAME
```

`VALUE` is the hexadecimal `st_value`, `SIZE` is `st_size`, `BIND` and `TYPE` decode the ELF symbol info byte, and `SHNDX` prints ordinary section indices plus `UND`, `ABS`, and `COM` for the corresponding reserved indices.

For a checked System V/GNU/BSD `ar` archive, `mini-elf-nm` walks ordinary members in archive order, skips special symbol/string-table members, prints a `<member>:` label, and applies the same checked ELF symbol walk to that member. The command validates every ordinary member before returning output, so a malformed member fails the invocation with `archive(member)` provenance rather than reporting a partial successful archive inspection.

Malformed or truncated ELF input, malformed archives or ordinary members, invalid section/symbol tables, invalid symbol names, unreadable files, missing input, and extra operands are rejected with a nonzero exit status.

This slice intentionally does not add recursive archives, symbol sorting, demangling, address rewriting, dynamic-loader semantics, linker extraction behavior, or archive-index semantics changes. GNU `as`, `ar`, `readelf -Ws`, and `nm` are used in integration testing as differential evidence for real `ET_REL` and archive symbol facts when those tools are available.