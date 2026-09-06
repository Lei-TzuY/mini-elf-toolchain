# `mini-elf-nm`

`mini-elf-nm` is a bounded ELF64 x86-64 symbol-table inspection tool built on the toolchain's existing checked ELF and archive parsers.

```sh
mini-elf-nm input.o
mini-elf-nm libsupport.a
mini-elf-nm -u input.o
mini-elf-nm --undefined-only input.o libsupport.a
mini-elf-nm -g input.o
mini-elf-nm --extern-only input.o libsupport.a
mini-elf-nm -g -u input.o
mini-elf-nm -n input.o
mini-elf-nm --numeric-sort input.o libsupport.a
mini-elf-nm -p input.o
mini-elf-nm --no-sort input.o
mini-elf-nm -r input.o
mini-elf-nm --numeric-sort --reverse-sort input.o
```

For a single ELF input, it prints named symbols in deterministic name order by default using these columns:

```text
VALUE             SIZE BIND   TYPE    SHNDX NAME
```

`VALUE` is the hexadecimal `st_value`, `SIZE` is `st_size`, `BIND` and `TYPE` decode the ELF symbol info byte, and `SHNDX` prints ordinary section indices plus `UND`, `ABS`, and `COM` for the corresponding reserved indices.

`-u` and `--undefined-only` are GNU-compatible bounded filters accepted before the input list. They preserve the same checked parsing and deterministic table format but emit only named symbols whose `st_shndx` is `SHN_UNDEF`. `-g` and `--extern-only` emit only named non-local symbols by excluding `STB_LOCAL`; the filters compose, so `-g -u` selects symbols that are both externally visible and undefined. By default, selected symbols are sorted lexically by name. `-n` and `--numeric-sort` switch to ascending `st_value` ordering; equal values retain their original checked symbol-table order. `-p` and `--no-sort` switch back to checked symbol-table order without sorting. As with GNU `nm`, the last ordering mode among `-n` and `-p` wins. `-r` and `--reverse-sort` reverse an active name or numeric sort, so `-n -r` yields descending numeric order; it has no effect with `-p`. Options apply consistently to ordinary ELF inputs, archive members, and multiple inputs. Archive-member order and top-level input order are not changed, and all inputs are still validated before stdout is emitted.

For a checked System V/GNU/BSD `ar` archive, `mini-elf-nm` walks ordinary members in archive order, skips special symbol/string-table members, prints a `<member>:` label, and applies the same checked ELF symbol walk to that member. The command validates every ordinary member before returning output, so a malformed member fails the invocation with `archive(member)` provenance rather than reporting a partial successful archive inspection.

Malformed or truncated ELF input, malformed archives or ordinary members, invalid section/symbol tables, invalid symbol names, unreadable files, missing input, and invalid option-only invocations are rejected with a nonzero exit status.

This slice intentionally does not add recursive archives, defined-only filtering, size sorting, demangling, address rewriting, dynamic-loader semantics, linker extraction behavior, or archive-index semantics changes. GNU `as`, `ar`, `readelf -Ws`, and `nm` are used in integration testing as differential evidence for real `ET_REL` and archive symbol facts when those tools are available.
