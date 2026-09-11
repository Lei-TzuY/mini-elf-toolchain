# mini-elf-gnu-hash-lookup

`mini-elf-gnu-hash-lookup` is a bounded ELF64 x86-64 dynamic-symbol lookup inspector for GNU-hash-backed `ET_DYN` images.

```sh
mini-elf-gnu-hash-lookup alpha libfixture.so
```

The tool reads `PT_DYNAMIC`, requires `DT_GNU_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, and performs the GNU hash lookup algorithm instead of linearly scanning the dynamic symbol table. Bloom-filter membership is checked first, followed by the selected bucket and its bounded chain. A matching hash is confirmed against the symbol name from `DT_STRTAB` before the symbol metadata is reported.

All GNU-hash metadata is required to be file-backed by `PT_LOAD`. Bucket and Bloom counts, Bloom shift, prefix arithmetic, chain addressing, dynamic-symbol addressing, string bounds, and termination are checked before use. A missing symbol is a successful lookup result reported as `not-found`; malformed metadata is an error.

This is deliberately a lookup/validation slice, not a dynamic loader. It does not perform dependency search, symbol versioning, interposition, relocation application, or runtime load-bias resolution.
