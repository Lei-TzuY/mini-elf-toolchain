# `mini-elf-dynrela-dtpoff64`

`mini-elf-dynrela-dtpoff64` validates one bounded x86-64 TLS dynamic-relocation slice for ELF64 `ET_DYN` images: `R_X86_64_DTPOFF64` (relocation type 17).

```sh
mini-elf-dynrela-dtpoff64 --load-bias 0x70000000 libexample.so
```

The validator requires checked `PT_DYNAMIC` metadata with `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, SysV `DT_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`. Each selected relocation must reference an in-range, defined `STT_TLS` dynamic symbol and an eight-byte target fully contained in a writable `PT_LOAD` memory range. The runtime target address `B + r_offset` is checked for overflow.

For this bounded same-image slice, a defined `STT_TLS` symbol's `st_value` is treated as its module TLS-block offset. The relocation result is checked as `st_value + A`; negative results or values outside unsigned 64-bit range are rejected rather than truncated. GNU `as`/`ld` TLSGD fixtures and `readelf -rW` are used by the focused integration tests to independently confirm that the fixture contains `R_X86_64_DTPOFF64`.

This is validation, not a complete TLS loader. Dependency lookup and interposition, cross-module TLS allocation, `R_X86_64_TPOFF64`, `R_X86_64_DTPOFF32`, TLSLD/GOTTPOFF/TLSDESC processing, IFUNC execution, and relocation memory writes remain outside this slice.
