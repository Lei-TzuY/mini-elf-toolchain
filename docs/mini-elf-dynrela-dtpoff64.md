# `mini-elf-dynrela-dtpoff64`

`mini-elf-dynrela-dtpoff64` validates one bounded x86-64 TLS dynamic-relocation slice for ELF64 `ET_DYN` images: `R_X86_64_DTPOFF64` (relocation type 17).

```sh
mini-elf-dynrela-dtpoff64 --load-bias 0x70000000 libexample.so
```

The validator requires checked `PT_DYNAMIC` metadata with `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, plus either SysV `DT_HASH` or `DT_GNU_HASH` to bound the dynamic-symbol table. When both hash tables are present, SysV `DT_HASH.nchain` remains authoritative. For GNU-hash-only images, the validator checks the GNU hash header, requires a nonzero bucket count and a nonzero power-of-two Bloom count, performs checked Bloom/bucket/chain arithmetic, rejects buckets below `symoffset`, and requires every traversed chain entry to remain file-backed until its terminator bit is reached.

Each selected relocation must reference an in-range, defined `STT_TLS` dynamic symbol and an eight-byte target fully contained in a writable `PT_LOAD` memory range. The runtime target address `B + r_offset` is checked for overflow. For this bounded same-image slice, a defined `STT_TLS` symbol's `st_value` is treated as its module TLS-block offset. The relocation result is checked as `st_value + A`; negative results or values outside unsigned 64-bit range are rejected rather than truncated.

Focused integration tests use GNU `as`/`ld`, including a `--hash-style=gnu` image with no SysV hash table, while GNU `readelf -dW` and `readelf -rW` independently confirm the hash style and `R_X86_64_DTPOFF64` relocation. Malformed GNU-hash metadata is rejected before symbol-table traversal.

This is validation, not a complete TLS loader. Dependency lookup and interposition, cross-module TLS allocation, `R_X86_64_TPOFF64`, `R_X86_64_DTPOFF32`, TLSLD/GOTTPOFF/TLSDESC processing, IFUNC execution, and relocation memory writes remain outside this slice.
