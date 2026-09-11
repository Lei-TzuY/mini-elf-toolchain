# `mini-elf-dynrela-dtpoff32`

`mini-elf-dynrela-dtpoff32` validates a bounded ELF64 x86-64 ET_DYN `R_X86_64_DTPOFF32` relocation slice without performing dependency lookup or mutating the image.

The validator requires one checked `PT_DYNAMIC` segment with `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`, plus either SysV `DT_HASH` or `DT_GNU_HASH` to bound the dynamic-symbol table. If both hash tables are present, SysV `DT_HASH.nchain` remains authoritative. GNU-hash-only images are bounded by checked GNU hash metadata: the bucket count must be nonzero, the Bloom count must be a nonzero power of two, Bloom/bucket/chain arithmetic is overflow checked, buckets below `symoffset` are rejected, and every traversed chain entry must remain file-backed until its terminator bit is reached.

Each selected relocation must reference a valid defined `STT_TLS` dynamic symbol and a complete writable 4-byte `PT_LOAD` target. For this slice the relocation result is the TLS module-relative offset `st_value + A`. Arithmetic is evaluated in a wide intermediate and must fit signed 32-bit exactly. The supplied `--load-bias` is used only to validate the runtime relocation target `B + r_offset`, with overflow rejected.

Focused regression coverage includes invalid symbol indexes, non-writable targets, signed-32 result overflow, runtime-target overflow, multi-input stdout atomicity, GNU-hash-only acceptance, and malformed GNU-hash Bloom metadata. GNU `readelf -dW/-rW` independently confirms that the differential fixture has `DT_GNU_HASH` without SysV `DT_HASH` and recognizes the patched relocation as `R_X86_64_DTPOFF32`.

Out of scope remain dependency symbol lookup, interposition/version matching, TLS block allocation, relocation writes, and TLSDESC execution.
