# `mini-elf-dynrela-tpoff32`

`mini-elf-dynrela-tpoff32` is a bounded ELF64 x86-64 dynamic-loader foundation tool for validating `R_X86_64_TPOFF32` relocations in an ET_DYN image's runtime-facing `DT_RELA` table.

The caller supplies both a load bias and a signed static-TLS block offset. For each selected relocation the validator requires a nonzero in-range dynamic symbol index, a defined `STT_TLS` symbol, and a complete 4-byte relocation target contained in writable `PT_LOAD` memory. It computes the ABI-style thread-pointer offset as `tls_block_offset + st_value + A` using wide intermediate arithmetic and rejects values that do not fit signed 32-bit. `B + r_offset` is also checked for unsigned address overflow.

Dynamic metadata is fail-closed: `PT_DYNAMIC` must terminate correctly; `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, SysV `DT_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ` are range-checked before use. Undefined TLS symbols are rejected because dependency lookup/interposition is outside this bounded slice.

Focused tests derive a GNU-linked TLS ET_DYN fixture, rewrite its relocation kind to the ABI-defined `R_X86_64_TPOFF32`, and require GNU `readelf -rW` to independently recognize that relocation. Regressions cover invalid symbol indices, non-writable targets, signed-32 overflow, runtime-target overflow, and multi-input stdout atomicity.

This command validates relocation semantics only. Static TLS allocation policy, dependency lookup, symbol interposition/versioning, relocation memory writes, and execution are intentionally outside scope.
