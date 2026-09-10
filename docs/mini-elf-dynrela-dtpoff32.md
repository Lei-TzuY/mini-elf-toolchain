# `mini-elf-dynrela-dtpoff32`

`mini-elf-dynrela-dtpoff32` validates a bounded ELF64 x86-64 ET_DYN `R_X86_64_DTPOFF32` relocation slice without performing dependency lookup or mutating the image.

The validator requires one checked `PT_DYNAMIC` segment with `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, SysV `DT_HASH`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`. Each selected relocation must reference a valid defined `STT_TLS` dynamic symbol and a complete writable 4-byte `PT_LOAD` target.

For this slice the relocation result is the TLS module-relative offset `st_value + A`. Arithmetic is evaluated in a wide intermediate and must fit signed 32-bit exactly. The supplied `--load-bias` is used only to validate the runtime relocation target `B + r_offset`, with overflow rejected.

Focused regression coverage includes invalid symbol indexes, non-writable targets, signed-32 result overflow, runtime-target overflow, and multi-input stdout atomicity. GNU `readelf -rW` independently recognizes the fixture relocation as `R_X86_64_DTPOFF32`.

Out of scope remain dependency symbol lookup, interposition/version matching, TLS block allocation, relocation writes, and TLSDESC execution.
