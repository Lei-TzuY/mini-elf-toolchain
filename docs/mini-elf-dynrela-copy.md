# `mini-elf-dynrela-copy`

`mini-elf-dynrela-copy` validates a bounded ELF64 x86-64 `ET_DYN` `R_X86_64_COPY` relocation slice without performing dependency lookup or copying bytes.

The validator requires one checked `PT_DYNAMIC` segment with canonical `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`. Dynamic-symbol bounds come from SysV `DT_HASH` when present, or from checked GNU `DT_GNU_HASH` metadata when `DT_HASH` is absent. The GNU-hash path validates nonzero bucket count, a nonzero power-of-two bloom count, bounded bloom/bucket prefix arithmetic, bucket lower bounds, file-backed chain traversal, and terminating chain entries before deriving the symbol-table upper bound.

Each selected COPY relocation must reference a valid defined non-TLS destination symbol with nonzero `st_size`. The relocation offset must equal that destination symbol's `st_value`, and the complete `st_size` byte target range must fit inside a writable `PT_LOAD` segment.

The supplied `--load-bias` is used only to validate the runtime target range with checked arithmetic. COPY entries require a zero RELA addend. Successful output explicitly reports that an external definition is still required as the source of the copied bytes.

Focused regressions cover GNU `readelf -rW` recognition, a real GNU `ld --hash-style=gnu` image with no SysV hash, malformed GNU-hash bloom metadata, invalid dynamic symbol indexes, zero-sized destinations, non-writable targets, runtime-address overflow, and malformed-later-input stdout atomicity.

Out of scope remain `DT_NEEDED` traversal, dependency symbol lookup, symbol versioning/interposition, source-size compatibility resolution, relocation writes, and memory copying.