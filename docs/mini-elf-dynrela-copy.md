# `mini-elf-dynrela-copy`

`mini-elf-dynrela-copy` validates a bounded ELF64 x86-64 `ET_DYN` `R_X86_64_COPY` relocation slice without performing dependency lookup or copying bytes.

The validator requires one checked `PT_DYNAMIC` segment with canonical `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, SysV `DT_HASH`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`. Each selected COPY relocation must reference a valid defined non-TLS destination symbol with nonzero `st_size`. The relocation offset must equal that destination symbol's `st_value`, and the complete `st_size` byte target range must fit inside a writable `PT_LOAD` segment.

The supplied `--load-bias` is used only to validate the runtime target range with checked arithmetic. COPY entries require a zero RELA addend. Successful output explicitly reports that an external definition is still required as the source of the copied bytes.

Focused regressions cover GNU `readelf -rW` recognition, invalid dynamic symbol indexes, zero-sized destinations, non-writable targets, runtime-address overflow, and malformed-later-input stdout atomicity.

Out of scope remain `DT_NEEDED` traversal, dependency symbol lookup, symbol versioning/interposition, source-size compatibility resolution, relocation writes, and memory copying.