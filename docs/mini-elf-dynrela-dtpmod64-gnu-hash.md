# GNU-hash-only `R_X86_64_DTPMOD64` validation

`mini-elf-dynrela-dtpmod64` accepts bounded ELF64 x86-64 `ET_DYN` images whose dynamic symbol table is bounded by either SysV `DT_HASH` or GNU `DT_GNU_HASH` metadata.

When both hashes are present, SysV `DT_HASH.nchain` remains authoritative. When SysV hash metadata is absent, the validator walks checked GNU-hash Bloom, bucket, and chain metadata to derive the dynamic-symbol upper bound before validating `R_X86_64_DTPMOD64` relocations.

The GNU-hash path rejects zero buckets, zero or non-power-of-two Bloom counts, arithmetic overflow, buckets below `symoffset`, non-file-backed chain entries, and symbol-index overflow. Existing relocation invariants remain unchanged: the target must be writable, the symbol must be a defined `STT_TLS` symbol in the current image, the RELA addend must be zero, the module id must be nonzero, and the runtime target computation must not overflow.

Integration coverage builds a real GNU-hash-only shared object with GNU `as` and `ld --hash-style=gnu`, verifies its dynamic tags and `R_X86_64_DTPMOD64` relocation with GNU `readelf`, exercises the validator, and includes malformed GNU-hash Bloom metadata rejection.
