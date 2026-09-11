# `mini-elf-dynrela-pc16`

`mini-elf-dynrela-pc16` validates one bounded ELF64 x86-64 dynamic-loader contract: `R_X86_64_PC16` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-pc16 <input>...
```

For every matching relocation in `DT_RELA`, the validator checks the `PT_DYNAMIC` / RELA metadata, bounds the dynamic symbol table through SysV `DT_HASH.nchain` when present or a checked GNU `DT_GNU_HASH` chain walk for GNU-hash-only images, requires a complete two-byte writable `PT_LOAD` relocation target, validates the referenced dynamic symbol and string-table entry, and treats undefined symbols as unresolved external bindings. When both hash tables are present, SysV `DT_HASH.nchain` remains authoritative for this bounded path.

The GNU-hash path validates a nonzero bucket count, a nonzero power-of-two Bloom count, checked Bloom/bucket prefix arithmetic, bucket lower bounds, file-backed chain entries and terminating chain bits before the derived dynamic-symbol bound is used.

For same-image defined symbols, it evaluates the ABI expression `S + A - P` with a wide intermediate and rejects any value outside the exact signed 16-bit range. Because both `S` and `P` receive the same ET_DYN load bias, the bias cancels and no runtime load-bias option is required. Absolute symbols, TLS semantics, dependency lookup, symbol interposition/versioning, IFUNC execution, and writing relocated bytes are intentionally outside this slice.

The focused regression suite builds real GNU `as` / `ld -shared` fixtures with both `--hash-style=sysv` and `--hash-style=gnu`, confirms `R_X86_64_PC16` independently with GNU `readelf -rW`, and covers malformed GNU-hash metadata, invalid symbol indexes, non-writable targets, signed-16 overflow, a negative same-image result, and multi-input stdout atomicity.
