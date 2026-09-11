# `mini-elf-dynrela-pc8`

`mini-elf-dynrela-pc8` validates one bounded ELF64 x86-64 dynamic-loader contract: `R_X86_64_PC8` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-pc8 <input>...
```

For every matching relocation in `DT_RELA`, the validator checks the `PT_DYNAMIC` / RELA metadata, bounds the dynamic symbol table through SysV `DT_HASH.nchain` when present or a checked GNU `DT_GNU_HASH` chain walk for GNU-hash-only images, requires a complete one-byte writable `PT_LOAD` relocation target, validates the referenced dynamic symbol and string-table entry, and treats undefined symbols as unresolved external bindings. SysV `DT_HASH` remains authoritative when both hash-table styles are present.

For same-image defined symbols, it evaluates the ABI expression `S + A - P` with a wide intermediate and rejects any value outside the exact signed 8-bit range. Because both `S` and `P` receive the same ET_DYN load bias, the bias cancels and no runtime load-bias option is required. Absolute symbols, TLS semantics, dependency lookup, symbol interposition/versioning, IFUNC execution, and writing relocated bytes are intentionally outside this slice.

The focused regression suite builds real GNU `as` / `ld -shared` fixtures, including a GNU-hash-only `--hash-style=gnu` image confirmed with GNU `readelf -dW` / `readelf -rW`. It also covers malformed GNU-hash Bloom metadata, invalid symbol indexes, non-writable targets, signed-8 overflow, a negative same-image result, and multi-input stdout atomicity.
