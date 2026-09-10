# `mini-elf-dynrela-pc64`

`mini-elf-dynrela-pc64` validates one bounded ELF64 x86-64 dynamic-loader contract: `R_X86_64_PC64` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-pc64 <input>...
```

For every matching relocation in `DT_RELA`, the validator checks the `PT_DYNAMIC` / RELA metadata, bounds the dynamic symbol table through SysV `DT_HASH.nchain`, requires a complete eight-byte writable `PT_LOAD` relocation target, validates the referenced dynamic symbol and string-table entry, and treats undefined symbols as unresolved external bindings.

For same-image defined symbols, it evaluates the ABI expression `S + A - P` with a wide intermediate and rejects any value outside the exact signed 64-bit range. Because both `S` and `P` receive the same ET_DYN load bias, the bias cancels and no runtime load-bias option is required. Absolute symbols, TLS semantics, dependency lookup, symbol interposition/versioning, IFUNC execution, and writing relocated bytes are intentionally outside this slice.

The focused regression suite builds a real GNU `as` / `ld -shared --hash-style=sysv` fixture containing `R_X86_64_PC64`, confirms it with GNU `readelf -rW`, and covers invalid symbol indexes, non-writable targets, signed-64 overflow, a negative same-image result, and multi-input stdout atomicity.
