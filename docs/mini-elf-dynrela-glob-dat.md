# mini-elf-dynrela-glob-dat

`mini-elf-dynrela-glob-dat` is a bounded ELF64 x86-64 dynamic-loader foundation tool for validating `R_X86_64_GLOB_DAT` relocations from an ET_DYN image's runtime-facing `DT_RELA` table.

```text
mini-elf-dynrela-glob-dat --load-bias 0x70000000 libsample.so
mini-elf-dynrela-glob-dat --load-bias=1879048192 first.so second.so
```

The current slice deliberately resolves only symbols defined by the same image. It requires `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, `DT_HASH`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, uses the SysV hash `nchain` value to bound the dynamic symbol table, and accepts the ELF64 entry sizes `24` for both RELA and symbols.

For each `R_X86_64_GLOB_DAT` relocation the validator requires:

- a non-zero dynamic symbol index strictly below the `DT_HASH` symbol count;
- a canonical zero RELA addend for this bounded `S`-semantics slice;
- an 8-byte relocation target wholly contained in a writable `PT_LOAD` memory range;
- a defined, non-absolute, non-TLS symbol from the same image;
- the symbol value to lie in a `PT_LOAD` memory range;
- the symbol name to be NUL-terminated inside `DT_STRTAB`;
- checked `load_bias + r_offset` and `load_bias + st_value` arithmetic.

The tool reports both the runtime relocation slot and the runtime symbol value as `B + object-relative-address`. Multiple inputs are validated completely before stdout is emitted, so a malformed later file cannot leave partial output.

Focused integration coverage builds a real GNU shared object with `as` and `ld --hash-style=sysv`, forces a GOT reference that GNU `ld` represents as `R_X86_64_GLOB_DAT`, and checks the relocation with `readelf -rW` plus the symbol value with `readelf -sW`. Malformed regressions cover out-of-range symbol indices, undefined symbols, non-writable relocation targets, non-zero RELA addends, and multi-input stdout atomicity.

This is not a complete dynamic symbol resolver. External dependency lookup, symbol interposition and versioning, GNU-hash-only symbol-table bounding, `SHN_ABS`, TLS, IFUNC/`STT_GNU_IFUNC`, copy relocations, PLT/JUMP_SLOT processing, and mutation of a process image remain separate executable slices.