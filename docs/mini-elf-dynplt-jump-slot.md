# mini-elf-dynplt-jump-slot

`mini-elf-dynplt-jump-slot` is a bounded ELF64 x86-64 dynamic-loader foundation tool for validating `R_X86_64_JUMP_SLOT` relocations from an ET_DYN image's runtime-facing `DT_JMPREL` table.

```text
mini-elf-dynplt-jump-slot --load-bias 0x70000000 libsample.so
mini-elf-dynplt-jump-slot --load-bias=1879048192 first.so second.so
```

The current slice requires `DT_JMPREL`, `DT_PLTRELSZ`, `DT_PLTREL=DT_RELA`, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`, plus runtime hash metadata that can safely bound the dynamic symbol table. SysV `DT_HASH.nchain` remains the direct bound when `DT_HASH` is present. GNU-hash-only images are accepted through checked `DT_GNU_HASH` Bloom/bucket/chain traversal when `DT_HASH` is absent; SysV hash therefore keeps precedence when both tags exist.

The GNU-hash fallback requires a non-zero bucket count, a non-zero power-of-two Bloom count, checked Bloom/bucket/prefix and chain-address arithmetic, bucket starts at or above `symoffset`, file-backed chain entries, and a terminating low-bit marker before the chain leaves mapped input. The highest terminated bucket chain determines the bounded dynamic-symbol count.

For each relocation the validator requires:

- a non-zero dynamic symbol index strictly below the bounded dynamic-symbol count;
- a canonical zero RELA addend for this bounded `S`-semantics slice;
- an 8-byte relocation slot wholly contained in a writable `PT_LOAD` memory range;
- a NUL-terminated dynamic symbol name inside `DT_STRTAB`;
- no `SHN_ABS`, TLS, or defined `STT_GNU_IFUNC` semantics;
- a defined same-image symbol value, when present, to lie in a `PT_LOAD` memory range;
- checked `load_bias + r_offset` and, for defined symbols, `load_bias + st_value` arithmetic.

Undefined symbols are deliberately reported as `binding=external`: this validates that the `JUMP_SLOT` is structurally safe for later lookup without pretending to implement dependency traversal, symbol interposition, versioning, or lazy binding. Defined same-image non-IFUNC symbols are reported with their checked runtime `B + S` value.

Focused integration coverage builds real GNU shared objects with `as` and `ld`, forces an external PLT call, and verifies GNU `readelf -rW` reports `R_X86_64_JUMP_SLOT`. Coverage includes both the existing SysV-hash path and a `--hash-style=gnu` GNU-hash-only image, plus malformed GNU Bloom metadata. Existing malformed regressions continue to cover out-of-range symbol indices, wrong relocation types inside `DT_JMPREL`, non-writable slots, non-zero addends, load-bias overflow, and multi-input stdout atomicity.

This tool does not execute PLT stubs, mutate GOT/PLT slots, resolve dependencies, perform symbol interposition/version matching, execute IFUNC resolvers, or implement lazy binding. Those remain separate executable slices.
