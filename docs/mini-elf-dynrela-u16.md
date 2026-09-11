# `mini-elf-dynrela-u16`

`mini-elf-dynrela-u16` validates one bounded ELF64 x86-64 dynamic-loader contract: same-image `R_X86_64_16` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-u16 --load-bias <address> <input>...
```

The validator requires checked `PT_DYNAMIC` metadata for `DT_RELA`, `DT_SYMTAB`, and `DT_STRTAB`, plus either SysV `DT_HASH` or GNU `DT_GNU_HASH` to bound the dynamic symbol table. When `DT_HASH` is present its `nchain` count remains authoritative. GNU-hash-only images are accepted by deriving the symbol upper bound from checked bucket, Bloom-filter, and chain metadata; bucket counts, non-zero power-of-two Bloom counts, prefix arithmetic, bucket lower bounds, file-backed chain traversal, terminators, and symbol/address overflow are all validated.

For every relocation of type 12 (`R_X86_64_16`), the tool requires a non-zero in-range dynamic symbol index, a two-byte relocation target fully contained in a writable `PT_LOAD`, and a same-image defined symbol whose value is mapped by a load segment. Absolute and TLS symbols are rejected because their loader semantics are outside this slice.

The relocation is evaluated as the ABI absolute formula `S + A`, using the explicit load bias to form the runtime symbol address. All load-bias and signed-addend arithmetic is checked. The final value must fit exactly in an unsigned 16-bit field; truncation is rejected.

The tool validates every input before producing stdout, so a malformed later input cannot leave partial output. Focused tests include GNU `as` and `ld --hash-style=gnu` to create a GNU-hash-only dynamic image and GNU `readelf -rW` to independently recognize the patched `R_X86_64_16` relocation. Regressions cover malformed GNU-hash Bloom metadata in addition to invalid dynamic symbol indices, non-writable targets, negative addends, unsigned-16 overflow, and multi-input stdout atomicity.

This checkpoint deliberately does not implement dependency lookup, symbol interposition/versioning, TLS, IFUNC execution, or actual relocation writes into a process image.
