# `mini-elf-dynrela-i32`

`mini-elf-dynrela-i32` validates one bounded ELF64 x86-64 dynamic-loader contract: same-image `R_X86_64_32S` relocations in an `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-i32 --load-bias <address> <input>...
```

The validator checks `PT_DYNAMIC`, the ELF64 `DT_RELA` tuple, `DT_SYMTAB`, `DT_SYMENT`, `DT_STRTAB`, and `DT_STRSZ`. Dynamic-symbol bounds come from SysV `DT_HASH.nchain` when present; GNU-hash-only images are also accepted by deriving the upper bound from checked `DT_GNU_HASH` metadata. When both hash tables are present, the SysV `DT_HASH` count remains authoritative for this bounded path. The GNU-hash path validates a nonzero bucket count, a nonzero power-of-two Bloom count, checked Bloom/bucket prefix arithmetic, bucket lower bounds, file-backed chain traversal, terminating chain entries, and symbol-index/address overflow. At least one of `DT_HASH` or `DT_GNU_HASH` is required.

Each `R_X86_64_32S` entry must reference a nonzero in-range same-image defined symbol, target a complete four-byte range in writable `PT_LOAD` memory, and avoid absolute and TLS symbol semantics. Dynamic symbol names must terminate within the declared string table.

With explicit load bias `B`, the slice checks `B + r_offset` and `B + S`, then evaluates `S + A` with checked signed-addend arithmetic. Unlike `R_X86_64_32`, the final value must fit a signed 32-bit field exactly. Multi-input operation validates every input before emitting stdout.

Focused integration coverage includes GNU `as`/`ld` fixtures for both SysV-hash and GNU-hash-only ET_DYN images. The fixture preserves GNU-generated dynamic metadata/layout, changes only a selected same-image data relocation type to `R_X86_64_32S`, and verifies GNU `readelf -rW` recognizes the patched relocation. Regressions cover invalid dynamic-symbol indices, non-writable destinations, signed-32 overflow, negative addends, malformed GNU-hash Bloom metadata, and stdout atomicity.

This remains deliberately narrower than a complete dynamic loader: external dependency lookup, symbol interposition/versioning, absolute-symbol rules, TLS, IFUNC execution, relocation ordering, and memory writes are outside this slice.
