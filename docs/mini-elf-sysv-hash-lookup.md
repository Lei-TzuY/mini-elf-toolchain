# mini-elf-sysv-hash-lookup

`mini-elf-sysv-hash-lookup <symbol> <input>...` performs a bounded ELF64 x86-64 `ET_DYN` symbol lookup through the legacy System V `DT_HASH` table.

The tool validates a single `PT_DYNAMIC`, requires `DT_HASH`, `DT_SYMTAB`, `DT_STRTAB`, `DT_STRSZ`, and the ELF64 `DT_SYMENT` size, and only reads metadata that is wholly file-backed by a `PT_LOAD`. The SysV hash header must contain non-zero bucket and chain counts; bucket and chain arrays are range-checked with checked arithmetic, every non-zero index must remain below `nchain`, and traversal is bounded by `nchain` so malformed cycles cannot loop indefinitely.

Lookup uses the ELF System V hash algorithm, follows only the selected bucket/chain, validates each candidate dynamic-symbol entry and name in `DT_STRTAB`, and reports the matching symbol index, value, size, binding, type, visibility, and section index. A missing symbol is a successful `not-found` result rather than an error.

The focused integration tests build a real GNU-binutils `--hash-style=sysv` shared object, cross-check the exported symbol with `readelf --dyn-syms`, and cover malformed bucket indices plus a `DT_HASH` virtual-range overflow.

This is a symbol-table lookup/validation foundation. Dependency search, symbol versioning, interposition scope, relocation application, and loader-wide definition selection remain outside this bounded slice.
