# mini-elf-gnu-hash-external-lookup

`mini-elf-gnu-hash-external-lookup <symbol> <input>...` adds one bounded loader-resolution step on top of the checked GNU `DT_GNU_HASH` name lookup path for ELF64 x86-64 `ET_DYN` images.

The command first performs the existing checked GNU hash Bloom/bucket/chain lookup, then validates the matched dynamic-symbol entry through `DT_SYMTAB` / `DT_SYMENT` mapped from a file-backed `PT_LOAD`. A hash/name match is externally eligible only when it is defined (`st_shndx != SHN_UNDEF`), non-local (`st_bind != STB_LOCAL`), and not `STV_INTERNAL` or `STV_HIDDEN`. `STV_DEFAULT` and `STV_PROTECTED` definitions remain eligible. Ineligible matches are reported as `not-found`, which models the bounded definition filter needed before cross-object loader resolution.

All inputs are validated before stdout is emitted. Focused integration coverage builds a real GNU-binutils `--hash-style=gnu` shared object, cross-checks the exported default-visible symbol with `readelf --dyn-syms`, mutates the matched dynamic symbol to hidden/local/undefined states while preserving hash membership, and verifies malformed later-input atomicity.

This slice deliberately does not implement `DT_NEEDED` traversal, lookup scope ordering, symbol-version matching, interposition, IFUNC invocation, or relocation application. Those remain separate loader milestones.
