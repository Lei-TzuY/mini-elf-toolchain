# mini-elf-gnu-hash-resolve

`mini-elf-gnu-hash-resolve <symbol> <input>...` is a bounded dynamic-loader resolution slice for ELF64 x86-64 `ET_DYN` inputs that use `DT_GNU_HASH`.

The resolver checks inputs strictly in command-line order and returns the first symbol that survives the existing checked GNU hash lookup plus external-definition eligibility rules. A candidate must be defined, non-local, and neither `STV_INTERNAL` nor `STV_HIDDEN`. If an earlier image contains the name but the matching dynamic symbol is not externally eligible, resolution continues with the next image.

Each input is validated through the existing checked GNU hash path, including file-backed `PT_LOAD` mapping, GNU Bloom/bucket/chain bounds, checked arithmetic, and dynamic-symbol metadata checks. Malformed inputs fail rather than being silently skipped. Once an eligible definition is found, later images are not inspected because explicit input order defines this slice's search scope.

This is intentionally not a complete ELF dynamic-linker search algorithm. It does not yet traverse `DT_NEEDED`, implement global/local dependency scopes, symbol version matching, ELF interposition beyond the explicit input order, IFUNC execution, or relocation application. Those remain separate vertical slices.
