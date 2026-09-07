# `mini-elf-dynrela`

`mini-elf-dynrela` inspects the ELF64 x86-64 dynamic RELA relocation table through the runtime-facing program-header path rather than section headers.

```text
mini-elf-dynrela <input>...
```

For each input, the tool parses the checked ELF header and program-header table, locates at most one `PT_DYNAMIC` segment, requires a `DT_NULL` terminator, and treats `DT_RELA`, `DT_RELASZ`, and `DT_RELAENT` as one coherent tuple. If no tuple is present, it reports that no dynamic RELA table exists. A partial tuple, duplicate tag, non-24-byte `DT_RELAENT`, or size that is not an integral number of ELF64 `Elf64_Rela` records is rejected.

The relocation table virtual range must be entirely backed by the file portion of one `PT_LOAD` segment. Address addition, virtual-to-file translation, table sizing, and per-entry offsets use checked arithmetic. Dynamic symbol references are resolved through `DT_SYMTAB` / `DT_SYMENT` and `DT_STRTAB` / `DT_STRSZ`. If SysV `DT_HASH` is present, its `nchain` field provides the direct checked dynamic-symbol bound. Otherwise, a GNU-hash-only object may derive the bound from `DT_GNU_HASH` after validating the header, nonzero power-of-two Bloom count, bucket prefix, bucket-to-symbol constraints, file-backed chain traversal, chain termination bits, and symbol-index arithmetic. At least one of `DT_HASH` or `DT_GNU_HASH` is required when nonzero relocation symbols need resolution.

Nonzero relocation symbol indexes must remain within the derived dynamic-symbol bound, and symbol names must remain within the mapped dynamic string table and terminate before `DT_STRSZ`. Each record prints the relocation offset, raw `r_info`, x86-64 relocation type, symbol-table index, signed addend, and resolved symbol name; symbol index zero is rendered without a name lookup.

Multiple inputs are fully read and validated before stdout is emitted, so a malformed later input cannot leave partial output from earlier files.

This is intentionally a bounded dynamic-link foundation. It does not apply relocations, inspect `DT_JMPREL`, implement `DT_REL`/`DT_RELR`, or act as a runtime loader.
