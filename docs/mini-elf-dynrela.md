# `mini-elf-dynrela`

`mini-elf-dynrela` inspects the ELF64 x86-64 dynamic RELA relocation table through the runtime-facing program-header path rather than section headers.

```text
mini-elf-dynrela <input>...
```

For each input, the tool parses the checked ELF header and program-header table, locates at most one `PT_DYNAMIC` segment, requires a `DT_NULL` terminator, and treats `DT_RELA`, `DT_RELASZ`, and `DT_RELAENT` as one coherent tuple. If no tuple is present, it reports that no dynamic RELA table exists. A partial tuple, duplicate tag, non-24-byte `DT_RELAENT`, or size that is not an integral number of ELF64 `Elf64_Rela` records is rejected.

The relocation table virtual range must be entirely backed by the file portion of one `PT_LOAD` segment. Address addition, virtual-to-file translation, table sizing, and per-entry offsets use checked arithmetic. Each record prints the relocation offset, raw `r_info`, x86-64 relocation type, symbol-table index, and signed addend.

Multiple inputs are fully read and validated before stdout is emitted, so a malformed later input cannot leave partial output from earlier files.

This is intentionally a bounded dynamic-link foundation. It does not apply relocations, resolve dynamic-symbol names, inspect `DT_JMPREL`, or implement `DT_REL`/`DT_RELR` yet.
