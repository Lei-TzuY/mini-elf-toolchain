# `mini-elf-dynhash`

`mini-elf-dynhash` is a bounded ELF64 x86-64 runtime-style inspection tool for the System V dynamic hash table referenced by `DT_HASH`.

```sh
mini-elf-dynhash libsample.so
mini-elf-dynhash first.so second.so
```

The tool does not depend on section headers to locate the table. It validates the ELF program-header table, requires at most one `PT_DYNAMIC`, parses dynamic entries through a checked `DT_NULL` terminator, resolves the unique `DT_HASH` virtual address through a file-backed `PT_LOAD`, and validates the complete SysV hash-table range before rendering it.

For a SysV hash table it reads `nbucket` and `nchain`, reports `nchain` as the dynamic-symbol count defined by the ABI format, and prints the bucket and chain arrays. Every non-zero bucket/chain symbol index must be smaller than `nchain`. Address, table-size, file-offset, and range arithmetic is checked before slicing.

Multiple inputs are validated before any output is emitted, so a malformed later input cannot leave partial stdout from an earlier file.

The focused differential test builds a real shared object with GNU `as` and `ld --hash-style=sysv`, compares the `nchain`-derived dynamic-symbol count against GNU `readelf --dyn-syms -W`, and covers malformed bucket indices plus an overflowing `DT_HASH` virtual range.

GNU hash (`DT_GNU_HASH`) is kept as an independent runtime-style inspection path in `mini-elf-gnuhash` rather than inferred from section metadata.
