# `mini-elf-verneed`

`mini-elf-verneed` is a bounded ELF64 x86-64 loader-inspection tool for GNU symbol-version dependency metadata carried by `DT_VERNEED` and `DT_VERNEEDNUM`.

```sh
mini-elf-verneed <input>...
```

For each input, the tool validates the ELF header and program-header table, requires one checked `PT_DYNAMIC` segment with a `DT_NULL` terminator, and treats `DT_VERNEED` plus `DT_VERNEEDNUM` as one coherent tuple. The version-need table is walked only through file-backed `PT_LOAD` mappings. Each `Elf64_Verneed` record must use the current version value, advertise at least one auxiliary record, and provide a checked `vn_aux` link. The `vn_next` chain must match `DT_VERNEEDNUM` exactly.

Each `Elf64_Vernaux` chain is bounded by `vn_cnt`. Intermediate records must provide a non-zero `vna_next`; the final record must terminate the chain. Dependency filenames and requested version names are resolved through checked `DT_STRTAB` / `DT_STRSZ` offsets and must be NUL-terminated inside the declared dynamic string table. Virtual-address arithmetic, linked-list offsets, virtual-to-file translation, string offsets, and file ranges use checked operations.

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

Focused integration coverage builds a versioned GNU shared-library dependency with `as` and `ld`, verifies that GNU `readelf -V` reports the same dependency and version name, and exercises malformed count/chain state plus virtual-range overflow. This slice intentionally does not interpret `DT_VERDEF` or `DT_VERSYM`, does not match version indices back to dynamic symbols, and does not perform runtime symbol resolution.
