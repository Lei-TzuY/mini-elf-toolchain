# `mini-elf-verdef`

`mini-elf-verdef` is a bounded ELF64 x86-64 loader-inspection tool for GNU symbol-version definition metadata carried by `DT_VERDEF` and `DT_VERDEFNUM`.

```sh
mini-elf-verdef <input>...
```

For each input, the tool validates the ELF header and program-header table, requires one checked `PT_DYNAMIC` segment with a `DT_NULL` terminator, and treats `DT_VERDEF` plus `DT_VERDEFNUM` as one coherent tuple. The version-definition table is walked only through file-backed `PT_LOAD` mappings. Each `Elf64_Verdef` record must use the current version value, advertise at least one auxiliary name record, and provide a checked `vd_aux` link. The `vd_next` chain must match `DT_VERDEFNUM` exactly.

Each `Elf64_Verdaux` chain is bounded by `vd_cnt`. Intermediate records must provide a non-zero `vda_next`; the final record must terminate the chain. The first auxiliary name is rendered as the definition name and any additional names as parent-version references. Names are resolved through checked `DT_STRTAB` / `DT_STRSZ` offsets and must be NUL-terminated inside the declared dynamic string table. Virtual-address arithmetic, linked-list offsets, virtual-to-file translation, string offsets, and file ranges use checked operations.

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

Focused integration coverage builds a GNU version-script shared object with `as` and `ld`, verifies that GNU `readelf -V` reports the same version definition, and exercises malformed count/chain state plus virtual-range overflow. This slice intentionally does not interpret `DT_VERSYM`, does not match version indices back to dynamic symbols, and does not perform runtime symbol resolution.
