# mini-elf-needed-check

`mini-elf-needed-check` validates one bounded dynamic-loader invariant for ELF64 x86-64 objects: every dependency named by `DT_VERNEED` must also be declared by at least one `DT_NEEDED` entry.

The command validates the ELF64 program-header table, requires exactly one well-formed `PT_DYNAMIC`, checks `DT_NULL` termination, maps `DT_STRTAB` through a file-backed `PT_LOAD`, validates `DT_STRSZ`, decodes every `DT_NEEDED` name, and walks the counted `DT_VERNEED` chain using checked address arithmetic. Each `vn_file` dependency string must be NUL-terminated inside the checked dynamic string table and must match a decoded `DT_NEEDED` name.

Each referenced `Elf64_Vernaux` chain is also traversed according to `vn_cnt`. Every auxiliary record must be fully file-backed, every version-name string must be in bounds and NUL-terminated inside `DT_STRSZ`, intermediate records must provide a non-zero `vna_next`, the counted final record must terminate with `vna_next == 0`, and all auxiliary-address arithmetic is checked before mapping.

```sh
mini-elf-needed-check consumer.so
```

For a valid versioned dependency the report names the requirement library, for example `dependency=libdep.so`. Multiple input files are validated before any output is emitted, so a malformed later file cannot leave partial stdout.

Focused regression coverage builds a real GNU `ld` versioned shared-library dependency and compares the result with `readelf -dW` and `readelf -VW`. Malformed coverage includes a `DT_VERNEED` dependency whose `DT_NEEDED` declaration was removed, a `DT_VERNEED` virtual-range overflow, an auxiliary chain that terminates before `vn_cnt`, and a counted final Vernaux record with a non-zero `vna_next`.

This slice checks declaration consistency and the structural integrity of the associated version-requirement metadata only. It does not load shared objects, search library paths, resolve runtime symbols, or verify that a named dependency actually exports the requested version.