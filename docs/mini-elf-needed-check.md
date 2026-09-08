# mini-elf-needed-check

`mini-elf-needed-check` validates one bounded dynamic-loader invariant for ELF64 x86-64 objects: every dependency named by `DT_VERNEED` must also be declared by at least one `DT_NEEDED` entry.

The command validates the ELF64 program-header table, requires exactly one well-formed `PT_DYNAMIC`, checks `DT_NULL` termination, maps `DT_STRTAB` through a file-backed `PT_LOAD`, validates `DT_STRSZ`, decodes every `DT_NEEDED` name, and walks the counted `DT_VERNEED` chain using checked address arithmetic. Each `vn_file` dependency string must be NUL-terminated inside the checked dynamic string table and must match a decoded `DT_NEEDED` name.

```sh
mini-elf-needed-check consumer.so
```

For a valid versioned dependency the report names the requirement library, for example `dependency=libdep.so`. Multiple input files are validated before any output is emitted, so a malformed later file cannot leave partial stdout.

Focused regression coverage builds a real GNU `ld` versioned shared-library dependency and compares the result with `readelf -dW` and `readelf -VW`. Malformed coverage includes a `DT_VERNEED` dependency whose `DT_NEEDED` declaration was removed and a `DT_VERNEED` virtual-range overflow.

This slice checks declaration consistency only. It does not load shared objects, search library paths, resolve runtime symbols, or verify that a named dependency actually exports the requested version.