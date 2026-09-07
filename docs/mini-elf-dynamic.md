# mini-elf-dynamic

`mini-elf-dynamic` is a checked ELF64 x86-64 dynamic-section inspection companion for bounded ET_DYN and dynamic-link foundations.

```sh
mini-elf-dynamic libexample.so
mini-elf-dynamic first.so second.so
```

The tool parses `SHT_DYNAMIC` entries after validating section-header bounds, the 16-byte ELF64 dynamic entry size, table-size divisibility, checked file ranges, and the linked `SHT_STRTAB`. String-valued tags such as `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and `DT_RUNPATH` are resolved only after checking string-table offsets and NUL termination.

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

GNU `readelf -dW` is used as a differential oracle on a real GNU-assembled and GNU-linked shared object. The focused differential checks core dynamic metadata including `SONAME`, `STRTAB`, and `SYMTAB`; malformed entry sizing and dynamic-section range overflow have dedicated regressions.

This slice is inspection-only. It does not yet emit ET_DYN files, resolve shared-library dependencies, construct GOT/PLT dynamic relocations, interpret symbol versions, or implement runtime-loader semantics.
