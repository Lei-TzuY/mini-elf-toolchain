# mini-elf-dyninit

`mini-elf-dyninit` is a bounded ELF64 x86-64 loader-foundation inspector for pre-constructor, constructor, and destructor pointer arrays described by `PT_DYNAMIC`.

```sh
mini-elf-dyninit sample
mini-elf-dyninit first.so second.so
```

The tool validates program-header bounds, `PT_DYNAMIC` file ranges, 16-byte dynamic-entry sizing, and a terminating `DT_NULL`. It recognizes the paired `DT_PREINIT_ARRAY` / `DT_PREINIT_ARRAYSZ`, `DT_INIT_ARRAY` / `DT_INIT_ARRAYSZ`, and `DT_FINI_ARRAY` / `DT_FINI_ARRAYSZ` tags, rejects duplicates or missing partners, requires each byte size to be a multiple of the ELF64 address width, and maps each non-empty array through a file-backed `PT_LOAD` virtual range using checked arithmetic before reading any entries.

Each array is reported with its link-time virtual address, entry count, and raw pointer values. `DT_PREINIT_ARRAY` is reported before the init and fini arrays, matching its lifecycle role in dynamically linked executables. Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave a partial successful report.

This slice intentionally inspects only the encoded lifecycle arrays. It does not apply dynamic relocations, add a runtime load bias, invoke preinit functions, constructors or destructors, resolve dependencies, build a process image, or mutate the ELF file.
