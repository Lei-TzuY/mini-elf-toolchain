# `mini-elf-versym-needed`

`mini-elf-versym-needed` extends the checked ELF64 x86-64 GNU version-symbol inspection path by joining external `DT_VERSYM` indices to the version requirements declared by `DT_VERNEED` / `DT_VERNEEDNUM`.

```sh
mini-elf-versym-needed libconsumer.so
mini-elf-versym-needed first.so second.so
```

The tool reuses the existing checked program-header, `PT_DYNAMIC`, dynamic-hash, `DT_VERSYM`, and local `DT_VERDEF` parsing. For external version requirements it requires `DT_VERNEED` and `DT_VERNEEDNUM` as a coherent pair, maps the version-need and Vernaux records only through file-backed `PT_LOAD` ranges, validates the linked-list counts and termination, and resolves both the dependency filename and required version name through the checked `DT_STRTAB` / `DT_STRSZ` table. Every `DT_VERNEED` dependency must also be declared by `DT_NEEDED`.

Each Vernaux `vna_other` value is masked with the GNU hidden-bit mask and becomes the external version index used by `DT_VERSYM`. Reserved indices 0 and 1 are rejected for external requirements, duplicate requirement indices are rejected, and an index may not simultaneously name a local `DT_VERDEF` definition and an external `DT_VERNEED` requirement. The rendered version-symbol table therefore reports local definitions as `definition=<name>` and external requirements as `requirement=<dependency>:<version>` while preserving the raw index, hidden bit, and local/global/versioned class.

Focused integration coverage builds a versioned provider plus dependent shared object with GNU `as` and `ld`, verifies the dependency and version requirement with GNU `readelf -V`, and requires the checked join to report `libprovider.so:VERS_1`. Malformed coverage rejects reserved Vernaux indices, and an overflowing `DT_VERNEED` virtual address is rejected with multi-input stdout atomicity.

This bounded slice does not yet implement runtime version-aware symbol selection across the `DT_NEEDED` scope, default-versus-hidden version preference, loader namespace rules, or relocation application. It establishes the checked version-index-to-requirement-name relation needed by those later loader-semantic slices.
