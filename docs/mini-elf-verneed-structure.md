# `mini-elf-verneed-structure`

`mini-elf-verneed-structure` is a bounded ELF64 x86-64 validator for the linked-record geometry of GNU `DT_VERNEED` metadata.

```sh
mini-elf-verneed-structure <input>...
```

The checker requires a coherent `DT_VERNEED` / `DT_VERNEEDNUM` tuple, walks the table only through file-backed `PT_LOAD` mappings, validates the current `Elf64_Verneed` version, and requires every dependency record to advertise at least one `Elf64_Vernaux` record.

This slice adds an explicit forward/non-overlap invariant for relative links. `vn_aux` must advance by at least one complete `Elf64_Verneed` record, every non-final `vna_next` must advance by at least one complete `Elf64_Vernaux` record, and every non-final `vn_next` must advance by at least one complete `Elf64_Verneed` record. Final `vna_next` and `vn_next` links must be zero. All virtual-address and file-range arithmetic is checked.

Multiple inputs are validated before stdout is emitted, so a malformed later input cannot leave a partial report. Focused integration coverage accepts a GNU `as`/`ld` versioned dependency verified with `readelf -V`, then mutates `vn_aux` to overlap the current Verneed record and requires fail-closed, atomic behavior.

This tool intentionally checks record topology only. Version-name/string validation, version-index joins, `vna_hash`/`vna_flags` semantics, and symbol binding remain the responsibility of the repository's other checked dynamic-version tools.
