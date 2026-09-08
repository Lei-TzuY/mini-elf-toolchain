# `mini-elf-versym`

`mini-elf-versym` inspects the GNU dynamic symbol-version index table referenced by `DT_VERSYM` in an ELF64 x86-64 dynamic object.

The tool validates the ELF and program-header ranges, requires at most one `PT_DYNAMIC`, and rejects duplicate `DT_VERSYM`, `DT_HASH`, or `DT_GNU_HASH` tags. It derives the checked dynamic-symbol count from the SysV `DT_HASH` `nchain` value when available and otherwise supports GNU-hash-only objects by validating the `DT_GNU_HASH` header, bloom and bucket prefix, bucket lower bounds, and terminating chain entries. At least one of the two dynamic hash tables is required because `DT_VERSYM` itself does not carry a symbol count.

The full two-byte-per-symbol `DT_VERSYM` table must be file-backed by a `PT_LOAD` segment before rendering any output. Each entry reports the raw 16-bit value, the version index after masking the GNU hidden bit, whether the symbol version is hidden, and the conventional `local` (0), `global` (1), or `versioned` (2+) class.

When `DT_VERDEF`/`DT_VERDEFNUM` are present, the tool also validates the local GNU version-definition chain and resolves matching versioned indices to names. This includes checked `DT_STRTAB`/`DT_STRSZ` mapping, `Elf64_Verdef` and `Elf64_Verdaux` record bounds, `vd_cnt`/`vd_aux` consistency, linked-list termination, duplicate version-index rejection, checked address arithmetic, and NUL-terminated version names. Version indices that are not defined locally remain numeric; in particular, `DT_VERNEED` name resolution is intentionally left to a later bounded slice. Multiple inputs are validated before stdout is emitted so a malformed later input cannot leave partial output.

```sh
cargo run --bin mini-elf-versym -- libexample.so
```

Focused integration coverage builds both SysV-hash and GNU-hash-only versioned shared objects with GNU `ld` and compares version-symbol behavior with GNU `readelf -V`. Dedicated `DT_VERDEF` coverage checks that a GNU version-script definition such as `VERS_1` is rendered beside the corresponding `DT_VERSYM` index, while malformed counts, version-definition ranges, and version-name strings are rejected before output.

This bounded slice does not join externally required version indices to `DT_VERNEED` names and does not implement runtime symbol-version resolution. Those remain separate loader-semantic capabilities.
