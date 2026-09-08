# `mini-elf-versym`

`mini-elf-versym` inspects the GNU dynamic symbol-version index table referenced by `DT_VERSYM` in an ELF64 x86-64 dynamic object.

The tool validates the ELF and program-header ranges, requires at most one `PT_DYNAMIC`, rejects duplicate `DT_VERSYM`/`DT_HASH` tags, and uses the SysV `DT_HASH` `nchain` value as the checked dynamic-symbol count. It then requires the full two-byte-per-symbol `DT_VERSYM` table to be file-backed by a `PT_LOAD` segment before rendering any output.

Each entry reports the raw 16-bit value, the version index after masking the GNU hidden bit, whether the symbol version is hidden, and the conventional `local` (0), `global` (1), or `versioned` (2+) class. Multiple inputs are validated before stdout is emitted so a malformed later input cannot leave partial output.

```sh
cargo run --bin mini-elf-versym -- libexample.so
```

This bounded slice intentionally does not join version indices to `DT_VERDEF`/`DT_VERNEED` names and does not implement runtime symbol-version resolution. Those are separate loader-semantic capabilities.
