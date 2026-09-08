# `mini-elf-vercheck`

`mini-elf-vercheck` validates the GNU dynamic symbol-version namespace of an ELF64 x86-64 dynamic object without relying on section headers.

It starts from `DT_VERSYM`, derives the dynamic-symbol count from checked `DT_HASH` or `DT_GNU_HASH` metadata, parses local definitions from paired `DT_VERDEF` / `DT_VERDEFNUM`, parses imported requirements from paired `DT_VERNEED` / `DT_VERNEEDNUM`, and resolves every versioned `DT_VERSYM` index to exactly one namespace record.

For definitions, the first `Verdaux` name is reported. For requirements, each `Vernaux` index is reported with both its dependency (`vn_file`) and requested version name. Indices 0 and 1 retain their reserved local/global meaning and are not inserted into the version namespace.

The checker rejects duplicate dynamic tags, malformed or prematurely terminated Verdef/Verdaux and Verneed/Vernaux chains, duplicate indices across definition/requirement records, unresolved versioned `DT_VERSYM` indices, malformed GNU-hash metadata, non-file-backed virtual ranges, string offsets outside `DT_STRSZ`, missing NUL terminators, and arithmetic/range overflow.

Multiple inputs are completely validated before any stdout is emitted, so a malformed later input cannot leave a partial successful report.

Focused regression coverage constructs a shared library with a GNU version-script definition and a versioned external dependency using GNU `as` and `ld`, then checks the resolved names against `readelf -VW`. Additional cases cover unresolved indices, `DT_VERNEED` virtual-range overflow, and multi-input stdout atomicity.

Example:

```text
mini-elf-vercheck consumer.so
DT_VERSYM namespace is consistent across 6 dynamic symbols; 2 referenced version indices:
  index=2 source=definition name=VERS_LOCAL
  index=3 source=requirement dependency=libdep.so name=VERS_DEP
```
