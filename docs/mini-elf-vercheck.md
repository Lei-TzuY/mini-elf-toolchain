# `mini-elf-vercheck`

`mini-elf-vercheck` validates the GNU dynamic symbol-version namespace of an ELF64 x86-64 dynamic object without relying on section headers.

It starts from `DT_VERSYM`, derives the dynamic-symbol count from checked `DT_HASH` or `DT_GNU_HASH` metadata, parses local definitions from paired `DT_VERDEF` / `DT_VERDEFNUM`, parses imported requirements from paired `DT_VERNEED` / `DT_VERNEEDNUM`, and resolves every versioned `DT_VERSYM` index to exactly one namespace record.

The checker also validates `DT_SYMTAB` / `DT_SYMENT` against that hash-derived symbol count, maps the complete ELF64 dynamic-symbol table through file-backed `PT_LOAD`, resolves every `st_name` through checked `DT_STRTAB` / `DT_STRSZ`, and reports each versioned dynamic symbol with its symbol index, name, hidden bit, version index, and definition/requirement source. This makes the namespace check directly traceable to the symbols that consume each version.

For definitions, the first `Verdaux` name is reported. For requirements, each `Vernaux` index is reported with both its dependency (`vn_file`) and requested version name. Indices 0 and 1 retain their reserved local/global meaning and are not inserted into the version namespace.

The checker rejects duplicate dynamic tags, malformed or prematurely terminated Verdef/Verdaux and Verneed/Vernaux chains, duplicate indices across definition/requirement records, unresolved versioned `DT_VERSYM` indices, malformed GNU-hash metadata, missing or non-ELF64 `DT_SYMENT`, non-file-backed dynamic-symbol/version/string ranges, string offsets outside `DT_STRSZ`, missing NUL terminators, and arithmetic/range overflow.

Multiple inputs are completely validated before any stdout is emitted, so a malformed later input cannot leave a partial successful report.

Focused regression coverage constructs a shared library with a GNU version-script definition and a versioned external dependency using GNU `as` and `ld`, then checks both namespace resolution and concrete dynamic-symbol bindings against GNU `readelf -VW` / `readelf --dyn-syms -W`. Additional cases cover unresolved indices, malformed `DT_SYMENT`, `DT_SYMTAB` and `DT_VERNEED` virtual-range overflow, and multi-input stdout atomicity.

Example:

```text
mini-elf-vercheck consumer.so
DT_VERSYM namespace is consistent across 6 dynamic symbols; 2 referenced version indices:
  index=2 source=definition name=VERS_LOCAL
  index=3 source=requirement dependency=libdep.so name=VERS_DEP
Versioned dynamic symbols (3):
  symbol=2 name=exported index=2 hidden=no source=definition version=VERS_LOCAL
  symbol=3 name=VERS_LOCAL index=2 hidden=no source=definition version=VERS_LOCAL
  symbol=5 name=dep index=3 hidden=no source=requirement dependency=libdep.so version=VERS_DEP
```
