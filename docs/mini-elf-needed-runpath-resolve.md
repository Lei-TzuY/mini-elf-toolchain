# mini-elf-needed-runpath-resolve

`mini-elf-needed-runpath-resolve <symbol> <root-et-dyn> <fallback-library-dir>` builds a deterministic breadth-first `DT_NEEDED` closure and resolves the requested external definition through the existing mixed GNU/SysV dynamic-hash resolver.

For each image independently, a checked `DT_RUNPATH` is consulted before the explicit fallback directory. When `DT_RUNPATH` is absent, the resolver instead accepts legacy checked `DT_RPATH`. If both tags are present, `DT_RUNPATH` takes precedence and `DT_RPATH` is not used for dependency search.

Both path tags use the same bounded expansion rules: `$ORIGIN` / `${ORIGIN}` and `$ORIGIN/<safe-relative-path>` / `${ORIGIN}/<safe-relative-path>` are accepted, entries preserve colon-separated order, and lookup remains confined beneath the parent image's containing directory. Empty entries, absolute/unanchored entries, parent traversal, duplicate `DT_RUNPATH` or `DT_RPATH`, malformed dynamic strings, missing dependencies, and non-file candidates fail closed before stdout is emitted.

The dependency scope remains breadth-first: the root is searched first, then direct dependencies in `DT_NEEDED` order, followed by newly discovered transitive dependencies. Repeated dependency basenames are collapsed after first discovery.

GNU binutils-backed regression coverage verifies legacy `DT_RPATH` images emitted by `ld --disable-new-dtags --rpath=...` and confirms their dynamic tags with `readelf -dW` before exercising transitive `$ORIGIN` search.

This slice intentionally does not implement unanchored relative RUNPATH/RPATH entries, `LD_LIBRARY_PATH`, ld.so cache/default directory search, other dynamic-string substitutions, symbol version matching, IFUNC execution, or relocation application.
