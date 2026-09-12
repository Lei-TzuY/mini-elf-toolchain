# mini-elf-needed-runpath-resolve

`mini-elf-needed-runpath-resolve <symbol> <root-et-dyn> <fallback-library-dir>` builds a deterministic breadth-first `DT_NEEDED` closure and resolves the requested external definition through the existing mixed GNU/SysV dynamic-hash resolver.

For each image independently, a checked `DT_RUNPATH` is consulted before the explicit fallback directory. This bounded slice accepts `$ORIGIN` / `${ORIGIN}` and `$ORIGIN/<safe-relative-path>` / `${ORIGIN}/<safe-relative-path>` entries, so each dependency can direct lookup beneath its own containing directory. Multiple RUNPATH entries preserve their colon-separated order. Empty entries, absolute/unanchored entries, parent traversal, duplicate `DT_RUNPATH`, malformed dynamic strings, missing dependencies, and non-file candidates fail closed before stdout is emitted.

The dependency scope remains breadth-first: the root is searched first, then direct dependencies in `DT_NEEDED` order, followed by newly discovered transitive dependencies. Repeated dependency basenames are collapsed after first discovery.

This slice intentionally does not implement `DT_RPATH`, unanchored relative RUNPATH entries, `LD_LIBRARY_PATH`, ld.so cache/default directory search, other dynamic-string substitutions, symbol version matching, IFUNC execution, or relocation application.
