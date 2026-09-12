# mini-elf-needed-runpath-resolve

`mini-elf-needed-runpath-resolve <symbol> <root-et-dyn> <fallback-library-dir>` builds a deterministic breadth-first `DT_NEEDED` closure and resolves the requested external definition through the existing mixed GNU/SysV dynamic-hash resolver.

For each image, checked legacy `DT_RPATH` entries participate in dependency search and are inherited by descendants, matching the important loader distinction that legacy RPATH can affect indirect dependencies. A descendant's own `DT_RPATH` entries are searched before inherited ancestor entries and then carried forward. Checked `DT_RUNPATH` remains local to the image that declares it: inherited ancestor RPATH entries are consulted before that image's RUNPATH, while the RUNPATH entries themselves are not propagated to grandchildren. If an image contains both tags, `DT_RUNPATH` takes precedence over that image's own `DT_RPATH`.

Both path tags use the same bounded expansion rules: `$ORIGIN` / `${ORIGIN}` and `$ORIGIN/<safe-relative-path>` / `${ORIGIN}/<safe-relative-path>` are accepted, entries preserve colon-separated order, and lookup remains confined beneath the declaring image's containing directory. Empty entries, absolute/unanchored entries, parent traversal, duplicate `DT_RUNPATH` or `DT_RPATH`, malformed dynamic strings, missing dependencies, and non-file candidates fail closed before stdout is emitted. Duplicate effective search directories are collapsed while preserving first occurrence.

The dependency scope remains breadth-first: the root is searched first, then direct dependencies in `DT_NEEDED` order, followed by newly discovered transitive dependencies. Repeated dependency basenames are collapsed after first discovery.

GNU binutils-backed regression coverage emits legacy RPATH with `ld --disable-new-dtags --rpath=...` and RUNPATH with `ld --enable-new-dtags --rpath=...`, then confirms the tags with `readelf -dW`. The focused inheritance fixture proves that a root RPATH can resolve a grandchild through an intermediate image with no path tag, while the otherwise-equivalent root RUNPATH fixture fails closed because RUNPATH is intentionally not inherited.

This slice intentionally does not implement unanchored relative RUNPATH/RPATH entries, `LD_LIBRARY_PATH`, ld.so cache/default directory search, other dynamic-string substitutions, symbol version matching, IFUNC execution, or relocation application.
