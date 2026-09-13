# `mini-elf-needed-system-preload-resolve`

`mini-elf-needed-system-preload-resolve` adds a bounded, explicit model of the system-wide preload-file layer represented by `/etc/ld.so.preload` without requiring tests or callers to modify the host `/etc` tree.

Usage:

```text
mini-elf-needed-system-preload-resolve <system-preload-file> <symbol> <root-et-dyn> <fallback-library-dir>
```

The file is read before any lookup output is committed. It must be UTF-8 and contains a whitespace-separated list of preload objects. Ambient `LD_PRELOAD` entries are kept first, then the file entries are appended in file order, matching the loader ordering in which environment preloads precede `/etc/ld.so.preload`. The combined scope is delegated to `mini-elf-needed-preload-deps-resolve`, so checked pathname/bare-name search, dynamic tokens, preload de-duplication, preload dependency closure, `LD_LIBRARY_PATH`, RPATH/RUNPATH, SONAME/hash lookup, and fail-closed validation remain shared with the existing loader model.

This bounded file model rejects an entry containing `:` rather than silently reinterpreting it through the ambient `LD_PRELOAD` colon separator used by the delegated resolver. Empty/whitespace-only files are valid and simply contribute no system preload entries.

The tool intentionally takes the preload-file path explicitly for deterministic tests. It does not automatically open `/etc/ld.so.preload`, and this slice does not yet model secure-execution filtering of system-file entries, audit namespaces, `ld.so.cache`/hwcap directories, or auxiliary-vector credential detection.

GNU-binutils-backed regression coverage builds real x86-64 ET_DYN fixtures with `as` and `ld`, verifies dynamic metadata with `readelf`, checks system-preload participation and environment-before-system precedence, and verifies unreadable/malformed file failures remain stdout-atomic.
