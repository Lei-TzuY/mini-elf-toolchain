# `mini-elf-needed-system-preload-resolve`

`mini-elf-needed-system-preload-resolve` adds a bounded, explicit model of the system-wide preload-file layer represented by `/etc/ld.so.preload` without requiring tests or callers to modify the host `/etc` tree.

Usage:

```text
mini-elf-needed-system-preload-resolve [--secure] <system-preload-file> <symbol> <root-et-dyn> <fallback-library-dir>
```

The file is opened and its actual handle is required to identify a regular file before any bytes are read, so directories and potentially blocking special files are rejected before parsing. Reads are capped at 1 MiB plus one sentinel byte used to detect overflow. The file is fully read and validated before any lookup output is committed. It must be UTF-8 and contains a whitespace-separated list of preload objects. A `#` starts a comment through the end of its line; comment-only and blank lines contribute no entries, and comments do not disturb the ordering of entries on surrounding lines. In normal mode, ambient `LD_PRELOAD` entries are kept first, then the file entries are appended in file order, matching the loader ordering in which environment preloads precede `/etc/ld.so.preload`. The combined scope is delegated to `mini-elf-needed-preload-deps-resolve`, so checked pathname/bare-name search, dynamic tokens, preload de-duplication, preload dependency closure, `LD_LIBRARY_PATH`, RPATH/RUNPATH, SONAME/hash lookup, and fail-closed validation remain shared with the existing loader model.

With `--secure`, the deterministic model suppresses ambient `LD_PRELOAD` and `LD_LIBRARY_PATH` before resolving the system preload file, while the explicit system-file entries remain in preload scope. This models the secure-execution distinction between environment-controlled loader state and the system-wide preload configuration without requiring credential changes or an `AT_SECURE` process. The caller environment is restored after the checked lookup completes, including error paths.

This bounded file model rejects an entry containing `:` rather than silently reinterpreting it through the ambient `LD_PRELOAD` colon separator used by the delegated resolver. Empty/whitespace/comment-only files are valid and simply contribute no system preload entries.

The tool intentionally takes the preload-file path explicitly for deterministic tests. It does not automatically open `/etc/ld.so.preload`. Secure mode does not yet model the stricter set-user-ID/standard-directory filtering that a real loader may apply to individual preload entries, and it does not infer secure execution from the auxiliary vector or credentials. Audit namespaces and `ld.so.cache`/hwcap directories also remain out of scope.

GNU-binutils-backed regression coverage builds real x86-64 ET_DYN fixtures with `as` and `ld`, verifies dynamic metadata with `readelf`, checks system-preload participation and comment parsing, normal environment-before-system precedence, secure suppression of ambient `LD_PRELOAD`, secure suppression of `LD_LIBRARY_PATH` during bare-name system preload resolution, and unreadable/malformed file failures with stdout atomicity. Unit coverage additionally verifies that non-regular preload inputs and oversized files fail before unbounded reading can occur.
