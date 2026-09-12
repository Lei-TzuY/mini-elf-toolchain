# `mini-elf-needed-loader-cwd-resolve`

`mini-elf-needed-loader-cwd-resolve --ld-library-path <dir[:dir...]> <symbol> <root-et-dyn> <fallback-library-dir>` is a bounded dynamic-loader front end over the existing explicit loader-path token resolver.

It adds one loader-compatible path-list rule: an empty component in the explicit `--ld-library-path` list is expanded to the process current working directory before the existing loader-path validation and `$ORIGIN` / `$LIB` / `$PLATFORM` token expansion runs. Leading, middle, trailing, and entirely empty components therefore name the current working directory. The tool remains deterministic with respect to its explicit command line and process working directory; it does not read ambient `LD_LIBRARY_PATH`.

The normalized path list then follows the existing checked search order and closure semantics: legacy inherited RPATH, explicit loader path, local RUNPATH, fallback directory, direct `DT_NEEDED` path handling, SONAME identity de-duplication, breadth-first dependency scope, and dynamic-hash symbol lookup. Existing directory validation remains fail-closed, so a later explicit component that names a non-directory rejects the request before stdout is emitted.

Focused GNU-binutils-backed integration builds real `ET_DYN` images with `DT_NEEDED` metadata and proves that an empty loader-path component resolves a dependency from the process working directory, that the empty component keeps its left-to-right precedence over a later explicit directory containing the same SONAME, and that malformed non-directory components still fail atomically.
