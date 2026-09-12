# `mini-elf-needed-absolute-runpath-resolve`

`mini-elf-needed-absolute-runpath-resolve [--ld-library-path <dir[:dir...]>] <symbol> <root-et-dyn> <fallback-library-dir>` extends the checked RUNPATH/RPATH dependency resolver with one bounded loader-compatible capability: ordinary absolute directory entries in `DT_RUNPATH` and `DT_RPATH`.

Absolute entries preserve the existing search semantics. `DT_RUNPATH` remains local to the image that declares it, while legacy `DT_RPATH` remains inheritable by descendants. Explicit loader-path directories retain their existing precedence, SONAME identity de-duplication and breadth-first dependency scope are unchanged, and the final symbol lookup still uses the existing checked GNU/SysV dynamic-hash resolver.

The slice deliberately remains narrower than a host dynamic loader. Absolute entries must be normalized paths containing only the root plus normal components; `.` / `..` traversal and dynamic tokens embedded in absolute entries are rejected before stdout is emitted. Existing `$ORIGIN`, `$LIB`, and `$PLATFORM` handling for the previously supported anchored form remains available. Relative non-token RUNPATH/RPATH entries, ambient `LD_LIBRARY_PATH`, loader cache/sysroot semantics, and general dynamic-loader emulation remain outside this bounded capability.

Focused integration uses GNU `as` / `ld` to construct real ELF64 shared objects and GNU `readelf -dW` to confirm emitted `RUNPATH` / `RPATH` metadata. Coverage proves direct absolute RUNPATH lookup, inherited absolute RPATH lookup across a transitive dependency, and fail-closed rejection of a non-normalized absolute entry with atomic stdout.
