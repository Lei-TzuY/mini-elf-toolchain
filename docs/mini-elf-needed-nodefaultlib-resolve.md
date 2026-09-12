# `mini-elf-needed-nodefaultlib-resolve`

`mini-elf-needed-nodefaultlib-resolve [--ld-library-path <dir[:dir...]>] <symbol> <root-et-dyn> <fallback-library-dir>` is a bounded dynamic-loader resolver layered on the existing checked `DT_NEEDED` / RPATH / RUNPATH / explicit-loader-path closure.

The tool inspects checked `DT_FLAGS_1` metadata on **each object that performs a dependency lookup**. When that loader object carries `DF_1_NODEFLIB`, the caller-provided fallback-library directory is suppressed only for that object's `DT_NEEDED` edges. The flag therefore does not become a global closure property: a marked root can still load an unmarked child through RPATH, explicit loader-path, RUNPATH, or a direct pathname, and that child may then use the fallback layer for its own dependencies; conversely, an unmarked root does not allow a marked transitive DSO to use the fallback layer.

This per-object rule mirrors glibc's link-map search decision, which checks the loader object's `l_flags_1 & DF_1_NODEFLIB` before searching default directories. RPATH, explicit loader-path, RUNPATH, direct `DT_NEEDED` pathnames, SONAME identity de-duplication, breadth-first scope construction, and dynamic-hash symbol resolution retain their existing behavior.

This slice intentionally does not model `/etc/ld.so.cache`, hardware-capability directories, ambient `LD_LIBRARY_PATH`, secure-execution mode, or a host system's real default library directories. The caller-provided fallback directory is the only default-search layer represented by this bounded resolver.

Focused integration coverage uses GNU `ld -z nodefaultlib` and `readelf -dW` to verify the emitted `FLAGS_1: NODEFLIB` metadata. It proves root-level suppression, explicit-loader-path preservation, suppression by a marked transitive DSO, and non-propagation from a marked root into an unmarked child. A malformed transitive object with duplicate `DT_FLAGS_1` metadata must fail before any stdout is committed.
