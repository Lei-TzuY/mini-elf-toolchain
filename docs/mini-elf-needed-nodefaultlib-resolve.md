# `mini-elf-needed-nodefaultlib-resolve`

`mini-elf-needed-nodefaultlib-resolve [--ld-library-path <dir[:dir...]>] <symbol> <root-et-dyn> <fallback-library-dir>` is a bounded dynamic-loader resolver layered on the existing checked `DT_NEEDED` / RPATH / RUNPATH / explicit-loader-path closure.

The tool inspects the root image's checked `DT_FLAGS_1` metadata. When `DF_1_NODEFLIB` is present, the explicit fallback-library directory is treated as the model's default library path and is suppressed. RPATH, explicit loader-path, RUNPATH, direct `DT_NEEDED` pathnames, SONAME identity de-duplication, breadth-first scope construction, and dynamic-hash symbol resolution retain their existing behavior.

This slice intentionally does not model `/etc/ld.so.cache`, hardware-capability directories, ambient `LD_LIBRARY_PATH`, secure-execution mode, or a host system's real default library directories. The caller-provided fallback directory is the only default-search layer represented by this bounded resolver.

Focused integration coverage builds the root image with GNU `ld -z nodefaultlib`, verifies `FLAGS_1: NODEFLIB` with `readelf -dW`, proves that a dependency reachable only through the fallback directory is rejected, and proves that the same flag does not suppress an explicit loader-path directory. Failures remain stdout-atomic.
