# `mini-elf-needed-env-resolve`

`mini-elf-needed-env-resolve <symbol> <root-et-dyn> <fallback-library-dir>` is a bounded dynamic-loader resolver that adds the process `LD_LIBRARY_PATH` environment layer to the existing checked `DT_NEEDED` / RPATH / RUNPATH dependency closure.

If `LD_LIBRARY_PATH` is unset, resolution delegates to the existing RUNPATH/RPATH resolver without an explicit loader-path layer. If it is set, its colon-separated entries use the same checked loader-path semantics as `mini-elf-needed-loader-cwd-resolve`: ordering is preserved, supported dynamic tokens retain their existing expansion rules, duplicate directories are removed deterministically by the underlying resolver, and empty components map to the process current working directory. This intentionally preserves the loader-visible distinction between an unset variable and a variable set to the empty string.

Search ordering remains bounded and explicit. Legacy inherited `DT_RPATH` directories are searched before the environment layer when no `DT_RUNPATH` supersedes them; `LD_LIBRARY_PATH` is searched before the declaring object's `DT_RUNPATH`; the caller-provided fallback directory remains the final modeled default layer. Slash-containing direct `DT_NEEDED` pathnames continue to bypass directory search.

Malformed environment entries fail closed before stdout is committed. Existing directory validation, `$ORIGIN`/`$LIB`/`$PLATFORM` handling, SONAME identity de-duplication, breadth-first dependency scope construction, dynamic-hash symbol resolution, and checked malformed-ELF behavior are reused rather than reimplemented.

This slice does not model secure-execution suppression of `LD_LIBRARY_PATH`, `/etc/ld.so.cache`, hardware-capability directories, audit/preload namespaces, or host default-library discovery. The fallback argument remains the only modeled default-search directory.

Focused integration coverage uses GNU `as`, `ld`, and `readelf` to construct and verify real `ET_DYN`, `DT_NEEDED`, and `DT_RUNPATH` metadata. It proves environment-before-RUNPATH precedence, the empty-value current-directory rule, unset-variable fallback behavior, and fail-closed handling for a non-directory environment entry.
