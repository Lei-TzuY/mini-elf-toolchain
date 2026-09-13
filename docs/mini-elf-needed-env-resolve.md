# `mini-elf-needed-env-resolve`

`mini-elf-needed-env-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>` is a bounded dynamic-loader resolver that adds the process `LD_LIBRARY_PATH` environment layer to the existing checked `DT_NEEDED` / RPATH / RUNPATH dependency closure.

If `LD_LIBRARY_PATH` is unset, resolution delegates to the existing RUNPATH/RPATH resolver without an explicit loader-path layer. If it is set, its colon-separated entries use the same checked loader-path semantics as `mini-elf-needed-loader-cwd-resolve`: ordering is preserved, supported dynamic tokens retain their existing expansion rules, duplicate directories are removed deterministically by the underlying resolver, and empty components map to the process current working directory. This intentionally preserves the loader-visible distinction between an unset variable and a variable set to the empty string.

`--secure` models the `AT_SECURE` loader rule relevant to this bounded surface: ambient `LD_LIBRARY_PATH` is ignored entirely before parsing or validation, so even a malformed environment value cannot affect dependency search. Existing `DT_RPATH`, `DT_RUNPATH`, slash-containing direct `DT_NEEDED` pathname handling, and the caller-provided modeled fallback directory retain their normal semantics. This is an explicit deterministic mode; the tool does not inspect process credentials or auxiliary vectors itself.

Search ordering remains bounded and explicit. Legacy inherited `DT_RPATH` directories are searched before the environment layer when no `DT_RUNPATH` supersedes them; `LD_LIBRARY_PATH` is searched before the declaring object's `DT_RUNPATH`; the caller-provided fallback directory remains the final modeled default layer. In `--secure` mode the environment layer is simply absent. Slash-containing direct `DT_NEEDED` pathnames continue to bypass directory search.

Malformed environment entries fail closed before stdout is committed in normal mode. Existing directory validation, `$ORIGIN`/`$LIB`/`$PLATFORM` handling, SONAME identity de-duplication, breadth-first dependency scope construction, dynamic-hash symbol resolution, and checked malformed-ELF behavior are reused rather than reimplemented.

This slice does not model `/etc/ld.so.cache`, hardware-capability directories, audit/preload namespaces, host default-library discovery, or automatic secure-execution detection from credentials/`AT_SECURE`. The fallback argument remains the only modeled default-search directory.

Focused integration coverage uses GNU `as`, `ld`, and `readelf` to construct and verify real `ET_DYN`, `DT_NEEDED`, and `DT_RUNPATH` metadata. It proves environment-before-RUNPATH precedence, the empty-value current-directory rule, unset-variable fallback behavior, fail-closed handling for a non-directory environment entry, secure-mode suppression of an otherwise winning ambient dependency, and secure-mode immunity to malformed `LD_LIBRARY_PATH` values.
