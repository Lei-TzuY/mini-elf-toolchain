# `mini-elf-needed-preload-resolve`

`mini-elf-needed-preload-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>` adds a bounded `LD_PRELOAD` interposition layer to the checked dynamic-loader foundation.

In normal mode, an ambient `LD_PRELOAD` value is parsed as colon- or ASCII-whitespace-separated entries. Absolute pathnames and normalized relative pathnames are supported; relative path entries are resolved against the process current working directory. Bare library basenames such as `libtrace.so` are also supported and are resolved through the modeled loader search order for the root image: legacy `DT_RPATH` when no `DT_RUNPATH` is present, then ambient `LD_LIBRARY_PATH`, then root `DT_RUNPATH`, then the modeled fallback directory. Ambient loader-path entries retain the existing empty-component-to-cwd and checked `$ORIGIN` / `$LIB` / `$PLATFORM` handling. Empty preload entries are ignored.

Explicit preload pathnames still reject `$` dynamic-token expansion, `.` / `..` traversal, non-files, unreadable paths, and malformed ELF images before stdout is committed. Bare names must be a single plain library basename and fail closed when they cannot be resolved. Root RPATH/RUNPATH entries used for bare preload lookup retain the checked absolute, normalized cwd-relative, empty-component, and supported dynamic-token semantics of the existing resolver.

The modeled global lookup scope is deterministic: the root image is searched first, then preload images in declared order, then the ordinary checked `DT_NEEDED` dependency closure from `mini-elf-needed-env-resolve`. This models the executable-before-preload and preload-before-normal-dependency interposition layers without pretending to implement the full system loader. Every preload image is resolved and checked before a successful result is committed, so a malformed or unresolved later preload cannot be hidden by an earlier matching definition.

`--secure` models the secure-execution suppression relevant to this bounded surface: ambient `LD_PRELOAD` is ignored without parsing, and resolution delegates to the existing secure environment resolver, which also suppresses ambient `LD_LIBRARY_PATH`. Automatic credential / `AT_SECURE` detection remains outside this tool.

The ordinary dependency phase retains the existing RPATH/RUNPATH, ambient `LD_LIBRARY_PATH`, direct slash-containing `DT_NEEDED`, SONAME identity, breadth-first closure, GNU/SysV dynamic-hash lookup, `DF_1_NODEFLIB`, and fallback-directory behavior of the underlying resolver.

This slice does **not** expand dynamic tokens inside explicit `LD_PRELOAD` pathname entries, load dependencies of preload DSOs into the global scope, model `/etc/ld.so.preload`, audit namespaces, ld.so.cache/hwcap directories, or the secure-mode standard-directory/set-user-ID preload exception. Those require separate loader-state slices rather than silent approximations.

Focused integration tests use GNU `as`, `ld`, and `readelf` to construct real `ET_DYN` inputs. Coverage proves root-before-preload ordering, declared preload order, preload-before-normal-dependency interposition, bare-name `LD_LIBRARY_PATH` precedence over root RUNPATH, root RUNPATH and fallback bare-name lookup, secure suppression, malformed-later-preload stdout atomicity, and fail-closed handling of unresolved bare or non-normalized entries.
