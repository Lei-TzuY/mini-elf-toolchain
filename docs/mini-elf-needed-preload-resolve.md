# `mini-elf-needed-preload-resolve`

`mini-elf-needed-preload-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>` adds one bounded `LD_PRELOAD` interposition layer to the checked dynamic-loader foundation.

In normal mode, an ambient `LD_PRELOAD` value is parsed as colon- or ASCII-whitespace-separated entries. This first slice deliberately accepts explicit pathnames only. Absolute pathnames and normalized relative pathnames are supported; relative entries are resolved against the process current working directory. Empty entries are ignored. Bare library names, `$` dynamic-token expansion, `.` / `..` traversal, non-files, unreadable paths, and malformed ELF preload images fail closed before stdout is committed.

The modeled global lookup scope is deterministic: the root image is searched first, then preload images in declared order, then the ordinary checked `DT_NEEDED` dependency closure from `mini-elf-needed-env-resolve`. This models the executable-before-preload and preload-before-normal-dependency interposition layers without pretending to implement the full system loader. Every preload image is checked before a successful result is committed, so a malformed later preload cannot be hidden by an earlier matching definition.

`--secure` models the secure-execution suppression relevant to this bounded surface: ambient `LD_PRELOAD` is ignored without parsing, and resolution delegates to the existing secure environment resolver, which also suppresses ambient `LD_LIBRARY_PATH`. Automatic credential / `AT_SECURE` detection remains outside this tool.

The ordinary dependency phase retains the existing RPATH/RUNPATH, ambient `LD_LIBRARY_PATH`, direct slash-containing `DT_NEEDED`, SONAME identity, breadth-first closure, GNU/SysV dynamic-hash lookup, `DF_1_NODEFLIB`, and fallback-directory behavior of the underlying resolver.

This slice does **not** resolve bare `LD_PRELOAD` SONAMEs through loader search paths, expand preload dynamic tokens, load dependencies of preload DSOs into the global scope, model `/etc/ld.so.preload`, audit namespaces, hwcap directories, or the secure-mode standard-directory/set-user-ID preload exception. Those require separate loader-state slices rather than silent approximations.

Focused integration tests use GNU `as`, `ld`, and `readelf` to construct real `ET_DYN` / `DT_NEEDED` inputs. Coverage proves root-before-preload ordering, declared preload order, preload-before-normal-dependency interposition, secure suppression, malformed-later-preload stdout atomicity, and fail-closed handling of bare or non-normalized entries.
