# `mini-elf-needed-resolve`

`mini-elf-needed-resolve <symbol> <root-et-dyn> <library-dir>` builds one bounded loader lookup scope from a root ELF64 x86-64 `ET_DYN` image and its direct `DT_NEEDED` entries, then resolves the requested external definition through the existing mixed GNU/SysV dynamic-hash resolver.

The root image is searched first. Direct dependencies follow in their original `DT_NEEDED` order. Each dependency name must be a plain basename and is resolved only as `<library-dir>/<name>`; missing or non-file dependencies fail closed before stdout is emitted. Duplicate `DT_NEEDED` names are collapsed after their first occurrence while preserving order.

Every input still passes through the existing checked dynamic metadata and external-definition eligibility paths. A present malformed GNU hash remains authoritative and is never silently replaced by SysV fallback.

This is deliberately not a complete runtime loader. It does not recursively expand dependency graphs, interpret `DT_RPATH`/`DT_RUNPATH`, consult `LD_LIBRARY_PATH`, the loader cache, or default system directories, apply symbol versioning or interposition policy, execute IFUNC resolvers, or apply relocations.