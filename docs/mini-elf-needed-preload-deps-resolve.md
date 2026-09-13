# `mini-elf-needed-preload-deps-resolve`

`mini-elf-needed-preload-deps-resolve [--secure] <symbol> <root-et-dyn> <fallback-library-dir>` extends the bounded `LD_PRELOAD` model so dependencies of preload DSOs participate in checked global symbol lookup.

The modeled lookup order is deterministic: root image first, then all preload images in declared order, then the checked `DT_NEEDED` dependency closures of those preload images in declared preload order, then the ordinary dependency closure of the root image. This keeps a later preload image ahead of an earlier preload's dependency while allowing preload dependencies to interpose on ordinary root dependencies.

Each preload dependency closure reuses the existing environment resolver, so per-object RPATH/RUNPATH, ambient `LD_LIBRARY_PATH`, direct slash-containing `DT_NEEDED`, SONAME identity, breadth-first traversal, GNU/SysV dynamic-hash lookup, `DF_1_NODEFLIB`, fallback-directory behavior, and malformed-input checks stay aligned with the current loader model. Every preload closure is validated before stdout is committed, so an invalid dependency cannot be hidden by a root or preload symbol match.

`--secure` delegates to the existing secure preload behavior and suppresses ambient `LD_PRELOAD` and `LD_LIBRARY_PATH` for this bounded surface.

This slice still does not model `/etc/ld.so.preload`, audit namespaces, ld.so.cache/hwcap directories, full auxiliary-vector credential detection, or the secure-mode standard-directory/set-user-ID preload exception.

Focused GNU-binutils-backed tests cover preload-dependency interposition ahead of root dependencies, preservation of all preload-image ordering ahead of preload dependencies, and malformed preload-dependency failure with stdout atomicity.