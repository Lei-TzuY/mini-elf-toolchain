# mini-elf-needed-closure-resolve

`mini-elf-needed-closure-resolve <symbol> <root-et-dyn> <library-dir>` builds a bounded transitive loader lookup scope from one ELF64 x86-64 `ET_DYN` root and its `DT_NEEDED` closure, then resolves the requested external definition through the existing mixed GNU/SysV dynamic-hash resolver.

The scope is deterministic breadth-first order: the root is searched first, then its direct dependencies in original `DT_NEEDED` order, then newly discovered dependencies of those images in the same order. Repeated dependency names are collapsed after their first discovery.

Every `DT_NEEDED` name must be a plain basename and is resolved only as `<library-dir>/<name>`. Missing or non-file dependencies, malformed ELF/dynamic metadata, invalid dependency names, and malformed hash/symbol metadata fail closed before stdout is emitted.

This slice intentionally does not implement `RPATH`/`RUNPATH`, `LD_LIBRARY_PATH`, ld.so cache/default directory search, symbol versioning, IFUNC execution, interposition beyond the explicit breadth-first scope, or relocation application.
