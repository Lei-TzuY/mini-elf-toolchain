# Bounded `--library-path=<dir>` static search

The static-link CLI accepts GNU ld's long-option equals form:

```sh
mini-elf-toolchain link -o a.out --library-path=./lib start.o -lhelper
```

`--library-path=<dir>` is equivalent to adding that directory with `-L<dir>` at the same command-line position. Directories are retained in declaration order and feed the existing deterministic static archive lookup. A subsequent `-lfoo` resolves to the first existing `libfoo.a` in the accumulated search path list; `-l:filename` continues to request an exact filename.

The equals form requires a non-empty directory. The directory is checked with filesystem metadata and must exist as a directory before library lookup proceeds. Missing libraries retain the existing diagnostic that reports the requested archive name and searched directories.

This slice does not add shared-library search, sysroot rewriting, environment-derived paths, default system directories, or the GNU `--library` long option. Archive extraction and left-to-right ordering semantics are unchanged after a library path resolves to an archive input.
