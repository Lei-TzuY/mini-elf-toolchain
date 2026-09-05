# Bounded `--library=<name>` static search

The static-link CLI accepts GNU-style `--library=<name>` in addition to the existing `-l<name>` and split `-l <name>` forms. The long equals form uses the same ordered `-L` / `--library-path=<dir>` search directories and resolves to the first existing `lib<name>.a` at that exact command-line position.

An exact archive filename may also be requested with `--library=:filename`, matching the existing bounded `-l:filename` semantics without adding the `lib` prefix or `.a` suffix. Empty names (`--library=` and `--library=:`) are rejected before link-input I/O.

This slice remains static-only. It does not add shared-library lookup, default system paths, sysroot handling, environment-driven paths, or broader option-placement semantics. Archive extraction, group rescans, and whole-archive behavior continue to use the existing checked ordered-input pipeline.
