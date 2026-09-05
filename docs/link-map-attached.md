# GNU attached link-map option

The bounded static linker accepts GNU ld's attached link-map spelling:

```sh
mini-elf-toolchain link -o app -Map=app.map start.o
```

This is an alias for the existing split `--map app.map` form and feeds the same deterministic link-map emitter. The option is accepted in the existing pre-input CLI option region; it does not change input ordering, archive semantics, entry selection, image layout, or map contents.

`-Map=` is rejected before link-input I/O because the output path is empty. Mixing `-Map=<file>` with `--map <file>` is also rejected as a duplicate map option.

GNU differential coverage assembles a real ELF64 x86-64 `_start` object, links it with both this linker and GNU `ld` using `-Map=<file>`, verifies both outputs are `ET_EXEC`, checks that each map contains `_start`, and executes both binaries on Linux.
