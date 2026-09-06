# GNU split link-map option

The bounded static linker accepts GNU ld's split link-map spelling:

```sh
mini-elf-toolchain link -o app -Map app.map start.o
```

This is equivalent to the existing `--map app.map` and `-Map=app.map` forms. It uses the same deterministic link-map generation path and does not change section layout, symbol resolution, archive extraction, or executable emission.

A missing or empty map path is rejected before link-input I/O, and mixing split, attached, or long map forms is treated as a duplicate map option.
