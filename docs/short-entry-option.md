# GNU short entry option compatibility

The static-link CLI accepts GNU `ld` short entry-symbol forms before link inputs:

```sh
mini-elf-toolchain link -o app -e custom_entry start.o
mini-elf-toolchain link -o app -ecustom_entry start.o
```

Both forms normalize into the same checked entry-selection path as `--entry <symbol>` and `--entry=<symbol>`. `_start` remains the default when no explicit entry is supplied, and an explicit CLI entry continues to override a bounded linker-script `ENTRY(symbol)` directive.

A missing value after split `-e` and an empty split value are rejected before link-input I/O. Mixing short and long entry options is treated as a duplicate entry selection by the existing CLI validation.

This compatibility slice does not broaden option placement, symbol resolution, linker-script grammar, or executable layout semantics. GNU differential coverage assembles the same ELF64 x86-64 object, links it with both short forms and GNU `ld -e`, checks the resulting entry address with `readelf`, and executes the outputs on Linux.
