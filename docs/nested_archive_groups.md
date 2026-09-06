# Bounded nested GNU archive groups

The static-link CLI accepts balanced nested GNU-style `--start-group ... --end-group` regions. Nested group markers are normalized into one outer fixpoint domain before the existing ordered archive engine runs, so the first pass keeps command-line order and subsequent bounded rescans revisit only lazy archives.

For example:

```sh
mini-elf-toolchain link -o app start.o \
  --start-group liba.a \
    --start-group libb.a --end-group \
  --end-group
```

is resolved as one archive-group fixpoint containing `liba.a` and `libb.a`. This preserves the current whole-archive and push/pop state tokens inside the group and does not introduce shared-library or `--as-needed` semantics.

Malformed outer group structure remains checked by the existing CLI parser: unmatched `--end-group`, missing closing markers, and empty effective groups are rejected before output emission. GNU differential coverage constructs a circular archive dependency requiring a rescan of the outer archive, links it with both this tool and GNU `ld`, validates both as `ET_EXEC`, and executes both outputs on Linux.
