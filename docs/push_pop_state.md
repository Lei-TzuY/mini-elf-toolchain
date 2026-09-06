# Bounded GNU `--push-state` / `--pop-state`

This checkpoint adds GNU-style linker state scoping for the static linker's existing `--whole-archive` mode.

`--push-state` records the current whole-archive flag. `--pop-state` restores the most recently pushed value, so a temporary force-inclusion region can be bounded without manually reconstructing the previous state:

```sh
mini-elf-toolchain link -o app start.o \
  --push-state --whole-archive libforced.a --pop-state \
  liblazy.a
```

The state stack is honored both outside and inside the existing bounded archive-group parser. Unmatched `--pop-state` and an unterminated pushed state are rejected before output emission. Nested state pushes are supported by the stack.

GNU differential coverage verifies that an unreferenced member inside the pushed whole-archive scope is included while an unreferenced archive after `--pop-state` remains lazy, and executes both the mini-linker and GNU `ld` outputs on Linux.

This slice deliberately saves only the already-supported whole-archive state. It does not add `--as-needed`, shared-library selection, dynamic linking, or other GNU linker state flags.
