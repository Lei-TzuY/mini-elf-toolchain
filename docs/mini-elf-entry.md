# `mini-elf-entry`

`mini-elf-entry` validates the ELF64 x86-64 image entry point against the loadable program-header layout for `ET_EXEC` and `ET_DYN` inputs.

```sh
cargo run --bin mini-elf-entry -- ./a.out
cargo run --bin mini-elf-entry -- ./a.out ./pie
```

A zero `e_entry` is reported as an absent entry point. For a nonzero `e_entry`, the tool checks `entry + 1` for unsigned overflow and requires that byte to lie inside the memory range of an executable (`PF_X`) `PT_LOAD` segment. An entry that is covered only by a non-executable load segment, or by no load segment, is rejected.

Before resolving the entry, every program header is checked for file-range bounds, `p_filesz <= p_memsz`, and virtual-memory-range overflow. This keeps malformed segment metadata from being accepted merely because it is unrelated to the selected entry address.

Multiple inputs are fully validated before stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

The focused integration coverage builds both a GNU `ET_EXEC` image and a GNU PIE (`ET_DYN`) with `as`/`ld`, compares the entry address with `readelf -hW`, verifies executable-load containment, and exercises malformed non-executable and overflowing entry-point cases.

This command is an inspection/validation slice only. It does not relocate or load an `ET_DYN` image, apply a runtime load bias, resolve entry symbols, or emulate process startup.
