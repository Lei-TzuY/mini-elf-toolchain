# Forced undefined roots

The static-link CLI supports GNU-style forced undefined roots with all of these forms:

```sh
mini-elf-toolchain link -o a.out -u helper start.o libextra.a
mini-elf-toolchain link -o a.out -uhelper start.o libextra.a
mini-elf-toolchain link -o a.out --undefined helper start.o libextra.a
mini-elf-toolchain link -o a.out --undefined=helper start.o libextra.a
```

Each requested symbol is inserted into the unresolved-symbol roots before ordered archive processing. This can cause an otherwise unused archive member that defines the symbol to be selected by the existing lazy extraction pipeline. The option does not change ordinary left-to-right archive ordering, explicit group rescans, or whole-archive behavior.

An empty root is rejected before input I/O. In particular, `--undefined=` is invalid rather than being treated as an input filename. Multiple forced roots remain ordered and are deduplicated by the existing resolver state.

The GNU differential integration test constructs a real archive with GNU `ar`, links the same forced root with this linker and GNU `ld`, verifies that the archive member is selected, checks the emitted ELF header with GNU `readelf`, and executes the produced static ELF on Linux.
