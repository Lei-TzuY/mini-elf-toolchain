# mini-elf-toolchain

A correctness-focused ELF64 x86-64 toolchain/linker laboratory. The project is intentionally staged so each layer is validated before the next one depends on it.

## Current stage

The repository now has a checked ELF64 x86-64 static-link path from validated `ET_REL` inputs through section extraction, symbol resolution, RELA application, permission-aware layout, `PT_LOAD` construction, and executable emission. The CLI exposes validation commands and a bounded `link -o <output> <input>...` path using `_start` as the entry symbol, with focused GNU binutils differential coverage.

```sh
mini-elf-toolchain link -o a.out start.o support.o
```

The initial link CLI intentionally fixes the image base at `0x400000` and page alignment at `0x1000`; linker scripts, archives, dynamic linking, and alternate architectures remain outside the current scope.

## Core roadmap

1. ELF64 header and table-bound validation
2. Validated section and symbol object model
3. RELA parsing and x86-64 relocation validation
4. Symbol resolution
5. Section layout
6. ELF executable emission
7. CLI and link map
8. Archive lazy extraction
9. Reproducibility and GNU/LLVM semantic differential harness

Each new capability should include focused malformed-input tests. Offsets, sizes, addresses, alignment, and relocation arithmetic must use checked operations where overflow can make an input invalid.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
