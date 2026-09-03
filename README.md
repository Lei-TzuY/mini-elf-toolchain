# mini-elf-toolchain

A correctness-focused ELF64 x86-64 toolchain/linker laboratory. The project is intentionally staged so each layer is validated before the next one depends on it.

## Current stage

The repository now has a checked ELF64 x86-64 static-link path from validated `ET_REL` inputs through section extraction, symbol resolution, RELA application, permission-aware layout, `PT_LOAD` construction, and executable emission. The CLI exposes validation commands and a bounded `link -o <output> <input>...` path using `_start` as the entry symbol, with focused GNU binutils differential coverage.

```sh
mini-elf-toolchain link -o a.out start.o support.o
mini-elf-toolchain link -o a.out start.o libsupport.a
mini-elf-toolchain link -o a.out --map a.out.map start.o support.o
```

The optional deterministic link map records the final entry address, allocatable section provenance and addresses, resolved global/weak symbol addresses, and emitted `PT_LOAD` ranges and permissions. The initial link CLI intentionally fixes the image base at `0x400000` and page alignment at `0x1000`; linker scripts, dynamic linking, and alternate architectures remain outside the current scope.

Archive support includes a checked System V/GNU `ar` parser, validated `/` and `/SYM64/` symbol-index parsing, unresolved-symbol-driven lazy member extraction, and ordered orchestration for regular `ET_REL` objects plus archives. The public `link` CLI preserves left-to-right input order, performs archive extraction only when an archive is encountered, does not implicitly rescan earlier archives, and feeds selected archive members through the same validated `LinkerInputObject` and static-link pipeline as regular objects. Extraction validates each selected member as ELF64 x86-64 `ET_REL`, propagates strong undefined references introduced by extracted members, does not let weak undefined references pull additional members, and leaves unreferenced members unparsed. Member headers, sizes, payload bounds, padding, GNU short/long names, symbol counts, big-endian member offsets, symbol strings, and index-to-member references are validated with checked arithmetic and GNU binutils differential coverage. BSD extended names remain intentionally unsupported.

## Core roadmap

1. ELF64 header and table-bound validation — complete
2. Validated section and symbol object model — complete
3. RELA parsing and x86-64 relocation validation — complete for the bounded relocation set
4. Symbol resolution — complete for the current static-link scope
5. Section layout — complete for the current permission-aware layout model
6. ELF executable emission — complete
7. CLI and deterministic link map — complete
8. System V/GNU archive parsing, indexed lazy extraction, ordered object/archive orchestration, and public CLI integration — complete
9. Reproducibility and GNU/LLVM semantic differential harness — ongoing hardening work

The current checkpoint is deliberately a bounded static-linker core, not a partial promise of a full system linker. Linker scripts, shared objects/dynamic linking, TLS, LTO, and alternate architectures should only enter scope through an explicit future milestone rather than incidental feature growth.

Each new capability should include focused malformed-input tests. Offsets, sizes, addresses, alignment, and relocation arithmetic must use checked operations where overflow can make an input invalid.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
