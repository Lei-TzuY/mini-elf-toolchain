# mini-elf-toolchain

A correctness-focused ELF64 x86-64 toolchain/linker laboratory. The project is intentionally staged so each layer is validated before the next one depends on it.

## Current stage

The repository now has a checked ELF64 x86-64 static-link path from validated `ET_REL` inputs through section extraction, symbol resolution, RELA application, permission-aware layout, `PT_LOAD` construction, and executable emission. The CLI exposes validation commands and a bounded `link -o <output> <input>...` path using `_start` as the default entry symbol, with focused GNU binutils differential coverage.

```sh
mini-elf-toolchain link -o a.out start.o support.o
mini-elf-toolchain link -o a.out start.o libsupport.a
mini-elf-toolchain link -o a.out start.o -L ./lib -lsupport
mini-elf-toolchain link -o a.out -u optional_hook start.o -L ./lib -lhooks
mini-elf-toolchain link -o a.out start.o --start-group -L ./lib -lfoo -lbar --end-group
mini-elf-toolchain link -o a.out start.o --whole-archive libextra.a --no-whole-archive
mini-elf-toolchain link -o a.out --map a.out.map start.o support.o
mini-elf-toolchain link -o a.out --entry custom_entry start.o support.o
mini-elf-toolchain link -o a.out --image-base 0x800000 start.o support.o
```

The optional deterministic link map records the final entry address, allocatable section provenance and addresses, resolved global/weak symbol addresses, and emitted `PT_LOAD` ranges and permissions. `--entry <symbol>` selects a resolved global/weak symbol as the executable entry point; `_start` remains the default. `-u <symbol>`, `-u<symbol>`, and `--undefined <symbol>` seed checked unresolved-symbol roots before ordered input processing, allowing otherwise-unreferenced archive members to participate in the existing lazy extraction pipeline. `--image-base <address>` accepts a checked unsigned 64-bit hexadecimal (`0x...`) or decimal base and feeds it through the existing layout/emission pipeline; the default remains `0x400000`. Page alignment remains fixed at `0x1000`; general linker scripts, arbitrary section placement, dynamic linking, and alternate architectures remain outside the current scope.

Archive support includes a checked System V/GNU/BSD `ar` parser, validated `/` and `/SYM64/` symbol-index parsing, unresolved-symbol-driven lazy member extraction, ordered orchestration for regular `ET_REL` objects plus archives, bounded GNU-style `--start-group ... --end-group` rescanning for circular dependencies across archives, stateful `--whole-archive` / `--no-whole-archive` force inclusion, bounded static `-L` / `-l` library search, and GNU-style forced undefined roots. BSD `#1/<len>` extended names are decoded from the inline filename prefix while preserving the raw member header offset and exposing only the remaining bytes as the object payload; malformed lengths and filename ranges are checked before slicing. `-L <dir>` and `-L<dir>` add checked search directories in order; `-l <name>` and `-l<name>` resolve deterministically to the first existing `lib<name>.a` in those directories, and the resulting archive remains at the original command-line position. Shared-library lookup is intentionally not attempted. The public `link` CLI preserves left-to-right input order, performs ordinary archive extraction only when an archive is encountered, does not implicitly rescan earlier archives outside an explicit group, and feeds selected archive members through the same validated `LinkerInputObject` and static-link pipeline as regular objects. Forced undefined roots are deduplicated through the resolver's ordered symbol state and are satisfied by earlier regular definitions or by subsequent archive extraction. Whole-archive mode validates and includes every ordinary member in archive order and intentionally does not require a System V/GNU symbol index; special archive members such as `/`, `/SYM64/`, and `//` are not treated as linkable objects. Within a group, the first pass preserves all input order and subsequent passes rescan only ordinary lazy archives; whole-archive inputs are force-included once and are not duplicated by group rescans. The number of lazy group passes is bounded by the checked total number of ordinary members in lazy archives, which is sufficient because every productive rescan must extract at least one previously unselected member. Nested groups are intentionally rejected in this bounded first slice. Extraction validates each selected member as ELF64 x86-64 `ET_REL`, propagates strong undefined references introduced by extracted members, does not let weak undefined references pull additional members, and leaves unreferenced members unparsed outside whole-archive mode. Member headers, sizes, payload bounds, padding, GNU short/long names, BSD extended names, symbol counts, big-endian member offsets, symbol strings, and index-to-member references are validated with checked arithmetic and GNU/LLVM differential coverage. BSD ranlib symbol-table parsing and thin archives remain intentionally unsupported.

The bounded relocation set includes absolute and PC-relative 8/16/32/64-bit forms already exercised by the static linker, `R_X86_64_SIZE32` / `R_X86_64_SIZE64`, and a real static-GOT slice for `R_X86_64_GOT32`, `R_X86_64_GOT64`, `R_X86_64_GOTPCREL`, `R_X86_64_GOTPCRELX`, and `R_X86_64_REX_GOTPCRELX`. SIZE relocations use the resolved definition's ELF `st_size` (`Z`) and apply the ABI `Z + A` formula with checked unsigned-width conversion, so cross-object references do not incorrectly rely on the undefined reference-side symbol metadata. GOT-family references collect unique global/weak symbols deterministically, allocate one 8-byte entry per symbol in a synthetic writable `SHT_PROGBITS` region, and initialize each entry with the final resolved symbol address. `R_X86_64_GOT32` and `R_X86_64_GOT64` write checked unsigned `G + A` values at 32-bit and 64-bit widths respectively, where `G` is the selected entry's offset from the synthetic GOT base; GOTPCREL-family relocations apply the signed 32-bit `GOT-entry + A - P` displacement. The relaxable GOTPCRELX relocation kinds are deliberately accepted as non-relaxed GOT references in the static-link path; instruction rewriting/relaxation itself remains out of scope. PLT construction, TLS, shared objects, dynamic loading, and broader GOT-base relocation families also remain outside this bounded slice.

Global `SHN_COMMON` tentative symbols are merged by maximum size and alignment, with a real strong definition taking precedence. Surviving commons are placed deterministically by symbol name into one synthetic writable `SHT_NOBITS` region, so existing relocation, symbol-address, load-segment, and link-map paths all observe the same final allocation. Common alignment must be a non-zero power of two, and alignment/size arithmetic is checked for overflow.

## Core roadmap

1. ELF64 header and table-bound validation — complete
2. Validated section and symbol object model — complete
3. RELA parsing and x86-64 relocation validation — complete for the bounded relocation set, including `SIZE32`/`SIZE64` and bounded static GOT-family relocations including `GOT32`/`GOT64`
4. Symbol resolution — complete for the current static-link scope, including bounded `SHN_COMMON` allocation
5. Section layout — complete for the current permission-aware layout model, including synthetic common/GOT regions
6. ELF executable emission — complete
7. CLI, selectable entry symbol, deterministic link map, forced undefined roots, and configurable image base — complete
8. System V/GNU/BSD archive parsing, indexed lazy extraction, ordered object/archive orchestration, public CLI integration, bounded archive groups, bounded whole-archive semantics, and bounded static library search — complete for the current archive scope
9. Reproducibility and GNU/LLVM semantic differential harness — ongoing hardening work

The current checkpoint is deliberately a bounded static-linker core, not a partial promise of a full system linker. Linker scripts, shared objects/dynamic linking, TLS, LTO, and alternate architectures should only enter scope through an explicit future milestone rather than incidental feature growth.

Each new capability should include focused malformed-input tests. Offsets, sizes, addresses, alignment, and relocation arithmetic must use checked operations where overflow can make an input invalid.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```
