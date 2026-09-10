# `mini-elf-dynrela-abs64`

`mini-elf-dynrela-abs64` validates one bounded x86-64 dynamic-loader contract: same-image `R_X86_64_64` relocations in an ELF64 `ET_DYN` image.

## Usage

```text
mini-elf-dynrela-abs64 --load-bias <address> <input>...
```

The load bias may be decimal or `0x` hexadecimal. Multiple inputs are validated before any stdout is emitted, so a malformed later input cannot leave partial success output.

## Validated semantics

The tool requires a checked `PT_DYNAMIC` with `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`, either SysV `DT_HASH` or GNU `DT_GNU_HASH`, `DT_SYMTAB`/`DT_SYMENT`, and `DT_STRTAB`/`DT_STRSZ`. For each `R_X86_64_64` relocation it validates:

- a nonzero dynamic-symbol index bounded by `DT_HASH.nchain` or a checked `DT_GNU_HASH` chain walk;
- an 8-byte relocation target contained in writable `PT_LOAD` memory;
- a same-image defined symbol that is neither `SHN_ABS` nor TLS;
- the symbol value lies in loadable memory;
- the dynamic symbol name is bounded and NUL-terminated;
- checked `B + r_offset`, checked `B + S`, and checked signed `S + A` arithmetic, including negative RELA addends.

The reported result follows the x86-64 ABI absolute relocation formula after applying the explicit load bias: `B + S + A` for this same-image bounded mode.

## Deliberate limits

This is not a general dynamic linker. It rejects undefined/external symbols instead of performing dependency lookup, and it does not implement symbol interposition, symbol versioning, TLS, `SHN_ABS`, IFUNC invocation, relocation ordering, or memory writes. Those require separate executable vertical slices.

## Differential coverage

Focused integration tests build a real shared object with GNU `as` and GNU `ld --hash-style=sysv` and `--hash-style=gnu`; GNU `readelf -rW` must independently report a real `R_X86_64_64` relocation. Malformed regressions cover invalid dynamic symbol indices, non-writable relocation targets, signed-addend arithmetic overflow, and multi-input stdout atomicity.

GNU-hash-only images are accepted with checked bucket, bloom, prefix, and chain arithmetic; malformed or unterminated file-backed chain metadata is rejected before symbol access.
