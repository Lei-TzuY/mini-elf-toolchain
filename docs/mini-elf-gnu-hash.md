# `mini-elf-gnu-hash`

`mini-elf-gnu-hash` is a bounded ELF64 dynamic-loader inspection tool for the GNU hash table referenced by `DT_GNU_HASH`.

```sh
mini-elf-gnu-hash libsample.so
mini-elf-gnu-hash first.so second.so
```

The inspector reads `PT_DYNAMIC`, requires exactly one `DT_GNU_HASH` entry, maps the table only through file-backed `PT_LOAD` ranges, and validates the GNU-hash header before following buckets and chains. It rejects zero bucket counts, zero or non-power-of-two Bloom counts, bucket values below `symoffset`, arithmetic overflow, and chain entries that escape file-backed load data.

For each valid image it reports the GNU-hash address, bucket count, Bloom-word count, symbol offset, Bloom shift, the dynamic-symbol upper bound derived from bucket/chain termination, each bucket value, and the number of chain words inspected.

The implementation intentionally does not perform symbol-name hash lookup yet. This slice establishes checked GNU-hash table parsing and symbol-bound derivation as an executable dynamic-link foundation; lookup semantics can build on the same validated metadata later.

Tests include a GNU `as` + `ld -shared --hash-style=gnu` fixture whose dynamic-symbol count is compared with GNU `readelf --dyn-syms`, plus malformed Bloom-count and overflowing-address regressions. Multiple-input output remains atomic: if any later input is invalid, no partial stdout is emitted.
