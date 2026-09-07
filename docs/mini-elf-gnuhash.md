# `mini-elf-gnuhash`

`mini-elf-gnuhash` is a bounded ELF64 x86-64 runtime-style inspector for the GNU dynamic hash table referenced by `DT_GNU_HASH`.

```sh
mini-elf-gnuhash libsample.so
mini-elf-gnuhash first.so second.so
```

The tool deliberately does not use section headers to locate the table. It validates program headers, requires at most one `PT_DYNAMIC`, parses dynamic entries through a checked `DT_NULL` terminator, resolves the unique `DT_GNU_HASH` virtual address through file-backed `PT_LOAD` ranges, and validates the GNU hash header before reading its bloom filter, buckets, or chains.

The GNU header fields `nbuckets`, `symoffset`, `bloom_size`, and `bloom_shift` are parsed with checked arithmetic. `bloom_size` must be a non-zero power of two, the complete bloom and bucket prefix must be file-backed, every non-zero bucket must start at or above `symoffset`, and each bucket chain is walked through individually checked 32-bit chain entries until its low-bit terminator. The highest terminated chain extent is reported as the dynamic-symbol upper count represented by the GNU hash table.

Multiple inputs are fully validated before output is emitted, so a malformed later input cannot leave partial stdout from an earlier file.

The focused differential test builds a real shared object with GNU `as` and `ld --hash-style=gnu`, compares the GNU-hash-derived symbol extent with GNU `readelf --dyn-syms -W`, and covers a malformed bucket below `symoffset` plus an overflowing `DT_GNU_HASH` virtual range.

This is an inspection foundation only. Dynamic symbol lookup, symbol versioning, dynamic relocations, loader search semantics, and shared-object emission remain outside this slice.
