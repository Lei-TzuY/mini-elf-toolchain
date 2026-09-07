# mini-elf-readelf

`mini-elf-readelf` is a bounded ELF64 x86-64 inspection CLI backed by the toolchain's checked ELF header parser.

## File header

```sh
mini-elf-readelf -h input.o
mini-elf-readelf --file-header input.o executable
```

The file-header view reports the ELF type, entry point, header-table offsets and sizes, flags, and table counts. Section-header structure is validated before output is emitted.

## Program headers

```sh
mini-elf-readelf -l executable
mini-elf-readelf --program-headers executable another-executable
```

The program-header view reports each ELF64 program header in file order, including type, file offset, virtual and physical addresses, file and memory sizes, flags, and alignment. Program-header table bounds, entry ranges, segment file ranges, and alignment are checked before output. For multiple inputs, all inputs are validated before any stdout is emitted, so a malformed later input cannot leave partial inspection output.

The command intentionally does not yet implement section listings, symbol listings, dynamic-section decoding, notes, or GNU `readelf`'s combined option surface.
