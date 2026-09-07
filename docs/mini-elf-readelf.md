# mini-elf-readelf

`mini-elf-readelf` is the checked ELF64 x86-64 inspection companion to the linker and `mini-elf-nm`.

The current bounded inspection surface includes ELF file headers, program headers, section headers, symbol tables, and relocation tables:

```sh
mini-elf-readelf -h input.o
mini-elf-readelf --file-header input.o executable
mini-elf-readelf -l executable
mini-elf-readelf --program-headers executable another-executable
mini-elf-readelf -S input.o
mini-elf-readelf --section-headers input.o executable
mini-elf-readelf -s input.o
mini-elf-readelf --symbols input.o executable
mini-elf-readelf -r input.o
mini-elf-readelf --relocs input.o another.o
```

The command reuses the repository's checked `Elf64Header` parser. File-header inspection validates the referenced section-header table before producing output. Program-header inspection additionally validates entry bounds, segment file ranges, checked arithmetic, and alignment. Section-header inspection uses the checked section-table parser, resolves names through the declared section-name string table with bounds and NUL-termination checks, and reports each section's type, address, file offset, size, entry size, flags, link/info fields, and alignment. Symbol-table inspection reuses the checked `SHT_SYMTAB`/`SHT_DYNSYM` parser and symbol-name resolver, validating symbol entry sizes, table sizes and ranges, linked string tables, name offsets, section indices, and NUL-terminated names before rendering value, size, type, binding, visibility, section index, and name. Relocation inspection accepts `SHT_RELA` and `SHT_REL`, validates entry size/table sizing, linked symbol-table and target-section indices, checked entry offsets/ranges, relocation symbol indices, and symbol names before rendering offset, raw info, x86-64 relocation type, symbol, and addend.

Multiple inputs are fully inspected before any stdout is emitted, so a malformed later input cannot leave a partial successful report behind.

GNU `readelf` is used as a differential oracle on real GNU-assembled or linked ELF inputs: `readelf -h` for core header facts, `readelf -lW` for program-header load-segment facts, `readelf -SW` for named section-header facts, `readelf -sW` for symbol value/size/type/binding/visibility/section facts, and `readelf -rW` for relocation type and symbol facts.

Dynamic metadata, notes, symbol-version decoding, and dynamic-loader semantics remain outside the current bounded inspection surface.
