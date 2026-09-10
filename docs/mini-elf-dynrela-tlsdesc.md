# mini-elf-dynrela-tlsdesc

`mini-elf-dynrela-tlsdesc` validates a bounded loader-facing subset of ELF64 x86-64 `ET_DYN` `R_X86_64_TLSDESC` relocations.

It requires `--load-bias`, checked `PT_DYNAMIC`/`DT_RELA` metadata, SysV `DT_HASH`-bounded dynamic symbols and strings, a defined `STT_TLS` symbol, and a complete writable 16-byte descriptor target. It validates the runtime descriptor address as `B + r_offset`, checks the full descriptor range for overflow, and validates the TLS symbol offset `st_value + A` as an unsigned 64-bit value.

The tool reports validated descriptor requirements but does not install or execute a TLS resolver. Dependency lookup, symbol interposition/versioning, TLSDESC resolver selection, static/dynamic TLS allocation, and relocation memory writes remain outside this slice.

The focused integration test constructs a GNU ELF fixture carrying a real `R_X86_64_TLSDESC` dynamic relocation and verifies GNU `readelf -rW` recognition. Negative coverage includes invalid dynamic symbol indices, non-writable descriptor targets, TLS-offset underflow, runtime descriptor overflow, and multi-input stdout atomicity on malformed later input.
