# `mini-elf-dynrela-tpoff64`

`mini-elf-dynrela-tpoff64` validates one bounded x86-64 static-TLS dynamic-relocation slice for ELF64 `ET_DYN` images: `R_X86_64_TPOFF64` (relocation type 18).

The validator requires explicit `--load-bias` and `--tls-block-offset` inputs. `--tls-block-offset` is the signed byte offset from the thread pointer to the start of this image's assigned static TLS block. For a defined `STT_TLS` symbol, the checked relocation result is:

`tls_block_offset + st_value + A`

The result must fit signed 64-bit exactly. The relocation target must be a complete writable eight-byte range inside a `PT_LOAD`; `load_bias + r_offset` is also checked for address overflow. Dynamic metadata, SysV `DT_HASH` symbol bounds, `DT_SYMTAB`, `DT_STRTAB`, `DT_RELA`, symbol type/definition, and malformed ranges are validated fail-closed.

Focused integration tests build a genuine GNU x86-64 initial-exec TLS fixture with `tlsvar@gottpoff`, and GNU `readelf -rW` independently confirms `R_X86_64_TPOFF64` before the validator is exercised. Regressions cover invalid dynamic-symbol indices, non-writable relocation targets, signed-result overflow, runtime-target overflow, and atomic stdout for malformed later inputs.

This is validation rather than a complete TLS loader. Static TLS block allocation, dependency lookup and interposition, TLS model relaxation, `R_X86_64_DTPOFF32`, TLSDESC processing, IFUNC execution, and relocation memory writes remain outside this slice.
