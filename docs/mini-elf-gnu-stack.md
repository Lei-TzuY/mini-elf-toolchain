# `mini-elf-gnu-stack`

`mini-elf-gnu-stack` inspects ELF64 x86-64 `PT_GNU_STACK` program-header policy as a bounded dynamic-loader/toolchain foundation.

The tool validates the ELF and program-header table with checked arithmetic, validates every program-header file range, and accepts at most one `PT_GNU_STACK` segment. It decodes the ELF `PF_R`, `PF_W`, and `PF_X` bits and reports whether the object requests an executable stack. Unknown permission bits and duplicate `PT_GNU_STACK` segments are rejected before stdout is emitted. Multiple inputs are validated before any output, preserving stdout atomicity when a later input is malformed.

```sh
cargo run --bin mini-elf-gnu-stack -- ./libsample.so
```

Example output:

```text
PT_GNU_STACK segment 6: flags=RW- (0x6), executable=no
```

GNU `readelf -lW` differential tests cover both non-executable and executable-stack fixtures. Focused malformed-input tests cover duplicate GNU-stack segments, unknown permission flag bits, checked program-header file-range overflow, and malformed later-input atomicity.

This slice only inspects declared stack policy. It does not create a process stack, apply memory protections, infer policy when `PT_GNU_STACK` is absent, mutate ELF files, or implement broader dynamic-loader behavior.
