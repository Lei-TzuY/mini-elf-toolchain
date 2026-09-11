# mini-elf-sysv-hash-resolve

`mini-elf-sysv-hash-resolve <symbol> <input>...` performs bounded ordered external-definition resolution across explicit ELF64 x86-64 `ET_DYN` inputs backed by System V `DT_HASH`.

Inputs are searched strictly in command-line order. For each image the tool reuses the checked SysV hash lookup and external-definition eligibility path; the first defined, non-local symbol whose visibility is not `STV_INTERNAL` or `STV_HIDDEN` wins. Ineligible earlier matches are skipped. If no eligible definition exists, the tool reports `not-found`.

Malformed images fail closed before stdout is emitted. Hash tables, dynamic metadata and dynamic symbols retain the existing checked file-backed `PT_LOAD` validation of the underlying lookup tools.

This slice does not implement `DT_NEEDED` dependency traversal, loader scope construction, symbol versioning, interposition rules, IFUNC resolution, or relocation application.
