# GNU `--entry=<symbol>` compatibility

The static-link CLI accepts both split `--entry <symbol>` and GNU-style `--entry=<symbol>` before link inputs. Both forms select the same resolved global/weak entry symbol; `_start` remains the default when no explicit entry is provided.

An explicit CLI entry overrides a bounded linker-script `ENTRY(symbol)` directive. Mixed split/equals duplicates are rejected as duplicate `--entry` options, and `--entry=` is rejected before link-input or output I/O.

This compatibility slice does not change the existing option-placement rule: entry selection remains part of the pre-input link-option prefix. It also does not broaden linker-script grammar or symbol-resolution semantics.
