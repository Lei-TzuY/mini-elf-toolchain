# `--image-base=<address>`

The static linker accepts GNU-style long-option assignment for the existing checked image-base override:

```sh
mini-elf-toolchain link -o app --image-base=0x800000 start.o
```

The value uses the same unsigned 64-bit hexadecimal or decimal parser as split `--image-base <address>`. Empty, malformed, and overflowing values are rejected before output emission. The option remains mutually exclusive with linker-script image-base selection and duplicate split/equals forms are rejected.

This is only a CLI compatibility form; it does not change layout semantics, page alignment, linker-script grammar, or dynamic-link behavior.
