# GNU `--output=<file>` compatibility

The public `link` command accepts GNU ld's long equals output form in addition to the existing split `-o <file>` form:

```sh
mini-elf-toolchain link --output=a.out start.o
```

The equals value must be non-empty and is validated before link-input I/O. This checkpoint only adds the `--output=<file>` spelling; it does not broaden output-option placement or add other output aliases.
