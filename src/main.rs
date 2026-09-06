use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::forced_undefined::{
    extract_forced_undefined_arguments, ForcedUndefinedArgumentError,
};
use mini_elf_toolchain::image_base::{extract_image_base_argument, ImageBaseArgumentError};
use mini_elf_toolchain::input_object::RelocatableObject;
use mini_elf_toolchain::library_search::{resolve_static_library_arguments, LibrarySearchError};
use mini_elf_toolchain::ordered_inputs::{
    prepare_ordered_link_inputs_with_forced_undefined, OrderedLinkInput, OrderedLinkInputError,
};
use mini_elf_toolchain::static_link::link_static_executable_with_map;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const DEFAULT_PAGE_ALIGNMENT: u64 = 0x1000;
const DEFAULT_ENTRY_SYMBOL: &str = "_start";
const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const START_GROUP: &str = "--start-group";
const END_GROUP: &str = "--end-group";
const WHOLE_ARCHIVE: &str = "--whole-archive";
const NO_WHOLE_ARCHIVE: &str = "--no-whole-archive";
const PUSH_STATE: &str = "--push-state";
const POP_STATE: &str = "--pop-state";

const USAGE: &str = "usage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...\n       mini-elf-toolchain link <-o <output>|--output=<output>> [--map <map-file>|-Map <map-file>|-Map=<map-file>] [--entry <symbol>] [--image-base <address>] [-u <symbol>|-u<symbol>|--undefined <symbol>] [-L <dir>|-L<dir>] <input|-l<name>|-l <name>|--start-group|--end-group|--whole-archive|--no-whole-archive|--push-state|--pop-state>...";

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(CliError::Usage(message)) => {
            eprintln!("{message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(CliError::Failure(message)) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CliError {
    Usage(String),
    Failure(String),
}

fn run<I>(mut args: I) -> Result<String, CliError>
where
    I: Iterator<Item = OsString>,
{
    let command = args
        .next()
        .ok_or_else(|| CliError::Usage("missing command".to_owned()))?;

    if command == "--help" || command == "-h" {
        return Ok(USAGE.to_owned());
    }

    if command == "validate" {
        let input = args
            .next()
            .ok_or_else(|| CliError::Usage("missing input path".to_owned()))?;
        if args.next().is_some() {
            return Err(CliError::Usage("too many arguments".to_owned()));
        }
        return validate_file(&input);
    }

    if command == "validate-rel" {
        let inputs: Vec<_> = args.collect();
        if inputs.is_empty() {
            return Err(CliError::Usage("missing relocatable input path".to_owned()));
        }
        return validate_relocatable_files(&inputs);
    }

    if command == "link" {
        let output_flag = args
            .next()
            .ok_or_else(|| CliError::Usage("missing -o <output>".to_owned()))?;
        let output = if output_flag == "-o" {
            args.next()
                .ok_or_else(|| CliError::Usage("missing output path after -o".to_owned()))?
        } else if let Some(path) = output_flag
            .to_str()
            .and_then(|argument| argument.strip_prefix("--output="))
        {
            if path.is_empty() {
                return Err(CliError::Usage("output path cannot be empty".to_owned()));
            }
            OsString::from(path)
        } else {
            return Err(CliError::Usage(
                "expected -o <output> after link".to_owned(),
            ));
        };
        let raw_remaining: Vec<_> = args.collect();
        let forced =
            extract_forced_undefined_arguments(&raw_remaining).map_err(forced_undefined_error)?;
        let image_base =
            extract_image_base_argument(&forced.arguments).map_err(image_base_error)?;
        let mut remaining = image_base.arguments;
        let mut map_output = None;
        let mut entry_symbol = OsString::from(DEFAULT_ENTRY_SYMBOL);
        let mut entry_seen = false;

        while let Some(argument) = remaining.first() {
            if argument == "--map" || argument == "-Map" {
                if remaining.len() < 2 {
                    let option = argument.to_string_lossy();
                    return Err(CliError::Usage(format!("missing map path after {option}")));
                }
                if map_output.is_some() {
                    return Err(CliError::Usage("duplicate --map option".to_owned()));
                }
                if remaining[1].is_empty() {
                    return Err(CliError::Usage("map path cannot be empty".to_owned()));
                }
                map_output = Some(remaining[1].clone());
                remaining.drain(0..2);
            } else if let Some(path) = argument
                .to_str()
                .and_then(|argument| argument.strip_prefix("-Map="))
            {
                if map_output.is_some() {
                    return Err(CliError::Usage("duplicate --map option".to_owned()));
                }
                if path.is_empty() {
                    return Err(CliError::Usage("map path cannot be empty".to_owned()));
                }
                map_output = Some(OsString::from(path));
                remaining.drain(0..1);
            } else if argument == "--entry" {
                if remaining.len() < 2 {
                    return Err(CliError::Usage(
                        "missing entry symbol after --entry".to_owned(),
                    ));
                }
                if entry_seen {
                    return Err(CliError::Usage("duplicate --entry option".to_owned()));
                }
                if remaining[1].is_empty() {
                    return Err(CliError::Usage("entry symbol cannot be empty".to_owned()));
                }
                entry_symbol = remaining[1].clone();
                entry_seen = true;
                remaining.drain(0..2);
            } else {
                break;
            }
        }

        let remaining =
            resolve_static_library_arguments(&remaining).map_err(library_search_error)?;
        if remaining.is_empty() {
            return Err(CliError::Usage("missing relocatable input path".to_owned()));
        }
        return link_files(
            &output,
            map_output.as_ref(),
            &entry_symbol,
            image_base.image_base,
            &forced.symbols,
            &remaining,
        );
    }

    Err(CliError::Usage(format!(
        "unknown command '{}'",
        command.to_string_lossy()
    )))
}

fn forced_undefined_error(error: ForcedUndefinedArgumentError) -> CliError {
    CliError::Usage(error.to_string())
}

fn image_base_error(error: ImageBaseArgumentError) -> CliError {
    CliError::Usage(error.to_string())
}

fn library_search_error(error: LibrarySearchError) -> CliError {
    match error {
        LibrarySearchError::MissingSearchPath
        | LibrarySearchError::EmptySearchPath
        | LibrarySearchError::MissingLibraryName
        | LibrarySearchError::EmptyLibraryName => CliError::Usage(error.to_string()),
        _ => CliError::Failure(format!("library search failed: {error}")),
    }
}

fn validate_file(path: &OsString) -> Result<String, CliError> {
    let file = read_file(path)?;
    let header = Elf64Header::parse(&file)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))?;
    let sections = header
        .section_headers(&file)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))?;
    let symbol_tables = header
        .symbol_tables(&file, &sections)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))?;
    let symbol_count = symbol_tables.iter().try_fold(0usize, |total, table| {
        total.checked_add(table.symbols.len())
    });
    let symbol_count = symbol_count.ok_or_else(|| {
        CliError::Failure(format!(
            "{}: total symbol count overflows host usize",
            path.to_string_lossy()
        ))
    })?;

    Ok(format!(
        "valid ELF64 x86-64: sections={}, symbol_tables={}, symbols={symbol_count}",
        sections.len(),
        symbol_tables.len()
    ))
}

fn validate_relocatable_files(paths: &[OsString]) -> Result<String, CliError> {
    let mut section_count = 0usize;
    let mut symbol_table_count = 0usize;
    let mut symbol_count = 0usize;
    let mut rela_table_count = 0usize;
    let mut relocation_count = 0usize;

    for path in paths {
        let file = read_file(path)?;
        let object = RelocatableObject::parse(&file)
            .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))?;

        section_count = checked_total(section_count, object.sections.len(), "section")?;
        symbol_table_count = checked_total(
            symbol_table_count,
            object.symbol_tables.len(),
            "symbol-table",
        )?;
        rela_table_count = checked_total(rela_table_count, object.rela_tables.len(), "RELA-table")?;

        for table in &object.symbol_tables {
            symbol_count = checked_total(symbol_count, table.symbols.len(), "symbol")?;
        }
        for table in &object.rela_tables {
            relocation_count =
                checked_total(relocation_count, table.relocations.len(), "relocation")?;
        }
    }

    Ok(format!(
        "valid relocatable ELF64 x86-64 inputs: objects={}, sections={section_count}, symbol_tables={symbol_table_count}, symbols={symbol_count}, rela_tables={rela_table_count}, relocations={relocation_count}",
        paths.len()
    ))
}

#[derive(Clone, Copy)]
struct LoadedLinkInputRef {
    file_index: usize,
    whole_archive: bool,
}

struct LoadedLinkInputSequence {
    files: Vec<Vec<u8>>,
    paths: Vec<OsString>,
    sequence: Vec<LoadedLinkInputRef>,
}

fn link_files(
    output: &OsString,
    map_output: Option<&OsString>,
    entry_symbol: &OsString,
    image_base: u64,
    forced_undefined: &[Vec<u8>],
    paths: &[OsString],
) -> Result<String, CliError> {
    let loaded = load_link_input_sequence(paths)?;
    let ordered_inputs = loaded
        .sequence
        .iter()
        .map(|input| {
            let file = &loaded.files[input.file_index];
            if file.starts_with(ARCHIVE_MAGIC) {
                if input.whole_archive {
                    OrderedLinkInput::WholeArchive(file)
                } else {
                    OrderedLinkInput::Archive(file)
                }
            } else {
                OrderedLinkInput::Object(file)
            }
        })
        .collect::<Vec<_>>();
    let expanded_paths = loaded
        .sequence
        .iter()
        .map(|input| loaded.paths[input.file_index].clone())
        .collect::<Vec<_>>();
    let prepared =
        prepare_ordered_link_inputs_with_forced_undefined(&ordered_inputs, forced_undefined)
            .map_err(|error| ordered_input_failure(&expanded_paths, error))?;
    let entry_symbol = entry_symbol.to_string_lossy();

    let linked = link_static_executable_with_map(
        &prepared.objects,
        image_base,
        DEFAULT_PAGE_ALIGNMENT,
        entry_symbol.as_bytes(),
    )
    .map_err(|error| CliError::Failure(format!("link failed: {error}")))?;

    fs::write(output, &linked.image.bytes)
        .map_err(|error| CliError::Failure(format!("{}: {error}", output.to_string_lossy())))?;
    set_executable_permissions(output)?;

    if let Some(map_output) = map_output {
        fs::write(map_output, linked.link_map.render()).map_err(|error| {
            CliError::Failure(format!("{}: {error}", map_output.to_string_lossy()))
        })?;
    }

    Ok(format!(
        "linked static ELF64 x86-64: output={}, objects={}, bytes={}, entry={:#x}",
        output.to_string_lossy(),
        prepared.objects.len(),
        linked.image.bytes.len(),
        linked.image.entry_address
    ))
}

fn load_link_input_sequence(paths: &[OsString]) -> Result<LoadedLinkInputSequence, CliError> {
    let mut files = Vec::new();
    let mut loaded_paths = Vec::new();
    let mut sequence = Vec::new();
    let mut input_index = 0usize;
    let mut whole_archive = false;
    let mut state_stack = Vec::new();

    while input_index < paths.len() {
        if paths[input_index] == PUSH_STATE {
            state_stack.push(whole_archive);
            input_index += 1;
            continue;
        }
        if paths[input_index] == POP_STATE {
            whole_archive = state_stack
                .pop()
                .ok_or_else(|| CliError::Usage("unmatched --pop-state".to_owned()))?;
            input_index += 1;
            continue;
        }
        if paths[input_index] == WHOLE_ARCHIVE {
            whole_archive = true;
            input_index += 1;
            continue;
        }
        if paths[input_index] == NO_WHOLE_ARCHIVE {
            whole_archive = false;
            input_index += 1;
            continue;
        }
        if paths[input_index] == END_GROUP {
            return Err(CliError::Usage("unmatched --end-group".to_owned()));
        }
        if paths[input_index] != START_GROUP {
            let file = read_file(&paths[input_index])?;
            let file_index = files.len();
            files.push(file);
            loaded_paths.push(paths[input_index].clone());
            sequence.push(LoadedLinkInputRef {
                file_index,
                whole_archive,
            });
            input_index += 1;
            continue;
        }

        input_index += 1;
        let mut group_inputs = Vec::new();
        let mut archive_inputs = Vec::new();
        let mut ordinary_member_count = 0usize;

        while input_index < paths.len() && paths[input_index] != END_GROUP {
            if paths[input_index] == START_GROUP {
                return Err(CliError::Usage(
                    "nested --start-group is not supported".to_owned(),
                ));
            }
            if paths[input_index] == PUSH_STATE {
                state_stack.push(whole_archive);
                input_index += 1;
                continue;
            }
            if paths[input_index] == POP_STATE {
                whole_archive = state_stack
                    .pop()
                    .ok_or_else(|| CliError::Usage("unmatched --pop-state".to_owned()))?;
                input_index += 1;
                continue;
            }
            if paths[input_index] == WHOLE_ARCHIVE {
                whole_archive = true;
                input_index += 1;
                continue;
            }
            if paths[input_index] == NO_WHOLE_ARCHIVE {
                whole_archive = false;
                input_index += 1;
                continue;
            }

            let path = paths[input_index].clone();
            let file = read_file(&path)?;
            let file_index = files.len();
            if file.starts_with(ARCHIVE_MAGIC) && !whole_archive {
                let archive = Archive::parse(&file).map_err(|error| {
                    CliError::Failure(format!("{}: {error}", path.to_string_lossy()))
                })?;
                let member_count = archive
                    .members
                    .iter()
                    .filter(|member| member.kind == ArchiveMemberKind::Ordinary)
                    .count();
                ordinary_member_count =
                    checked_total(ordinary_member_count, member_count, "archive-group member")?;
                archive_inputs.push(LoadedLinkInputRef {
                    file_index,
                    whole_archive: false,
                });
            }
            files.push(file);
            loaded_paths.push(path);
            group_inputs.push(LoadedLinkInputRef {
                file_index,
                whole_archive,
            });
            input_index += 1;
        }

        if input_index == paths.len() {
            return Err(CliError::Usage("missing --end-group".to_owned()));
        }
        if group_inputs.is_empty() {
            return Err(CliError::Usage("archive group cannot be empty".to_owned()));
        }

        sequence.extend(group_inputs);
        for _ in 0..ordinary_member_count {
            sequence.extend(archive_inputs.iter().copied());
        }
        input_index += 1;
    }

    if !state_stack.is_empty() {
        return Err(CliError::Usage("missing --pop-state".to_owned()));
    }
    if sequence.is_empty() {
        return Err(CliError::Usage("missing relocatable input path".to_owned()));
    }

    Ok(LoadedLinkInputSequence {
        files,
        paths: loaded_paths,
        sequence,
    })
}

fn ordered_input_failure(paths: &[OsString], error: OrderedLinkInputError) -> CliError {
    let input_index = match &error {
        OrderedLinkInputError::InvalidObject { input_index, .. }
        | OrderedLinkInputError::ObjectSymbols { input_index, .. }
        | OrderedLinkInputError::UnsupportedBinding { input_index, .. }
        | OrderedLinkInputError::InvalidArchive { input_index, .. }
        | OrderedLinkInputError::InvalidArchiveIndex { input_index, .. }
        | OrderedLinkInputError::MissingArchiveIndex { input_index }
        | OrderedLinkInputError::InvalidArchiveMember { input_index, .. }
        | OrderedLinkInputError::ArchiveExtraction { input_index, .. } => *input_index,
    };

    match paths.get(input_index) {
        Some(path) => CliError::Failure(format!("{}: {error}", path.to_string_lossy())),
        None => CliError::Failure(format!("link input {input_index}: {error}")),
    }
}

#[cfg(unix)]
fn set_executable_permissions(path: &OsString) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &OsString) -> Result<(), CliError> {
    Ok(())
}

fn read_file(path: &OsString) -> Result<Vec<u8>, CliError> {
    fs::read(path)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))
}

fn checked_total(total: usize, addend: usize, kind: &str) -> Result<usize, CliError> {
    total
        .checked_add(addend)
        .ok_or_else(|| CliError::Failure(format!("total {kind} count overflows host usize")))
}

#[cfg(test)]
mod tests {
    use super::{run, CliError, USAGE};
    use std::ffi::OsString;

    #[test]
    fn help_is_available_without_input() {
        assert_eq!(
            run([OsString::from("--help")].into_iter()),
            Ok(USAGE.to_owned())
        );
    }

    #[test]
    fn unknown_command_is_usage_error() {
        assert_eq!(
            run([OsString::from("frobnicate")].into_iter()),
            Err(CliError::Usage("unknown command 'frobnicate'".to_owned()))
        );
    }

    #[test]
    fn validate_rejects_extra_arguments_before_io() {
        let args = [
            OsString::from("validate"),
            OsString::from("one.o"),
            OsString::from("two.o"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("too many arguments".to_owned()))
        );
    }

    #[test]
    fn validate_rel_requires_at_least_one_input() {
        assert_eq!(
            run([OsString::from("validate-rel")].into_iter()),
            Err(CliError::Usage("missing relocatable input path".to_owned()))
        );
    }

    #[test]
    fn link_requires_output_flag_before_io() {
        let args = [OsString::from("link"), OsString::from("input.o")];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage(
                "expected -o <output> after link".to_owned()
            ))
        );
    }

    #[test]
    fn link_requires_at_least_one_input_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("missing relocatable input path".to_owned()))
        );
    }

    #[test]
    fn link_whole_archive_markers_alone_are_not_inputs() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--whole-archive"),
            OsString::from("--no-whole-archive"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("missing relocatable input path".to_owned()))
        );
    }

    #[test]
    fn link_state_stack_rejects_unmatched_pop_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--pop-state"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("unmatched --pop-state".to_owned()))
        );
    }

    #[test]
    fn link_state_stack_requires_balanced_pop_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--push-state"),
            OsString::from("--whole-archive"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("missing --pop-state".to_owned()))
        );
    }

    #[test]
    fn link_forced_undefined_requires_symbol_before_io() {
        let missing = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-u"),
        ];
        assert_eq!(
            run(missing.into_iter()),
            Err(CliError::Usage(
                "missing symbol after -u/--undefined".to_owned()
            ))
        );

        let empty = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--undefined"),
            OsString::new(),
        ];
        assert_eq!(
            run(empty.into_iter()),
            Err(CliError::Usage(
                "forced undefined symbol cannot be empty".to_owned()
            ))
        );
    }

    #[test]
    fn link_image_base_requires_valid_single_value_before_io() {
        let missing = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--image-base"),
        ];
        assert_eq!(
            run(missing.into_iter()),
            Err(CliError::Usage(
                "missing address after --image-base".to_owned()
            ))
        );

        let overflow = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--image-base"),
            OsString::from("0x10000000000000000"),
            OsString::from("input.o"),
        ];
        assert!(
            matches!(run(overflow.into_iter()), Err(CliError::Usage(message)) if message.contains("invalid image base"))
        );

        let duplicate = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--image-base"),
            OsString::from("0x400000"),
            OsString::from("--image-base"),
            OsString::from("0x800000"),
            OsString::from("input.o"),
        ];
        assert_eq!(
            run(duplicate.into_iter()),
            Err(CliError::Usage("duplicate --image-base option".to_owned()))
        );
    }

    #[test]
    fn link_library_options_require_values_before_io() {
        let missing_path = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-L"),
        ];
        assert_eq!(
            run(missing_path.into_iter()),
            Err(CliError::Usage("missing directory after -L".to_owned()))
        );

        let missing_name = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-l"),
        ];
        assert_eq!(
            run(missing_name.into_iter()),
            Err(CliError::Usage("missing library name after -l".to_owned()))
        );
    }

    #[test]
    fn link_map_requires_map_path_before_io() {
        for option in ["--map", "-Map"] {
            let args = [
                OsString::from("link"),
                OsString::from("-o"),
                OsString::from("a.out"),
                OsString::from(option),
            ];
            assert_eq!(
                run(args.into_iter()),
                Err(CliError::Usage(format!("missing map path after {option}")))
            );
        }
    }

    #[test]
    fn link_map_rejects_empty_split_path_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-Map"),
            OsString::new(),
            OsString::from("input.o"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("map path cannot be empty".to_owned()))
        );
    }

    #[test]
    fn link_map_rejects_empty_attached_path_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-Map="),
            OsString::from("input.o"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("map path cannot be empty".to_owned()))
        );
    }

    #[test]
    fn link_map_rejects_mixed_duplicate_forms_before_io() {
        let forms = [
            vec![
                OsString::from("-Map"),
                OsString::from("first.map"),
                OsString::from("--map"),
                OsString::from("second.map"),
            ],
            vec![
                OsString::from("-Map=first.map"),
                OsString::from("-Map"),
                OsString::from("second.map"),
            ],
        ];
        for form in forms {
            let mut args = vec![
                OsString::from("link"),
                OsString::from("-o"),
                OsString::from("a.out"),
            ];
            args.extend(form);
            args.push(OsString::from("input.o"));
            assert_eq!(
                run(args.into_iter()),
                Err(CliError::Usage("duplicate --map option".to_owned()))
            );
        }
    }

    #[test]
    fn link_entry_requires_symbol_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--entry"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage(
                "missing entry symbol after --entry".to_owned()
            ))
        );
    }

    #[test]
    fn link_entry_rejects_empty_symbol_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--entry"),
            OsString::new(),
            OsString::from("input.o"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("entry symbol cannot be empty".to_owned()))
        );
    }

    #[test]
    fn link_entry_rejects_duplicate_default_symbol_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--entry"),
            OsString::from("_start"),
            OsString::from("--entry"),
            OsString::from("custom_entry"),
            OsString::from("input.o"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("duplicate --entry option".to_owned()))
        );
    }

    #[test]
    fn link_group_rejects_unmatched_end_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--end-group"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("unmatched --end-group".to_owned()))
        );
    }

    #[test]
    fn link_group_requires_end_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--start-group"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage("missing --end-group".to_owned()))
        );
    }

    #[test]
    fn link_group_rejects_nested_group_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--start-group"),
            OsString::from("--start-group"),
            OsString::from("--end-group"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage(
                "nested --start-group is not supported".to_owned()
            ))
        );
    }
}
