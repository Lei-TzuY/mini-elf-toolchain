use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::forced_undefined::{
    extract_forced_undefined_arguments, ForcedUndefinedArgumentError,
};
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

const DEFAULT_START_ADDRESS: u64 = 0x400000;
const DEFAULT_PAGE_ALIGNMENT: u64 = 0x1000;
const DEFAULT_ENTRY_SYMBOL: &str = "_start";
const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const START_GROUP: &str = "--start-group";
const END_GROUP: &str = "--end-group";
const WHOLE_ARCHIVE: &str = "--whole-archive";
const NO_WHOLE_ARCHIVE: &str = "--no-whole-archive";

const USAGE: &str = "usage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...\n       mini-elf-toolchain link -o <output> [--map <map-file>] [--entry <symbol>] [-u <symbol>|-u<symbol>|--undefined <symbol>] [-L <dir>|-L<dir>] <input|-l<name>|-l <name>|--start-group|--end-group|--whole-archive|--no-whole-archive>...";

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

    if command != "link" {
        return Err(CliError::Usage(format!(
            "unknown command '{}'",
            command.to_string_lossy()
        )));
    }

    let output_flag = args
        .next()
        .ok_or_else(|| CliError::Usage("missing -o <output>".to_owned()))?;
    if output_flag != "-o" {
        return Err(CliError::Usage(
            "expected -o <output> after link".to_owned(),
        ));
    }
    let output = args
        .next()
        .ok_or_else(|| CliError::Usage("missing output path after -o".to_owned()))?;

    let raw_remaining = args.collect::<Vec<_>>();
    let forced = extract_forced_undefined_arguments(&raw_remaining)
        .map_err(forced_undefined_error)?;
    let mut remaining = forced.arguments;
    let mut map_output = None;
    let mut entry_symbol = OsString::from(DEFAULT_ENTRY_SYMBOL);
    let mut entry_seen = false;

    while let Some(argument) = remaining.first() {
        if argument == "--map" {
            if remaining.len() < 2 {
                return Err(CliError::Usage("missing map path after --map".to_owned()));
            }
            if map_output.is_some() {
                return Err(CliError::Usage("duplicate --map option".to_owned()));
            }
            map_output = Some(remaining[1].clone());
            remaining.drain(0..2);
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

    let remaining = resolve_static_library_arguments(&remaining).map_err(library_search_error)?;
    if remaining.is_empty() {
        return Err(CliError::Usage("missing relocatable input path".to_owned()));
    }

    link_files(
        &output,
        map_output.as_ref(),
        &entry_symbol,
        &forced.symbols,
        &remaining,
    )
}

fn forced_undefined_error(error: ForcedUndefinedArgumentError) -> CliError {
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
    let symbol_count = symbol_tables
        .iter()
        .try_fold(0usize, |total, table| total.checked_add(table.symbols.len()))
        .ok_or_else(|| {
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
            relocation_count = checked_total(relocation_count, table.relocations.len(), "relocation")?;
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
    let prepared = prepare_ordered_link_inputs_with_forced_undefined(
        &ordered_inputs,
        forced_undefined,
    )
    .map_err(|error| ordered_input_failure(&expanded_paths, error))?;
    let entry_symbol = entry_symbol.to_string_lossy();

    let linked = link_static_executable_with_map(
        &prepared.objects,
        DEFAULT_START_ADDRESS,
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

    while input_index < paths.len() {
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
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
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
        assert_eq!(run([OsString::from("--help")].into_iter()), Ok(USAGE.to_owned()));
    }

    #[test]
    fn link_forced_undefined_rejects_missing_symbol_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("-u"),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage(
                "missing symbol after -u/--undefined".to_owned()
            ))
        );
    }

    #[test]
    fn link_forced_undefined_rejects_empty_symbol_before_io() {
        let args = [
            OsString::from("link"),
            OsString::from("-o"),
            OsString::from("a.out"),
            OsString::from("--undefined"),
            OsString::new(),
        ];
        assert_eq!(
            run(args.into_iter()),
            Err(CliError::Usage(
                "forced undefined symbol cannot be empty".to_owned()
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
}
