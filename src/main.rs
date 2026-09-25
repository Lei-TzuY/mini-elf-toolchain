use mini_elf_toolchain::archive::{Archive, ArchiveMemberKind};
use mini_elf_toolchain::dynamic_provider::{inspect_dynamic_provider, DynamicProviderMetadata};
use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::forced_undefined::{
    extract_forced_undefined_arguments, ForcedUndefinedArgumentError,
};
use mini_elf_toolchain::image_base::{extract_image_base_argument, ImageBaseArgumentError};
use mini_elf_toolchain::input_object::RelocatableObject;
use mini_elf_toolchain::library_search::{
    resolve_shared_library_arguments, resolve_static_library_arguments, LibrarySearchError,
};
use mini_elf_toolchain::ordered_inputs::{
    prepare_ordered_link_inputs_with_forced_undefined, LinkObjectOrigin, OrderedLinkInput,
    OrderedLinkInputError,
};
use mini_elf_toolchain::partial_link::{
    link_relocatable_objects_with_forced_undefined, PartialLinkInput,
};
use mini_elf_toolchain::provider_closure::resolve_provider_path;
use mini_elf_toolchain::shared_object::{
    dynamic_pie_import_requirements, link_dynamic_pie_with_checked_providers,
    link_shared_object_with_version_script_and_checked_providers, shared_import_requirements,
    DynamicPieCopyRelocation, DynamicPieLinkOptions, SharedImportRequirement,
    SharedObjectLinkOptions, SharedVersionRequirement,
};
use mini_elf_toolchain::static_link::{
    link_static_executable_with_map, link_static_position_independent_executable_with_map,
};
use mini_elf_toolchain::version_script::VersionScript;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_PAGE_ALIGNMENT: u64 = 0x1000;
const DEFAULT_ENTRY_SYMBOL: &str = "_start";
const STT_FUNC: u8 = 2;
const STT_GNU_IFUNC: u8 = 10;
const ARCHIVE_MAGIC: &[u8] = b"!<arch>\n";
const START_GROUP: &str = "--start-group";
const END_GROUP: &str = "--end-group";
const WHOLE_ARCHIVE: &str = "--whole-archive";
const NO_WHOLE_ARCHIVE: &str = "--no-whole-archive";
const PUSH_STATE: &str = "--push-state";
const POP_STATE: &str = "--pop-state";

const USAGE: &str = "usage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...\n       mini-elf-toolchain partial <-o <output>|--output=<output>> [-u <symbol>|-u<symbol>|--undefined <symbol>] [-L <dir>|-L<dir>] <input|-l<name>|-l <name>|--start-group|--end-group|--whole-archive|--no-whole-archive>...\n       mini-elf-toolchain link <-o <output>|--output=<output>> [--pie|--dynamic-pie|--shared] [-Bsymbolic] [-z ibtplt|-z ibt|-z now|-z pack-relative-relocs] [--dynamic-linker <path>|--dynamic-linker=<path>] [--soname <name>|--soname=<name>] [--runpath <path>|--runpath=<path>] [-init <symbol>|-init=<symbol>] [-fini <symbol>|-fini=<symbol>] [--version-script <file>|--version-script=<file>] [--needed <soname>|--needed=<soname>|--needed-from <provider>|--needed-from=<provider>] [--map <map-file>|-Map <map-file>|-Map=<map-file>] [--entry <symbol>] [--image-base <address>] [-u <symbol>|-u<symbol>|--undefined <symbol>] [-L <dir>|-L<dir>] <input|-l<name>|-l <name>|--start-group|--end-group|--whole-archive|--no-whole-archive|--push-state|--pop-state>...";

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

    if command == "partial" {
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
                "expected -o <output> after partial".to_owned(),
            ));
        };
        let raw_inputs = args.collect::<Vec<_>>();
        let forced =
            extract_forced_undefined_arguments(&raw_inputs).map_err(forced_undefined_error)?;
        validate_partial_group_nesting(&forced.arguments)?;
        let inputs =
            resolve_static_library_arguments(&forced.arguments).map_err(library_search_error)?;
        if inputs.is_empty() {
            return Err(CliError::Usage("missing relocatable input path".to_owned()));
        }
        return partial_files(&output, &forced.symbols, &inputs);
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
        let (position_independent, raw_remaining) = extract_pie_argument(&raw_remaining)?;
        let (dynamic_pie, raw_remaining) = extract_dynamic_pie_argument(&raw_remaining)?;
        let (shared_object, raw_remaining) = extract_shared_argument(&raw_remaining)?;
        let dynamic_linker = extract_dynamic_linker_argument(&raw_remaining)?;
        let lifecycle_hooks = extract_dynamic_lifecycle_hook_arguments(&dynamic_linker.arguments)?;
        let raw_remaining = lifecycle_hooks.arguments;
        if dynamic_pie && dynamic_linker.path.is_none() {
            return Err(CliError::Usage(
                "--dynamic-pie requires --dynamic-linker <absolute-path>".to_owned(),
            ));
        }
        if !dynamic_pie && dynamic_linker.path.is_some() {
            return Err(CliError::Usage(
                "--dynamic-linker is only supported with --dynamic-pie".to_owned(),
            ));
        }
        if !(dynamic_pie || shared_object)
            && (lifecycle_hooks.init.is_some() || lifecycle_hooks.fini.is_some())
        {
            return Err(CliError::Usage(
                "-init/-fini are only supported with --dynamic-pie or --shared".to_owned(),
            ));
        }
        let (symbolic, raw_remaining) = extract_symbolic_argument(&raw_remaining)?;
        if symbolic && !shared_object {
            return Err(CliError::Usage(
                "-Bsymbolic is only supported with --shared".to_owned(),
            ));
        }
        let (ibt_plt, raw_remaining) = extract_ibt_plt_argument(&raw_remaining)?;
        if ibt_plt && !(shared_object || dynamic_pie) {
            return Err(CliError::Usage(
                "-z ibtplt is only supported with --shared or --dynamic-pie".to_owned(),
            ));
        }
        let (ibt, raw_remaining) = extract_ibt_argument(&raw_remaining)?;
        if ibt && !(shared_object || dynamic_pie) {
            return Err(CliError::Usage(
                "-z ibt is only supported with --shared or --dynamic-pie".to_owned(),
            ));
        }
        let (bind_now, raw_remaining) = extract_bind_now_argument(&raw_remaining)?;
        if bind_now && !(shared_object || dynamic_pie) {
            return Err(CliError::Usage(
                "-z now is only supported with --shared or --dynamic-pie".to_owned(),
            ));
        }
        let (pack_relative_relocs, raw_remaining) =
            extract_pack_relative_relocs_argument(&raw_remaining)?;
        if pack_relative_relocs && !dynamic_pie {
            return Err(CliError::Usage(
                "-z pack-relative-relocs is only supported with --dynamic-pie".to_owned(),
            ));
        }
        let soname = extract_soname_argument(&raw_remaining)?;
        if !shared_object && soname.soname.is_some() {
            return Err(CliError::Usage(
                "--soname is only supported with --shared".to_owned(),
            ));
        }
        let runpath = extract_runpath_argument(&soname.arguments)?;
        if !(shared_object || dynamic_pie) && runpath.runpath.is_some() {
            return Err(CliError::Usage(
                "--runpath is only supported with --shared or --dynamic-pie".to_owned(),
            ));
        }
        let mut needed = extract_needed_arguments(&runpath.arguments)?;
        if !(shared_object || dynamic_pie) && !needed.specs.is_empty() {
            let provider_requested = needed
                .specs
                .iter()
                .any(|spec| matches!(spec, NeededSpec::Provider(_)));
            return Err(CliError::Usage(
                if provider_requested {
                    "--needed-from is only supported with --shared or --dynamic-pie"
                } else {
                    "--needed is only supported with --shared or --dynamic-pie"
                }
                .to_owned(),
            ));
        }
        let version_script = extract_version_script_argument(&needed.arguments)?;
        if !shared_object && version_script.path.is_some() {
            return Err(CliError::Usage(
                "--version-script is only supported with --shared".to_owned(),
            ));
        }
        let parsed_version_script = if let Some(path) = version_script.path.as_ref() {
            let bytes = read_file(path)?;
            Some(VersionScript::parse(&bytes).map_err(|error| {
                CliError::Failure(format!("{}: {error}", path.to_string_lossy()))
            })?)
        } else {
            None
        };
        let raw_remaining = version_script.arguments;
        let selected_dynamic_modes = usize::from(position_independent)
            + usize::from(dynamic_pie)
            + usize::from(shared_object);
        if selected_dynamic_modes > 1 {
            return Err(CliError::Usage(
                "--pie, --dynamic-pie, and --shared are mutually exclusive".to_owned(),
            ));
        }
        if (position_independent || dynamic_pie || shared_object)
            && contains_image_base_argument(&raw_remaining)
        {
            let mode = if shared_object {
                "--shared"
            } else if dynamic_pie {
                "--dynamic-pie"
            } else {
                "--pie"
            };
            return Err(CliError::Usage(format!(
                "{mode} cannot be combined with --image-base"
            )));
        }
        let forced =
            extract_forced_undefined_arguments(&raw_remaining).map_err(forced_undefined_error)?;
        if (shared_object || dynamic_pie) && !forced.symbols.is_empty() {
            return Err(CliError::Usage(format!(
                "{} does not support forced undefined roots",
                if shared_object {
                    "--shared"
                } else {
                    "--dynamic-pie"
                }
            )));
        }
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

        if (shared_object || dynamic_pie) && map_output.is_some() {
            return Err(CliError::Usage(format!(
                "{} does not support link map output",
                if shared_object {
                    "--shared"
                } else {
                    "--dynamic-pie"
                }
            )));
        }
        if shared_object && entry_seen {
            return Err(CliError::Usage(
                "--shared does not support --entry".to_owned(),
            ));
        }

        let mut provider_search_paths = Vec::new();
        let remaining = if shared_object || dynamic_pie {
            let resolution =
                resolve_shared_library_arguments(&remaining).map_err(library_search_error)?;
            provider_search_paths = resolution.search_paths;
            needed.specs.extend(
                resolution
                    .providers
                    .into_iter()
                    .map(|path| NeededSpec::Provider(path.into_os_string())),
            );
            resolution.arguments
        } else {
            resolve_static_library_arguments(&remaining).map_err(library_search_error)?
        };
        if remaining.is_empty() {
            return Err(CliError::Usage("missing relocatable input path".to_owned()));
        }
        let options = LinkFilesOptions {
            map_output: map_output.as_ref(),
            entry_symbol: &entry_symbol,
            image_base: image_base.image_base,
            position_independent,
            dynamic_pie,
            dynamic_linker: dynamic_linker.path.as_deref(),
            init_symbol: lifecycle_hooks.init.as_deref(),
            fini_symbol: lifecycle_hooks.fini.as_deref(),
            shared_object,
            symbolic,
            ibt_plt,
            ibt,
            bind_now,
            pack_relative_relocs,
            soname: soname.soname.as_deref(),
            runpath: runpath.runpath.as_deref(),
            needed: &needed.specs,
            provider_search_paths: &provider_search_paths,
            forced_undefined: &forced.symbols,
            version_script: parsed_version_script.as_ref(),
        };
        return link_files(&output, &options, &remaining);
    }

    Err(CliError::Usage(format!(
        "unknown command '{}'",
        command.to_string_lossy()
    )))
}

fn validate_partial_group_nesting(arguments: &[OsString]) -> Result<(), CliError> {
    let mut depth = 0usize;
    for argument in arguments {
        if argument == START_GROUP || argument == "-(" {
            if depth != 0 {
                return Err(CliError::Usage(
                    "nested --start-group is not supported".to_owned(),
                ));
            }
            depth = 1;
        } else if argument == END_GROUP || argument == "-)" {
            depth = depth.saturating_sub(1);
        }
    }
    Ok(())
}

fn extract_pie_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut position_independent = false;
    let mut remaining = Vec::with_capacity(arguments.len());

    for argument in arguments {
        if argument == "--pie" {
            if position_independent {
                return Err(CliError::Usage("duplicate --pie option".to_owned()));
            }
            position_independent = true;
        } else if argument
            .to_str()
            .is_some_and(|argument| argument.starts_with("--pie="))
        {
            return Err(CliError::Usage("--pie does not accept a value".to_owned()));
        } else {
            remaining.push(argument.clone());
        }
    }

    Ok((position_independent, remaining))
}

fn extract_dynamic_pie_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut dynamic_pie = false;
    let mut remaining = Vec::with_capacity(arguments.len());

    for argument in arguments {
        if argument == "--dynamic-pie" {
            if dynamic_pie {
                return Err(CliError::Usage("duplicate --dynamic-pie option".to_owned()));
            }
            dynamic_pie = true;
        } else if argument
            .to_str()
            .is_some_and(|argument| argument.starts_with("--dynamic-pie="))
        {
            return Err(CliError::Usage(
                "--dynamic-pie does not accept a value".to_owned(),
            ));
        } else {
            remaining.push(argument.clone());
        }
    }

    Ok((dynamic_pie, remaining))
}

struct DynamicLinkerArguments {
    path: Option<Vec<u8>>,
    arguments: Vec<OsString>,
}

fn extract_dynamic_linker_argument(
    arguments: &[OsString],
) -> Result<DynamicLinkerArguments, CliError> {
    let mut path = None;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        let value = if argument == "--dynamic-linker" {
            index += 1;
            Some(
                arguments
                    .get(index)
                    .ok_or_else(|| {
                        CliError::Usage("missing path after --dynamic-linker".to_owned())
                    })?
                    .to_str()
                    .ok_or_else(|| {
                        CliError::Usage("dynamic linker path must be valid UTF-8".to_owned())
                    })?
                    .to_owned(),
            )
        } else {
            argument
                .to_str()
                .and_then(|argument| argument.strip_prefix("--dynamic-linker="))
                .map(ToOwned::to_owned)
        };

        if let Some(value) = value {
            if path.is_some() {
                return Err(CliError::Usage(
                    "duplicate --dynamic-linker option".to_owned(),
                ));
            }
            if value.is_empty() {
                return Err(CliError::Usage(
                    "dynamic linker path cannot be empty".to_owned(),
                ));
            }
            if !value.starts_with('/') {
                return Err(CliError::Usage(
                    "dynamic linker path must be absolute".to_owned(),
                ));
            }
            path = Some(value.into_bytes());
        } else {
            remaining.push(argument.clone());
        }
        index += 1;
    }

    Ok(DynamicLinkerArguments {
        path,
        arguments: remaining,
    })
}

struct DynamicLifecycleHookArguments {
    init: Option<Vec<u8>>,
    fini: Option<Vec<u8>>,
    arguments: Vec<OsString>,
}

fn extract_dynamic_lifecycle_hook_arguments(
    arguments: &[OsString],
) -> Result<DynamicLifecycleHookArguments, CliError> {
    let mut init = None;
    let mut fini = None;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        let (kind, value) = if argument == "-init" || argument == "-fini" {
            let kind = if argument == "-init" { "init" } else { "fini" };
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| CliError::Usage(format!("missing symbol after -{kind}")))?
                .to_str()
                .ok_or_else(|| {
                    CliError::Usage(format!("symbol after -{kind} must be valid UTF-8"))
                })?
                .to_owned();
            (Some(kind), Some(value))
        } else if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("-init="))
        {
            (Some("init"), Some(value.to_owned()))
        } else if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("-fini="))
        {
            (Some("fini"), Some(value.to_owned()))
        } else {
            (None, None)
        };

        if let (Some(kind), Some(value)) = (kind, value) {
            let slot = if kind == "init" { &mut init } else { &mut fini };
            if slot.is_some() {
                return Err(CliError::Usage(format!("duplicate -{kind} option")));
            }
            if value.is_empty() {
                return Err(CliError::Usage(format!("-{kind} symbol cannot be empty")));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage(format!(
                    "-{kind} symbol cannot contain NUL"
                )));
            }
            *slot = Some(value.into_bytes());
        } else {
            remaining.push(argument.clone());
        }
        index += 1;
    }

    Ok(DynamicLifecycleHookArguments {
        init,
        fini,
        arguments: remaining,
    })
}

fn extract_shared_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut shared = false;
    let mut remaining = Vec::with_capacity(arguments.len());

    for argument in arguments {
        if argument == "--shared" {
            if shared {
                return Err(CliError::Usage("duplicate --shared option".to_owned()));
            }
            shared = true;
        } else if argument
            .to_str()
            .is_some_and(|argument| argument.starts_with("--shared="))
        {
            return Err(CliError::Usage(
                "--shared does not accept a value".to_owned(),
            ));
        } else {
            remaining.push(argument.clone());
        }
    }

    Ok((shared, remaining))
}

fn extract_symbolic_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut symbolic = false;
    let mut remaining = Vec::with_capacity(arguments.len());

    for argument in arguments {
        if argument == "-Bsymbolic" {
            if symbolic {
                return Err(CliError::Usage("duplicate -Bsymbolic option".to_owned()));
            }
            symbolic = true;
        } else if argument
            .to_str()
            .is_some_and(|argument| argument.starts_with("-Bsymbolic="))
        {
            return Err(CliError::Usage(
                "-Bsymbolic does not accept a value".to_owned(),
            ));
        } else {
            remaining.push(argument.clone());
        }
    }

    Ok((symbolic, remaining))
}

fn extract_ibt_plt_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut ibt_plt = false;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        if arguments[index] == "-z"
            && arguments
                .get(index + 1)
                .is_some_and(|keyword| keyword == "ibtplt")
        {
            if ibt_plt {
                return Err(CliError::Usage("duplicate -z ibtplt option".to_owned()));
            }
            ibt_plt = true;
            index += 2;
            continue;
        }
        remaining.push(arguments[index].clone());
        index += 1;
    }

    Ok((ibt_plt, remaining))
}

fn extract_ibt_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut ibt = false;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        if arguments[index] == "-z"
            && arguments
                .get(index + 1)
                .is_some_and(|keyword| keyword == "ibt")
        {
            if ibt {
                return Err(CliError::Usage("duplicate -z ibt option".to_owned()));
            }
            ibt = true;
            index += 2;
            continue;
        }
        remaining.push(arguments[index].clone());
        index += 1;
    }

    Ok((ibt, remaining))
}

fn extract_bind_now_argument(arguments: &[OsString]) -> Result<(bool, Vec<OsString>), CliError> {
    let mut bind_now = false;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        if arguments[index] == "-z"
            && arguments
                .get(index + 1)
                .is_some_and(|keyword| keyword == "now")
        {
            if bind_now {
                return Err(CliError::Usage("duplicate -z now option".to_owned()));
            }
            bind_now = true;
            index += 2;
            continue;
        }
        remaining.push(arguments[index].clone());
        index += 1;
    }

    Ok((bind_now, remaining))
}

fn extract_pack_relative_relocs_argument(
    arguments: &[OsString],
) -> Result<(bool, Vec<OsString>), CliError> {
    let mut pack_relative_relocs = false;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        if arguments[index] == "-z"
            && arguments
                .get(index + 1)
                .is_some_and(|keyword| keyword == "pack-relative-relocs")
        {
            if pack_relative_relocs {
                return Err(CliError::Usage(
                    "duplicate -z pack-relative-relocs option".to_owned(),
                ));
            }
            pack_relative_relocs = true;
            index += 2;
            continue;
        }
        remaining.push(arguments[index].clone());
        index += 1;
    }

    Ok((pack_relative_relocs, remaining))
}

struct SonameArguments {
    soname: Option<Vec<u8>>,
    arguments: Vec<OsString>,
}

fn extract_soname_argument(arguments: &[OsString]) -> Result<SonameArguments, CliError> {
    let mut soname = None;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--soname" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| CliError::Usage("missing name after --soname".to_owned()))?;
            if soname.is_some() {
                return Err(CliError::Usage("duplicate --soname option".to_owned()));
            }
            let value = value.to_str().ok_or_else(|| {
                CliError::Usage("SONAME after --soname must be valid UTF-8".to_owned())
            })?;
            if value.is_empty() {
                return Err(CliError::Usage("SONAME cannot be empty".to_owned()));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage("SONAME cannot contain NUL".to_owned()));
            }
            soname = Some(value.as_bytes().to_vec());
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--soname="))
        {
            if soname.is_some() {
                return Err(CliError::Usage("duplicate --soname option".to_owned()));
            }
            if value.is_empty() {
                return Err(CliError::Usage("SONAME cannot be empty".to_owned()));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage("SONAME cannot contain NUL".to_owned()));
            }
            soname = Some(value.as_bytes().to_vec());
            index += 1;
            continue;
        }

        remaining.push(argument.clone());
        index += 1;
    }

    Ok(SonameArguments {
        soname,
        arguments: remaining,
    })
}

struct RunpathArguments {
    runpath: Option<Vec<u8>>,
    arguments: Vec<OsString>,
}

fn extract_runpath_argument(arguments: &[OsString]) -> Result<RunpathArguments, CliError> {
    let mut runpath = None;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--runpath" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| CliError::Usage("missing path after --runpath".to_owned()))?;
            if runpath.is_some() {
                return Err(CliError::Usage("duplicate --runpath option".to_owned()));
            }
            let value = value.to_str().ok_or_else(|| {
                CliError::Usage("RUNPATH after --runpath must be valid UTF-8".to_owned())
            })?;
            if value.is_empty() {
                return Err(CliError::Usage("RUNPATH cannot be empty".to_owned()));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage("RUNPATH cannot contain NUL".to_owned()));
            }
            runpath = Some(value.as_bytes().to_vec());
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--runpath="))
        {
            if runpath.is_some() {
                return Err(CliError::Usage("duplicate --runpath option".to_owned()));
            }
            if value.is_empty() {
                return Err(CliError::Usage("RUNPATH cannot be empty".to_owned()));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage("RUNPATH cannot contain NUL".to_owned()));
            }
            runpath = Some(value.as_bytes().to_vec());
            index += 1;
            continue;
        }

        remaining.push(argument.clone());
        index += 1;
    }

    Ok(RunpathArguments {
        runpath,
        arguments: remaining,
    })
}

#[derive(Debug, Clone)]
enum NeededSpec {
    Name(Vec<u8>),
    Provider(OsString),
}

struct NeededArguments {
    specs: Vec<NeededSpec>,
    arguments: Vec<OsString>,
}

fn extract_needed_arguments(arguments: &[OsString]) -> Result<NeededArguments, CliError> {
    let mut specs = Vec::new();
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--needed" {
            let value = arguments.get(index + 1).ok_or_else(|| {
                CliError::Usage("missing dependency name after --needed".to_owned())
            })?;
            let value = value.to_str().ok_or_else(|| {
                CliError::Usage("dependency name after --needed must be valid UTF-8".to_owned())
            })?;
            if value.is_empty() {
                return Err(CliError::Usage(
                    "dependency name after --needed cannot be empty".to_owned(),
                ));
            }
            if value.as_bytes().contains(&0) {
                return Err(CliError::Usage(
                    "dependency name after --needed cannot contain NUL".to_owned(),
                ));
            }
            specs.push(NeededSpec::Name(value.as_bytes().to_vec()));
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--needed="))
        {
            if value.is_empty() {
                return Err(CliError::Usage(
                    "dependency name after --needed= cannot be empty".to_owned(),
                ));
            }
            specs.push(NeededSpec::Name(value.as_bytes().to_vec()));
            index += 1;
            continue;
        }
        if argument == "--needed-from" {
            let path = arguments.get(index + 1).ok_or_else(|| {
                CliError::Usage("missing provider path after --needed-from".to_owned())
            })?;
            if path.is_empty() {
                return Err(CliError::Usage(
                    "provider path after --needed-from cannot be empty".to_owned(),
                ));
            }
            specs.push(NeededSpec::Provider(path.clone()));
            index += 2;
            continue;
        }
        if let Some(path) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--needed-from="))
        {
            if path.is_empty() {
                return Err(CliError::Usage(
                    "provider path after --needed-from= cannot be empty".to_owned(),
                ));
            }
            specs.push(NeededSpec::Provider(OsString::from(path)));
            index += 1;
            continue;
        }

        remaining.push(argument.clone());
        index += 1;
    }

    Ok(NeededArguments {
        specs,
        arguments: remaining,
    })
}

struct VersionScriptArguments {
    path: Option<OsString>,
    arguments: Vec<OsString>,
}

fn extract_version_script_argument(
    arguments: &[OsString],
) -> Result<VersionScriptArguments, CliError> {
    let mut path = None;
    let mut remaining = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--version-script" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| CliError::Usage("missing file after --version-script".to_owned()))?;
            if path.is_some() {
                return Err(CliError::Usage(
                    "duplicate --version-script option".to_owned(),
                ));
            }
            if value.is_empty() {
                return Err(CliError::Usage(
                    "version-script path cannot be empty".to_owned(),
                ));
            }
            path = Some(value.clone());
            index += 2;
            continue;
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--version-script="))
        {
            if path.is_some() {
                return Err(CliError::Usage(
                    "duplicate --version-script option".to_owned(),
                ));
            }
            if value.is_empty() {
                return Err(CliError::Usage(
                    "version-script path cannot be empty".to_owned(),
                ));
            }
            path = Some(OsString::from(value));
            index += 1;
            continue;
        }

        remaining.push(argument.clone());
        index += 1;
    }

    Ok(VersionScriptArguments {
        path,
        arguments: remaining,
    })
}

fn contains_image_base_argument(arguments: &[OsString]) -> bool {
    arguments.iter().any(|argument| {
        argument == "--image-base"
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with("--image-base="))
    })
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

fn partial_files(
    output: &OsString,
    forced_undefined: &[Vec<u8>],
    paths: &[OsString],
) -> Result<String, CliError> {
    for argument in paths {
        if argument == PUSH_STATE || argument == POP_STATE {
            return Err(CliError::Usage(format!(
                "'{}' is not supported by partial linking",
                argument.to_string_lossy()
            )));
        }
    }

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
    let inputs = prepared
        .objects
        .iter()
        .map(|object| PartialLinkInput { file: object.file })
        .collect::<Vec<_>>();
    let bytes = link_relocatable_objects_with_forced_undefined(&inputs, forced_undefined)
        .map_err(|error| partial_input_failure(&expanded_paths, &prepared.origins, error))?;

    fs::write(output, &bytes)
        .map_err(|error| CliError::Failure(format!("{}: {error}", output.to_string_lossy())))?;

    Ok(format!(
        "partial ELF64 x86-64: output={}, objects={}, bytes={}",
        output.to_string_lossy(),
        prepared.objects.len(),
        bytes.len()
    ))
}

fn partial_input_failure(
    paths: &[OsString],
    origins: &[LinkObjectOrigin],
    error: mini_elf_toolchain::partial_link::PartialLinkError,
) -> CliError {
    let Some(object_index) = error.input_index() else {
        return CliError::Failure(format!("partial link failed: {error}"));
    };
    match origins.get(object_index) {
        Some(LinkObjectOrigin::Regular { input_index }) => match paths.get(*input_index) {
            Some(path) => CliError::Failure(format!("{}: {error}", path.to_string_lossy())),
            None => CliError::Failure(format!("partial link input {object_index}: {error}")),
        },
        Some(LinkObjectOrigin::ArchiveMember {
            input_index,
            member_name,
            ..
        }) => match paths.get(*input_index) {
            Some(path) => CliError::Failure(format!(
                "{}({}): {error}",
                path.to_string_lossy(),
                String::from_utf8_lossy(member_name)
            )),
            None => CliError::Failure(format!("partial link input {object_index}: {error}")),
        },
        None => CliError::Failure(format!("partial link input {object_index}: {error}")),
    }
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

struct LinkFilesOptions<'a> {
    map_output: Option<&'a OsString>,
    entry_symbol: &'a OsString,
    image_base: u64,
    position_independent: bool,
    dynamic_pie: bool,
    dynamic_linker: Option<&'a [u8]>,
    init_symbol: Option<&'a [u8]>,
    fini_symbol: Option<&'a [u8]>,
    shared_object: bool,
    symbolic: bool,
    ibt_plt: bool,
    ibt: bool,
    bind_now: bool,
    pack_relative_relocs: bool,
    soname: Option<&'a [u8]>,
    runpath: Option<&'a [u8]>,
    needed: &'a [NeededSpec],
    provider_search_paths: &'a [PathBuf],
    forced_undefined: &'a [Vec<u8>],
    version_script: Option<&'a VersionScript>,
}

struct ResolvedNeededDependencies {
    names: Vec<Vec<u8>>,
    version_requirements: Vec<SharedVersionRequirement>,
    checked_version_providers: Vec<Vec<u8>>,
    copy_relocations: Vec<DynamicPieCopyRelocation>,
}

#[derive(Default)]
struct TransitiveProviderMatches {
    matched_any: bool,
    version_requirements: Vec<SharedVersionRequirement>,
}

fn resolve_needed_dependencies(
    specs: &[NeededSpec],
    imports: &[SharedImportRequirement],
    search_paths: &[PathBuf],
) -> Result<ResolvedNeededDependencies, CliError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut names = Vec::new();
    let mut version_requirements =
        std::collections::BTreeMap::<Vec<u8>, SharedVersionRequirement>::new();
    let mut copy_relocations =
        std::collections::BTreeMap::<Vec<u8>, DynamicPieCopyRelocation>::new();

    for spec in specs {
        let name = match spec {
            NeededSpec::Name(name) => name.clone(),
            NeededSpec::Provider(path) => {
                let root_path = PathBuf::from(path);
                let root_file = read_provider_file(&root_path, "shared dependency provider")?;
                let provider = inspect_dynamic_provider(&root_file).map_err(|error| {
                    CliError::Failure(format!(
                        "{}: cannot inspect shared dependency provider: {error}",
                        root_path.display()
                    ))
                })?;

                let direct_matches = imports
                    .iter()
                    .filter(|import| provider_matches_import(&provider, import))
                    .collect::<Vec<_>>();
                let direct_match = !direct_matches.is_empty();

                for import in &direct_matches {
                    if import.requires_copy && !copy_relocations.contains_key(&import.linker_name) {
                        if import.version.is_some() {
                            return Err(CliError::Failure(format!(
                                "{}: dynamic PIE COPY relocation {:?} must be unversioned in this bounded phase",
                                root_path.display(),
                                String::from_utf8_lossy(&import.name)
                            )));
                        }
                        let sizes = provider
                            .export_sizes
                            .get(&(import.name.clone(), import.symbol_type))
                            .ok_or_else(|| {
                                CliError::Failure(format!(
                                    "{}: checked direct provider {:?} has no size metadata for dynamic PIE COPY symbol {:?}",
                                    root_path.display(),
                                    String::from_utf8_lossy(&provider.soname),
                                    String::from_utf8_lossy(&import.name)
                                ))
                            })?;
                        if sizes.len() != 1 {
                            return Err(CliError::Failure(format!(
                                "{}: checked direct provider {:?} has ambiguous sizes {:?} for dynamic PIE COPY symbol {:?}",
                                root_path.display(),
                                String::from_utf8_lossy(&provider.soname),
                                sizes,
                                String::from_utf8_lossy(&import.name)
                            )));
                        }
                        let size = *sizes.iter().next().expect("non-empty unique size set");
                        if size == 0 {
                            return Err(CliError::Failure(format!(
                                "{}: dynamic PIE COPY symbol {:?} requires nonzero provider size",
                                root_path.display(),
                                String::from_utf8_lossy(&import.name)
                            )));
                        }
                        copy_relocations.insert(
                            import.linker_name.clone(),
                            DynamicPieCopyRelocation {
                                linker_name: import.linker_name.clone(),
                                size,
                            },
                        );
                    }

                    let Some(version) = import.version.as_ref() else {
                        continue;
                    };
                    version_requirements
                        .entry(import.linker_name.clone())
                        .or_insert_with(|| SharedVersionRequirement {
                            linker_name: import.linker_name.clone(),
                            provider: provider.soname.clone(),
                            version: version.clone(),
                        });
                }

                let missing_versioned = imports
                    .iter()
                    .filter(|import| {
                        import.version.is_some()
                            && !version_requirements.contains_key(&import.linker_name)
                    })
                    .map(|import| import.linker_name.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                let transitive = if !direct_match || !missing_versioned.is_empty() {
                    inspect_transitive_provider_exports(
                        &root_path,
                        &provider,
                        search_paths,
                        imports,
                        &missing_versioned,
                    )?
                } else {
                    TransitiveProviderMatches::default()
                };
                for requirement in transitive.version_requirements {
                    version_requirements
                        .entry(requirement.linker_name.clone())
                        .or_insert(requirement);
                }
                let matched = direct_match || transitive.matched_any;
                if !matched {
                    if let Some(import) = imports.iter().find(|import| import.version.is_some()) {
                        let version = import
                            .version
                            .as_deref()
                            .expect("versioned import predicate guarantees a version");
                        return Err(CliError::Failure(format!(
                            "{}: provider SONAME {:?} and its checked transitive dependency closure do not satisfy named-version import {:?}@{:?}",
                            root_path.display(),
                            String::from_utf8_lossy(&provider.soname),
                            String::from_utf8_lossy(&import.name),
                            String::from_utf8_lossy(version)
                        )));
                    }
                    return Err(CliError::Failure(format!(
                        "{}: provider SONAME {:?} and its checked transitive dependency closure exports none of the consumer's bounded external imports",
                        root_path.display(),
                        String::from_utf8_lossy(&provider.soname)
                    )));
                }

                provider.soname
            }
        };
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }

    for import in imports {
        if import.requires_copy && !copy_relocations.contains_key(&import.linker_name) {
            return Err(CliError::Failure(format!(
                "dynamic PIE COPY symbol {:?} requires a checked direct provider with nonzero provider size metadata",
                String::from_utf8_lossy(&import.name)
            )));
        }
        let Some(version) = import.version.as_ref() else {
            continue;
        };
        if !version_requirements.contains_key(&import.linker_name) {
            return Err(CliError::Failure(format!(
                "versioned shared import {:?}@{:?} requires a checked direct/transitive provider exporting the requested symbol version",
                String::from_utf8_lossy(&import.name),
                String::from_utf8_lossy(version)
            )));
        }
    }

    let version_requirements = version_requirements.into_values().collect::<Vec<_>>();
    let mut checked_version_providers = names.clone();
    for requirement in &version_requirements {
        if !checked_version_providers
            .iter()
            .any(|provider| provider == &requirement.provider)
        {
            checked_version_providers.push(requirement.provider.clone());
        }
    }

    Ok(ResolvedNeededDependencies {
        names,
        version_requirements,
        checked_version_providers,
        copy_relocations: copy_relocations.into_values().collect(),
    })
}

fn provider_symbol_types_match_import(
    provider_types: &std::collections::BTreeSet<u8>,
    import_type: u8,
) -> bool {
    provider_types.contains(&import_type)
        || (import_type == STT_FUNC && provider_types.contains(&STT_GNU_IFUNC))
}

fn provider_matches_import(
    provider: &DynamicProviderMetadata,
    import: &SharedImportRequirement,
) -> bool {
    let matches_type = |types: &std::collections::BTreeSet<u8>| {
        provider_symbol_types_match_import(types, import.symbol_type)
    };
    match &import.version {
        Some(version) => provider
            .versioned_exports
            .get(&(import.name.clone(), version.clone()))
            .is_some_and(matches_type),
        None => provider.exports.get(&import.name).is_some_and(matches_type),
    }
}

fn inspect_transitive_provider_exports(
    root_path: &Path,
    root: &DynamicProviderMetadata,
    search_paths: &[PathBuf],
    imports: &[SharedImportRequirement],
    required_versioned: &std::collections::BTreeSet<Vec<u8>>,
) -> Result<TransitiveProviderMatches, CliError> {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    let root_canonical = fs::canonicalize(root_path).map_err(|error| {
        CliError::Failure(format!(
            "{}: cannot canonicalize shared dependency provider: {error}",
            root_path.display()
        ))
    })?;
    let mut visited = BTreeSet::new();
    visited.insert(root_canonical);

    let root_parent = root_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut queue = VecDeque::new();
    for needed in &root.needed {
        queue.push_back((needed.clone(), root_parent.clone(), root.runpath.clone()));
    }

    let mut matched_any = false;
    let mut version_requirements = BTreeMap::<Vec<u8>, SharedVersionRequirement>::new();

    while let Some((needed, provider_directory, runpath)) = queue.pop_front() {
        let dependency_path = resolve_provider_path(
            &needed,
            &provider_directory,
            runpath.as_deref(),
            search_paths,
        )
        .map_err(|error| CliError::Failure(error.to_string()))?;
        let canonical = fs::canonicalize(&dependency_path).map_err(|error| {
            CliError::Failure(format!(
                "{}: cannot canonicalize transitive shared provider dependency {:?}: {error}",
                dependency_path.display(),
                String::from_utf8_lossy(&needed)
            ))
        })?;
        if !visited.insert(canonical) {
            continue;
        }

        let file = read_provider_file(&dependency_path, "transitive shared provider dependency")?;
        let provider = inspect_dynamic_provider(&file).map_err(|error| {
            CliError::Failure(format!(
                "{}: cannot inspect transitive shared provider dependency {:?}: {error}",
                dependency_path.display(),
                String::from_utf8_lossy(&needed)
            ))
        })?;

        for import in imports {
            if !provider_matches_import(&provider, import) {
                continue;
            }
            matched_any = true;
            if !required_versioned.contains(&import.linker_name) {
                continue;
            }
            let Some(version) = import.version.as_ref() else {
                continue;
            };
            version_requirements
                .entry(import.linker_name.clone())
                .or_insert_with(|| SharedVersionRequirement {
                    linker_name: import.linker_name.clone(),
                    provider: provider.soname.clone(),
                    version: version.clone(),
                });
        }

        if matched_any
            && required_versioned
                .iter()
                .all(|name| version_requirements.contains_key(name))
        {
            return Ok(TransitiveProviderMatches {
                matched_any,
                version_requirements: version_requirements.into_values().collect(),
            });
        }

        let parent = dependency_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        for child in &provider.needed {
            queue.push_back((child.clone(), parent.clone(), provider.runpath.clone()));
        }
    }

    Ok(TransitiveProviderMatches {
        matched_any,
        version_requirements: version_requirements.into_values().collect(),
    })
}

fn read_provider_file(path: &Path, role: &str) -> Result<Vec<u8>, CliError> {
    fs::read(path).map_err(|error| {
        CliError::Failure(format!("{}: cannot read {role}: {error}", path.display()))
    })
}

fn link_files(
    output: &OsString,
    options: &LinkFilesOptions<'_>,
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
        options.forced_undefined,
    )
    .map_err(|error| ordered_input_failure(&expanded_paths, error))?;
    if options.shared_object || options.dynamic_pie {
        let imports = if options.dynamic_pie {
            dynamic_pie_import_requirements(&prepared.objects)
        } else {
            shared_import_requirements(&prepared.objects)
        }
        .map_err(|error| CliError::Failure(format!("loader image link failed: {error}")))?;
        let needed =
            resolve_needed_dependencies(options.needed, &imports, options.provider_search_paths)?;
        let image = if options.dynamic_pie {
            let interpreter = options.dynamic_linker.ok_or_else(|| {
                CliError::Usage("--dynamic-pie requires --dynamic-linker".to_owned())
            })?;
            link_dynamic_pie_with_checked_providers(
                &prepared.objects,
                DEFAULT_PAGE_ALIGNMENT,
                DynamicPieLinkOptions {
                    needed: &needed.names,
                    runpath: options.runpath,
                    version_requirements: &needed.version_requirements,
                    checked_version_providers: &needed.checked_version_providers,
                    entry_symbol: options.entry_symbol.to_string_lossy().as_bytes(),
                    interpreter,
                    init_symbol: options.init_symbol,
                    fini_symbol: options.fini_symbol,
                    ibt_plt: options.ibt_plt,
                    gnu_property_ibt: options.ibt,
                    bind_now: options.bind_now,
                    pack_relative_relocs: options.pack_relative_relocs,
                    copy_relocations: &needed.copy_relocations,
                },
            )
        } else {
            link_shared_object_with_version_script_and_checked_providers(
                &prepared.objects,
                DEFAULT_PAGE_ALIGNMENT,
                SharedObjectLinkOptions {
                    needed: &needed.names,
                    soname: options.soname,
                    runpath: options.runpath,
                    version_requirements: &needed.version_requirements,
                    checked_version_providers: &needed.checked_version_providers,
                    version_script: options.version_script,
                    symbolic: options.symbolic,
                    ibt_plt: options.ibt_plt,
                    gnu_property_ibt: options.ibt,
                    bind_now: options.bind_now,
                    init_symbol: options.init_symbol,
                    fini_symbol: options.fini_symbol,
                },
            )
        }
        .map_err(|error| CliError::Failure(format!("loader image link failed: {error}")))?;
        fs::write(output, &image.bytes)
            .map_err(|error| CliError::Failure(format!("{}: {error}", output.to_string_lossy())))?;
        if options.dynamic_pie {
            set_executable_permissions(output)?;
        }
        return Ok(format!(
            "{}: output={}, objects={}, bytes={}",
            if options.dynamic_pie {
                "linked dynamic PIE ELF64 x86-64"
            } else {
                "linked shared ELF64 x86-64"
            },
            output.to_string_lossy(),
            prepared.objects.len(),
            image.bytes.len()
        ));
    }

    let entry_symbol = options.entry_symbol.to_string_lossy();
    let linked = if options.position_independent {
        link_static_position_independent_executable_with_map(
            &prepared.objects,
            DEFAULT_PAGE_ALIGNMENT,
            entry_symbol.as_bytes(),
        )
    } else {
        link_static_executable_with_map(
            &prepared.objects,
            options.image_base,
            DEFAULT_PAGE_ALIGNMENT,
            entry_symbol.as_bytes(),
        )
    }
    .map_err(|error| CliError::Failure(format!("link failed: {error}")))?;

    fs::write(output, &linked.image.bytes)
        .map_err(|error| CliError::Failure(format!("{}: {error}", output.to_string_lossy())))?;
    set_executable_permissions(output)?;

    if let Some(map_output) = options.map_output {
        fs::write(map_output, linked.link_map.render()).map_err(|error| {
            CliError::Failure(format!("{}: {error}", map_output.to_string_lossy()))
        })?;
    }

    Ok(format!(
        "{}: output={}, objects={}, bytes={}, entry={:#x}",
        if options.position_independent {
            "linked static PIE ELF64 x86-64"
        } else {
            "linked static ELF64 x86-64"
        },
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
    use super::{
        provider_symbol_types_match_import, run, CliError, STT_FUNC, STT_GNU_IFUNC, USAGE,
    };
    use std::collections::BTreeSet;
    use std::ffi::OsString;

    #[test]
    fn ifunc_provider_type_only_satisfies_function_imports() {
        let provider_types = BTreeSet::from([STT_GNU_IFUNC]);
        assert!(provider_symbol_types_match_import(
            &provider_types,
            STT_FUNC
        ));
        assert!(!provider_symbol_types_match_import(&provider_types, 1));
        assert!(!provider_symbol_types_match_import(&provider_types, 6));
    }

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
