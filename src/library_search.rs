use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

const START_GROUP: &str = "--start-group";
const END_GROUP: &str = "--end-group";
const START_GROUP_ALIAS: &str = "-(";
const END_GROUP_ALIAS: &str = "-)";

#[derive(Debug)]
pub enum LibrarySearchError {
    MissingSearchPath,
    EmptySearchPath,
    MissingLibraryName,
    EmptyLibraryName,
    SearchPathMetadata {
        path: PathBuf,
        source: std::io::Error,
    },
    SearchPathNotDirectory {
        path: PathBuf,
    },
    LibraryNotFound {
        filename: OsString,
        search_paths: Vec<PathBuf>,
    },
}

impl fmt::Display for LibrarySearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSearchPath => write!(f, "missing directory after -L"),
            Self::EmptySearchPath => write!(f, "library search directory cannot be empty"),
            Self::MissingLibraryName => write!(f, "missing library name after -l"),
            Self::EmptyLibraryName => write!(f, "library name cannot be empty"),
            Self::SearchPathMetadata { path, source } => {
                write!(
                    f,
                    "cannot inspect library search directory '{}': {source}",
                    path.display()
                )
            }
            Self::SearchPathNotDirectory { path } => {
                write!(
                    f,
                    "library search path '{}' is not a directory",
                    path.display()
                )
            }
            Self::LibraryNotFound {
                filename,
                search_paths,
            } => {
                write!(
                    f,
                    "cannot find static library '{}'",
                    filename.to_string_lossy()
                )?;
                if search_paths.is_empty() {
                    write!(f, "; no -L search directories were provided")
                } else {
                    write!(f, " in")?;
                    for path in search_paths {
                        write!(f, " '{}'", path.display())?;
                    }
                    Ok(())
                }
            }
        }
    }
}

impl std::error::Error for LibrarySearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SearchPathMetadata { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn resolve_static_library_arguments(
    arguments: &[OsString],
) -> Result<Vec<OsString>, LibrarySearchError> {
    let flatten_nested_groups = archive_group_markers_balanced(arguments);
    let mut search_paths = Vec::new();
    let mut resolved = Vec::with_capacity(arguments.len());
    let mut index = 0usize;
    let mut group_depth = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if is_start_group(argument) {
            if !flatten_nested_groups || group_depth == 0 {
                resolved.push(OsString::from(START_GROUP));
            }
            group_depth += 1;
            index += 1;
            continue;
        }
        if is_end_group(argument) {
            if !flatten_nested_groups {
                resolved.push(OsString::from(END_GROUP));
            } else if group_depth > 0 {
                group_depth -= 1;
                if group_depth == 0 {
                    resolved.push(OsString::from(END_GROUP));
                }
            } else {
                resolved.push(OsString::from(END_GROUP));
            }
            index += 1;
            continue;
        }
        if argument == "-L" || argument == "--library-path" {
            let path = arguments
                .get(index + 1)
                .ok_or(LibrarySearchError::MissingSearchPath)?;
            add_search_path(path, &mut search_paths)?;
            index += 2;
            continue;
        }
        if let Some(path) = strip_os_prefix(argument, "--library-path=") {
            add_search_path(&path, &mut search_paths)?;
            index += 1;
            continue;
        }
        if let Some(path) = strip_os_prefix(argument, "-L") {
            add_search_path(&path, &mut search_paths)?;
            index += 1;
            continue;
        }
        if argument == "-l" || argument == "--library" {
            let name = arguments
                .get(index + 1)
                .ok_or(LibrarySearchError::MissingLibraryName)?;
            resolved.push(resolve_library(name, &search_paths)?);
            index += 2;
            continue;
        }
        if let Some(name) = strip_os_prefix(argument, "--library=") {
            resolved.push(resolve_library(&name, &search_paths)?);
            index += 1;
            continue;
        }
        if let Some(name) = strip_os_prefix(argument, "-l") {
            resolved.push(resolve_library(&name, &search_paths)?);
            index += 1;
            continue;
        }

        resolved.push(argument.clone());
        index += 1;
    }

    Ok(resolved)
}

fn is_start_group(argument: &OsStr) -> bool {
    argument == START_GROUP || argument == START_GROUP_ALIAS
}

fn is_end_group(argument: &OsStr) -> bool {
    argument == END_GROUP || argument == END_GROUP_ALIAS
}

fn archive_group_markers_balanced(arguments: &[OsString]) -> bool {
    let mut depth = 0usize;
    for argument in arguments {
        if is_start_group(argument) {
            depth += 1;
        } else if is_end_group(argument) {
            if depth == 0 {
                return false;
            }
            depth -= 1;
        }
    }
    depth == 0
}

fn add_search_path(
    path: &OsStr,
    search_paths: &mut Vec<PathBuf>,
) -> Result<(), LibrarySearchError> {
    if path.is_empty() {
        return Err(LibrarySearchError::EmptySearchPath);
    }
    let path = PathBuf::from(path);
    let metadata =
        fs::metadata(&path).map_err(|source| LibrarySearchError::SearchPathMetadata {
            path: path.clone(),
            source,
        })?;
    if !metadata.is_dir() {
        return Err(LibrarySearchError::SearchPathNotDirectory { path });
    }
    search_paths.push(path);
    Ok(())
}

fn resolve_library(name: &OsStr, search_paths: &[PathBuf]) -> Result<OsString, LibrarySearchError> {
    if name.is_empty() {
        return Err(LibrarySearchError::EmptyLibraryName);
    }

    let filename = if let Some(exact) = strip_os_prefix(name, ":") {
        if exact.is_empty() {
            return Err(LibrarySearchError::EmptyLibraryName);
        }
        exact
    } else {
        let mut filename = OsString::from("lib");
        filename.push(name);
        filename.push(".a");
        filename
    };

    for directory in search_paths {
        let candidate = directory.join(Path::new(&filename));
        if candidate.is_file() {
            return Ok(candidate.into_os_string());
        }
    }

    Err(LibrarySearchError::LibraryNotFound {
        filename,
        search_paths: search_paths.to_vec(),
    })
}

#[cfg(unix)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = value.as_bytes();
    let prefix = prefix.as_bytes();
    bytes
        .starts_with(prefix)
        .then(|| OsString::from_vec(bytes[prefix.len()..].to_vec()))
}

#[cfg(windows)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    let text = value.to_str()?;
    text.strip_prefix(prefix).map(OsString::from)
}

#[cfg(test)]
mod tests {
    use super::{resolve_static_library_arguments, LibrarySearchError};
    use std::ffi::OsString;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mini-elf-toolchain-library-search-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp directory");
        path
    }

    #[test]
    fn resolves_split_joined_and_long_equals_search_paths_in_place() {
        let first = temp_dir();
        let second = temp_dir();
        let third = temp_dir();
        fs::write(first.join("libfoo.a"), b"archive").expect("write foo");
        fs::write(second.join("libbar.a"), b"archive").expect("write bar");
        fs::write(third.join("libbaz.a"), b"archive").expect("write baz");
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("-L"),
            first.as_os_str().to_os_string(),
            OsString::from("-lfoo"),
            OsString::from("--whole-archive"),
            OsString::from(format!("-L{}", second.display())),
            OsString::from("-l"),
            OsString::from("bar"),
            OsString::from("--no-whole-archive"),
            OsString::from(format!("--library-path={}", third.display())),
            OsString::from("--library=baz"),
        ];
        let resolved = resolve_static_library_arguments(&arguments).expect("resolve libraries");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                first.join("libfoo.a").into_os_string(),
                OsString::from("--whole-archive"),
                second.join("libbar.a").into_os_string(),
                OsString::from("--no-whole-archive"),
                third.join("libbaz.a").into_os_string(),
            ]
        );
        fs::remove_dir_all(first).expect("remove first temp directory");
        fs::remove_dir_all(second).expect("remove second temp directory");
        fs::remove_dir_all(third).expect("remove third temp directory");
    }

    #[test]
    fn flattens_nested_archive_group_markers_without_reordering_inputs() {
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("--start-group"),
            OsString::from("liba.a"),
            OsString::from("--start-group"),
            OsString::from("libb.a"),
            OsString::from("--end-group"),
            OsString::from("libc.a"),
            OsString::from("--end-group"),
            OsString::from("tail.o"),
        ];

        let resolved = resolve_static_library_arguments(&arguments).expect("flatten nested group");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                OsString::from("--start-group"),
                OsString::from("liba.a"),
                OsString::from("libb.a"),
                OsString::from("libc.a"),
                OsString::from("--end-group"),
                OsString::from("tail.o"),
            ]
        );
    }

    #[test]
    fn canonicalizes_gnu_short_archive_group_aliases() {
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("-("),
            OsString::from("liba.a"),
            OsString::from("--start-group"),
            OsString::from("libb.a"),
            OsString::from("-)"),
            OsString::from("libc.a"),
            OsString::from("--end-group"),
            OsString::from("tail.o"),
        ];

        let resolved =
            resolve_static_library_arguments(&arguments).expect("canonicalize aliases");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                OsString::from("--start-group"),
                OsString::from("liba.a"),
                OsString::from("libb.a"),
                OsString::from("libc.a"),
                OsString::from("--end-group"),
                OsString::from("tail.o"),
            ]
        );
    }

    #[test]
    fn canonicalizes_unbalanced_aliases_for_existing_cli_diagnostics() {
        let arguments = vec![OsString::from("-)"), OsString::from("root.o")];
        let resolved =
            resolve_static_library_arguments(&arguments).expect("canonicalize malformed alias");
        assert_eq!(
            resolved,
            vec![OsString::from("--end-group"), OsString::from("root.o")]
        );
    }

    #[test]
    fn preserves_unbalanced_nested_group_markers_for_cli_diagnostics() {
        let arguments = vec![
            OsString::from("--start-group"),
            OsString::from("--start-group"),
            OsString::from("--end-group"),
        ];
        let resolved =
            resolve_static_library_arguments(&arguments).expect("preserve malformed group");
        assert_eq!(resolved, arguments);
    }

    #[test]
    fn resolves_split_long_search_path_and_library_in_place() {
        let directory = temp_dir();
        fs::write(directory.join("libhelper.a"), b"archive").expect("write helper");
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("--library-path"),
            directory.as_os_str().to_os_string(),
            OsString::from("--library"),
            OsString::from("helper"),
        ];

        let resolved =
            resolve_static_library_arguments(&arguments).expect("resolve split long forms");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                directory.join("libhelper.a").into_os_string(),
            ]
        );
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn resolves_exact_filename_library_forms_in_place() {
        let directory = temp_dir();
        fs::write(directory.join("custom-name.a"), b"archive").expect("write exact archive");
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("-L"),
            directory.as_os_str().to_os_string(),
            OsString::from("-l:custom-name.a"),
            OsString::from("-l"),
            OsString::from(":custom-name.a"),
        ];

        let resolved =
            resolve_static_library_arguments(&arguments).expect("resolve exact libraries");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                directory.join("custom-name.a").into_os_string(),
                directory.join("custom-name.a").into_os_string(),
            ]
        );
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn resolves_long_library_exact_filename_in_place() {
        let directory = temp_dir();
        fs::write(directory.join("custom-name.a"), b"archive").expect("write exact archive");
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("-L"),
            directory.as_os_str().to_os_string(),
            OsString::from("--library=:custom-name.a"),
        ];

        let resolved =
            resolve_static_library_arguments(&arguments).expect("resolve long exact library");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                directory.join("custom-name.a").into_os_string(),
            ]
        );
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn resolves_split_long_exact_filename_in_place() {
        let directory = temp_dir();
        fs::write(directory.join("custom-name.a"), b"archive").expect("write exact archive");
        let arguments = vec![
            OsString::from("root.o"),
            OsString::from("--library-path"),
            directory.as_os_str().to_os_string(),
            OsString::from("--library"),
            OsString::from(":custom-name.a"),
        ];

        let resolved =
            resolve_static_library_arguments(&arguments).expect("resolve split long exact library");
        assert_eq!(
            resolved,
            vec![
                OsString::from("root.o"),
                directory.join("custom-name.a").into_os_string(),
            ]
        );
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn rejects_missing_library_with_search_context() {
        let directory = temp_dir();
        let error = resolve_static_library_arguments(&[
            OsString::from("-L"),
            directory.as_os_str().to_os_string(),
            OsString::from("-lmissing"),
        ])
        .expect_err("missing library must fail");
        assert!(matches!(error, LibrarySearchError::LibraryNotFound { .. }));
        assert!(error.to_string().contains("libmissing.a"));
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn rejects_missing_exact_library_with_exact_filename() {
        let directory = temp_dir();
        let error = resolve_static_library_arguments(&[
            OsString::from("-L"),
            directory.as_os_str().to_os_string(),
            OsString::from("-l:missing-custom.a"),
        ])
        .expect_err("missing exact library must fail");
        assert!(matches!(error, LibrarySearchError::LibraryNotFound { .. }));
        let message = error.to_string();
        assert!(message.contains("missing-custom.a"));
        assert!(!message.contains("libmissing-custom.a.a"));
        fs::remove_dir_all(directory).expect("remove temp directory");
    }

    #[test]
    fn rejects_missing_or_empty_option_values() {
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-L")]),
            Err(LibrarySearchError::MissingSearchPath)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library-path")]),
            Err(LibrarySearchError::MissingSearchPath)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library-path"), OsString::new(),]),
            Err(LibrarySearchError::EmptySearchPath)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library-path=")]),
            Err(LibrarySearchError::EmptySearchPath)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-l")]),
            Err(LibrarySearchError::MissingLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library")]),
            Err(LibrarySearchError::MissingLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library"), OsString::new()]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-l:")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-l"), OsString::from(":")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library=")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("--library=:")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
    }
}
