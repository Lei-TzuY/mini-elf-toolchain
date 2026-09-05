use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

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
    let mut search_paths = Vec::new();
    let mut resolved = Vec::with_capacity(arguments.len());
    let mut index = 0usize;

    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-L" {
            let path = arguments
                .get(index + 1)
                .ok_or(LibrarySearchError::MissingSearchPath)?;
            add_search_path(path, &mut search_paths)?;
            index += 2;
            continue;
        }
        if let Some(path) = strip_os_prefix(argument, "-L") {
            add_search_path(&path, &mut search_paths)?;
            index += 1;
            continue;
        }
        if argument == "-l" {
            let name = arguments
                .get(index + 1)
                .ok_or(LibrarySearchError::MissingLibraryName)?;
            resolved.push(resolve_library(name, &search_paths)?);
            index += 2;
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

    let filename = if let Some(exact) = strip_os_prefix_including_empty(name, ":") {
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
    (bytes.len() > prefix.len() && bytes.starts_with(prefix))
        .then(|| OsString::from_vec(bytes[prefix.len()..].to_vec()))
}

#[cfg(windows)]
fn strip_os_prefix(value: &OsStr, prefix: &str) -> Option<OsString> {
    let text = value.to_str()?;
    text.strip_prefix(prefix)
        .filter(|suffix| !suffix.is_empty())
        .map(OsString::from)
}

#[cfg(unix)]
fn strip_os_prefix_including_empty(value: &OsStr, prefix: &str) -> Option<OsString> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = value.as_bytes();
    let prefix = prefix.as_bytes();
    bytes
        .starts_with(prefix)
        .then(|| OsString::from_vec(bytes[prefix.len()..].to_vec()))
}

#[cfg(windows)]
fn strip_os_prefix_including_empty(value: &OsStr, prefix: &str) -> Option<OsString> {
    value
        .to_str()?
        .strip_prefix(prefix)
        .map(OsString::from)
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
    fn resolves_split_and_joined_library_forms_in_place() {
        let first = temp_dir();
        let second = temp_dir();
        fs::write(first.join("libfoo.a"), b"archive").expect("write foo");
        fs::write(second.join("libbar.a"), b"archive").expect("write bar");
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
            ]
        );
        fs::remove_dir_all(first).expect("remove first temp directory");
        fs::remove_dir_all(second).expect("remove second temp directory");
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

        let resolved = resolve_static_library_arguments(&arguments).expect("resolve exact libraries");
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
            resolve_static_library_arguments(&[OsString::from("-l")]),
            Err(LibrarySearchError::MissingLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-l:")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
        assert!(matches!(
            resolve_static_library_arguments(&[OsString::from("-l"), OsString::from(":")]),
            Err(LibrarySearchError::EmptyLibraryName)
        ));
    }
}
