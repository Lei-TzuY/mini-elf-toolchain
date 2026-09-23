use core::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderClosurePathError {
    InvalidDependencyNameUtf8 {
        name: Vec<u8>,
    },
    EmptyDependencyName,
    DependencyNameContainsSeparator {
        name: String,
    },
    InvalidRunpathUtf8 {
        runpath: Vec<u8>,
    },
    EmptyRunpath,
    EmptyRunpathEntry {
        runpath: String,
    },
    UnsupportedRunpathToken {
        entry: String,
    },
    RelativeRunpathEntry {
        entry: String,
    },
    DependencyNotFound {
        name: String,
        directories: Vec<PathBuf>,
    },
}

impl fmt::Display for ProviderClosurePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDependencyNameUtf8 { name } => write!(
                f,
                "transitive shared provider dependency name {:?} is not valid UTF-8",
                String::from_utf8_lossy(name)
            ),
            Self::EmptyDependencyName => {
                f.write_str("transitive shared provider dependency name is empty")
            }
            Self::DependencyNameContainsSeparator { name } => write!(
                f,
                "transitive shared provider dependency '{name}' contains a path separator; bounded closure resolution accepts SONAME-style filenames only"
            ),
            Self::InvalidRunpathUtf8 { runpath } => write!(
                f,
                "provider DT_RUNPATH {:?} is not valid UTF-8",
                String::from_utf8_lossy(runpath)
            ),
            Self::EmptyRunpath => f.write_str(
                "provider DT_RUNPATH is empty; bounded closure resolution rejects empty search entries",
            ),
            Self::EmptyRunpathEntry { runpath } => write!(
                f,
                "provider DT_RUNPATH '{runpath}' contains an empty search entry"
            ),
            Self::UnsupportedRunpathToken { entry } => write!(
                f,
                "provider DT_RUNPATH entry '{entry}' uses an unsupported loader token; bounded closure resolution supports only $ORIGIN"
            ),
            Self::RelativeRunpathEntry { entry } => write!(
                f,
                "provider DT_RUNPATH entry '{entry}' is relative; bounded closure resolution accepts only absolute paths or $ORIGIN-based entries"
            ),
            Self::DependencyNotFound { name, directories } => {
                write!(
                    f,
                    "cannot resolve transitive shared provider dependency '{name}'"
                )?;
                if directories.is_empty() {
                    f.write_str("; no bounded provider search directories are available")
                } else {
                    f.write_str(" in")?;
                    for directory in directories {
                        write!(f, " '{}'", directory.display())?;
                    }
                    Ok(())
                }
            }
        }
    }
}

impl std::error::Error for ProviderClosurePathError {}

pub fn resolve_provider_path(
    name: &[u8],
    provider_directory: &Path,
    runpath: Option<&[u8]>,
    search_paths: &[PathBuf],
) -> Result<PathBuf, ProviderClosurePathError> {
    let name = std::str::from_utf8(name).map_err(|_| {
        ProviderClosurePathError::InvalidDependencyNameUtf8 {
            name: name.to_vec(),
        }
    })?;
    if name.is_empty() {
        return Err(ProviderClosurePathError::EmptyDependencyName);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(ProviderClosurePathError::DependencyNameContainsSeparator {
            name: name.to_owned(),
        });
    }

    let mut directories = Vec::new();
    push_unique_directory(&mut directories, provider_directory.to_path_buf());
    if let Some(runpath) = runpath {
        for directory in expand_provider_runpath(runpath, provider_directory)? {
            push_unique_directory(&mut directories, directory);
        }
    }
    for path in search_paths {
        push_unique_directory(&mut directories, path.clone());
    }

    for directory in &directories {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(ProviderClosurePathError::DependencyNotFound {
        name: name.to_owned(),
        directories,
    })
}

pub fn expand_provider_runpath(
    runpath: &[u8],
    provider_directory: &Path,
) -> Result<Vec<PathBuf>, ProviderClosurePathError> {
    let runpath =
        std::str::from_utf8(runpath).map_err(|_| ProviderClosurePathError::InvalidRunpathUtf8 {
            runpath: runpath.to_vec(),
        })?;
    if runpath.is_empty() {
        return Err(ProviderClosurePathError::EmptyRunpath);
    }

    let mut result = Vec::new();
    for entry in runpath.split(':') {
        if entry.is_empty() {
            return Err(ProviderClosurePathError::EmptyRunpathEntry {
                runpath: runpath.to_owned(),
            });
        }
        let path = if entry == "$ORIGIN" || entry == "${ORIGIN}" {
            provider_directory.to_path_buf()
        } else if let Some(suffix) = entry.strip_prefix("$ORIGIN/") {
            provider_directory.join(suffix)
        } else if let Some(suffix) = entry.strip_prefix("${ORIGIN}/") {
            provider_directory.join(suffix)
        } else if entry.contains('$') {
            return Err(ProviderClosurePathError::UnsupportedRunpathToken {
                entry: entry.to_owned(),
            });
        } else {
            let path = PathBuf::from(entry);
            if !path.is_absolute() {
                return Err(ProviderClosurePathError::RelativeRunpathEntry {
                    entry: entry.to_owned(),
                });
            }
            path
        };
        push_unique_directory(&mut result, path);
    }
    Ok(result)
}

fn push_unique_directory(directories: &mut Vec<PathBuf>, directory: PathBuf) {
    if !directories.iter().any(|candidate| candidate == &directory) {
        directories.push(directory);
    }
}
