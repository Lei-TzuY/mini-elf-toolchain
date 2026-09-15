//! Reusable LD_PRELOAD entry parsing and file-identity normalization.
//!
//! This module owns representation and filesystem identity rules only. Search
//! order and symbol-resolution policy remain separate loader concerns.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreloadEntry {
    Path(PathBuf),
    Bare(String),
}

pub fn deduplicate_preload_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, String> {
    let mut unique = Vec::new();
    let mut identities = Vec::new();

    for path in paths {
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "cannot inspect resolved LD_PRELOAD entry '{}' for file identity: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "resolved LD_PRELOAD entry '{}' is not a regular file",
                path.display()
            ));
        }

        let identity = preload_file_identity(&path, &metadata)?;
        if !identities.contains(&identity) {
            identities.push(identity);
            unique.push(path);
        }
    }
    Ok(unique)
}

#[cfg(unix)]
fn preload_file_identity(_path: &Path, metadata: &fs::Metadata) -> Result<(u64, u64), String> {
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn preload_file_identity(path: &Path, _metadata: &fs::Metadata) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| {
        format!(
            "cannot canonicalize resolved LD_PRELOAD entry '{}' for file identity: {error}",
            path.display()
        )
    })
}

pub fn parse_preload_entries(value: &OsStr) -> Result<Vec<PreloadEntry>, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "LD_PRELOAD value is not UTF-8".to_owned())?;
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot determine current working directory: {error}"))?;
    value
        .split(|character: char| character == ':' || character.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            if entry.contains('/') {
                normalize_preload_path(entry, &cwd).map(PreloadEntry::Path)
            } else {
                normalize_preload_basename(entry).map(PreloadEntry::Bare)
            }
        })
        .collect()
}

fn normalize_preload_basename(entry: &str) -> Result<String, String> {
    if entry.contains('$') {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' contains an unsupported dynamic token"
        ));
    }
    let path = Path::new(entry);
    if entry.is_empty()
        || path.file_name() != Some(OsStr::new(entry))
        || !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.components().count() != 1
    {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' is not a plain library basename"
        ));
    }
    Ok(entry.to_owned())
}

fn normalize_preload_path(entry: &str, cwd: &Path) -> Result<PathBuf, String> {
    if entry.contains('$') {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' contains an unsupported dynamic token"
        ));
    }

    let path = Path::new(entry);
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => saw_normal = true,
            _ => {
                return Err(format!(
                    "LD_PRELOAD entry '{entry}' is not a normalized pathname"
                ));
            }
        }
    }
    if !saw_normal {
        return Err(format!(
            "LD_PRELOAD entry '{entry}' must name a shared-object pathname"
        ));
    }

    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => Ok(path),
        Ok(_) => Err(format!(
            "LD_PRELOAD entry '{}' resolved to non-file '{}'",
            entry,
            path.display()
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(format!(
            "cannot resolve LD_PRELOAD entry '{}' as '{}'",
            entry,
            path.display()
        )),
        Err(error) => Err(format!(
            "cannot inspect LD_PRELOAD entry '{}' as '{}': {error}",
            entry,
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_preload_entries, PreloadEntry};
    use std::ffi::OsStr;

    #[test]
    fn splits_colon_and_ascii_whitespace_without_silent_deduplication() {
        let entries = parse_preload_entries(OsStr::new("libfirst.so:libsecond.so libfirst.so"))
            .expect("valid preload entries");
        assert_eq!(
            entries,
            vec![
                PreloadEntry::Bare("libfirst.so".to_owned()),
                PreloadEntry::Bare("libsecond.so".to_owned()),
                PreloadEntry::Bare("libfirst.so".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_parent_directory_escape() {
        let error = parse_preload_entries(OsStr::new("../libescape.so"))
            .expect_err("parent path must be rejected");
        assert!(error.contains("not a normalized path"), "{error}");
    }
}
