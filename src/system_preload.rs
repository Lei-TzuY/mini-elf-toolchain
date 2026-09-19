use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::Path;

const MAX_SYSTEM_PRELOAD_BYTES: u64 = 1024 * 1024;

/// Parsed, owned system-preload request independent of any command wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPreloadRequest {
    secure: bool,
    entries: Vec<String>,
    resolver_args: Vec<OsString>,
}

fn parse_entries(contents: &str) -> Result<Vec<String>, String> {
    if contents.contains('\0') {
        return Err("system preload file contains NUL byte".to_owned());
    }

    let mut entries = Vec::new();
    for line in contents.lines() {
        let uncommented = line.split('#').next().unwrap_or_default();
        entries.extend(uncommented.split_ascii_whitespace().map(str::to_owned));
    }
    for entry in &entries {
        if entry.contains(':') {
            return Err(format!(
                "system preload entry '{entry}' contains ':'; this bounded file model accepts whitespace-separated entries only"
            ));
        }
    }
    Ok(entries)
}

fn read_preload_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = fs::File::open(path).map_err(|error| {
        format!(
            "cannot read system preload file '{}': {error}",
            path.display()
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "cannot inspect system preload file '{}': {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "system preload file '{}' is not a regular file",
            path.display()
        ));
    }

    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SYSTEM_PRELOAD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            format!(
                "cannot read system preload file '{}': {error}",
                path.display()
            )
        })?;
    if bytes.len() as u64 > MAX_SYSTEM_PRELOAD_BYTES {
        return Err(format!(
            "system preload file '{}' exceeds {} byte limit",
            path.display(),
            MAX_SYSTEM_PRELOAD_BYTES
        ));
    }
    Ok(bytes)
}

impl SystemPreloadRequest {
    /// Parse the bounded system-preload CLI shape and read its explicit file.
    ///
    /// `Ok(None)` means the argument shape was not recognized. File and
    /// representation failures remain explicit errors.
    pub fn parse(args: &[OsString]) -> Result<Option<Self>, String> {
        let (secure, preload_file, symbol, root, fallback) = match args {
            [flag, preload_file, symbol, root, fallback] if flag == "--secure" => {
                (true, preload_file, symbol, root, fallback)
            }
            [preload_file, symbol, root, fallback] => (false, preload_file, symbol, root, fallback),
            _ => return Ok(None),
        };

        let preload_file = Path::new(preload_file);
        let bytes = read_preload_file(preload_file)?;
        let contents = String::from_utf8(bytes).map_err(|_| {
            format!(
                "system preload file '{}' is not UTF-8",
                preload_file.display()
            )
        })?;
        let entries = parse_entries(&contents)?;

        Ok(Some(Self {
            secure,
            entries,
            resolver_args: vec![symbol.clone(), root.clone(), fallback.clone()],
        }))
    }

    #[must_use]
    pub fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Apply the request as a scoped process environment and invoke the loader model.
    ///
    /// The original environment is restored on success, error, or panic unwind.
    pub fn resolve<T>(
        self,
        resolver: impl FnOnce(Vec<OsString>) -> Result<T, String>,
    ) -> Result<SystemPreloadResolution<T>, String> {
        let restore = EnvironmentRestore::capture(self.secure);
        let system_value = self.entries.join(" ");
        let combined = if self.secure {
            system_value
        } else {
            match restore.preload.as_ref().and_then(|value| value.to_str()) {
                Some(value) if !value.is_empty() && !system_value.is_empty() => {
                    format!("{value} {system_value}")
                }
                Some(value) if !value.is_empty() => value.to_owned(),
                _ => system_value,
            }
        };

        if combined.is_empty() {
            env::remove_var("LD_PRELOAD");
        } else {
            env::set_var("LD_PRELOAD", &combined);
        }
        if self.secure {
            env::remove_var("LD_LIBRARY_PATH");
        }

        let output = resolver(self.resolver_args);
        drop(restore);
        Ok(SystemPreloadResolution {
            output: output?,
            entry_count: self.entries.len(),
            secure: self.secure,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPreloadResolution<T> {
    pub output: T,
    pub entry_count: usize,
    pub secure: bool,
}

struct EnvironmentRestore {
    preload: Option<OsString>,
    library_path: Option<Option<OsString>>,
}

impl EnvironmentRestore {
    fn capture(secure: bool) -> Self {
        Self {
            preload: env::var_os("LD_PRELOAD"),
            library_path: secure.then(|| env::var_os("LD_LIBRARY_PATH")),
        }
    }
}

impl Drop for EnvironmentRestore {
    fn drop(&mut self) {
        match self.preload.take() {
            Some(value) => env::set_var("LD_PRELOAD", value),
            None => env::remove_var("LD_PRELOAD"),
        }
        if let Some(previous) = self.library_path.take() {
            match previous {
                Some(value) => env::set_var("LD_LIBRARY_PATH", value),
                None => env::remove_var("LD_LIBRARY_PATH"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn invalid_argument_shape_is_not_a_loader_error() {
        assert_eq!(SystemPreloadRequest::parse(&[]).unwrap(), None);
    }

    #[test]
    fn parser_preserves_comment_and_whitespace_semantics() {
        assert_eq!(
            parse_entries("# leading\nlibfirst.so  libsecond.so # trailing\n").unwrap(),
            vec!["libfirst.so", "libsecond.so"]
        );
    }

    #[test]
    fn parser_rejects_nul_before_environment_or_path_resolution() {
        assert_eq!(
            parse_entries("libfirst.so\0libsecond.so").unwrap_err(),
            "system preload file contains NUL byte"
        );
    }

    #[test]
    fn parser_rejects_nul_hidden_in_comment() {
        assert_eq!(
            parse_entries("libfirst.so # ignored\0suffix\n").unwrap_err(),
            "system preload file contains NUL byte"
        );
    }

    #[test]
    fn file_reader_rejects_non_regular_input_before_reading() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("mini-elf-system-preload-dir-{nonce}"));
        fs::create_dir(&path).unwrap();

        let error = read_preload_file(&path).unwrap_err();
        fs::remove_dir(&path).unwrap();
        assert!(error.contains("is not a regular file"), "{error}");
    }

    #[test]
    fn file_reader_rejects_oversized_input_without_reading_unbounded_data() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("mini-elf-system-preload-{nonce}"));
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&vec![b'x'; (MAX_SYSTEM_PRELOAD_BYTES + 1) as usize])
            .unwrap();
        drop(file);

        let error = read_preload_file(&path).unwrap_err();
        fs::remove_file(&path).unwrap();
        assert!(error.contains("exceeds 1048576 byte limit"), "{error}");
    }
}
