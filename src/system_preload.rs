use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

/// Parsed, owned system-preload request independent of any command wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPreloadRequest {
    secure: bool,
    entries: Vec<String>,
    resolver_args: Vec<OsString>,
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
        let bytes = fs::read(preload_file).map_err(|error| {
            format!(
                "cannot read system preload file '{}': {error}",
                preload_file.display()
            )
        })?;
        let contents = String::from_utf8(bytes).map_err(|_| {
            format!(
                "system preload file '{}' is not UTF-8",
                preload_file.display()
            )
        })?;

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

    #[test]
    fn invalid_argument_shape_is_not_a_loader_error() {
        assert_eq!(SystemPreloadRequest::parse(&[]).unwrap(), None);
    }
}
