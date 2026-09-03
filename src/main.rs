use mini_elf_toolchain::elf64::Elf64Header;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str = "usage: mini-elf-toolchain validate <input>";

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
    if command != "validate" {
        return Err(CliError::Usage(format!(
            "unknown command '{}'",
            command.to_string_lossy()
        )));
    }

    let input = args
        .next()
        .ok_or_else(|| CliError::Usage("missing input path".to_owned()))?;
    if args.next().is_some() {
        return Err(CliError::Usage("too many arguments".to_owned()));
    }

    validate_file(&input)
}

fn validate_file(path: &OsString) -> Result<String, CliError> {
    let file = fs::read(path)
        .map_err(|error| CliError::Failure(format!("{}: {error}", path.to_string_lossy())))?;
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
            run([OsString::from("link")].into_iter()),
            Err(CliError::Usage("unknown command 'link'".to_owned()))
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
}
