use mini_elf_toolchain::elf64::Elf64Header;
use mini_elf_toolchain::input_object::RelocatableObject;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::process::ExitCode;

const USAGE: &str =
    "usage: mini-elf-toolchain validate <input>\n       mini-elf-toolchain validate-rel <input>...";

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

    Err(CliError::Usage(format!(
        "unknown command '{}'",
        command.to_string_lossy()
    )))
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

    #[test]
    fn validate_rel_requires_at_least_one_input() {
        assert_eq!(
            run([OsString::from("validate-rel")].into_iter()),
            Err(CliError::Usage("missing relocatable input path".to_owned()))
        );
    }
}
