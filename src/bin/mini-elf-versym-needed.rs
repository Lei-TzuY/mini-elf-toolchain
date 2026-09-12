use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

#[allow(dead_code)]
mod checked {
    include!("mini-elf-versym.rs");

    const DT_NEEDED_X: i64 = 1;
    const DT_VERNEED_X: i64 = 0x6fff_fffe;
    const DT_VERNEEDNUM_X: i64 = 0x6fff_ffff;
    const ELF64_VERNEED_SIZE_X: u64 = 16;
    const ELF64_VERNAUX_SIZE_X: u64 = 16;
    const VER_NEED_CURRENT_X: u16 = 1;

    #[derive(Clone)]
    struct RequirementName {
        dependency: String,
        version: String,
    }

    pub fn inspect(input: &std::ffi::OsStr) -> Result<String, String> {
        let display = input.to_string_lossy().into_owned();
        let file =
            std::fs::read(input).map_err(|error| format!("cannot read '{display}': {error}"))?;
        let header = Elf64Header::parse(&file).map_err(|error| format!("{display}: {error}"))?;
        let program_headers =
            program_headers(header, &file).map_err(|error| format!("{display}: {error}"))?;
        let entries = dynamic_entries(&program_headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        let Some(versym_address) = unique_tag_value(&entries, DT_VERSYM, "DT_VERSYM")
            .map_err(|error| format!("{display}: {error}"))?
        else {
            return Ok("No DT_VERSYM version-symbol table found.\n".to_owned());
        };
        let symbol_count = dynamic_symbol_count(&entries, &program_headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        let definition_names = version_definition_names(&entries, &program_headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;
        let requirement_names = version_requirement_names(&entries, &program_headers, &file)
            .map_err(|error| format!("{display}: {error}"))?;

        for index in definition_names.keys() {
            if requirement_names.contains_key(index) {
                return Err(format!(
                    "{display}: version index {index} is defined by both DT_VERDEF and DT_VERNEED"
                ));
            }
        }

        let table_size = u64::from(symbol_count)
            .checked_mul(ELF64_VERSYM_SIZE)
            .ok_or_else(|| format!("{display}: DT_VERSYM table size overflows u64"))?;
        let table_offset = map_virtual_range(
            &program_headers,
            file.len(),
            versym_address,
            table_size,
            "DT_VERSYM table",
        )
        .map_err(|error| format!("{display}: {error}"))?;
        let table_offset = usize::try_from(table_offset)
            .map_err(|_| format!("{display}: DT_VERSYM table offset does not fit usize"))?;

        let mut output = format!(
            "DT_VERSYM at {versym_address:#x} contains {symbol_count} entries with checked version names:\n"
        );
        for symbol_index in 0..symbol_count {
            let relative = u64::from(symbol_index)
                .checked_mul(ELF64_VERSYM_SIZE)
                .ok_or_else(|| format!("{display}: DT_VERSYM entry offset overflows u64"))?;
            let relative = usize::try_from(relative)
                .map_err(|_| format!("{display}: DT_VERSYM entry offset does not fit usize"))?;
            let raw = read_u16(&file, table_offset + relative);
            let version_index = raw & VERSYM_INDEX_MASK;
            let hidden = raw & VERSYM_HIDDEN != 0;
            let class = match version_index {
                0 => "local",
                1 => "global",
                _ => "versioned",
            };
            let binding = if let Some(name) = definition_names.get(&version_index) {
                format!(" definition={name}")
            } else if let Some(requirement) = requirement_names.get(&version_index) {
                format!(
                    " requirement={}:{}",
                    requirement.dependency, requirement.version
                )
            } else {
                String::new()
            };
            output.push_str(&format!(
                "  symbol[{symbol_index}] raw={raw:#06x} index={version_index} hidden={} class={class}{binding}\n",
                if hidden { "yes" } else { "no" }
            ));
        }
        Ok(output)
    }

    fn sysv_elf_hash(name: &str) -> u32 {
        let mut hash = 0u32;
        for byte in name.bytes() {
            hash = hash.wrapping_shl(4).wrapping_add(u32::from(byte));
            let high = hash & 0xf000_0000;
            if high != 0 {
                hash ^= high >> 24;
            }
            hash &= !high;
        }
        hash
    }

    fn version_requirement_names(
        entries: &[DynamicEntry],
        program_headers: &[ProgramHeader],
        file: &[u8],
    ) -> Result<BTreeMap<u16, RequirementName>, String> {
        let verneed = unique_tag_value(entries, DT_VERNEED_X, "DT_VERNEED")?;
        let verneednum = unique_tag_value(entries, DT_VERNEEDNUM_X, "DT_VERNEEDNUM")?;
        let present = usize::from(verneed.is_some()) + usize::from(verneednum.is_some());
        if present == 0 {
            return Ok(BTreeMap::new());
        }
        if present != 2 {
            return Err("PT_DYNAMIC must provide DT_VERNEED and DT_VERNEEDNUM together".to_owned());
        }
        let count = verneednum.unwrap();
        if count == 0 {
            return Err("DT_VERNEEDNUM must be non-zero when DT_VERNEED is present".to_owned());
        }

        let strtab = unique_tag_value(entries, DT_STRTAB, "DT_STRTAB")?
            .ok_or_else(|| "DT_VERNEED requires DT_STRTAB".to_owned())?;
        let strsz = unique_tag_value(entries, DT_STRSZ, "DT_STRSZ")?
            .ok_or_else(|| "DT_VERNEED requires DT_STRSZ".to_owned())?;
        let strtab_offset = map_virtual_range(
            program_headers,
            file.len(),
            strtab,
            strsz,
            "DT_STRTAB table",
        )?;

        let needed = entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED_X)
            .map(|entry| dynamic_string(file, strtab_offset, strsz, entry.value, "DT_NEEDED name"))
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?;

        let mut names = BTreeMap::new();
        let mut address = verneed.unwrap();
        for record_index in 0..count {
            let offset = map_virtual_range(
                program_headers,
                file.len(),
                address,
                ELF64_VERNEED_SIZE_X,
                &format!("DT_VERNEED entry {record_index}"),
            )?;
            let offset = usize::try_from(offset)
                .map_err(|_| "DT_VERNEED file offset does not fit usize".to_owned())?;
            let version = read_u16(file, offset);
            let aux_count = read_u16(file, offset + 2);
            let dependency_offset = u64::from(read_u32(file, offset + 4));
            let aux_relative = read_u32(file, offset + 8);
            let next_relative = read_u32(file, offset + 12);

            if version != VER_NEED_CURRENT_X {
                return Err(format!(
                    "DT_VERNEED entry {record_index} has version {version}, expected {VER_NEED_CURRENT_X}"
                ));
            }
            if aux_count == 0 || aux_relative == 0 {
                return Err(format!(
                    "DT_VERNEED entry {record_index} has an invalid Vernaux chain"
                ));
            }
            let dependency = dynamic_string(
                file,
                strtab_offset,
                strsz,
                dependency_offset,
                "DT_VERNEED dependency name",
            )?;
            if !needed.contains(&dependency) {
                return Err(format!(
                    "DT_VERNEED dependency '{dependency}' is not declared by DT_NEEDED"
                ));
            }

            let mut aux_address = address
                .checked_add(u64::from(aux_relative))
                .ok_or_else(|| format!("DT_VERNEED entry {record_index} vn_aux overflows u64"))?;
            for aux_index in 0..u64::from(aux_count) {
                let aux_offset = map_virtual_range(
                    program_headers,
                    file.len(),
                    aux_address,
                    ELF64_VERNAUX_SIZE_X,
                    &format!("DT_VERNEED entry {record_index} Vernaux {aux_index}"),
                )?;
                let aux_offset = usize::try_from(aux_offset)
                    .map_err(|_| "DT_VERNEED Vernaux offset does not fit usize".to_owned())?;
                let stored_hash = read_u32(file, aux_offset);
                let raw_index = read_u16(file, aux_offset + 6);
                let version_index = raw_index & VERSYM_INDEX_MASK;
                if version_index < 2 {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} Vernaux {aux_index} uses reserved version index {version_index}"
                    ));
                }
                let name_offset = u64::from(read_u32(file, aux_offset + 8));
                let next = read_u32(file, aux_offset + 12);
                let version_name = dynamic_string(
                    file,
                    strtab_offset,
                    strsz,
                    name_offset,
                    "Vernaux version name",
                )?;
                let expected_hash = sysv_elf_hash(&version_name);
                if stored_hash != expected_hash {
                    return Err(format!(
                        "DT_VERNEED entry {record_index} Vernaux {aux_index} has vna_hash {stored_hash:#010x}, expected {expected_hash:#010x} for version '{version_name}'"
                    ));
                }
                if names
                    .insert(
                        version_index,
                        RequirementName {
                            dependency: dependency.clone(),
                            version: version_name,
                        },
                    )
                    .is_some()
                {
                    return Err(format!(
                        "DT_VERNEED contains duplicate version index {version_index}"
                    ));
                }

                let last = aux_index + 1 == u64::from(aux_count);
                if last {
                    if next != 0 {
                        return Err(format!(
                            "DT_VERNEED entry {record_index} final Vernaux has non-zero vna_next {next}"
                        ));
                    }
                } else {
                    if next == 0 {
                        return Err(format!(
                            "DT_VERNEED entry {record_index} Vernaux chain ends before vn_cnt {aux_count}"
                        ));
                    }
                    aux_address = aux_address.checked_add(u64::from(next)).ok_or_else(|| {
                        format!("DT_VERNEED entry {record_index} Vernaux address overflows u64")
                    })?;
                }
            }

            let last = record_index + 1 == count;
            if last {
                if next_relative != 0 {
                    return Err(format!(
                        "final DT_VERNEED entry has non-zero vn_next beyond count {count}"
                    ));
                }
            } else {
                if next_relative == 0 {
                    return Err(format!("DT_VERNEED chain ends before count {count}"));
                }
                address = address
                    .checked_add(u64::from(next_relative))
                    .ok_or_else(|| "DT_VERNEED next-entry address overflows u64".to_owned())?;
            }
        }
        Ok(names)
    }
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<String, String>
where
    I: Iterator<Item = OsString>,
{
    let args = args.collect::<Vec<_>>();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return if args.len() <= 1 {
            Ok("usage: mini-elf-versym-needed <input>...\n".to_owned())
        } else {
            Err("usage: mini-elf-versym-needed <input>...".to_owned())
        };
    }
    if args
        .iter()
        .any(|arg| arg.to_string_lossy().starts_with('-'))
    {
        return Err("usage: mini-elf-versym-needed <input>...".to_owned());
    }

    let multiple = args.len() > 1;
    let mut reports = Vec::with_capacity(args.len());
    for input in args {
        let display = input.to_string_lossy().into_owned();
        let report = checked::inspect(&input)?;
        reports.push((display, report));
    }

    let mut output = String::new();
    for (index, (display, report)) in reports.into_iter().enumerate() {
        if index != 0 {
            output.push('\n');
        }
        if multiple {
            output.push_str(&format!("File: {display}\n"));
        }
        output.push_str(&report);
    }
    Ok(output)
}
