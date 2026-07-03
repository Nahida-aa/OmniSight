use anyhow::Result;
use goblin::elf::Elf;
use omnisight_shared::types::{ElfModuleInfo, ElfSection, EngineType, ScannedString};

pub fn analyze_elf(elf_files: &[(String, Vec<u8>)]) -> Result<Vec<ElfModuleInfo>> {
    let mut modules = Vec::new();

    for (name, data) in elf_files {
        let mut info = ElfModuleInfo {
            path: name.clone(),
            is_native: true,
            engine_type: EngineType::Unknown,
            exported_symbols: Vec::new(),
            imported_symbols: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
        };

        match Elf::parse(data) {
            Ok(elf) => {
                // Sections
                for section in &elf.section_headers {
                    let sname = elf.shdr_strtab
                        .get_at(section.sh_name)
                        .unwrap_or("unknown")
                        .to_string();
                    info.sections.push(ElfSection {
                        name: sname.clone(),
                        size: section.sh_size,
                        offset: section.sh_offset,
                        flags: format!("{:x}", section.sh_flags),
                    });

                    // Extract strings from .rodata and .strtab
                    if sname == ".rodata" || sname == ".strtab" {
                        let start = section.sh_offset as usize;
                        let end = start + section.sh_size as usize;
                        if end <= data.len() && start < end {
                            let raw = &data[start..end];
                            extract_strings_from_buf(raw, name, &sname, &mut info.strings);
                        }
                    }
                }

                // Static symbol table (Symtab derefs to &[Sym], not Option)
                for sym in elf.syms.iter() {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if sym.st_value != 0 && sym.st_shndx != 0 {
                            info.exported_symbols.push(name.to_string());
                        } else {
                            info.imported_symbols.push(name.to_string());
                        }
                    }
                }

                // Dynamic symbol table
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if sym.st_value != 0 && sym.st_shndx != 0 {
                            info.exported_symbols.push(name.to_string());
                        } else {
                            info.imported_symbols.push(name.to_string());
                        }
                    }
                }

                // Detect engine type
                info.engine_type = detect_engine(name, &info.exported_symbols, &info.imported_symbols, data);
            }
            Err(e) => {
                log::warn!("Failed to parse ELF {}: {}", name, e);
            }
        }

        modules.push(info);
    }

    log::info!("Analyzed {} ELF modules", modules.len());
    Ok(modules)
}

fn detect_engine(name: &str, exported: &[String], imported: &[String], data: &[u8]) -> EngineType {
    let name_lower = name.to_lowercase();

    // UE5 check first (UE5 mobile still ships libUE4.so; check binary for UE5 sigs)
    if name_lower.contains("ue5") || name_lower.contains("libue5") {
        return EngineType::UnrealEngine5;
    }
    if name_lower.contains("unity") || name_lower.contains("libunity") {
        return EngineType::Unity;
    }

    // libUE4.so could be UE4 or UE5 on mobile; check imported symbols for UE5 patterns
    if name_lower.contains("ue4") || name_lower.contains("libue4") {
        let raw = String::from_utf8_lossy(data);
        if raw.contains("UE5") || raw.contains("UnrealEngine5") || raw.contains("UE5-") {
            return EngineType::UnrealEngine5;
        }
        // Check symbols for UE5-specific patterns
        for sym in exported.iter().chain(imported) {
            if sym.contains("UE5") || sym.contains("UnrealEngine5") {
                return EngineType::UnrealEngine5;
            }
        }
        return EngineType::UnrealEngine4;
    }

    for sym in exported.iter().chain(imported) {
        if sym.contains("UObject") || sym.contains("AActor") || sym.contains("FName") {
            return EngineType::UnrealEngine4;
        }
        if sym.contains("MonoBehaviour") || sym.contains("UnityEngine") {
            return EngineType::Unity;
        }
    }

    let raw = String::from_utf8_lossy(data);
    if raw.contains("UnrealEngine") || raw.contains("UE4") {
        return EngineType::UnrealEngine4;
    }
    if raw.contains("UE5") || raw.contains("UnrealEngine5") {
        return EngineType::UnrealEngine5;
    }

    EngineType::Unknown
}

fn extract_strings_from_buf(buf: &[u8], module_name: &str, section: &str, strings: &mut Vec<ScannedString>) {
    let mut current = Vec::new();
    for &byte in buf {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'/' || byte == b'.' || byte == b':' || byte == b'-' || byte == b'_' {
            current.push(byte);
        } else {
            if current.len() >= 8 {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(ScannedString {
                        value: s,
                        context: None,
                        location: format!("{}:{}", module_name, section),
                        category: "string".to_string(),
                    });
                }
            }
            current.clear();
        }
    }
    if current.len() >= 8 {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(ScannedString {
                value: s,
                context: None,
                location: format!("{}:{}", module_name, section),
                category: "string".to_string(),
            });
        }
    }
}
