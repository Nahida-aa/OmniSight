use anyhow::{Context, Result};
use omnisight_shared::types::{self, ScannedString};
use std::path::Path;
use std::io::Read;
use zip::ZipArchive;

pub struct ApkData {
    pub info: types::ApkInfo,
    pub manifest: types::ManifestInfo,
    pub dex_files: Vec<Vec<u8>>,
    pub elf_files: Vec<(String, Vec<u8>)>,
    pub all_strings: Vec<ScannedString>,
}

pub fn parse_apk(path: &Path) -> Result<ApkData> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open APK: {}", path.display()))?;
    let file_size = file.metadata()?.len();
    let mut archive = ZipArchive::new(file)
        .context("Failed to parse APK as ZIP archive")?;

    let mut dex_files = Vec::new();
    let mut elf_files = Vec::new();
    let mut manifest_xml = None;
    let mut package_name = String::new();
    let version_name = String::new();
    let version_code = 0u64;
    let min_sdk = 0u32;
    let target_sdk = 0u32;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        if name == "AndroidManifest.xml" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            manifest_xml = Some(buf);
        } else if name.starts_with("classes") && name.ends_with(".dex") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            dex_files.push(buf);
        } else if name.contains("lib/arm64-v8a/") && name.ends_with(".so") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let lib_name = name.rsplit('/').next().unwrap_or(&name).to_string();
            elf_files.push((lib_name, buf));
        }
    }

    // Parse AndroidManifest binary XML (simplified: extract package/version string references)
    if let Some(xml) = &manifest_xml {
        // Minimal: scan for package name and version strings
        // Full binary XML parsing is complex; using string scanning for now
        let raw = String::from_utf8_lossy(xml);
        for line in raw.split('\0') {
            let s = line.trim_matches(char::from(0)).trim();
            if s.starts_with("com.") || s.starts_with("org.") || s.starts_with("net.") {
                if s.chars().filter(|&c| c == '.').count() >= 2 {
                    package_name = s.to_string();
                }
            }
        }
    }

    // Parse package name from AndroidManifest binary using known utf8 offsets
    // Fallback: extract last part from path
    if package_name.is_empty() {
        if let Some(name) = path.file_stem() {
            package_name = name.to_string_lossy().to_string();
        }
    }

    Ok(ApkData {
        info: types::ApkInfo {
            package_name,
            version_name,
            version_code,
            min_sdk,
            target_sdk,
            file_size,
        },
        manifest: types::ManifestInfo {
            main_activity: None,
            services: Vec::new(),
            receivers: Vec::new(),
            permissions: Vec::new(),
            network_security_config: None,
        },
        dex_files,
        elf_files,
        all_strings: Vec::new(),
    })
}
