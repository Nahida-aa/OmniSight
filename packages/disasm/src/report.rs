use anyhow::Result;
use omnisight_shared::types::AnalysisReport;

pub fn generate_markdown(report: &AnalysisReport) -> Result<String> {
    let mut md = String::new();

    md.push_str("# OmniSight Static Analysis Report\n\n");

    // APK Info
    md.push_str("## APK Information\n\n");
    md.push_str(&format!("- **Package**: {}\n", report.apk_info.package_name));
    md.push_str(&format!("- **Version**: {} (code: {})\n", report.apk_info.version_name, report.apk_info.version_code));
    md.push_str(&format!("- **Min SDK**: {}, **Target SDK**: {}\n", report.apk_info.min_sdk, report.apk_info.target_sdk));
    md.push_str(&format!("- **File Size**: {} bytes\n\n", report.apk_info.file_size));

    // Manifest
    md.push_str("## AndroidManifest\n\n");
    if let Some(ref activity) = report.manifest.main_activity {
        md.push_str(&format!("- **Main Activity**: {}\n", activity));
    }
    md.push_str(&format!("- **Permissions**: {} found\n", report.manifest.permissions.len()));
    md.push_str(&format!("- **Services**: {}\n\n", report.manifest.services.len()));

    // DEX
    md.push_str("## DEX Classes\n\n");
    md.push_str(&format!("Total: **{}** classes\n\n", report.dex_classes.len()));
    for class in report.dex_classes.iter().take(50) {
        md.push_str(&format!("- `{}`\n", class.name));
    }
    if report.dex_classes.len() > 50 {
        md.push_str(&format!("... and {} more\n", report.dex_classes.len() - 50));
    }
    md.push('\n');

    // ELF
    md.push_str("## ELF Modules\n\n");
    for module in &report.elf_modules {
        md.push_str(&format!("- **{}** ({:?})\n", module.path, module.engine_type));
        md.push_str(&format!("  - Exported symbols: {}, Imported: {}\n",
            module.exported_symbols.len(), module.imported_symbols.len()));
        md.push_str(&format!("  - Strings found: {}\n", module.strings.len()));
    }
    md.push('\n');

    // String scan results
    md.push_str("## String Scan Results\n\n");
    md.push_str(&format!("- **URLs**: {}\n", report.strings.urls.len()));
    md.push_str(&format!("- **IPs**: {}\n", report.strings.ips.len()));
    md.push_str(&format!("- **Domains**: {}\n", report.strings.domains.len()));
    md.push_str(&format!("- **Crypto Keys/References**: {}\n", report.strings.crypto_keys.len()));
    md.push_str(&format!("- **Protobuf Descriptors**: {}\n", report.strings.proto_descriptors.len()));
    md.push_str(&format!("- **Keywords**: {}\n\n", report.strings.keywords.len()));

    if !report.strings.urls.is_empty() {
        md.push_str("### URLs\n\n```\n");
        for url in &report.strings.urls {
            md.push_str(&format!("{}\n", url.value));
        }
        md.push_str("```\n\n");
    }

    // Crypto
    md.push_str("## Crypto\n\n");
    md.push_str(&format!("- **Algorithms detected**: {:?}\n\n", report.crypto.algorithms));

    // Network
    md.push_str("## Network\n\n");
    md.push_str(&format!("- **Protocols**: {:?}\n", report.network.protocols));
    md.push_str(&format!("- **Endpoints found**: {}\n", report.network.endpoints.len()));
    md.push_str(&format!("- **Certificate Pinning**: {}\n", report.network.certificate_pinning));

    Ok(md)
}
