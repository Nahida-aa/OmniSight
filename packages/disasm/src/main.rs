mod apk;
mod elf;
mod dex;
mod scanner;
mod report;

use clap::Parser;
use anyhow::Result;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "disasm", about = "OmniSight static analyzer for Android APKs")]
struct Cli {
    /// Path to the APK file
    apk: PathBuf,

    /// Output directory for analysis results
    #[arg(short, long, default_value = "output")]
    output: PathBuf,

    /// Generate markdown report
    #[arg(long)]
    markdown: bool,

    /// Thread count for parallel scanning
    #[arg(short, long, default_value = "4")]
    threads: usize,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let apk_path = std::fs::canonicalize(&cli.apk)?;
    println!("🔍 Analyzing: {}", apk_path.display());

    // Phase 1: APK info + manifest
    println!("[1/5] Parsing APK...");
    let apk_data = apk::parse_apk(&apk_path)?;

    // Phase 2: DEX analysis
    println!("[2/5] Analyzing DEX files...");
    let dex_classes = dex::analyze_dex(&apk_data.dex_files)?;

    // Phase 3: ELF analysis
    println!("[3/5] Analyzing ELF binaries...");
    let elf_modules = elf::analyze_elf(&apk_data.elf_files)?;

    // Phase 4: String scanning
    println!("[4/5] Scanning strings...");
    let strings = scanner::scan_all(&apk_data, &elf_modules)?;

    // Phase 5: Crypto + network detection
    println!("[5/5] Detecting crypto & network patterns...");
    let crypto = scanner::detect_crypto(&strings, &elf_modules)?;
    let network = scanner::detect_network(&strings, &elf_modules)?;

    // Build report
    let report = omnisight_shared::types::AnalysisReport {
        apk_info: apk_data.info,
        manifest: apk_data.manifest,
        dex_classes,
        elf_modules,
        strings,
        crypto,
        network,
    };

    // Output
    std::fs::create_dir_all(&cli.output)?;
    let json_path = cli.output.join("report.json");
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&json_path, &json)?;
    println!("✅ JSON report: {}", json_path.display());

    if cli.markdown {
        let md_path = cli.output.join("report.md");
        let md = report::generate_markdown(&report)?;
        std::fs::write(&md_path, &md)?;
        println!("✅ Markdown report: {}", md_path.display());
    }

    Ok(())
}
