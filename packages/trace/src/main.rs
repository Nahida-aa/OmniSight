mod adb;
mod logcat;
mod matcher;
mod types;

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "trace", about = "OmniSight logcat tracer for Android apps")]
struct Cli {
    /// Package name of the target app
    package: String,

    /// Device serial
    #[arg(short, long)]
    serial: Option<String>,

    /// Path to static analysis report.json for keyword patterns
    #[arg(short, long)]
    report: Option<PathBuf>,

    /// Output directory
    #[arg(short, long, default_value = "trace_output")]
    output: PathBuf,

    /// Only show lines matching known patterns
    #[arg(long)]
    keywords_only: bool,

    /// Additional keywords to match (comma-separated)
    #[arg(short, long)]
    keywords: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("🔍 OmniSight trace — log analyzer");
    println!("   Target: {}", cli.package);
    if let Some(ref s) = cli.serial {
        println!("   Device: {}", s);
    }

    // Load patterns
    let patterns = if let Some(ref report_path) = cli.report {
        println!("   Loading patterns from: {}", report_path.display());
        let p = matcher::Patterns::from_report(report_path)?;
        println!("   Loaded {} keywords from static analysis", p.keywords.len());
        p
    } else {
        matcher::Patterns::new(Vec::new())
    };

    let mut all_keywords = patterns.keywords.clone();
    if let Some(ref extra) = cli.keywords {
        for kw in extra.split(',') {
            let trimmed = kw.trim();
            if !trimmed.is_empty() {
                all_keywords.push(trimmed.to_string());
            }
        }
    }
    let patterns = matcher::Patterns::new(all_keywords);

    if patterns.is_empty() && cli.keywords_only {
        println!("   ⚠️  No keywords loaded — use --report or --keywords to define patterns");
        println!("      Falling back to showing all log lines.");
    }
    let keywords_only = cli.keywords_only && !patterns.is_empty();

    // Signal handler: Enter to stop
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    std::thread::spawn(move || {
        let mut _input = String::new();
        let _ = std::io::stdin().read_line(&mut _input);
        r.store(false, Ordering::Relaxed);
    });

    // PID resolution with auto-retry
    let pid = loop {
        if !running.load(Ordering::Relaxed) {
            println!("   Cancelled by user.");
            return Ok(());
        }
        match adb::resolve_pid(cli.serial.as_deref(), &cli.package) {
            Ok(pid) => break pid,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("ADB error") {
                    println!("   ⚠️  {} — check USB / authorized devices, then press Enter", msg);
                    let _ = std::io::stdin().read_line(&mut String::new());
                } else {
                    print!("\r   ⏳ Waiting for '{}' to launch... (Enter to cancel)", cli.package);
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
            }
        }
    };
    println!("\n   ✓ PID = {}", pid);

    // Polling loop
    println!("\n📡 Polling logcat (PID {}, every 2s)... Press Enter to stop.\n", pid);
    let start = Instant::now();
    let mut seen_lines = std::collections::HashSet::new();
    let mut total_lines = 0usize;
    let mut matched_lines = 0usize;
    let mut matches_by_pattern: HashMap<String, usize> = HashMap::new();
    let mut matched_entries: Vec<types::MatchedEntry> = Vec::new();
    let max_matched = 1000;

    while running.load(Ordering::Relaxed) {
        let lines = match adb::dump_logcat(cli.serial.as_deref(), pid) {
            Ok(l) => l,
            Err(e) => {
                println!("   Logcat error: {}", e);
                break;
            }
        };

        for line in &lines {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            line.hash(&mut hasher);
            let sig = hasher.finish();
            if !seen_lines.insert(sig) {
                continue;
            }

            total_lines += 1;

            if line.contains("--------- beginning") {
                continue;
            }

            if let Some(entry) = logcat::parse_logcat_line(line) {
                let matched = patterns.match_line(&entry.message);
                let is_match = !matched.is_empty();

                if keywords_only && !is_match {
                    continue;
                }

                if is_match {
                    matched_lines += 1;
                    for pat in &matched {
                        *matches_by_pattern.entry(pat.clone()).or_insert(0) += 1;
                    }
                    if matched_entries.len() < max_matched {
                        matched_entries.push(types::MatchedEntry {
                            entry: entry.clone(),
                            matched_patterns: matched.clone(),
                        });
                    }
                    println!(
                        "  \x1b[33m[{:.1}s]\x1b[0m \x1b[36m{}\x1b[0m: {}",
                        start.elapsed().as_secs_f32(),
                        entry.tag,
                        entry.message
                    );
                } else {
                    println!(
                        "  [{:.1}s] {}/{}: {}",
                        start.elapsed().as_secs_f32(),
                        entry.tag,
                        entry.priority,
                        entry.message
                    );
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // Summary
    let duration = start.elapsed();
    println!("\n\n📊 Trace Summary");
    println!("   Duration: {:.1}s", duration.as_secs_f32());
    println!("   Total lines from target: {}", total_lines);
    println!("   Matched: {} lines", matched_lines);
    println!("   Match rate: {:.1}%",
        if total_lines > 0 { matched_lines as f64 / total_lines as f64 * 100.0 } else { 0.0 });

    if !matches_by_pattern.is_empty() {
        println!("\n   Top patterns:");
        let mut sorted: Vec<_> = matches_by_pattern.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (pat, count) in sorted.iter().take(20) {
            println!("     {}: {}", pat, count);
        }
    }

    let report = types::TraceReport {
        target_package: cli.package,
        duration_secs: duration.as_secs(),
        total_lines,
        matched_lines,
        matches_by_pattern: matches_by_pattern.clone(),
        matched_entries,
    };

    std::fs::create_dir_all(&cli.output)?;
    let report_path = cli.output.join("trace_report.json");
    std::fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;
    println!("\n   Report saved to: {}", report_path.display());
    Ok(())
}
