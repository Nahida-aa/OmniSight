use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

mod capture;
mod analyze;
mod ips;

#[derive(Parser)]
#[command(name = "packet", about = "OmniSight network capture (via dumpcap)")]
struct Cli {
    /// List available capture interfaces and exit
    #[arg(long)]
    list_interfaces: bool,

    /// Network interface name or GUID to capture on
    #[arg(short, long)]
    interface: Option<String>,

    /// Output pcap file path
    #[arg(short, long, default_value = "capture/dfm.pcapng")]
    output: PathBuf,

    /// BPF capture filter (e.g. "host 1.2.3.4 or port 53")
    #[arg(short, long)]
    filter: Option<String>,

    /// Static analysis report.json for known server IPs
    #[arg(short, long)]
    report: Option<PathBuf>,

    /// Auto-stop after N seconds (0 = manual Ctrl+C)
    #[arg(short, long, default_value = "0")]
    duration: u64,
}

fn main() -> Result<()> {
    // Set console to UTF-8 on Windows
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("cmd").args(["/c", "chcp", "65001"]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).output();
    }

    let cli = Cli::parse();

    let dumpcap = capture::find_dumpcap()?;

    if cli.list_interfaces {
        capture::list_interfaces(&dumpcap)?;
        return Ok(());
    }

    println!("🔍 OmniSight packet — network capture (via dumpcap)\n");

    let known_ips = if let Some(ref path) = cli.report {
        let ips = ips::load_known_ips(path)?;
        println!("   Loaded {} known server IPs", ips.len());
        for ip in &ips { println!("     {}", ip); }
        ips
    } else {
        Vec::new()
    };
    println!();

    let filter = if let Some(ref f) = cli.filter {
        Some(f.clone())
    } else {
        None  // Capture everything; tshark will filter in analysis
    };

    if let Some(parent) = cli.output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let interface = if let Some(ref name) = cli.interface {
        name.clone()
    } else {
        capture::guess_interface(&dumpcap)?
    };

    // Show interface info
    let alias = capture::find_hotspot_alias().unwrap_or_else(|| interface.clone());
    println!("   Interface: {alias} (192.168.137.1 — 移动热点)");

    let mut child = capture::spawn(&dumpcap, &interface, &cli.output, filter.as_deref())?;
    println!("📡 Capturing... Press Ctrl+C to stop.\n");
    println!("   Output: {}", cli.output.display());

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n   ⏹️  Stopping...");
        r.store(false, Ordering::Relaxed);
    })?;

    let start = Instant::now();
    let pid = child.id();

    'wait: loop {
        if !running.load(Ordering::Relaxed) { capture::kill(pid); let _ = child.wait(); break; }
        if cli.duration > 0 && start.elapsed().as_secs() >= cli.duration {
            println!("   Duration limit reached ({}s)", cli.duration);
            capture::kill(pid); let _ = child.wait(); break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() { eprintln!("   dumpcap error: {status}"); }
                break 'wait;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(500)),
            Err(e) => { eprintln!("   Error: {e}"); break; }
        }
    }

    let elapsed = start.elapsed();
    let sz = std::fs::metadata(&cli.output).map(|m| m.len()).unwrap_or(0);

    println!("\n📊 Capture Summary");
    println!("   Duration: {:.1}s", elapsed.as_secs_f32());
    println!("   Output: {} ({:.1} MB)", cli.output.display(), sz as f64 / 1024.0 / 1024.0);

    if sz > 0 {
        analyze::pcap(&cli.output, &known_ips)?;
    }
    Ok(())
}
