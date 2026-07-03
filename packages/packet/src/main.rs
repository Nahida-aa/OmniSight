use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "packet", about = "OmniSight network capture (via dumpcap)")]
struct Cli {
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

    /// Max file size in MB before rotation (0 = unlimited)
    #[arg(long, default_value = "100")]
    max_size: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dumpcap = find_dumpcap()?;

    println!("🔍 OmniSight packet — network capture (via dumpcap)\n");

    // Load known IPs
    let known_ips = if let Some(ref path) = cli.report {
        let ips = load_known_ips(path)?;
        println!("   Loaded {} known server IPs", ips.len());
        for ip in &ips { println!("     {}", ip); }
        ips
    } else {
        Vec::new()
    };
    println!();

    // Build filter
    let filter = if let Some(ref f) = cli.filter {
        Some(f.clone())
    } else if !known_ips.is_empty() {
        let ips_part = known_ips.iter().map(|ip| format!("host {}", ip)).collect::<Vec<_>>().join(" or ");
        Some(format!("({}) or port 53 or port 443", ips_part))
    } else {
        None
    };

    // Ensure output directory exists
    if let Some(parent) = cli.output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Build dumpcap command
    let mut cmd = Command::new(&dumpcap);
    cmd.arg("-F").arg("pcapng");
    cmd.arg("-w").arg(&cli.output);
    if let Some(ref f) = filter {
        cmd.arg("-f").arg(f);
        println!("   Capture filter: {}", f);
    }
    println!();

    // Signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n   ⏹️  Stopping...");
        r.store(false, Ordering::Relaxed);
    })?;

    // Start capture
    println!("📡 Capturing... Press Ctrl+C to stop.\n");
    println!("   Output: {}", cli.output.display());
    let start = Instant::now();

    let mut child = cmd.spawn().context("Failed to start dumpcap")?;
    let pid = child.id();

    // Wait loop
    loop {
        if !running.load(Ordering::Relaxed) {
            kill_process(pid);
            let _ = child.wait();
            break;
        }
        if cli.duration > 0 && start.elapsed().as_secs() >= cli.duration {
            println!("   Duration limit reached ({}s)", cli.duration);
            kill_process(pid);
            let _ = child.wait();
            break;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() { eprintln!("   dumpcap exited with error: {}", status); }
                break;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(500)),
            Err(e) => { eprintln!("   Error: {}", e); break; }
        }
    }

    let elapsed = start.elapsed();
    let sz = std::fs::metadata(&cli.output).map(|m| m.len()).unwrap_or(0);

    println!("\n📊 Capture Summary");
    println!("   Duration: {:.1}s", elapsed.as_secs_f32());
    println!("   Output: {} ({:.1} MB)", cli.output.display(), sz as f64 / 1024.0 / 1024.0);

    // Analyze with tshark
    if sz > 0 {
        analyze_pcap(&cli.output, &known_ips)?;
    }

    Ok(())
}

fn analyze_pcap(pcap: &PathBuf, known_ips: &[String]) -> Result<()> {
    let tshark = r"C:\Program Files\Wireshark\tshark.exe";

    println!("\n   Packet count:");
    let out = Command::new(tshark).args(&["-r", &pcap.to_string_lossy()]).arg("-T").arg("fields")
        .arg("-e").arg("frame.number").output()?;
    let n = String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.is_empty()).count();
    println!("     {} packets", n);

    if !known_ips.is_empty() {
        println!("\n   Game server conversations:");
        let conv = Command::new(tshark).args(&["-r", &pcap.to_string_lossy()])
            .arg("-z").arg("conv,ip").output()?;
        for line in String::from_utf8_lossy(&conv.stdout).lines() {
            if known_ips.iter().any(|ip| line.contains(ip.as_str())) {
                println!("     {}", line.trim());
            }
        }

        println!("\n   Protocol hierarchy:");
        let phs = Command::new(tshark).args(&["-r", &pcap.to_string_lossy()])
            .arg("-z").arg("io,phs").output()?;
        for line in String::from_utf8_lossy(&phs.stdout).lines().skip(2).take(15) {
            let t = line.trim();
            if !t.is_empty() { println!("     {}", t); }
        }
    }
    Ok(())
}

fn find_dumpcap() -> Result<String> {
    let candidates = [r"C:\Program Files\Wireshark\dumpcap.exe"];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Ok(c.to_string());
        }
    }
    anyhow::bail!("dumpcap not found. Install Wireshark from https://wireshark.org")
}

fn kill_process(pid: u32) {
    #[cfg(windows)]
    let _ = Command::new("taskkill").args(&["/PID", &pid.to_string()]).output();
    #[cfg(not(windows))]
    let _ = Command::new("kill").arg(pid.to_string()).output();
}

fn load_known_ips(path: &PathBuf) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)?;
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    let mut ips = Vec::new();

    if let Some(entries) = report["strings"]["ips"].as_array() {
        for entry in entries {
            if let Some(val) = entry["value"].as_str() {
                if let Some(colon) = val.find(':') { ips.push(val[..colon].to_string()); }
                else { ips.push(val.to_string()); }
            }
        }
    }
    ips.extend(["58.217.180.240", "58.217.182.91", "1.13.155.158", "222.94.109.121", "182.254.116.117"].map(String::from));
    // Filter out loopback and private IPs
    ips.retain(|ip| !ip.starts_with("127.") && !ip.starts_with("10.") && !ip.starts_with("192.168."));
    ips.sort(); ips.dedup();
    Ok(ips)
}
