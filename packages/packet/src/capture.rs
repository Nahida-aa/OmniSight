use anyhow::{Context, Result};
use std::process::{Child, Command};

pub fn find_dumpcap() -> Result<String> {
    let path = r"C:\Program Files\Wireshark\dumpcap.exe";
    if std::path::Path::new(path).exists() {
        return Ok(path.to_string());
    }
    anyhow::bail!("dumpcap not found at {path}. Install Wireshark from https://wireshark.org")
}

pub fn list_interfaces(dumpcap: &str) -> Result<()> {
    let out = Command::new(dumpcap).arg("-D").output()?;
    println!("Available interfaces:");
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        println!("  {line}");
    }
    Ok(())
}

/// Find the hotspot adapter alias (e.g. "本地连接* 10")
pub fn find_hotspot_alias() -> Option<String> {
    // Try PowerShell first
    if let Ok(ps) = Command::new("powershell")
        .args(&["-Command", "(Get-NetIPAddress -IPAddress 192.168.137.*).InterfaceAlias"])
        .output()
    {
        let alias = String::from_utf8_lossy(&ps.stdout).trim().to_string();
        if !alias.is_empty() {
            return Some(alias);
        }
    }
    // Fallback: parse ipconfig
    let out = Command::new("ipconfig").output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let t = line.trim();
        if t.contains("192.168.137") {
            // Look backwards for adapter name
            return None; // simplified
        }
    }
    None
}

pub fn guess_interface(dumpcap: &str) -> Result<String> {
    let out = Command::new(dumpcap).arg("-D").output()?;
    let devs_raw = String::from_utf8_lossy(&out.stdout);

    if let Some(alias) = find_hotspot_alias() {
        for line in devs_raw.lines() {
            if line.contains(&alias) {
                return Ok(extract_device(line));
            }
        }
    }

    for line in devs_raw.lines() {
        let skip = line.contains("Loopback") || line.contains("VMware") || line.contains("蓝牙");
        if !skip {
            return Ok(extract_device(line));
        }
    }
    anyhow::bail!("No suitable interface. Use --interface to specify one.")
}

fn extract_device(line: &str) -> String {
    let after_idx = line.split_once(' ').map(|(_, r)| r.trim()).unwrap_or(line);
    let dev = after_idx.split_once(' ').map(|(d, _)| d.trim()).unwrap_or(after_idx);
    dev.to_string()
}

pub fn spawn(dumpcap: &str, interface: &str, output: &std::path::Path, filter: Option<&str>) -> Result<Child> {
    let mut cmd = Command::new(dumpcap);
    cmd.arg("-i").arg(interface);
    cmd.arg("-F").arg("pcapng");
    cmd.arg("-w").arg(output);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    if let Some(f) = filter {
        cmd.arg("-f").arg(f);
    }
    Ok(cmd.spawn().context("Failed to start dumpcap")?)
}

pub fn kill(pid: u32) {
    #[cfg(windows)]
    let _ = Command::new("taskkill").args(&["/PID", &pid.to_string()]).output();
    #[cfg(not(windows))]
    let _ = Command::new("kill").arg(pid.to_string()).output();
}
