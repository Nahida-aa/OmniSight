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

pub fn guess_interface(dumpcap: &str) -> Result<String> {
    let out = Command::new(dumpcap).arg("-D").output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Try to find hotspot adapter with 192.168.137.x IP
    if let Ok(ipc) = Command::new("ipconfig").output() {
        let ips = String::from_utf8_lossy(&ipc.stdout);
        if ips.contains("192.168.137") {
            for line in stdout.lines() {
                if line.contains("本地连接") {
                    let name = line.split(')').next().unwrap_or("").trim();
                    return Ok(name.trim_end_matches('.').to_string());
                }
            }
        }
    }

    // Fallback: first non-VMware, non-loopback
    for line in stdout.lines() {
        let skip = line.contains("Loopback") || line.contains("VMware") || line.contains("蓝牙");
        if !skip {
            let name = line.split(')').next().unwrap_or("").trim();
            return Ok(name.trim_end_matches('.').to_string());
        }
    }
    anyhow::bail!("No suitable interface. Use --interface to specify one.")
}

pub fn spawn(dumpcap: &str, interface: &str, output: &std::path::Path, filter: Option<&str>) -> Result<Child> {
    let mut cmd = Command::new(dumpcap);
    cmd.arg("-i").arg(interface);
    cmd.arg("-F").arg("pcapng");
    cmd.arg("-w").arg(output);
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
