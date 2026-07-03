use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

pub fn pcap(pcap: &PathBuf, known_ips: &[String]) -> Result<()> {
    let tshark = r"C:\Program Files\Wireshark\tshark.exe";

    println!("\n   Packet count:");
    let out = Command::new(tshark)
        .args(&["-r", &pcap.to_string_lossy()])
        .arg("-T").arg("fields").arg("-e").arg("frame.number")
        .output()?;
    let n = String::from_utf8_lossy(&out.stdout).lines().filter(|l| !l.is_empty()).count();
    println!("     {} packets", n);

    if known_ips.is_empty() {
        return Ok(());
    }

    println!("\n   Game server conversations:");
    let conv = Command::new(tshark)
        .args(&["-r", &pcap.to_string_lossy()])
        .arg("-z").arg("conv,ip").output()?;
    for line in String::from_utf8_lossy(&conv.stdout).lines() {
        if known_ips.iter().any(|ip| line.contains(ip.as_str())) {
            println!("     {}", line.trim());
        }
    }

    println!("\n   Protocol hierarchy:");
    let phs = Command::new(tshark)
        .args(&["-r", &pcap.to_string_lossy()])
        .arg("-z").arg("io,phs").output()?;
    for line in String::from_utf8_lossy(&phs.stdout).lines().skip(2).take(15) {
        let t = line.trim();
        if !t.is_empty() { println!("     {t}"); }
    }
    Ok(())
}
