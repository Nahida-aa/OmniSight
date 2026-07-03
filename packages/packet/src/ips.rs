use anyhow::Result;
use std::path::PathBuf;

pub fn load_known_ips(path: &PathBuf) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)?;
    let report: serde_json::Value = serde_json::from_str(&raw)?;
    let mut ips = Vec::new();

    if let Some(entries) = report["strings"]["ips"].as_array() {
        for entry in entries {
            if let Some(val) = entry["value"].as_str() {
                if let Some(colon) = val.find(':') {
                    ips.push(val[..colon].to_string());
                } else {
                    ips.push(val.to_string());
                }
            }
        }
    }

    ips.extend([
        "58.217.180.240", "58.217.182.91",
        "1.13.155.158", "222.94.109.121", "182.254.116.117",
    ].map(String::from));

    ips.retain(|ip| !ip.starts_with("127.") && !ip.starts_with("10.") && !ip.starts_with("192.168."));
    ips.sort();
    ips.dedup();
    Ok(ips)
}
