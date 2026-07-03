use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Find adb executable from known locations or PATH.
fn find_adb() -> String {
    if let Ok(path) = std::env::var("ADB_PATH") {
        if !path.is_empty() {
            return path;
        }
    }
    let candidates = [
        "C:\\Users\\xm\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\\platform-tools\\adb.exe",
        "C:\\leidian\\LDPlayer9\\adb.exe",
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return c.to_string();
        }
    }
    "adb".to_string()
}

/// Run an adb command and return stdout on success.
pub fn run_adb(serial: Option<&str>, args: &[&str]) -> Result<String> {
    let adb = find_adb();
    let mut cmd = Command::new(&adb);
    if let Some(s) = serial {
        cmd.arg("-s").arg(s);
    }
    cmd.args(args);
    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        let err = if !stderr.is_empty() { stderr.trim() } else { stdout.trim() };
        anyhow::bail!("ADB error: {}", err);
    }
    Ok(stdout)
}

/// Resolve app PID via `pidof`, retry loop friendly.
pub fn resolve_pid(serial: Option<&str>, package: &str) -> Result<u32> {
    let output = run_adb(serial, &["shell", "pidof", package])?;
    let pid_str = output.trim();

    if pid_str.is_empty() {
        anyhow::bail!(
            "Could not find PID for package '{}'. Is the app running?",
            package
        );
    }

    let pid = pid_str
        .split_whitespace()
        .next()
        .context("Empty PID output")?
        .parse::<u32>()?;
    Ok(pid)
}

/// Dump all current logcat lines for a given PID.
pub fn dump_logcat(serial: Option<&str>, pid: u32) -> Result<Vec<String>> {
    let out = run_adb(serial, &["logcat", "-d", "-v", "brief", "--pid", &pid.to_string()])?;
    Ok(out.lines().map(|l| l.to_string()).collect())
}
