use regex::Regex;
use crate::types::LogEntry;

/// Parse a logcat line in brief format:
///   D/TAG     ( 1234): message
pub fn parse_logcat_line(line: &str) -> Option<LogEntry> {
    let re = Regex::new(r"^([A-Z])/(\S+)\s*\(\s*(\d+)\s*\):\s+(.*)$").unwrap();
    if let Some(cap) = re.captures(line) {
        return Some(LogEntry {
            timestamp: String::new(),
            pid: cap[3].parse().unwrap_or(0),
            tid: 0,
            priority: cap[1].to_string(),
            tag: cap[2].to_string(),
            message: cap[4].to_string(),
        });
    }
    None
}
