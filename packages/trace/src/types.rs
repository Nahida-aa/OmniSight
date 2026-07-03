use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub pid: u32,
    pub tid: u32,
    pub priority: String,
    pub tag: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MatchedEntry {
    pub entry: LogEntry,
    pub matched_patterns: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TraceReport {
    pub target_package: String,
    pub duration_secs: u64,
    pub total_lines: usize,
    pub matched_lines: usize,
    pub matches_by_pattern: HashMap<String, usize>,
    pub matched_entries: Vec<MatchedEntry>,
}
