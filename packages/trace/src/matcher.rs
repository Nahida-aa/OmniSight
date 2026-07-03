use regex::RegexSet;
use std::path::PathBuf;

pub struct Patterns {
    pub keywords: Vec<String>,
    pattern_names: Vec<String>,
    set: RegexSet,
}

impl Patterns {
    pub fn from_report(report_path: &PathBuf) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(report_path)?;
        let report: serde_json::Value = serde_json::from_str(&raw)?;
        let mut keywords = Vec::new();

        if let Some(kws) = report["strings"]["keywords"].as_array() {
            for kw in kws {
                let val = kw["value"].as_str().unwrap_or("");
                if let Some(name) = val.split('(').next() {
                    let t = name.trim().to_lowercase();
                    if t.len() >= 3 {
                        keywords.push(t);
                    }
                }
            }
        }

        if let Some(algo) = report["crypto"]["algorithms"].as_array() {
            for a in algo {
                if let Some(name) = a.as_str() {
                    keywords.push(name.to_lowercase());
                }
            }
        }

        if let Some(protos) = report["network"]["protocols"].as_array() {
            for p in protos {
                if let Some(name) = p.as_str() {
                    keywords.push(name.to_lowercase());
                }
            }
        }

        Ok(Self::new(keywords))
    }

    pub fn new(keywords: Vec<String>) -> Self {
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<String> = keywords
            .into_iter()
            .filter(|k| {
                let lower = k.to_lowercase();
                seen.insert(lower)
            })
            .collect();

        let patterns: Vec<String> = unique.iter().map(|k| regex::escape(k)).collect();
        let pattern_names = unique.clone();
        let set = RegexSet::new(&patterns).unwrap_or_else(|_| RegexSet::empty());

        Self {
            keywords: unique,
            pattern_names,
            set,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keywords.is_empty()
    }

    pub fn match_line(&self, line: &str) -> Vec<String> {
        self.set
            .matches(line)
            .into_iter()
            .map(|i| self.pattern_names[i].clone())
            .collect()
    }
}
