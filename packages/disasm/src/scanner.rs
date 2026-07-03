use anyhow::Result;
use omnisight_shared::types::{
    CryptoInfo, ElfModuleInfo, NetworkInfo, ScannedString, StringScanResult,
};
use regex::Regex;
use crate::apk::ApkData;

/// Scan all data for interesting strings: URLs, IPs, crypto keys, proto descriptors
#[allow(unused_variables)]
pub fn scan_all(apk: &ApkData, elf_modules: &[ElfModuleInfo]) -> Result<StringScanResult> {
    let mut all_data = Vec::new();

    // Collect all raw bytes we have
    for dex in &apk.dex_files {
        all_data.extend_from_slice(dex);
    }
    for (_, elf_data) in &apk.elf_files {
        all_data.extend_from_slice(elf_data);
    }

    let haystack = String::from_utf8_lossy(&all_data);

    let urls = scan_urls(&haystack);
    let ips = scan_ips(&haystack);
    let domains = scan_domains(&haystack);
    let crypto_keys = scan_crypto_keys(&haystack);
    let proto_descriptors = scan_proto_descriptors(&haystack);
    let keywords = scan_keywords(&haystack);

    Ok(StringScanResult {
        total_count: urls.len() + ips.len() + domains.len() + crypto_keys.len() + proto_descriptors.len() + keywords.len(),
        urls,
        ips,
        domains,
        crypto_keys,
        proto_descriptors,
        keywords,
    })
}

fn scan_urls(haystack: &str) -> Vec<ScannedString> {
    let re = Regex::new(r#"(https?://[^\s"'>)\]]+)"#).unwrap();
    re.captures_iter(haystack)
        .map(|c| ScannedString {
            value: c[1].to_string(),
            context: None,
            location: "all".to_string(),
            category: "url".to_string(),
        })
        .collect()
}

fn scan_ips(haystack: &str) -> Vec<ScannedString> {
    let re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})\b").unwrap();
    re.captures_iter(haystack)
        .map(|c| ScannedString {
            value: c[1].to_string(),
            context: None,
            location: "all".to_string(),
            category: "ip".to_string(),
        })
        .collect()
}

fn scan_domains(haystack: &str) -> Vec<ScannedString> {
    let re = Regex::new(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").unwrap();
    let mut results = Vec::new();
    for cap in re.captures_iter(haystack) {
        let domain = cap[0].to_string();
        // Filter out non-domain matches
        if domain.len() > 4 && !domain.contains("_") {
            results.push(ScannedString {
                value: domain,
                context: None,
                location: "all".to_string(),
                category: "domain".to_string(),
            });
        }
    }
    results
}

fn scan_crypto_keys(haystack: &str) -> Vec<ScannedString> {
    let mut results = Vec::new();

    // Look for base64-like strings that might be keys
    let re = Regex::new(r#"[A-Za-z0-9+/=]{20,64}"#).unwrap();
    for cap in re.captures_iter(haystack) {
        let s = cap[0].to_string();
        if s.chars().filter(|&c| c == '=').count() <= 2 && s.len() >= 20 {
            results.push(ScannedString {
                value: s,
                context: None,
                location: "all".to_string(),
                category: "potential_key".to_string(),
            });
        }
    }

    // Look for known key patterns
    let patterns = [
        "AES", "RSA", "DES", "3DES", "SecretKey", "private_key", "public_key",
        "api_key", "apikey", "token", "secret", "sign_key",
    ];
    for pat in patterns {
        let re = Regex::new(&format!(r#"(?i)({}[\s:=]+["']?([^"'\)\s]+))"#, regex::escape(pat))).unwrap();
        for cap in re.captures_iter(haystack) {
            results.push(ScannedString {
                value: cap[0].to_string(),
                context: None,
                location: "all".to_string(),
                category: "key_reference".to_string(),
            });
        }
    }

    results
}

fn scan_proto_descriptors(haystack: &str) -> Vec<ScannedString> {
    let mut results = Vec::new();

    // Protobuf field descriptors contain patterns like `\n\x02\x08\x01`
    // Also look for literal "message " and "package " patterns
    let re = Regex::new(r#"(?m)^\s*(message|enum|service|package)\s+([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
    for cap in re.captures_iter(haystack) {
        results.push(ScannedString {
            value: format!("{} {}", &cap[1], &cap[2]),
            context: None,
            location: "all".to_string(),
            category: "protobuf".to_string(),
        });
    }

    results
}

fn scan_keywords(haystack: &str) -> Vec<ScannedString> {
    let keywords = [
        "opcode", "packet", "session", "heartbeat", "login", "auth",
        "register", "connect", "disconnect", "websocket", "tcp", "udp",
        "kcp", "quic", "http2", "grpc", "protobuf", "flatbuffers",
        "encrypt", "decrypt", "cipher", "digest", "md5", "sha",
        "base64", "url", "endpoint", "gateway", "router",
    ];

    let mut results = Vec::new();
    let haystack_lower = haystack.to_lowercase();

    for kw in &keywords {
        let count = haystack_lower.matches(kw).count();
        if count > 0 {
            results.push(ScannedString {
                value: format!("{} ({} occurrences)", kw, count),
                context: None,
                location: "all".to_string(),
                category: "keyword".to_string(),
            });
        }
    }

    results
}

#[allow(unused_variables)]
pub fn detect_crypto(scan: &StringScanResult, elf_modules: &[ElfModuleInfo]) -> Result<CryptoInfo> {
    let mut algorithms = Vec::new();
    let known_algorithms = ["AES", "RSA", "DES", "3DES", "Blowfish", "ChaCha20", "SM4", "SM3"];

    for algo in &known_algorithms {
        if scan.keywords.iter().any(|s| s.value.to_uppercase().contains(algo)) {
            algorithms.push(algo.to_string());
        }
    }

    Ok(CryptoInfo {
        algorithms,
        key_lengths: Vec::new(),
        custom_patterns: scan.crypto_keys.clone(),
    })
}

#[allow(unused_variables)]
pub fn detect_network(scan: &StringScanResult, elf_modules: &[ElfModuleInfo]) -> Result<NetworkInfo> {
    let mut endpoints: Vec<String> = scan.urls.iter().map(|s| s.value.clone()).collect();
    endpoints.extend(scan.ips.iter().map(|s| s.value.clone()));
    endpoints.extend(scan.domains.iter().map(|s| s.value.clone()));

    let mut protocols = Vec::new();
    for kw in &scan.keywords {
        if kw.category == "keyword" {
            for proto in &["tcp", "udp", "websocket", "http2", "grpc", "kcp", "quic"] {
                if kw.value.to_lowercase().contains(proto) {
                    protocols.push(proto.to_string());
                }
            }
        }
    }
    protocols.sort();
    protocols.dedup();

    Ok(NetworkInfo {
        endpoints,
        protocols,
        certificate_pinning: false,
    })
}
