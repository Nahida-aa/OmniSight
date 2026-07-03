use serde::{Deserialize, Serialize};

/// 静态分析报告顶层结构
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AnalysisReport {
    pub apk_info: ApkInfo,
    pub manifest: ManifestInfo,
    pub dex_classes: Vec<DexClassInfo>,
    pub elf_modules: Vec<ElfModuleInfo>,
    pub strings: StringScanResult,
    pub crypto: CryptoInfo,
    pub network: NetworkInfo,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ApkInfo {
    pub package_name: String,
    pub version_name: String,
    pub version_code: u64,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub file_size: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ManifestInfo {
    pub main_activity: Option<String>,
    pub services: Vec<String>,
    pub receivers: Vec<String>,
    pub permissions: Vec<String>,
    pub network_security_config: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DexClassInfo {
    pub name: String,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<DexMethodInfo>,
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DexMethodInfo {
    pub name: String,
    pub signature: String,
    pub access_flags: u32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ElfModuleInfo {
    pub path: String,
    pub is_native: bool,
    pub engine_type: EngineType,
    pub exported_symbols: Vec<String>,
    pub imported_symbols: Vec<String>,
    pub strings: Vec<ScannedString>,
    pub sections: Vec<ElfSection>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub enum EngineType {
    #[default]
    Unknown,
    UnrealEngine4,
    UnrealEngine5,
    Unity,
    Custom,
    Other(String),
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ElfSection {
    pub name: String,
    pub size: u64,
    pub offset: u64,
    pub flags: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScannedString {
    pub value: String,
    pub context: Option<String>,
    pub location: String,
    pub category: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StringScanResult {
    pub total_count: usize,
    pub urls: Vec<ScannedString>,
    pub ips: Vec<ScannedString>,
    pub domains: Vec<ScannedString>,
    pub crypto_keys: Vec<ScannedString>,
    pub proto_descriptors: Vec<ScannedString>,
    pub keywords: Vec<ScannedString>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CryptoInfo {
    pub algorithms: Vec<String>,
    pub key_lengths: Vec<u32>,
    pub custom_patterns: Vec<ScannedString>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NetworkInfo {
    pub endpoints: Vec<String>,
    pub protocols: Vec<String>,
    pub certificate_pinning: bool,
}
