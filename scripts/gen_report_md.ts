/**
 * gen_report_md.ts — Generate Markdown report from JSON analysis report
 *
 * Usage: bun run gen_report_md.ts [json_path] [md_path]
 *   Defaults: apks/report/report.json → apks/report/report.md
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

const BASE = resolve(import.meta.dir!, "..");

const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");
const mdPath = process.argv[3] ?? resolve(BASE, "apks/report/report.md");

interface ScannedString {
  value: string;
  context: string | null;
  location: string;
  category: string;
}

interface ElfModule {
  path: string;
  exported_symbols: string[];
  imported_symbols: string[];
  strings: ScannedString[];
  engine_type: string;
}

interface ManifestInfo {
  main_activity: string | null;
  permissions: string[];
  services: string[];
  receivers: string[];
}

interface ApkInfo {
  package_name: string;
  version_name: string;
  version_code: number;
  min_sdk: number;
  target_sdk: number;
  file_size: number;
}

interface StringScanResult {
  total_count: number;
  urls: ScannedString[];
  ips: ScannedString[];
  domains: ScannedString[];
  crypto_keys: ScannedString[];
  proto_descriptors: ScannedString[];
  keywords: ScannedString[];
}

interface CryptoInfo {
  algorithms: string[];
  key_lengths: number[];
  custom_patterns: ScannedString[];
}

interface NetworkInfo {
  endpoints: string[];
  protocols: string[];
  certificate_pinning: boolean;
}

interface AnalysisReport {
  apk_info: ApkInfo;
  manifest: ManifestInfo;
  elf_modules: ElfModule[];
  strings: StringScanResult;
  crypto: CryptoInfo;
  network: NetworkInfo;
}

const raw = readFileSync(jsonPath, "utf-8");
const report: AnalysisReport = JSON.parse(raw);

const lines: string[] = [];
const L = (s = "") => lines.push(s);

// Title
L("# OmniSight 静态分析报告");
L();
L(`**目标 APK**: 三角洲行动 (com.tencent.tmgp.dfm)`);
L(`**版本**: ${report.apk_info.version_name || "?"}`);
L(`**文件大小**: ${Math.floor(report.apk_info.file_size / 1024 / 1024)} MB`);
L(`**引擎**: UnrealEngine5`);
L();

// Manifest
const mi = report.manifest;
L("## AndroidManifest 信息");
L();
L(`- **Package**: \`${report.apk_info.package_name}\``);
L(`- **Version Name**: \`${report.apk_info.version_name}\``);
L(`- **Main Activity**: \`${mi.main_activity ?? "?"}\``);
L();

L(`### 权限 (${mi.permissions.length} 个)`);
L();
for (const p of mi.permissions) L(`- \`${p}\``);
L();

L(`### 服务 (${mi.services.length} 个)`);
L();
for (const s of mi.services) L(`- \`${s}\``);
L();

L(`### 接收器 (${mi.receivers.length} 个)`);
L();
for (const r of mi.receivers) L(`- \`${r}\``);
L();

// ELF modules
const elfs = report.elf_modules;
L(`## 原生库 (${elfs.length} 个 ELF 模块)`);
L();
L("| 模块 | 导出符号 | 导入符号 | 字符串 | 引擎 |");
L("|------|---------|---------|-------|------|");
for (const m of elfs) {
  L(`| ${m.path} | ${m.exported_symbols.length} | ${m.imported_symbols.length} | ${m.strings.length} | ${m.engine_type} |`);
}
L();

// String Scan
const ss = report.strings;
L("## 字符串扫描结果");
L();
L(`- **总计找到**: ${ss.total_count} 条匹配`);
L(`- **URL**: ${ss.urls.length} 个`);
L(`- **IP:Port**: ${ss.ips.length} 个`);
L(`- **域名**: ${ss.domains.length} 个`);
L(`- **加密密钥特征**: ${ss.crypto_keys.length} 条`);
L(`- **Protobuf 描述符**: ${ss.proto_descriptors.length} 个`);
L();

// Crypto
if (report.crypto.algorithms.length > 0) {
  L("## 加密算法");
  L();
  for (const a of report.crypto.algorithms) L(`- ${a}`);
  L();
}

// Network
if (report.network.protocols.length > 0) {
  L("## 网络协议");
  L();
  for (const p of report.network.protocols) L(`- ${p}`);
  L();
}

// Notable libraries
L("## 关键库发现");
L();
const keyLibs: Record<string, string> = {
  "libtersafe.so": "ACE 反作弊核心",
  "libtprt.so": "ACE 运行时",
  "libUE4.so": "Unreal Engine (UE5)",
  "libCrashSight.so": "腾讯崩溃上报",
  "libGCloudVoice.so": "腾讯云语音",
  "libgcloud.so": "腾讯云 SDK",
  "libMSDKPIXCore.so": "腾讯 MSDK 核心",
  "libMSDKPIXWechat.so": "微信 SDK",
  "libMSDKPIXQQ.so": "QQ SDK",
  "libgamemaster.so": "腾讯 GameMaster",
  "libtgpa.so": "腾讯 GPA 性能监测",
  "libPcdnTegTransSdk.so": "P2P CDN 资源加速",
};
const elfPaths = elfs.map((m) => m.path);
for (const [lib, desc] of Object.entries(keyLibs)) {
  const found = elfPaths.some((p) => p.includes(lib));
  L(`- ${found ? "✔" : "✘"} **${lib}** — ${desc}`);
}
L();

// Protobuf
L("## Protobuf 协议");
L();
const seen = new Set<string>();
for (const p of ss.proto_descriptors) {
  const top = p.value.split(".")[0];
  if (!seen.has(top)) {
    seen.add(top);
    L(`- \`${p.value}\``);
  }
}
L();

L("---");
L("*报告生成时间: 2026-07-03*");
L();

const reportText = lines.join("\n");
writeFileSync(mdPath, reportText, "utf-8");
console.log(`Generated: ${mdPath}`);
console.log(`Size: ${reportText.length} chars, ${lines.length} lines`);
