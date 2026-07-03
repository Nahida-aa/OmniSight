/**
 * analyze_network.ts — Extract and categorize network endpoints from JSON report
 *
 * Usage: bun run analyze_network.ts [json_path]
 *   Output: apks/report/network_endpoints.md
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

const BASE = resolve(import.meta.dir!, "..");
const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");

const raw = readFileSync(jsonPath, "utf-8");
const report = JSON.parse(raw);

const ss = report.strings ?? {};

const urls: string[] = (ss.urls ?? []).map((s: any) => s.value);
const ips: string[] = (ss.ips ?? []).map((s: any) => s.value);
const domains: string[] = (ss.domains ?? []).map((s: any) => s.value);

// Deduplicate
const uniqueUrls = [...new Set(urls)];
const uniqueIps = [...new Set(ips)];
const uniqueDomains = [...new Set(domains)];

// Categorize domains
const tencentDomains = uniqueDomains.filter(d => d.endsWith(".qq.com") || d.endsWith(".tencent.com") || d.includes("tencent") || d.includes("gcloud") || d.includes("tpns") || d.includes("tpush") || d.endsWith(".gtimg.cn"));
const cdnDomains = uniqueDomains.filter(d => d.includes("cdn") || d.includes("cloudfront") || d.includes("akamai") || d.includes("cloudflare"));
const googleDomains = uniqueDomains.filter(d => d.endsWith(".google.com") || d.endsWith(".googleapis.com") || d.endsWith(".gstatic.com") || d.endsWith(".android.com"));
const appleDomains = uniqueDomains.filter(d => d.endsWith(".apple.com") || d.endsWith(".icloud.com"));
const huaweiDomains = uniqueDomains.filter(d => d.includes("huawei") || d.includes("hicloud"));
const xiaomiDomains = uniqueDomains.filter(d => d.includes("xiaomi") || d.includes("mi.com"));
const otherDomains = uniqueDomains.filter(d =>
  !tencentDomains.includes(d) &&
  !cdnDomains.includes(d) &&
  !googleDomains.includes(d) &&
  !appleDomains.includes(d) &&
  !huaweiDomains.includes(d) &&
  !xiaomiDomains.includes(d)
);

// Filter URLs for likely game servers (not CDN/CMS/ad/tracking)
const gameUrlKeywords = ["game", "delta", "dfm", "sight", "battle", "match", "login", "api", "ws", "wss"];
const gameUrls = uniqueUrls.filter(u => gameUrlKeywords.some(k => u.toLowerCase().includes(k)));

const lines: string[] = [];
const L = (s = "") => lines.push(s);

L("# 网络端点分析");
L();
L(`基于静态扫描结果：URL ${uniqueUrls.length} 个，IP:Port ${uniqueIps.length} 个，域名 ${uniqueDomains.length} 个`);
L();
L("---");
L();
L("## 域名分类");
L();
L(`- **腾讯系**: ${tencentDomains.length} 个`);
L(`- **CDN**: ${cdnDomains.length} 个`);
L(`- **Google**: ${googleDomains.length} 个`);
L(`- **华为**: ${huaweiDomains.length} 个`);
L(`- **小米**: ${xiaomiDomains.length} 个`);
L(`- **其他**: ${otherDomains.length} 个`);
L();
L("### 腾讯系域名（选）");
L();
for (const d of tencentDomains.slice(0, 30)) L(`- \`${d}\``);
if (tencentDomains.length > 30) L(`- ... 还有 ${tencentDomains.length - 30} 个`);
L();
L("### 可能为游戏服地址");
L();
for (const d of otherDomains.filter(d => gameUrlKeywords.some(k => d.includes(k))).slice(0, 20)) {
  L(`- \`${d}\``);
}
L();
L("### 其他域名（选）");
L();
for (const d of otherDomains.filter(d => !gameUrlKeywords.some(k => d.includes(k))).slice(0, 30)) {
  L(`- \`${d}\``);
}
if (otherDomains.length > 60) L(`- ... 还有 ${otherDomains.length - 60} 个`);
L();
L("## URL 端点");
L();
L(`总计 ${uniqueUrls.length} 条 URL`);
L();
L("### 可能的游戏服务器 URL");
L();
for (const u of gameUrls.slice(0, 20)) L(`- \`${u}\``);
L();
L("### 其他 URL（选）");
L();
for (const u of uniqueUrls.filter(u => !gameUrlKeywords.some(k => u.toLowerCase().includes(k))).slice(0, 30)) {
  L(`- \`${u}\``);
}
L();
L("## IP:Port 端点");
L();
for (const ip of uniqueIps.slice(0, 20)) L(`- \`${ip}\``);
if (uniqueIps.length > 20) L(`- ... 还有 ${uniqueIps.length - 20} 个`);
L();
L("---");
L("分析时间: 2026-07-03");

const outPath = resolve(BASE, "apks/report/network_endpoints.md");
writeFileSync(outPath, lines.join("\n"), "utf-8");
console.log(`Generated: ${outPath}`);
console.log(`  ${uniqueUrls.length} URLs, ${uniqueIps.length} IPs, ${uniqueDomains.length} domains`);
