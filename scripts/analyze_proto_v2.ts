/**
 * analyze_proto_v2.ts — Enhanced protobuf analysis with context and categorization
 *
 * Usage: bun run analyze_proto_v2.ts [json_path]
 *   Updates: apks/proto/*.proto with better comments
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { resolve } from "path";

const BASE = resolve(import.meta.dir!, "..");
const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");
const outDir = resolve(BASE, "apks/proto");

const raw = readFileSync(jsonPath, "utf-8");
const report = JSON.parse(raw);
const protos: { value: string; location: string }[] = report.strings?.proto_descriptors ?? [];
const keywords: { value: string; category: string }[] = report.strings?.keywords ?? [];

// Module classification based on context
const nsPurpose: Record<string, string> = {
  "SightPkg": "CrashSight SDK 崩溃上报协议",
  "GCloud": "腾讯云 SDK (GCloud) — 含登录/内购/社交",
  "MicroMsg": "微信/微服务通信协议",
  "ANDROIDSDK": "Android SDK 内部协议",
  "ANDROIDQQ": "QQ SDK 内部协议",
  "Config": "游戏配置协议",
  "TPUSH": "腾讯移动推送 (TPNS/XG Push)",
  "PUSH": "通用推送协议",
  "GameActivity": "UE GameActivity JNI 通信",
  "Message": "通用消息协议",
  "UpdateParams": "Wwise 音频引擎参数更新",
  "GVoice": "GCloud 语音 SDK",
  "GVoiceWSS": "GCloud 语音 WebSocket 协议",
  "ApolloVoiceConfig": "腾讯 Apollo 语音配置",
  "ApolloVoiceLog": "腾讯 Apollo 语音日志",
  "ApolloVoiceDeviceMgr": "腾讯 Apollo 语音设备管理",
  "NetStream": "网络流协议",
  "PufferUpdateService": "P2P 更新服务协议",
  "VersionUpdate": "版本更新协议",
  "DirService": "目录服务协议",
  "QOS": "服务质量/QoS 协议",
  "Auth": "认证协议",
  "HuaweiGame": "华为游戏 SDK",
  "HuaweiIap": "华为内购 SDK",
  "HuaweiPush": "华为推送 SDK",
  "VivoPush": "Vivo 推送 SDK",
  "MSDKPopupConfig": "腾讯 MSDK 弹窗配置",
  "MSDKDnsResolver": "腾讯 MSDK DNS 解析",
  "Matrix": "腾讯 Matrix 性能监控",
  "CrashSight": "CrashSight 崩溃上报",
  "Udp": "UDP 协议",
  "Tcp": "TCP 协议",
  "Rudp": "可靠 UDP 协议",
  "BrokerSocket": "代理 Socket 协议",
  "PebbleChannelMgrService": "Pebble 通道管理服务",
  "QueryAddrSvr": "地址查询服务",
};

// Identify actual game protocol candidates
const knownSdkNs = [
  "SightPkg", "GCloud", "MicroMsg", "TPUSH", "PUSH", "GVoice",
  "ApolloVoice", "Huawei", "Vivo", "Xiaomi", "MSDK",
  "Matrix", "CrashSight", "Tracer",
];
// Namespaces that might be game protocol
const gameProtoNs = [...new Set(protos
  .map(p => p.value.split(".")[0])
  .filter(ns => !knownSdkNs.some(sdk => ns.startsWith(sdk)))
)];

console.log(`Total protobuf namespaces: ${new Set(protos.map(p => p.value.split(".")[0])).size}`);
console.log(`SDK namespaces: ${Object.keys(nsPurpose).length} classified`);
console.log(`Game protocol candidates: ${gameProtoNs.length}`);

// Regenerate proto files with better comments
function rewriteProto(ns: string, types: string[], purpose: string) {
  const nsLines: string[] = [];
  nsLines.push('syntax = "proto3";');
  nsLines.push(`package ${ns};`);
  nsLines.push("");
  nsLines.push(`// ${purpose}`);
  nsLines.push(`// Auto-generated from OmniSight — field numbers need runtime traffic analysis`);
  nsLines.push("");

  // Build tree
  interface Node { name: string; nested: Map<string, Node>; typeNames: string[]; }
  const root = new Map<string, Node>();
  for (const t of types) {
    const parts = t.split(".");
    let current: Map<string, Node> = root;
    for (const p of parts) {
      if (!current.has(p)) current.set(p, { name: p, nested: new Map(), typeNames: [] });
      const node = current.get(p)!;
      // On last part add t to typeNames, otherwise descend into nested
      if (p === parts[parts.length - 1]) {
        node.typeNames.push(t);
      }
      current = node.nested;
    }
  }

  function emit(n: Node, indent: string) {
    const isEntry = n.name.endsWith("Entry");
    const isList = n.name.endsWith("List");
    nsLines.push(`${indent}message ${n.name} {`);
    if (isEntry) {
      nsLines.push(`${indent}  // map<K,V> entry — inferred from naming pattern`);
      nsLines.push(`${indent}  // TODO: determine K and V types from traffic analysis`);
    }
    if (isList || n.name.includes("Reserved")) {
      nsLines.push(`${indent}  // repeated/list field — inferred from naming pattern`);
    }
    if (n.name.includes("Security") || n.name.includes("Encrypt")) {
      nsLines.push(`${indent}  // security/encryption related`);
    }
    if (n.name === "ResponsePkg" || n.name === "RequestPkg") {
      nsLines.push(`${indent}  // TODO: field 1 = headers (map), field 2 = body (bytes), etc.`);
    }
    if (n.nested.size > 0) {
      for (const [, child] of n.nested) {
        nsLines.push("");
        emit(child, `${indent}  `);
      }
    }
    nsLines.push(`${indent}}`);
    nsLines.push("");
  }

  for (const [, node] of root) {
    emit(node, "");
  }

  const path = resolve(outDir, `${ns}.proto`);
  writeFileSync(path, nsLines.join("\n"), "utf-8");
  return { path, lines: nsLines.length };
}

if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

const nsMap = new Map<string, Set<string>>();
for (const p of protos) {
  const ns = p.value.split(".")[0];
  if (!nsMap.has(ns)) nsMap.set(ns, new Set());
  nsMap.get(ns)!.add(p.value);
}

for (const [ns, types] of nsMap) {
  const purpose = nsPurpose[ns] ?? (gameProtoNs.includes(ns) ? "游戏协议候选" : "未知协议");
  const { path, lines } = rewriteProto(ns, [...types], purpose);
  console.log(`  ${purpose ? "✅" : "❓"} ${ns} (${types.size} types, ${lines} lines) → ${path}`);
}

// Generate summary
const summaryLines: string[] = [];
summaryLines.push("# Protobuf 协议分析总结");
summaryLines.push("");
summaryLines.push(`总命名空间: ${nsMap.size}`);
summaryLines.push(`总类型引用: ${protos.length}`);
summaryLines.push("");

// SDK protocols
summaryLines.push("## SDK 协议 (非游戏协议)");
summaryLines.push("");
for (const [ns, purpose] of Object.entries(nsPurpose).sort()) {
  if (nsMap.has(ns)) {
    summaryLines.push(`- **${ns}** (${nsMap.get(ns)!.size} 类型) — ${purpose}`);
  }
}
summaryLines.push("");

// Game protocol candidates
if (gameProtoNs.length > 0) {
  summaryLines.push("## 游戏协议候选");
  summaryLines.push("(这些命名空间不在已知 SDK 列表中，可能是游戏自身协议)");
  summaryLines.push("");
  for (const ns of gameProtoNs.sort()) {
    if (nsMap.has(ns)) {
      const types = [...nsMap.get(ns)!];
      summaryLines.push(`- **${ns}** (${types.length} 类型)`);
      for (const t of types.slice(0, 5)) summaryLines.push(`  - \`${t}\``);
      if (types.length > 5) summaryLines.push(`  - ... 还有 ${types.length - 5} 个`);
    }
  }
  summaryLines.push("");
} else {
  summaryLines.push("## 游戏协议");
  summaryLines.push("未从 protobuf 扫描中识别到游戏自有协议类型。");
  summaryLines.push("三角洲行动的游戏网络协议可能使用：");
  summaryLines.push("- **自定义二进制协议** (非 protobuf)");
  summaryLines.push("- **Protobuf 但类型名被混淆**");
  summaryLines.push("- **FlatBuffers / 其他序列化格式**");
  summaryLines.push("");
}

summaryLines.push("## 下一步建议");
summaryLines.push("");
summaryLines.push("1. **抓包分析**: 运行游戏捕获网络流量，确定实际协议格式");
summaryLines.push("2. **DEX 逆向**: 扫描 DEX 中网络相关类的实际调用链");
summaryLines.push("3. **ELF 深层分析**: 在 libUE4.so 中寻找 UE5 网络组件 (Iris/Engine)");

const summaryPath = resolve(outDir, "SUMMARY.md");
writeFileSync(summaryPath, summaryLines.join("\n"), "utf-8");
console.log(`\nSummary: ${summaryPath}`);
