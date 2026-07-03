/**
 * analyze_ue5.ts — Scan UE5 engine for GName/GObjects/UObject patterns
 *
 * Usage: bun run analyze_ue5.ts [json_path]
 *   Output: apks/report/ue5_analysis.md
 *   Reads: apks/report/report.json for string data
 *          apks/com_tencent_tmgp_dfm.apk for binary scanning of libUE4.so
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { execSync } from "child_process";

const BASE = resolve(import.meta.dir!, "..");
const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");
const apkPath = resolve(BASE, "apks/com_tencent_tmgp_dfm.apk");
const outPath = resolve(BASE, "apks/report/ue5_analysis.md");

const raw = readFileSync(jsonPath, "utf-8");
const report = JSON.parse(raw);

const elfs = report.elf_modules ?? [];
const libUE4 = elfs.find((m: any) => m.path?.includes("libUE4.so"));

if (!libUE4) {
  console.log("libUE4.so not found in analysis!");
  process.exit(0);
}

console.log(`libUE4.so: ${libUE4.exported_symbols.length} exported, ${libUE4.imported_symbols.length} imported, ${libUE4.strings.length} strings`);

// Get all strings from libUE4
const ue4Strings: string[] = (libUE4.strings ?? []).map((s: any) => s.value);
const exportedSyms: string[] = libUE4.exported_symbols ?? [];
const importedSyms: string[] = libUE4.imported_symbols ?? [];

// Known UE pattern keywords
const uePatterns: Record<string, string[]> = {
  "GName": ["GName", "FNamePool", "FNameEntry", "NamePool", "NameHash"],
  "GObjects": ["GObjects", "GUObjectArray", "TUObjectArray", "FUObjectItem", "ObjectArray"],
  "FName": ["FName", "FNameInit", "ComparisonIndex", "DisplayIndex"],
  "UObject": ["UObject", "StaticClass", "ClassPrivate", "OuterPrivate", "InternalIndex"],
  "EngineSubsystems": ["FEngineSubsystem", "UGameInstance", "UWorld", "ULevel", "APlayerController"],
  "UE5Features": ["UE5", "EnhancedInput", "Chaos", "Niagara", "MetaSound"],
  "CoreTypes": ["FString", "TArray", "TMap", "TSet", "FMemory", "FString::Printf"],
};

// Check for pattern presence
const foundPatterns: string[] = [];
for (const [category, patterns] of Object.entries(uePatterns)) {
  const hits = patterns.filter(p =>
    ue4Strings.some(s => s.includes(p)) ||
    exportedSyms.some(s => s.includes(p)) ||
    importedSyms.some(s => s.includes(p))
  );
  if (hits.length > 0) {
    foundPatterns.push(`- **${category}**: ${hits.join(", ")}`);
  }
}

// Look for offset-related strings
const offsetPatterns = ue4Strings.filter(s =>
  /0x[0-9a-fA-F]{4,8}/.test(s) && s.length < 60 &&
  (s.includes("GName") || s.includes("Object") || s.includes("World") || s.includes("Chunk") || s.includes("Offset"))
);

// Look for version strings
const versions = ue4Strings.filter(s => /UE\d/.test(s) || s.includes("UnrealEngine") || /Engine_Version/i.test(s) || /\d+\.\d+/.test(s) && s.length < 30);

const lines: string[] = [];
const L = (s = "") => lines.push(s);

L("# UE5 引擎偏移分析 (libUE4.so)");
L();
L(`**库路径**: libUE4.so`);
L(`**分析时间**: 2026-07-03`);
L();

L("## 基础统计");
L();
L(`- 导出符号: ${libUE4.exported_symbols.length}`);
L(`- 导入符号: ${libUE4.imported_symbols.length}`);
L(`- 字符串: ${ue4Strings.length}`);
L();

L("## 引擎版本特征");
L();
for (const v of versions.slice(0, 20)) L(`- \`${v}\``);
L();

L("## UE 模式匹配结果");
L();
for (const p of foundPatterns) L(p);
L();

L("## 可能的偏移量 / 地址引用");
L();
for (const o of offsetPatterns.slice(0, 30)) L(`- \`${o}\``);
L();

L("## 导出符号 (前 50)");
L();
for (const s of exportedSyms.slice(0, 50)) L(`- \`${s}\``);
if (exportedSyms.length > 50) L(`- ... 还有 ${exportedSyms.length - 50} 个`);
L();

L("## 导入符号 (前 100)");
L();
for (const s of importedSyms.slice(0, 100)) L(`- \`${s}\``);
if (importedSyms.length > 100) L(`- ... 还有 ${importedSyms.length - 100} 个`);
L();

L("## 关键字符串 (前 100)");
L();
// Filter out garbage strings
const cleanStrings = ue4Strings.filter(s => s.length >= 6 && s.length < 80 && /[a-zA-Z]{3,}/.test(s));
for (const s of cleanStrings.slice(0, 100)) L(`- \`${s}\``);
L();

writeFileSync(outPath, lines.join("\n"), "utf-8");
console.log(`Generated: ${outPath}`);
