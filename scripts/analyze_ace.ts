/**
 * analyze_ace.ts — Extract ACE anti-cheat detection points from JSON report
 *
 * Usage: bun run analyze_ace.ts [json_path]
 *   Output: apks/report/ace_analysis.md
 */

import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

const BASE = resolve(import.meta.dir!, "..");
const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");

const raw = readFileSync(jsonPath, "utf-8");
const report = JSON.parse(raw);

const elfs = report.elf_modules ?? [];

// Find ACE-related modules
const tersafe = elfs.find((m: any) => m.path?.includes("libtersafe.so"));
const tprt = elfs.find((m: any) => m.path?.includes("libtprt.so"));

if (!tersafe) {
  console.log("libtersafe.so not found in analysis!");
  process.exit(0);
}

console.log(`ACE core (libtersafe.so): ${tersafe.strings.length} strings`);
console.log(`ACE runtime (libtprt.so): ${tprt?.strings?.length ?? 0} strings`);

// Categorize detection strings
const categories: Record<string, string[]> = {
  "调试器检测": [],
  "进程文件检测": [],
  "内存检测": [],
  "反Frida/Xposed": [],
  "反模拟器": [],
  "系统调用": [],
  "加密混淆": [],
  "其他": [],
};

const allStrings: string[] = (tersafe.strings ?? []).map((s: any) => s.value);
const tprtStrings: string[] = (tprt?.strings ?? []).map((s: any) => s.value);

function classify(s: string): string {
  const l = s.toLowerCase();
  if (l.includes("debugger") || l.includes("pt") || l.includes("trarce") || l.includes("bp") || l.includes("breakpoint") || l.includes("gdb"))
    return "调试器检测";
  if (l.includes("proc/") || l.includes("/maps") || l.includes("/status") || l.includes("/fd/") || l.includes("stat") || l.includes("readlink"))
    return "进程文件检测";
  if (l.includes("maps") || l.includes("dac") || l.includes("memory") || l.includes("alloc") || l.includes("mmap") || l.includes("mprotect"))
    return "内存检测";
  if (l.includes("frida") || l.includes("xposed") || l.includes("substrate") || l.includes("cydia"))
    return "反Frida/Xposed";
  if (l.includes("emul") || l.includes("virt") || l.includes("qemu") || l.includes("genymotion") || l.includes("nox"))
    return "反模拟器";
  if (l.includes("syscall") || l.includes("seccomp") || l.includes("ioctl") || l.includes("socket"))
    return "系统调用";
  if (l.includes("encrypt") || l.includes("cipher") || l.includes("xor") || l.includes("tea") || l.includes("obfus"))
    return "加密混淆";
  return "其他";
}

// Only collect interesting strings (longer than 8 chars, printable)
const interesting = allStrings.filter(s => s.length >= 12)
  .filter(s => !s.startsWith("N12") && !s.startsWith("N2") && !s.startsWith("N8")); // Filter mangled C++ names

for (const s of interesting) {
  const cat = classify(s);
  categories[cat].push(s);
}

const lines: string[] = [];
const L = (s = "") => lines.push(s);

L("# ACE 反作弊分析 (libtersafe.so)");
L();
L(`**总字符串数**: ${tersafe.strings.length}`);
L(`**ACE Runtime (libtprt.so)**: ${tprt?.strings?.length ?? 0} 条字符串`);
L();

// Build path
L("## 构建信息");
L();
const buildPaths = allStrings.filter(s => s.includes("/Users/") || s.includes("/home/") || s.includes("/root/"));
for (const p of buildPaths) L(`- \`${p}\``);
L();

// ACE package reference
L("## ACE 包名引用");
L();
const pkgRefs = allStrings.filter(s => s.includes(".ace.") || s.includes("gamesafe"));
for (const p of pkgRefs) L(`- \`${p}\``);
L();

// Data files
L("## ACE 数据文件引用");
L();
const datFiles = tprtStrings.filter(s => s.includes(".dat") || s.includes(".sig") || s.includes(".PK"));
for (const d of datFiles) L(`- \`${d}\``);
L();

// Detection strings by category
for (const [cat, strs] of Object.entries(categories)) {
  if (strs.length === 0) continue;
  L(`## ${cat} (${strs.length} 条)`);
  L();
  for (const s of strs.slice(0, 30)) {
    L(`- \`${s}\``);
  }
  if (strs.length > 30) L(`- ... 还有 ${strs.length - 30} 条`);
  L();
}

// All strings dump
L("---");
L("## libtersafe.so 全部字符串");
L();
for (const s of allStrings) L(`- \`${s}\``);
L();

const outPath = resolve(BASE, "apks/report/ace_analysis.md");
writeFileSync(outPath, lines.join("\n"), "utf-8");
console.log(`Generated: ${outPath}`);
