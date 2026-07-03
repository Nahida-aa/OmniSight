/**
 * pull-apk.ts — Extract APK from connected Android device
 *
 * Usage: bun run pull-apk.ts [package-name]
 *   If no package name given, lists installed packages.
 *
 * Auto-detects adb from common locations; override via ADB_PATH env var.
 */

import { execSync, spawnSync } from "child_process";
import { existsSync, mkdirSync, readFileSync } from "fs";
import { resolve } from "path";

function detectAdb(): string {
  if (process.env.ADB_PATH) return process.env.ADB_PATH;

  // Known good path from LDPlayer installation
  const knownPaths = [
    "C:\\leidian\\LDPlayer9\\adb.exe",
    "C:\\leidian\\remote\\bin\\adb.exe",
  ];

  for (const p of knownPaths) {
    if (existsSync(p)) return p;
  }

  return "adb";
}

const ADB = detectAdb();
const OUTPUT_DIR = resolve(import.meta.dir!, "../apks");

function runAdb(args: string[]): string {
  const result = spawnSync(ADB, args, { encoding: "utf-8" });
  if (result.error) {
    console.error(`adb error: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`adb exited with code ${result.status}: ${result.stderr}`);
    process.exit(1);
  }
  return result.stdout.trim();
}

function listPackages(): string[] {
  const output = runAdb(["shell", "pm", "list", "packages"]);
  return output
    .split("\n")
    .filter((l) => l.startsWith("package:"))
    .map((l) => l.slice(8));
}

function searchPackages(query: string): string[] {
  const all = listPackages();
  const q = query.toLowerCase();
  return all.filter((pkg) => pkg.toLowerCase().includes(q));
}

function pullApk(packageName: string): string {
  const output = runAdb(["shell", "pm", "path", packageName]);
  const match = output.match(/package:(.+)/);
  if (!match) {
    throw new Error(`Package "${packageName}" not found or no APK path`);
  }

  const apkPath = match[1];
  const destName = packageName.replace(/\./g, "_") + ".apk";
  const destPath = resolve(OUTPUT_DIR, destName);

  if (!existsSync(OUTPUT_DIR)) {
    mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  console.error(`Pulling ${apkPath} → ${destPath} ...`);
  runAdb(["pull", apkPath, destPath]);
  console.error(`✅ Pulled: ${destPath}`);

  const dumpsys = runAdb(["shell", "dumpsys", "package", packageName, "|", "grep", "-i", "version"]);
  console.error(`📋 Version info:\n${dumpsys}`);

  return destPath;
}

// ---- Main
const searchQuery = process.argv[2];

if (!searchQuery) {
  console.error("📱 Connected devices:");
  const devices = runAdb(["devices"]);
  console.error(devices);

  console.error("\n📦 Installed packages (search with: bun run pull-apk.ts <query>):");
  const packages = listPackages();
  console.error(`Total: ${packages.length} packages`);

  const games = packages.filter(
    (p) => p.includes("game") || p.includes("tencent") || p.includes("com.tencent")
  );
  if (games.length > 0) {
    console.error("\nPossible game/tencent packages:");
    games.forEach((p) => console.error(`  ${p}`));
  }
} else {
  const matching = searchPackages(searchQuery);
  if (matching.length === 0) {
    console.error(`No packages matching "${searchQuery}"`);
    process.exit(1);
  }

  if (matching.length === 1) {
    const path = pullApk(matching[0]);
    console.log(path); // stdout so scripts can capture
  } else {
    console.error(`Multiple packages match "${searchQuery}":`);
    matching.forEach((p, i) => console.error(`  [${i}] ${p}`));
    console.error("\nRun again with exact package name.");
  }
}
