/**
 * analyze_proto.ts — Extract protobuf type structure from JSON report
 *
 * Usage: bun run analyze_proto.ts [json_path]
 *   Defaults: apks/report/report.json
 *   Output: apks/proto/
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { resolve, dirname } from "path";

const BASE = resolve(import.meta.dir!, "..");
const jsonPath = process.argv[2] ?? resolve(BASE, "apks/report/report.json");
const outDir = resolve(BASE, "apks/proto");

interface ScannedString {
  value: string;
  context: string | null;
  location: string;
  category: string;
}

const raw = readFileSync(jsonPath, "utf-8");
const report = JSON.parse(raw);

const protos: ScannedString[] = report.strings?.proto_descriptors ?? [];
console.log(`Total protobuf descriptors: ${protos.length}`);

// Group by top-level namespace
const namespaceMap = new Map<string, Set<string>>();
const allTypes = new Set<string>();

for (const p of protos) {
  const val = p.value;
  allTypes.add(val);
  const parts = val.split(".");
  if (parts.length >= 2) {
    const ns = parts[0];
    if (!namespaceMap.has(ns)) namespaceMap.set(ns, new Set());
    namespaceMap.get(ns)!.add(val);
  }
}

// Create output directory
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

let combinedLines: string[] = [];
combinedLines.push('syntax = "proto3";');
combinedLines.push("");
combinedLines.push('// Auto-generated from OmniSight static analysis');
combinedLines.push(`// ${protos.length} type references found`);
combinedLines.push("");

// Infer message hierarchy: ParentType.SubType → nested messages
interface MessageNode {
  name: string;
  fields: string[];
  nested: Map<string, MessageNode>;
}

function buildTree(types: string[]): Map<string, MessageNode> {
  const root = new Map<string, MessageNode>();

  for (const t of types) {
    const parts = t.split(".");
    let current = root;
    let full = "";

    for (let i = 0; i < parts.length; i++) {
      full = full ? `${full}.${parts[i]}` : parts[i];
      if (!current.has(parts[i])) {
        current.set(parts[i], { name: parts[i], fields: [], nested: new Map() });
      }
      // Leaf node — check if it looks like a field entry (ValueMapEntry, ReservedEntry, etc.)
      if (i === parts.length - 1) {
        const node = current.get(parts[i])!;
        // Infer field names from common patterns
        if (parts[i].endsWith("Entry")) {
          node.fields.push("// map field (inferred from naming)");
        }
        if (parts[i].endsWith("List")) {
          node.fields.push("// repeated field (inferred from naming)");
        }
        // Try to infer from sibling relationships
        if (parts.length >= 2) {
          const parentName = parts[parts.length - 2];
          node.fields.push(`// child of ${parentName}`);
        }
      }
      // Descend only if not last part
      if (i < parts.length - 1) {
        current = current.get(parts[i])!.nested;
      }
    }
  }
  return root;
}

function emitProto(node: MessageNode, indent: string, lines: string[]) {
  lines.push(`${indent}message ${node.name} {`);
  if (node.fields.length > 0) {
    for (const f of node.fields) {
      lines.push(`${indent}  ${f}`);
    }
    lines.push("");
  }
  if (node.nested.size > 0) {
    for (const [, child] of node.nested) {
      emitProto(child, `${indent}  `, lines);
    }
  }
  lines.push(`${indent}}`);
  lines.push("");
}

// Generate per-namespace proto files
for (const [ns, types] of namespaceMap) {
  const nsLines: string[] = [];
  nsLines.push('syntax = "proto3";');
  nsLines.push(`package ${ns};`);
  nsLines.push("");
  nsLines.push(`// ${ns} — ${types.size} type references`);
  nsLines.push("");

  const tree = buildTree([...types]);
  for (const [, node] of tree) {
    emitProto(node, "", nsLines);
  }

  const filePath = resolve(outDir, `${ns}.proto`);
  writeFileSync(filePath, nsLines.join("\n"), "utf-8");
  console.log(`  Wrote ${nsLines.length} lines → ${filePath}`);

  combinedLines.push(`// === ${ns} (${types.size} types) ===`);
  combinedLines.push(`import "${ns}.proto";`);
  combinedLines.push("");
}

// Also dump raw type list
const rawPath = resolve(outDir, "proto_types.txt");
const rawList = [...allTypes].sort().join("\n");
writeFileSync(rawPath, rawList, "utf-8");
console.log(`  Wrote ${allTypes.size} type names → ${rawPath}`);

// Summary
console.log(`\nNamespaces:`);
for (const [ns, types] of namespaceMap) {
  console.log(`  ${ns}: ${types.size} types`);
}
