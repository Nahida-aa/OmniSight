#!/usr/bin/env python3
"""Reverse engineer ApolloBuffer serialization format from libgcloudcore.so"""
import zipfile, re, struct, sys

apk_path = r"D:\repos\game_ls\OmniSight\apks\com_tencent_tmgp_dfm.apk"

# Extract libgcloudcore.so
print("Extracting libgcloudcore.so...")
with zipfile.ZipFile(apk_path, 'r') as z:
    for name in z.namelist():
        if name.endswith("libgcloudcore.so"):
            data = z.read(name)
            print(f"  Found: {name} ({len(data)} bytes)")
            break
    else:
        print("  NOT FOUND")
        sys.exit(1)

# ---- Scan 1: Format-related strings ----
print("\n=== Serialization Keywords ===")
keywords = [
    "ApolloBuffer", "apollo", "tag", "field", "encode", "decode",
    "varint", "fixed32", "fixed64", "length", "delimite",
    "Write", "Read", "AObject", "AString", "AArray",
    "Tdr", "tdr", "buffer", "type",
]
for kw in keywords:
    count = data.lower().count(kw.lower().encode())
    if count > 0:
        positions = []
        pos = 0
        while len(positions) < 3:
            idx = data.lower().find(kw.lower().encode(), pos)
            if idx == -1: break
            positions.append(f"0x{idx:x}")
            pos = idx + 1
        print(f"  '{kw}': {count} hits [{', '.join(positions)}]")

# ---- Scan 2: Known serialization constants ----
print("\n=== Wire Format Constants ===")
# Protobuf-style wire types
wire_types = {
    "VARINT (0)": 0,
    "FIXED64 (1)": 1,
    "LENGTH_DELIMITED (2)": 2,
    "FIXED32 (5)": 5,
}
for name, val in wire_types.items():
    # Search for patterns near wire type values
    buf = struct.pack('<I', val)
    idx = data.find(buf)
    if idx >= 0 and idx < len(data):
        print(f"  {name}: offset 0x{idx:x}")

# ---- Scan 3: TdrBufUtil format strings ----
print("\n=== TdrBufUtil Format Strings ===")
tdr_patterns = [
    (b"%d", "int format"),
    (b"%u", "uint format"),
    (b"%lld", "long long"),
    (b"%s", "string format"),
    (b"tag", "tag keyword"),
    (b"type", "type keyword"),
    (b"count", "count keyword"),
    (b"size", "size keyword"),
    (b"field", "field keyword"),
    (b"len", "len keyword"),
]
for pat, desc in tdr_patterns:
    idx = data.find(pat)
    if idx >= 0:
        ctx = data[max(0,idx-4):idx+len(pat)+20]
        s = ''.join(chr(b) if 32<=b<127 else '.' for b in ctx)
        print(f"  {desc} at 0x{idx:x}: {s}")

# ---- Scan 4: Look for field encoding patterns in packet data ----
print("\n=== Analyzing Captured Packet (TCP 65010) ===")
# First TCP packet from our pcap: 3366000b000c401300000004c0000000190000003000000000...
packet_hex = "3366000b000c401300000004c0000000190000003000000000a1ed15b07dbca557dd8fde6dec231f0eb1713272ab9db9c9b1c236c762797afe4836a407c44cdc7402d91e6306ddf037"
packet = bytes.fromhex(packet_hex)

print(f"  Packet length: {len(packet)} bytes")
print(f"  Raw hex: {packet[:40].hex()}")

# Parse potential header
magic = packet[0:2]
print(f"  Magic: {magic.hex()} (0x{struct.unpack('<H', magic)[0]:04x})")

# Try different field layouts
for offset_name, offset, fmt in [
    ("u16", 2, '<H'), ("u16", 4, '<H'), ("u32", 2, '<I'), ("u32", 4, '<I'),
    ("u32", 8, '<I'), ("u32", 12, '<I'), ("u32", 16, '<I'),
]:
    if offset + struct.calcsize(fmt) <= len(packet):
        val = struct.unpack(fmt, packet[offset:offset+struct.calcsize(fmt)])[0]
        print(f"  Field at offset {offset} ({offset_name}): {val} (0x{val:x})")

# Varint decode test
def read_varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos

print("\n  Varint decode attempt:")
for start in range(0, min(20, len(packet))):
    val, end = read_varint(packet, start)
    if end > start and val < 0x10000:
        print(f"    offset {start}: varint = {val} (0x{val:x})")

# Search for tag+type patterns (like protobuf)
print("\n  Tag+Type field parsing (proto-like):")
pos = 0
fields = []
while pos < len(packet) - 1:
    tag_type = packet[pos]
    field_num = tag_type >> 3
    wire_type = tag_type & 7
    if field_num == 0:
        break
    pos += 1
    if wire_type == 0:  # varint
        val, pos = read_varint(packet, pos)
        fields.append((field_num, wire_type, val))
    elif wire_type == 2:  # length-delimited
        length, pos = read_varint(packet, pos)
        val = packet[pos:pos+length]
        pos += length
        fields.append((field_num, wire_type, val.hex()[:40]))
    elif wire_type == 5:  # fixed32
        if pos + 4 <= len(packet):
            val = struct.unpack('<I', packet[pos:pos+4])[0]
            pos += 4
            fields.append((field_num, wire_type, val))
    else:
        break

for fn, wt, val in fields[:10]:
    print(f"    field={fn} type={wt} val={val}")

if not fields:
    print("    (no protobuf-like structure)")

# Analyze the packet header more carefully
print("\n  Header structure analysis:")
print(f"    [0-1] magic: 0x{struct.unpack('<H', packet[0:2])[0]:04x}")
if len(packet) >= 4:
    print(f"    [2-3] u16: {struct.unpack('<H', packet[2:4])[0]}")
if len(packet) >= 6:
    print(f"    [4-5] u16: {struct.unpack('<H', packet[4:6])[0]}")
if len(packet) >= 8:
    print(f"    [6-7] u16: {struct.unpack('<H', packet[6:8])[0]}")
# Try 4-byte fields from offset 2
for i in range(2, min(20, len(packet)-3), 4):
    val = struct.unpack('<I', packet[i:i+4])[0]
    print(f"    [{i}-{i+3}] u32: {val} (0x{val:08x})")
