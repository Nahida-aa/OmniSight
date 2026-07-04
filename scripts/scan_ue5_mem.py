#!/usr/bin/env python3
"""Scan libUE4.so for GName, GObjects, and encryption patterns."""
import zipfile, re, struct, sys

apk_path = r"D:\repos\game_ls\OmniSight\apks\com_tencent_tmgp_dfm.apk"

# Extract libUE4.so from APK
print("Extracting libUE4.so from APK...")
with zipfile.ZipFile(apk_path, 'r') as z:
    for name in z.namelist():
        if name.endswith("libUE4.so"):
            data = z.read(name)
            print(f"  Found: {name} ({len(data)} bytes)")
            break
    else:
        print("  libUE4.so not found!")
        sys.exit(1)

# ---- Scan 1: GName patterns ----
print("\n=== GName / FName Pattern Scan ===")
gname_patterns = [
    b"GName",
    b"FNamePool",
    b"FNameEntry",
    b"NamePool",
    b"NameHash",
    b"Names",
    b"FName",
]
for pat in gname_patterns:
    pos = 0
    count = 0
    while True:
        idx = data.find(pat, pos)
        if idx == -1:
            break
        if count < 3:
            context = data[max(0,idx-8):idx+len(pat)+8]
            print(f"  Offset 0x{idx:x}: {context[:48]}")
        count += 1
        pos = idx + 1
    print(f"  '{pat.decode()}': {count} occurrences")

# ---- Scan 2: AES S-box ----
print("\n=== AES Constants ===")
aes_sbox = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
])
idx = data.find(aes_sbox)
if idx >= 0:
    print(f"  AES S-box (start): offset 0x{idx:x}")
else:
    print("  AES S-box not found")

# TEA delta constant
tea_delta = struct.pack('<I', 0x9E3779B9)
idx = data.find(tea_delta)
if idx >= 0:
    print(f"  TEA delta (0x9E3779B9): offset 0x{idx:x}")
else:
    print("  TEA delta not found")

# XXTEA constants
tea_delta2 = struct.pack('>I', 0x9E3779B9)
idx = data.find(tea_delta2)
if idx >= 0:
    print(f"  TEA delta (big-endian): offset 0x{idx:x}")

# CRC32 polynomial
crc32 = struct.pack('<I', 0xEDB88320)
idx = data.find(crc32)
if idx >= 0:
    print(f"  CRC32 polynomial: offset 0x{idx:x}")

# ---- Scan 3: UE5 class patterns ----
print("\n=== UE5 Class/String Patterns ===")
ue_patterns = [
    b"UObject",
    b"UWorld",
    b"ULevel",
    b"APlayerController",
    b"UGameInstance",
    b"ULocalPlayer",
    b"UEngine",
    b"AActor",
    b"AGameState",
    b"FString",
    b"TArray",
    b"TMap",
    b"FMemory",
    b"FNamePool",
    b"GObjects",
    b"ObjectArray",
    b"TUObjectArray",
    b"FUObjectItem",
]

# Find offset-like numbers near patterns
for pat in ue_patterns:
    pos = 0
    count = 0
    while True:
        idx = data.find(pat, pos)
        if idx == -1:
            break
        count += 1
        pos = idx + 1
    if count > 0:
        print(f"  '{pat.decode()}': {count} occurrences")

# ---- Scan 4: Known GName offset signatures ----
print("\n=== GName Offset Signatures ===")
# UE5 GName offset signature (varies by version)
# Search for common patterns near name data
for pat in [b"NamePool", b"FNamePool", b"Pool"]:
    idx = data.find(pat)
    if idx >= 0:
        region = data[max(0,idx-16):idx+32]
        print(f"  Near '{pat.decode()}' at 0x{idx:x}: {region.hex()[:96]}")

# ---- Scan 5: Encryption function patterns ----
print("\n=== Cryptography Patterns ===")
crypto_patterns = [
    (b"AES", "AES reference"),
    (b"RSA", "RSA reference"),
    (b"encrypt", "encrypt keyword"),
    (b"decrypt", "decrypt keyword"),
    (b"cipher", "cipher keyword"),
    (b"XXTEA", "XXTEA keyword"),
    (b"TEA::", "TEA:: keyword"),
    (b"Blowfish", "Blowfish"),
    (b"ChaCha", "ChaCha"),
    (b"libsodium", "libsodium"),
    (b"openssl", "openssl"),
    (b"mbedtls", "mbedtls"),
]
for pat, desc in crypto_patterns:
    idx = data.find(pat)
    if idx >= 0:
        context = data[max(0,idx-4):idx+len(pat)+20]
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
        print(f"  {desc}: offset 0x{idx:x} -> {printable}")
