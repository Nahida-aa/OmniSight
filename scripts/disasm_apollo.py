#!/usr/bin/env python3
"""Disassemble ApolloBuffer Write functions from libgcloudcore.so using capstone"""
import zipfile, struct, sys
from capstone import *

apk_path = r"D:\repos\game_ls\OmniSight\apks\com_tencent_tmgp_dfm.apk"

with zipfile.ZipFile(apk_path, 'r') as z:
    for name in z.namelist():
        if name.endswith("libgcloudcore.so"):
            elf = z.read(name)
            print(f"Loaded: {name} ({len(elf)} bytes)")
            break

# Parse ELF to find sections
def read_elf_sections(data):
    if data[0:4] != b'\x7fELF': return None
    is_64 = data[4] == 2
    e_shoff = struct.unpack('<Q' if is_64 else '<I', data[40:40+(8 if is_64 else 4)])[0]
    e_shentsize = struct.unpack('<H', data[58:60])[0]
    e_shnum = struct.unpack('<H', data[60:62])[0]
    e_shstrndx = struct.unpack('<H', data[62:64])[0]
    
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name = struct.unpack('<I', data[off:off+4])[0]
        sh_type = struct.unpack('<I', data[off+4:off+8])[0]
        sh_flags = struct.unpack('<Q', data[off+8:off+16])[0]
        sh_addr = struct.unpack('<Q', data[off+16:off+24])[0]
        sh_offset = struct.unpack('<Q', data[off+24:off+32])[0]
        sh_size = struct.unpack('<Q', data[off+32:off+40])[0]
        sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))
    
    # Get section names
    shstrtab_off = sections[e_shstrndx][4]
    shstrtab_size = sections[e_shstrndx][5]
    shstrtab = data[shstrtab_off:shstrtab_off+shstrtab_size]
    
    named = {}
    for s in sections:
        end = shstrtab.index(b'\x00', s[0]) if b'\x00' in shstrtab[s[0]:] else len(shstrtab)
        name = shstrtab[s[0]:end].decode('ascii', errors='replace')
        named[name] = s
    return named

sections = read_elf_sections(elf)
if not sections:
    print("Failed to parse ELF")
    sys.exit(1)

print(f"\nSections found: {list(sections.keys())[:20]}")

# Find .dynsym and .dynstr
for sec_name in ['.dynsym', '.dynstr', '.text']:
    if sec_name in sections:
        s = sections[sec_name]
        print(f"  {sec_name}: addr=0x{s[3]:x} offset=0x{s[4]:x} size={s[5]}")

# Parse .dynsym for ApolloBuffer functions
if '.dynsym' in sections and '.dynstr' in sections:
    ds = sections['.dynsym']
    ds_data = elf[ds[4]:ds[4]+ds[5]]
    ds_entsize = 24  # 64-bit ELF
    dstr = elf[sections['.dynstr'][4]:sections['.dynstr'][4]+sections['.dynstr'][5]]
    
    print(f"\n=== ApolloBuffer Write/Read Functions ===")
    funcs = []
    for i in range(ds[5] // ds_entsize):
        off = i * ds_entsize
        st_name = struct.unpack('<I', ds_data[off:off+4])[0]
        st_info = ds_data[off+4]
        st_shndx = struct.unpack('<H', ds_data[off+6:off+8])[0]
        st_value = struct.unpack('<Q', ds_data[off+8:off+16])[0]
        st_size = struct.unpack('<Q', ds_data[off+16:off+24])[0]
        
        name = dstr[st_name:dstr.index(b'\x00', st_name)].decode('ascii', errors='replace') if st_name < len(dstr) else ''
        
        if 'ApolloBufferWrite' in name or 'ApolloBufferReader' in name:
            funcs.append((st_value, st_size, name, st_shndx))
    
    for addr, size, name, shndx in sorted(funcs, key=lambda x: x[0]):
        # Demangle
        demangled = name.replace('_ZN5ABase19CApolloBufferWriter5WriteE', '→ ')
        demangled = demangled.replace('_ZN5ABase19CApolloBufferReader4ReadE', '→ ')
        demangled = demangled.replace('RKNS_7AStringE', 'const AString&')
        demangled = demangled.replace('RKNS_6AArrayE', 'const AArray&')
        demangled = demangled.replace('PKNS_7AObjectE', 'const AObject*')
        demangled = demangled.replace('RKNS_20_tagApolloBufferBaseE', 'const tagApolloBufferBase&')
        demangled = demangled.replace('PKNS_20_tagApolloBufferBaseE', 'const tagApolloBufferBase*')
        demangled = demangled.replace('PNS_20_tagApolloBufferBaseE', 'tagApolloBufferBase*')
        demangled = demangled.replace('RNS_20_tagApolloBufferBaseE', 'tagApolloBufferBase&')
        demangled = demangled.replace('RNS_7AStringE', 'AString&')
        demangled = demangled.replace('Ei', '(int)')
        demangled = demangled.replace('ERi', '(int&)')
        demangled = demangled.replace('ERKNS_7AStringE', '(const AString&)')
        
        # Get code bytes from .text section
        if '.text' in sections:
            text = sections['.text']
            code_offset = text[4] + (addr - text[3])
            code_size = min(size, 200)
            code_bytes = elf[code_offset:code_offset + code_size]
            
            # Disassemble with capstone
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            md.detail = True
            
            # Find varint encoding loops (pattern: shift + add + branch)
            has_varint = False
            has_store = False
            has_load = False
            
            insns = []
            for insn in md.disasm(code_bytes, addr):
                insns.append(insn)
                if 'strb' in insn.mnemonic or 'str' in insn.mnemonic:
                    has_store = True
                if 'ldrb' in insn.mnemonic or 'ldr' in insn.mnemonic:
                    has_load = True
                if 'add' in insn.mnemonic and 'lsl' in insn.op_str:
                    has_varint = True
                if len(insns) >= 20:
                    break
            
            # First 5 instructions summary
            first5 = ' ; '.join(f"{i.mnemonic} {i.op_str}" for i in insns[:5])
            
            print(f"\n  {name[:80]}...")
            print(f"    @ 0x{addr:x}  size={size}")
            print(f"    [{first5}]")
            print(f"    varint={has_varint} store={has_store} load={has_load}")
    
    print(f"\nTotal ApolloBuffer functions: {len(funcs)}")

# Also look for encryption-related functions
print(f"\n=== Crypto/Encryption Related ===")
ds = sections['.dynsym']
ds_data = elf[ds[4]:ds[4]+ds[5]]
dstr = elf[sections['.dynstr'][4]:sections['.dynstr'][4]+sections['.dynstr'][5]]

crypto_funcs = []
for i in range(ds[5] // 24):
    off = i * 24
    st_name = struct.unpack('<I', ds_data[off:off+4])[0]
    st_size = struct.unpack('<Q', ds_data[off+16:off+24])[0]
    name = dstr[st_name:dstr.index(b'\x00', st_name)].decode('ascii', errors='replace') if st_name < len(dstr) else ''
    
    if st_size > 0 and any(k in name.lower() for k in ['encrypt','decrypt','cipher','tea','aes','xor','blowfish']):
        crypto_funcs.append((name, st_size))

for name, size in crypto_funcs:
    print(f"  {name[:80]}")
    print(f"    size={size}")
