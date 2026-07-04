#!/usr/bin/env python3
"""Disassemble ApolloBuffer Write/Read functions from libgcloudcore.so"""
import zipfile, struct, sys

apk_path = r"D:\repos\game_ls\OmniSight\apks\com_tencent_tmgp_dfm.apk"

# Extract libgcloudcore.so
with zipfile.ZipFile(apk_path, 'r') as z:
    for name in z.namelist():
        if name.endswith("libgcloudcore.so"):
            elf = z.read(name)
            print(f"Loaded: {name} ({len(elf)} bytes)")
            break

# Parse ELF header
if elf[0:4] != b'\x7fELF':
    print("Not an ELF file!")
    sys.exit(1)

e_shoff = struct.unpack('<Q', elf[40:48])[0]    # Section header offset
e_shentsize = struct.unpack('<H', elf[58:60])[0] # Section header entry size
e_shnum = struct.unpack('<H', elf[60:62])[0]     # Number of sections
e_shstrndx = struct.unpack('<H', elf[62:64])[0]  # Section name string table index

# Read section headers
sections = []
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    sh_name = struct.unpack('<I', elf[off:off+4])[0]
    sh_type = struct.unpack('<I', elf[off+4:off+8])[0]
    sh_flags = struct.unpack('<Q', elf[off+8:off+16])[0]
    sh_addr = struct.unpack('<Q', elf[off+16:off+24])[0]
    sh_offset = struct.unpack('<Q', elf[off+24:off+32])[0]
    sh_size = struct.unpack('<Q', elf[off+32:off+40])[0]
    sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size))

# Get section names
shstrtab_off = sections[e_shstrndx][4]
shstrtab_size = sections[e_shstrndx][5]
shstrtab = elf[shstrtab_off:shstrtab_off + shstrtab_size]

section_names = []
for s in sections:
    name = shstrtab[s[0]:shstrtab.index(b'\x00', s[0])].decode('ascii', errors='replace')
    section_names.append(name)

# Find strtab and symtab
strtab = None
symtab = None
for i, name in enumerate(section_names):
    if name == '.strtab':
        strtab_off = sections[i][4]
        strtab_size = sections[i][5]
        strtab = elf[strtab_off:strtab_off + strtab_size]
    elif name == '.symtab':
        symtab_idx = i

# Parse symbol table
if symtab_idx is not None:
    s = sections[symtab_idx]
    sym_size = 24  # 64-bit ELF symbol entry size
    sym_count = s[5] // sym_size
    entry_size = s[5]
    sym_start = s[4]

    print(f"\n=== ApolloBuffer Functions in libgcloudcore.so ===")
    print(f"Symbol table: {sym_count} entries @ 0x{sym_start:x}")
    
    for i in range(sym_count):
        off = sym_start + i * sym_size
        if off + sym_size > len(elf):
            break
        st_name = struct.unpack('<I', elf[off:off+4])[0]
        st_info = elf[off+4]
        st_other = elf[off+5]
        st_shndx = struct.unpack('<H', elf[off+6:off+8])[0]
        st_value = struct.unpack('<Q', elf[off+8:off+16])[0]
        st_size = struct.unpack('<Q', elf[off+16:off+24])[0]
        
        # Get symbol name
        name_end = strtab.index(b'\x00', st_name) if strtab else st_name + 1
        sym_name = strtab[st_name:name_end].decode('ascii', errors='replace') if strtab else ''
        
        if 'ApolloBuffer' in sym_name and st_size > 0:
            # Find which section this belongs to
            sec_name = section_names[st_shndx] if st_shndx < len(section_names) else '?'
            sec_offset = sections[st_shndx][4] if st_shndx < len(sections) else 0
            file_offset = sec_offset + (st_value - sections[st_shndx][3]) if st_shndx < len(sections) else st_value
            
            # Read function bytes
            func_bytes = elf[file_offset:file_offset + min(st_size, 64)]
            hex_bytes = ' '.join(f'{b:02x}' for b in func_bytes[:16])
            
            # Demangle simplified
            readable = sym_name
            for prefix, replacement in [
                ('_ZN5ABase19CApolloBufferWriter5WriteE', 'ABase::CApolloBufferWriter::Write('),
                ('_ZN5ABase19CApolloBufferReader4ReadE', 'ABase::CApolloBufferReader::Read('),
                ('_ZN5ABase19CApolloBufferWriter5WriteEPKNS_7AObjectE', 'ABase::CApolloBufferWriter::Write(const AObject*)'),
                ('_ZN5ABase19CApolloBufferWriter5WriteERKNS_20_tagApolloBufferBaseE', 'ABase::CApolloBufferWriter::Write(const tagApolloBufferBase&)'),
                ('_ZN5ABase19CApolloBufferWriter5WriteEi', 'ABase::CApolloBufferWriter::Write(int)'),
                ('_ZN5ABase19CApolloBufferWriter5WriteERKNS_7AStringE', 'ABase::CApolloBufferWriter::Write(const AString&)'),
                ('_ZN5ABase19CApolloBufferWriter5WriteERKNS_6AArrayE', 'ABase::CApolloBufferWriter::Write(const AArray&)'),
                ('_ZN5ABase19CApolloBufferReader4ReadERi', 'ABase::CApolloBufferReader::Read(int&)'),
                ('_ZN5ABase19CApolloBufferReader4ReadERNS_7AStringE', 'ABase::CApolloBufferReader::Read(AString&)'),
            ]:
                if prefix in sym_name:
                    readable = sym_name.replace(prefix, replacement)
                    break
            
            print(f"\n  {sym_name}")
            print(f"    Demangled: {readable}")
            print(f"    Size: {st_size} bytes @ 0x{st_value:x} (section: {sec_name})")
            print(f"    First bytes: {hex_bytes}")
else:
    print("No symbol table found!")

# Also scan for TdrBufUtil functions
print(f"\n=== TdrBufUtil Functions ===")
for i in range(sym_count):
    off = sym_start + i * sym_size
    if off + sym_size > len(elf):
        break
    st_name = struct.unpack('<I', elf[off:off+4])[0]
    st_value = struct.unpack('<Q', elf[off+8:off+16])[0]
    st_size = struct.unpack('<Q', elf[off+16:off+24])[0]
    name_end = strtab.index(b'\x00', st_name) if strtab else st_name + 1
    sym_name = strtab[st_name:name_end].decode('ascii', errors='replace') if strtab else ''
    
    if 'TdrBufUtil' in sym_name and st_size > 0:
        readable = sym_name.replace('_ZN5ABase10TdrBufUtil', 'ABase::TdrBufUtil')
        print(f"  {readable}")
        print(f"    size: {st_size} bytes")
