use anyhow::Result;
use omnisight_shared::types::DexClassInfo;

/// Minimal DEX parser.
/// For a production tool, delegate to `jadx` or use a full DEX parsing library.
/// Here we extract class names, method signatures, and string pool.
pub fn analyze_dex(dex_files: &[Vec<u8>]) -> Result<Vec<DexClassInfo>> {
    let mut classes = Vec::new();

    for (idx, dex) in dex_files.iter().enumerate() {
        if dex.len() < 0x70 {
            continue; // too small to be valid DEX
        }

        // Parse DEX header
        let _magic = &dex[0..8];
        let _checksum = u32::from_le_bytes(dex[8..12].try_into().unwrap());
        let _signature = &dex[12..32];
        let _file_size = u32::from_le_bytes(dex[32..36].try_into().unwrap());
        let _header_size = u32::from_le_bytes(dex[36..40].try_into().unwrap());
        let _endian_tag = u32::from_le_bytes(dex[40..44].try_into().unwrap());
        let _link_size = u32::from_le_bytes(dex[44..48].try_into().unwrap());
        let _link_off = u32::from_le_bytes(dex[48..52].try_into().unwrap());
        let _map_off = u32::from_le_bytes(dex[52..56].try_into().unwrap());
        let string_ids_size = u32::from_le_bytes(dex[56..60].try_into().unwrap());
        let string_ids_off = u32::from_le_bytes(dex[60..64].try_into().unwrap());
        let type_ids_size = u32::from_le_bytes(dex[64..68].try_into().unwrap());
        let type_ids_off = u32::from_le_bytes(dex[68..72].try_into().unwrap());
        let proto_ids_size = u32::from_le_bytes(dex[72..76].try_into().unwrap());
        let _proto_ids_off = u32::from_le_bytes(dex[76..80].try_into().unwrap());
        let field_ids_size = u32::from_le_bytes(dex[80..84].try_into().unwrap());
        let _field_ids_off = u32::from_le_bytes(dex[84..88].try_into().unwrap());
        let method_ids_size = u32::from_le_bytes(dex[88..92].try_into().unwrap());
        let _method_ids_off = u32::from_le_bytes(dex[92..96].try_into().unwrap());
        let class_defs_size = u32::from_le_bytes(dex[96..100].try_into().unwrap());
        let _class_defs_off = u32::from_le_bytes(dex[100..104].try_into().unwrap());
        let _data_size = u32::from_le_bytes(dex[104..108].try_into().unwrap());
        let _data_off = u32::from_le_bytes(dex[108..112].try_into().unwrap());

        log::info!(
            "DEX[{}]: strings={}, types={}, protos={}, fields={}, methods={}, classes={}",
            idx, string_ids_size, type_ids_size, proto_ids_size,
            field_ids_size, method_ids_size, class_defs_size
        );

        // Extract string pool
        let strings = extract_string_pool(dex, string_ids_off as usize, string_ids_size as usize);

        // Extract type names
        let type_names: Vec<String> = (0..type_ids_size)
            .map(|i| {
                let off = type_ids_off as usize + i as usize * 4;
                if off + 4 <= dex.len() {
                    let str_idx = u32::from_le_bytes(dex[off..off + 4].try_into().unwrap()) as usize;
                    strings.get(str_idx).cloned().unwrap_or_default()
                } else {
                    String::new()
                }
            })
            .collect();

        // Parse class definitions
        let class_defs_off = _class_defs_off as usize;
        for i in 0..class_defs_size {
            let off = class_defs_off + i as usize * 32;
            if off + 32 > dex.len() {
                break;
            }
            let class_idx = u32::from_le_bytes(dex[off..off + 4].try_into().unwrap()) as usize;
            let _access_flags = u32::from_le_bytes(dex[off + 4..off + 8].try_into().unwrap());
            let _superclass_idx = u32::from_le_bytes(dex[off + 8..off + 12].try_into().unwrap());
            let _interfaces_off = u32::from_le_bytes(dex[off + 12..off + 16].try_into().unwrap());
            let _source_file_idx = u32::from_le_bytes(dex[off + 16..off + 20].try_into().unwrap());
            let _annotations_off = u32::from_le_bytes(dex[off + 20..off + 24].try_into().unwrap());
            let _class_data_off = u32::from_le_bytes(dex[off + 24..off + 28].try_into().unwrap());

            let class_name = type_names.get(class_idx).cloned().unwrap_or_default();
            if class_name.is_empty() {
                continue;
            }

            classes.push(DexClassInfo {
                name: class_name,
                super_class: None,
                interfaces: Vec::new(),
                methods: Vec::new(),
                fields: Vec::new(),
            });
        }
    }

    log::info!("Extracted {} classes from DEX", classes.len());
    Ok(classes)
}

fn extract_string_pool(dex: &[u8], offset: usize, count: usize) -> Vec<String> {
    let mut strings = Vec::with_capacity(count);
    for i in 0..count {
        let str_off_addr = offset + i * 4;
        if str_off_addr + 4 > dex.len() {
            strings.push(String::new());
            continue;
        }
        let str_data_off = u32::from_le_bytes(
            dex[str_off_addr..str_off_addr + 4].try_into().unwrap()
        ) as usize;

        if str_data_off >= dex.len() {
            strings.push(String::new());
            continue;
        }

        // ULEB128 encoded string length
        let (len, consumed) = read_uleb128(&dex[str_data_off..]);
        let str_start = str_data_off + consumed;
        let str_end = str_start + len;

        if str_end > dex.len() {
            strings.push(String::new());
            continue;
        }

        let s = String::from_utf8_lossy(&dex[str_start..str_end]).to_string();
        strings.push(s);
    }
    strings
}

fn read_uleb128(data: &[u8]) -> (usize, usize) {
    let mut result = 0usize;
    let mut shift = 0;
    let mut consumed = 0;

    for &byte in data {
        consumed += 1;
        result |= ((byte & 0x7f) as usize) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }

    (result, consumed)
}
