use anyhow::Result;
use omnisight_shared::types::{DexClassInfo, DexMethodInfo};

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
        let proto_ids_off = u32::from_le_bytes(dex[76..80].try_into().unwrap());
        let field_ids_size = u32::from_le_bytes(dex[80..84].try_into().unwrap());
        let _field_ids_off = u32::from_le_bytes(dex[84..88].try_into().unwrap());
        let method_ids_size = u32::from_le_bytes(dex[88..92].try_into().unwrap());
        let method_ids_off = u32::from_le_bytes(dex[92..96].try_into().unwrap());
        let class_defs_size = u32::from_le_bytes(dex[96..100].try_into().unwrap());
        let class_defs_off = u32::from_le_bytes(dex[100..104].try_into().unwrap());
        let _data_size = u32::from_le_bytes(dex[104..108].try_into().unwrap());
        let _data_off = u32::from_le_bytes(dex[108..112].try_into().unwrap());

        log::info!(
            "DEX[{}]: strings={}, types={}, protos={}, fields={}, methods={}, classes={}",
            idx, string_ids_size, type_ids_size, proto_ids_size,
            field_ids_size, method_ids_size, class_defs_size
        );

        // Extract string pool
        let strings = extract_string_pool(dex, string_ids_off as usize, string_ids_size as usize);

        // Extract type names (type_id → string_idx)
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

        // Build method name lookup: method_id_idx → (name, proto_idx)
        // method_ids entry: class_idx(u2) + proto_idx(u2) + name_idx(u4) = 8 bytes
        let method_names: Vec<(String, u32)> = (0..method_ids_size)
            .map(|i| {
                let off = method_ids_off as usize + i as usize * 8;
                if off + 8 <= dex.len() {
                    let name_idx = u32::from_le_bytes(dex[off + 4..off + 8].try_into().unwrap()) as usize;
                    let proto_idx = u16::from_le_bytes(dex[off + 2..off + 4].try_into().unwrap()) as u32;
                    let name = strings.get(name_idx).cloned().unwrap_or_default();
                    (name, proto_idx)
                } else {
                    (String::new(), 0)
                }
            })
            .collect();

        // Build proto signature lookup: proto_idx → return_type(param_types)
        // proto_ids entry: shorty_idx(u4) + return_type_idx(u4) + parameters_off(u4) = 12 bytes
        let proto_signatures: Vec<String> = (0..proto_ids_size)
            .map(|i| {
                let off = proto_ids_off as usize + i as usize * 12;
                if off + 12 <= dex.len() {
                    let _shorty_idx = u32::from_le_bytes(dex[off..off + 4].try_into().unwrap()) as usize;
                    let return_type_idx = u32::from_le_bytes(dex[off + 4..off + 8].try_into().unwrap()) as usize;
                    let params_off = u32::from_le_bytes(dex[off + 8..off + 12].try_into().unwrap()) as usize;
                    let return_type = type_names.get(return_type_idx).cloned().unwrap_or_default();
                    // Parse parameter type list (type_list: size(u4) + types(u2 each))
                    let mut params = Vec::new();
                    if params_off > 0 && params_off + 4 <= dex.len() {
                        let param_count = u32::from_le_bytes(dex[params_off..params_off + 4].try_into().unwrap()) as usize;
                        for j in 0..param_count {
                            let toff = params_off + 4 + j * 2;
                            if toff + 2 <= dex.len() {
                                let tidx = u16::from_le_bytes(dex[toff..toff + 2].try_into().unwrap()) as usize;
                                params.push(type_names.get(tidx).cloned().unwrap_or_default());
                            }
                        }
                    }
                    format!("({}){}", params.join(","), return_type)
                } else {
                    String::new()
                }
            })
            .collect();

        // Read class_data for methods and fields
        // class_data: static_fields_count(u) + instance_fields_count(u) + direct_methods_count(u)
        //            + virtual_methods_count(u) + encoded_field[] + encoded_method[]
        fn parse_class_data(
            dex: &[u8], class_data_off: usize,
            method_names: &[(String, u32)],
            proto_signatures: &[String],
            _method_ids_off: u32,
        ) -> (Vec<DexMethodInfo>, Vec<String>) {
            let mut methods = Vec::new();
            let fields = Vec::new();

            if class_data_off == 0 || class_data_off >= dex.len() {
                return (methods, fields);
            }

            let mut pos = class_data_off;
            // Read counts
            let (static_fields_count, consumed) = read_uleb128(&dex[pos..]);
            pos += consumed;
            let (_instance_fields_count, consumed) = read_uleb128(&dex[pos..]);
            pos += consumed;
            let (direct_methods_count, consumed) = read_uleb128(&dex[pos..]);
            pos += consumed;
            let (virtual_methods_count, consumed) = read_uleb128(&dex[pos..]);
            pos += consumed;

            // Skip encoded fields (static + instance)
            let total_fields = static_fields_count + _instance_fields_count;
            let mut _last_field_idx = 0usize;
            for _ in 0..total_fields {
                let (_field_idx_diff, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                let (_access_flags, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                _last_field_idx += _field_idx_diff;
            }

            // Parse direct methods
            let mut last_method_idx = 0usize;
            for _ in 0..direct_methods_count {
                let (method_idx_diff, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                let (_access_flags, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                let (_code_off, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;

                last_method_idx += method_idx_diff;
                if let Some((name, proto_idx)) = method_names.get(last_method_idx) {
                    let sig = proto_signatures.get(*proto_idx as usize).cloned().unwrap_or_default();
                    methods.push(DexMethodInfo {
                        name: name.clone(),
                        signature: sig,
                        access_flags: _access_flags as u32,
                    });
                }
            }

            // Parse virtual methods
            for _ in 0..virtual_methods_count {
                let (method_idx_diff, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                let (_access_flags, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;
                let (_code_off, consumed) = read_uleb128(&dex[pos..]);
                pos += consumed;

                last_method_idx += method_idx_diff;
                if let Some((name, proto_idx)) = method_names.get(last_method_idx) {
                    let sig = proto_signatures.get(*proto_idx as usize).cloned().unwrap_or_default();
                    methods.push(DexMethodInfo {
                        name: name.clone(),
                        signature: sig,
                        access_flags: _access_flags as u32,
                    });
                }
            }

            (methods, fields)
        }

        // Parse class definitions
        for i in 0..class_defs_size {
            let off = class_defs_off as usize + i as usize * 32;
            if off + 32 > dex.len() {
                break;
            }
            let class_idx = u32::from_le_bytes(dex[off..off + 4].try_into().unwrap()) as usize;
            let _access_flags = u32::from_le_bytes(dex[off + 4..off + 8].try_into().unwrap());
            let _superclass_idx = u32::from_le_bytes(dex[off + 8..off + 12].try_into().unwrap());
            let _interfaces_off = u32::from_le_bytes(dex[off + 12..off + 16].try_into().unwrap());
            let _source_file_idx = u32::from_le_bytes(dex[off + 16..off + 20].try_into().unwrap());
            let _annotations_off = u32::from_le_bytes(dex[off + 20..off + 24].try_into().unwrap());
            let class_data_off = u32::from_le_bytes(dex[off + 24..off + 28].try_into().unwrap());

            let class_name = type_names.get(class_idx).cloned().unwrap_or_default();
            if class_name.is_empty() {
                continue;
            }

            let (methods, _fields) = parse_class_data(
                dex, class_data_off as usize,
                &method_names, &proto_signatures, method_ids_off,
            );

            classes.push(DexClassInfo {
                name: class_name,
                super_class: None,
                interfaces: Vec::new(),
                methods,
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
