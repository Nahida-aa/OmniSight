use anyhow::{Context, Result};
use omnisight_shared::types::{self, ScannedString};
use std::path::Path;
use std::io::Read;
use zip::ZipArchive;

pub struct ApkData {
    pub info: types::ApkInfo,
    pub manifest: types::ManifestInfo,
    pub dex_files: Vec<Vec<u8>>,
    pub elf_files: Vec<(String, Vec<u8>)>,
    pub all_strings: Vec<ScannedString>,
}

pub fn parse_apk(path: &Path) -> Result<ApkData> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open APK: {}", path.display()))?;
    let file_size = file.metadata()?.len();
    let mut archive = ZipArchive::new(file)
        .context("Failed to parse APK as ZIP archive")?;

    let mut dex_files = Vec::new();
    let mut elf_files = Vec::new();
    let mut manifest_xml = None;
    let mut package_name = String::new();
    let mut version_name = String::new();
    let mut version_code = 0u64;
    let mut min_sdk = 0u32;
    let mut target_sdk = 0u32;
    let mut main_activity = None;
    let mut permissions = Vec::new();
    let mut services = Vec::new();
    let mut receivers = Vec::new();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();

        if name == "AndroidManifest.xml" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            manifest_xml = Some(buf);
        } else if name.starts_with("classes") && name.ends_with(".dex") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            dex_files.push(buf);
        } else if name.contains("lib/arm64-v8a/") && name.ends_with(".so") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            let lib_name = name.rsplit('/').next().unwrap_or(&name).to_string();
            elf_files.push((lib_name, buf));
        }
    }

    // Parse AndroidManifest binary XML (AXML)
    if let Some(xml) = &manifest_xml {
        let info = parse_axml(xml);
        if !info.package_name.is_empty() {
            package_name = info.package_name;
        }
        if !info.version_name.is_empty() {
            version_name = info.version_name;
        }
        if info.version_code > 0 {
            version_code = info.version_code;
        }
        if info.min_sdk > 0 {
            min_sdk = info.min_sdk;
        }
        if info.target_sdk > 0 {
            target_sdk = info.target_sdk;
        }
        if let Some(act) = info.main_activity {
            main_activity = Some(act);
        }
        permissions = info.permissions;
        services = info.services;
        receivers = info.receivers;
    }

    // Fallback: extract package name from APK filename
    if package_name.is_empty() {
        if let Some(name) = path.file_stem() {
            package_name = name.to_string_lossy().to_string();
        }
    }

    Ok(ApkData {
        info: types::ApkInfo {
            package_name,
            version_name,
            version_code,
            min_sdk,
            target_sdk,
            file_size,
        },
        manifest: types::ManifestInfo {
            main_activity,
            services,
            receivers,
            permissions,
            network_security_config: None,
        },
        dex_files,
        elf_files,
        all_strings: Vec::new(),
    })
}

// ---- Android Binary XML (AXML) Parser ----

#[derive(Default)]
struct AxmlResult {
    package_name: String,
    version_name: String,
    version_code: u64,
    min_sdk: u32,
    target_sdk: u32,
    main_activity: Option<String>,
    permissions: Vec<String>,
    services: Vec<String>,
    receivers: Vec<String>,
}

fn parse_axml(data: &[u8]) -> AxmlResult {
    use std::collections::HashMap;

    let mut result = AxmlResult::default();
    let mut permissions = Vec::new();
    let mut services = Vec::new();
    let mut receivers = Vec::new();

    if data.len() < 8 {
        return result;
    }

    // Read chunk header for XML document
    let chunk_type = u16::from_le_bytes([data[0], data[1]]);
    if chunk_type != 0x0003 {
        // RES_XML_TYPE
        return result;
    }

    let header_size = u16::from_le_bytes([data[2], data[3]]);
    let _chunk_size = u32::from_le_bytes(data[4..8].try_into().unwrap());

    // Parse the string pool (first child chunk)
    let mut pos = header_size as usize;
    if pos + 8 > data.len() {
        return result;
    }

    let pool = parse_string_pool(data, pos);

    // Walk chunks and extract XML structure
    let mut element_stack: Vec<(String, HashMap<String, Vec<(u32, u32)>>)> = Vec::new();
    let mut _in_application = false;
    let mut in_activity = false;

    let mut activity_name = String::new();
    let mut activity_has_main = false;
    let mut activity_has_launcher = false;

    while pos + 8 <= data.len() {
        let ctype = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let _hsize = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
        let csize = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
        if csize == 0 || pos + csize > data.len() {
            break;
        }

        match ctype {
            0x0102 => {
                // START_TAG
                // ResXMLTree_node(header=8 + line=4 + comment=4) + ResXMLTree_attrExt(20)
                // attrExt starts at offset 16 from chunk
                // attributeStart at offset 24 from chunk (relative to attrExt)
                // attributeCount at offset 28 from chunk
                if pos + 32 > data.len() { break; }
                let _line = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
                let _comment = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap());
                let _ns = i32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
                let name_idx = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap());
                let attr_start_off = u16::from_le_bytes([data[pos + 24], data[pos + 25]]) as usize;
                let attr_size = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
                let attr_count = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
                let _id_index = u16::from_le_bytes([data[pos + 30], data[pos + 31]]);
                let _class_index = u16::from_le_bytes([data[pos + 32], data[pos + 33]]);
                let element_name = pool.get(name_idx as usize).cloned().unwrap_or_default();

                // Parse attributes: they start at attrExt + attr_start_off
                // attribute entry (standard 20 bytes):
                //   ns(u4) + name(u4) + rawValue(s4) + value_size(u2) + value_res0(u1) + value_dataType(u1) + value_data(u4)
                let attr_ext_start = pos + 16; // ResChunk_header(8) + ResXMLTree_node(8) = 16
                let attr_start = attr_ext_start + attr_start_off;
                let attr_entry_size = if attr_size > 0 { attr_size } else { 20 };
                let mut attrs = HashMap::new();
                for j in 0..attr_count {
                    let aoff = attr_start + j * attr_entry_size;
                    if aoff + 20 > data.len() { break; }
                    let _ans = u32::from_le_bytes(data[aoff..aoff + 4].try_into().unwrap());
                    let aname_idx = u32::from_le_bytes(data[aoff + 4..aoff + 8].try_into().unwrap()) as usize;
                    let attr_name = pool.get(aname_idx).cloned().unwrap_or_default();
                    let _val_str_idx = u32::from_le_bytes(data[aoff + 8..aoff + 12].try_into().unwrap()) as i32;
                    let _val_size = u16::from_le_bytes([data[aoff + 12], data[aoff + 13]]);
                    let val_type = data[aoff + 15]; // single-byte Res_value.dataType
                    let val_data = u32::from_le_bytes(data[aoff + 16..aoff + 20].try_into().unwrap());
                    attrs.entry(attr_name)
                        .or_insert_with(Vec::new)
                        .push((val_type as u32, val_data));
                }

                // Process elements by name
                match element_name.as_str() {
                    "manifest" => {
                        if let Some(pkg) = get_attr_str(&attrs, "package", &pool) {
                            result.package_name = pkg;
                        }
                        result.version_code = get_attr_int(&attrs, "versionCode") as u64;
                        if let Some(vn) = get_attr_str(&attrs, "versionName", &pool) {
                            result.version_name = vn;
                        }
                    }
                    "uses-sdk" => {
                        result.min_sdk = get_attr_int(&attrs, "minSdkVersion");
                        result.target_sdk = get_attr_int(&attrs, "targetSdkVersion");
                    }
                    "uses-permission" => {
                        if let Some(p) = get_attr_str(&attrs, "name", &pool) {
                            permissions.push(p);
                        }
                    }
                    "application" => {
                        _in_application = true;
                    }
                    "activity" => {
                        in_activity = true;
                        activity_name = get_attr_str(&attrs, "name", &pool).unwrap_or_default();
                        activity_has_main = false;
                        activity_has_launcher = false;
                    }
                    "service" => {
                        if let Some(svc) = get_attr_str(&attrs, "name", &pool) {
                            services.push(svc);
                        }
                    }
                    "receiver" => {
                        if let Some(rcv) = get_attr_str(&attrs, "name", &pool) {
                            receivers.push(rcv);
                        }
                    }
                    "action" => {
                        if let Some(act) = get_attr_str(&attrs, "name", &pool) {
                            if act == "android.intent.action.MAIN" {
                                activity_has_main = true;
                            }
                        }
                    }
                    "category" => {
                        if let Some(cat) = get_attr_str(&attrs, "name", &pool) {
                            if cat == "android.intent.category.LAUNCHER" {
                                activity_has_launcher = true;
                            }
                        }
                    }
                    _ => {}
                }

                element_stack.push((element_name, attrs));
            }
            0x0103 => {
                // END_TAG
                if element_stack.is_empty() { break; }
                let (end_name, _) = element_stack.pop().unwrap();
                match end_name.as_str() {
                    "activity" => {
                        if in_activity && activity_has_main && activity_has_launcher && !activity_name.is_empty() {
                            result.main_activity = Some(activity_name.clone());
                        }
                        in_activity = false;
                        activity_name.clear();
                    }
                    "application" => {
                        _in_application = false;
                    }
                    _ => {}
                }
            }
            _ => {
                // Skip unknown chunks (text, namespace, etc.)
            }
        }

        // Move to next chunk
        if csize == 0 { break; }
        pos += csize;
    }

    result.permissions = permissions;
    result.services = services;
    result.receivers = receivers;
    result
}

/// Parse the AXML string pool chunk starting at `pos`
fn parse_string_pool(data: &[u8], pos: usize) -> Vec<String> {
    if pos + 8 > data.len() {
        return Vec::new();
    }
    let chunk_type = u16::from_le_bytes([data[pos], data[pos + 1]]);
    if chunk_type != 0x0001 {
        // RES_STRING_POOL_TYPE
        return Vec::new();
    }
    let _hsize = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);
    let csize = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
    if csize < 28 || pos + csize > data.len() {
        return Vec::new();
    }

    let string_count = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap()) as usize;
    let _style_count = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(data[pos + 16..pos + 20].try_into().unwrap());
    let strings_start = u32::from_le_bytes(data[pos + 20..pos + 24].try_into().unwrap()) as usize;
    let _styles_start = u32::from_le_bytes(data[pos + 24..pos + 28].try_into().unwrap()) as usize;

    let is_utf8 = (flags & 0x0100) != 0;
    let string_offsets_start = pos + 28;

    let mut strings = Vec::with_capacity(string_count);
    for i in 0..string_count {
        let off_addr = string_offsets_start + i * 4;
        if off_addr + 4 > data.len() {
            strings.push(String::new());
            continue;
        }
        let str_off = u32::from_le_bytes(data[off_addr..off_addr + 4].try_into().unwrap()) as usize;
        let str_data_pos = pos + strings_start + str_off;
        if str_data_pos >= data.len() {
            strings.push(String::new());
            continue;
        }

        if is_utf8 {
            // UTF-8: uleb128 encoded_length, uleb128 actual_length, data...
            let (_, consumed) = read_uleb128_from(&data[str_data_pos..]);
            let (act_len, consumed2) = read_uleb128_from(&data[str_data_pos + consumed..]);
            let total_consumed = consumed + consumed2;
            let chr_start = str_data_pos + total_consumed;
            let chr_end = chr_start + act_len;
            if chr_end <= data.len() {
                let s = String::from_utf8_lossy(&data[chr_start..chr_end]).to_string();
                strings.push(s);
            } else {
                strings.push(String::new());
            }
        } else {
            // UTF-16LE: length(u2 or u4) + data
            if str_data_pos + 2 > data.len() {
                strings.push(String::new());
                continue;
            }
            let u16len = u16::from_le_bytes([data[str_data_pos], data[str_data_pos + 1]]) as usize;
            let char_start = str_data_pos + 2;
            let char_end = char_start + u16len * 2;
            if char_end <= data.len() {
                // Decode UTF-16LE
                let mut s = String::new();
                for j in (0..u16len * 2).step_by(2) {
                    if char_start + j + 2 <= data.len() {
                        let code = u16::from_le_bytes([data[char_start + j], data[char_start + j + 1]]);
                        s.push(char::from_u32(code as u32).unwrap_or('?'));
                    }
                }
                strings.push(s);
            } else {
                strings.push(String::new());
            }
        }
    }

    strings
}

fn read_uleb128_from(data: &[u8]) -> (usize, usize) {
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

/// Get a string attribute value by attribute name (Res_value dataType = 0x03)
fn get_attr_str(
    attrs: &std::collections::HashMap<String, Vec<(u32, u32)>>,
    name: &str,
    pool: &[String],
) -> Option<String> {
    attrs.get(name).and_then(|vals| {
        for &(ty, data) in vals {
            if ty == 0x03 {
                // Res_value type STRING: data is string pool index
                return pool.get(data as usize).cloned();
            }
        }
        None
    })
}

/// Get an integer attribute value by attribute name (Res_value dataType = 0x11 INT_DEC)
fn get_attr_int(attrs: &std::collections::HashMap<String, Vec<(u32, u32)>>, name: &str) -> u32 {
    attrs.get(name).and_then(|vals| {
        for &(ty, data) in vals {
            if ty == 0x11 {
                // Res_value type INT_DEC
                return Some(data);
            }
        }
        None
    }).unwrap_or(0)
}
