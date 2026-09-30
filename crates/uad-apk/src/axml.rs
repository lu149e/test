//! Parser for Android binary XML (the compiled `AndroidManifest.xml` inside APKs).
//!
//! Format reference: `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`
//! (ResChunk_header, ResStringPool_header, ResXMLTree_node, ResXMLTree_attrExt, Res_value).
//! Every read is bounds-checked; malformed input yields an error instead of a panic.

use std::collections::HashMap;

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const UTF8_FLAG: u32 = 1 << 8;
const NO_INDEX: u32 = 0xFFFF_FFFF;
const MAX_DEPTH: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AxmlError {
    #[error("truncated binary XML at offset {0}")]
    Truncated(usize),
    #[error("malformed binary XML: {0}")]
    Malformed(&'static str),
}

/// Typed attribute value (subset of `Res_value` types relevant to manifests).
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    String(String),
    Int(i64),
    Bool(bool),
    /// Resource reference `@0xPPTTEEEE` (not resolved: requires resources.arsc).
    Reference(u32),
    Float(f32),
    Other {
        data_type: u8,
        data: u32,
    },
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            AttrValue::Int(i) => Some(*i),
            AttrValue::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttrValue::Bool(b) => Some(*b),
            AttrValue::Int(i) => Some(*i != 0),
            AttrValue::String(s) => match s.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    /// Display form, similar to `aapt2 dump xmltree`.
    pub fn display(&self) -> String {
        match self {
            AttrValue::String(s) => s.clone(),
            AttrValue::Int(i) => i.to_string(),
            AttrValue::Bool(b) => b.to_string(),
            AttrValue::Reference(r) => format!("@0x{r:08x}"),
            AttrValue::Float(f) => f.to_string(),
            AttrValue::Other { data_type, data } => format!("(type 0x{data_type:02x})0x{data:x}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    pub namespace: Option<String>,
    pub name: String,
    pub resource_id: Option<u32>,
    pub value: AttrValue,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Element {
    pub namespace: Option<String>,
    pub name: String,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    /// Attribute in the android namespace (matched by name or by well-known resource id).
    pub fn android_attr(&self, name: &str) -> Option<&AttrValue> {
        let id = known_attr_id(name);
        self.attributes
            .iter()
            .find(|a| (a.name == name && a.namespace.as_deref() == Some(ANDROID_NS)) || (id.is_some() && a.resource_id == id))
            .map(|a| &a.value)
    }

    /// Attribute without namespace (e.g. `package`, `split`).
    pub fn plain_attr(&self, name: &str) -> Option<&AttrValue> {
        self.attributes.iter().find(|a| a.name == name && a.namespace.is_none()).map(|a| &a.value)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
}

/// Android framework attribute ids (from `android.R.attr`), used when obfuscators blank out
/// attribute names in the string pool. Verified against `aapt2 dump xmltree` output.
pub fn known_attr_id(name: &str) -> Option<u32> {
    Some(match name {
        "label" => 0x0101_0001,
        "icon" => 0x0101_0002,
        "name" => 0x0101_0003,
        "hasCode" => 0x0101_000c,
        "debuggable" => 0x0101_000f,
        "value" => 0x0101_0024,
        "resource" => 0x0101_0025,
        "minSdkVersion" => 0x0101_020c,
        "versionCode" => 0x0101_021b,
        "versionName" => 0x0101_021c,
        "targetSdkVersion" => 0x0101_0270,
        "maxSdkVersion" => 0x0101_0271,
        "required" => 0x0101_028e,
        "extractNativeLibs" => 0x0101_04ea,
        "compileSdkVersion" => 0x0101_0572,
        "requiredSplitTypes" => 0x0101_064e,
        "splitTypes" => 0x0101_064f,
        _ => return None,
    })
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&self, off: usize) -> Result<u8, AxmlError> {
        self.data.get(off).copied().ok_or(AxmlError::Truncated(off))
    }
    fn u16(&self, off: usize) -> Result<u16, AxmlError> {
        let b = self.data.get(off..off + 2).ok_or(AxmlError::Truncated(off))?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&self, off: usize) -> Result<u32, AxmlError> {
        let b = self.data.get(off..off + 4).ok_or(AxmlError::Truncated(off))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn slice(&self, off: usize, len: usize) -> Result<&'a [u8], AxmlError> {
        let end = off.checked_add(len).ok_or(AxmlError::Truncated(off))?;
        self.data.get(off..end).ok_or(AxmlError::Truncated(off))
    }
}

struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    fn parse(r: &Reader<'_>, start: usize, size: usize) -> Result<Self, AxmlError> {
        let string_count = r.u32(start + 8)? as usize;
        let flags = r.u32(start + 16)?;
        let strings_start = r.u32(start + 20)? as usize;
        let header_size = r.u16(start + 2)? as usize;
        if string_count > size / 4 {
            return Err(AxmlError::Malformed("string count exceeds chunk"));
        }
        let utf8 = flags & UTF8_FLAG != 0;
        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off = r.u32(start + header_size + i * 4)? as usize;
            let pos = start + strings_start + off;
            if pos >= start + size {
                return Err(AxmlError::Malformed("string offset outside pool"));
            }
            let s = if utf8 { Self::read_utf8(r, pos)? } else { Self::read_utf16(r, pos)? };
            strings.push(s);
        }
        Ok(Self { strings })
    }

    fn read_utf8(r: &Reader<'_>, mut pos: usize) -> Result<String, AxmlError> {
        // UTF-16 length (skipped), then UTF-8 byte length; each 1 or 2 bytes.
        let b = r.u8(pos)?;
        pos += if b & 0x80 != 0 { 2 } else { 1 };
        let b0 = r.u8(pos)? as usize;
        let len = if b0 & 0x80 != 0 {
            let b1 = r.u8(pos + 1)? as usize;
            pos += 2;
            ((b0 & 0x7f) << 8) | b1
        } else {
            pos += 1;
            b0
        };
        let bytes = r.slice(pos, len)?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    fn read_utf16(r: &Reader<'_>, mut pos: usize) -> Result<String, AxmlError> {
        let l0 = r.u16(pos)? as usize;
        let len = if l0 & 0x8000 != 0 {
            let l1 = r.u16(pos + 2)? as usize;
            pos += 4;
            ((l0 & 0x7fff) << 16) | l1
        } else {
            pos += 2;
            l0
        };
        let bytes = r.slice(pos, len * 2)?;
        let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Ok(String::from_utf16_lossy(&units))
    }

    fn get(&self, idx: u32) -> Option<&str> {
        if idx == NO_INDEX {
            return None;
        }
        self.strings.get(idx as usize).map(|s| s.as_str())
    }
}

/// Parses binary XML into an element tree and returns the root element.
pub fn parse(data: &[u8]) -> Result<Element, AxmlError> {
    let r = Reader { data };
    if r.u16(0)? != RES_XML_TYPE {
        return Err(AxmlError::Malformed("not a binary XML document"));
    }
    let header_size = r.u16(2)? as usize;
    let total = (r.u32(4)? as usize).min(data.len());

    let mut pool: Option<StringPool> = None;
    let mut res_map: Vec<u32> = Vec::new();
    let mut ns_stack: HashMap<String, String> = HashMap::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    let mut off = header_size;
    while off + 8 <= total {
        let ty = r.u16(off)?;
        let hsize = r.u16(off + 2)? as usize;
        let size = r.u32(off + 4)? as usize;
        if size < 8 || off + size > total || hsize > size {
            return Err(AxmlError::Malformed("invalid chunk size"));
        }
        match ty {
            RES_STRING_POOL_TYPE => pool = Some(StringPool::parse(&r, off, size)?),
            RES_XML_RESOURCE_MAP_TYPE => {
                let n = (size - hsize) / 4;
                res_map = (0..n).map(|i| r.u32(off + hsize + i * 4)).collect::<Result<_, _>>()?;
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let p = pool.as_ref().ok_or(AxmlError::Malformed("namespace before string pool"))?;
                let prefix = p.get(r.u32(off + hsize)?).unwrap_or_default().to_string();
                let uri = p.get(r.u32(off + hsize + 4)?).unwrap_or_default().to_string();
                ns_stack.insert(uri, prefix);
            }
            RES_XML_END_NAMESPACE_TYPE | RES_XML_CDATA_TYPE => {}
            RES_XML_START_ELEMENT_TYPE => {
                let p = pool.as_ref().ok_or(AxmlError::Malformed("element before string pool"))?;
                let ext = off + hsize;
                let ns = p.get(r.u32(ext)?).map(str::to_string);
                let name = p.get(r.u32(ext + 4)?).unwrap_or_default().to_string();
                let attr_start = r.u16(ext + 8)? as usize;
                let attr_size = r.u16(ext + 10)? as usize;
                let attr_count = r.u16(ext + 12)? as usize;
                if attr_size < 20 {
                    return Err(AxmlError::Malformed("attribute size too small"));
                }
                let mut attributes = Vec::with_capacity(attr_count);
                for i in 0..attr_count {
                    let a = ext + attr_start + i * attr_size;
                    let a_ns = p.get(r.u32(a)?).map(str::to_string).filter(|s| !s.is_empty());
                    let name_idx = r.u32(a + 4)?;
                    let raw = r.u32(a + 8)?;
                    let data_type = r.u8(a + 15)?;
                    let data = r.u32(a + 16)?;
                    let resource_id = res_map.get(name_idx as usize).copied().filter(|id| *id != 0);
                    let mut a_name = p.get(name_idx).unwrap_or_default().to_string();
                    if a_name.is_empty() {
                        if let Some(id) = resource_id {
                            a_name = format!("0x{id:08x}");
                        }
                    }
                    let value = match data_type {
                        0x03 => AttrValue::String(p.get(data).or_else(|| p.get(raw)).unwrap_or_default().to_string()),
                        0x01 | 0x02 => AttrValue::Reference(data),
                        0x04 => AttrValue::Float(f32::from_bits(data)),
                        0x10 | 0x11 => AttrValue::Int(data as i32 as i64),
                        0x12 => AttrValue::Bool(data != 0),
                        _ => match p.get(raw) {
                            Some(s) => AttrValue::String(s.to_string()),
                            None => AttrValue::Other { data_type, data },
                        },
                    };
                    attributes.push(Attribute {
                        namespace: a_ns,
                        name: a_name,
                        resource_id,
                        value,
                    });
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(AxmlError::Malformed("element nesting too deep"));
                }
                stack.push(Element {
                    namespace: ns,
                    name,
                    attributes,
                    children: Vec::new(),
                });
            }
            RES_XML_END_ELEMENT_TYPE => {
                let el = stack.pop().ok_or(AxmlError::Malformed("unbalanced end element"))?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => {
                        if root.is_none() {
                            root = Some(el);
                        }
                    }
                }
            }
            _ => {} // unknown chunks are skipped, as the platform does
        }
        off += size;
    }
    // Tolerate missing end tags (seen in some packers): close whatever is open.
    while let Some(el) = stack.pop() {
        match stack.last_mut() {
            Some(parent) => parent.children.push(el),
            None => {
                if root.is_none() {
                    root = Some(el)
                }
            }
        }
    }
    root.ok_or(AxmlError::Malformed("document has no root element"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[3, 0, 8, 0, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(parse(b"<?xml version='1.0'?><manifest/>").is_err());
        // Header claiming a huge string count must not allocate or panic.
        let mut v = vec![3, 0, 8, 0, 0, 0, 0, 0];
        let pool = [1u16.to_le_bytes(), 28u16.to_le_bytes()].concat();
        v.extend_from_slice(&pool);
        v.extend_from_slice(&36u32.to_le_bytes());
        v.extend_from_slice(&u32::MAX.to_le_bytes());
        v.extend_from_slice(&[0u8; 20]);
        let len = v.len() as u32;
        v[4..8].copy_from_slice(&len.to_le_bytes());
        assert!(parse(&v).is_err());
    }
}
