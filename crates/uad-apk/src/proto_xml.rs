//! Minimal decoder for aapt2's protobuf XML (`Resources.proto`: XmlNode/XmlElement/XmlAttribute),
//! used for `AndroidManifest.xml` inside Android App Bundles. Converted into the same element
//! tree as binary XML so a single manifest model serves APKs and AABs.

use crate::axml::{AttrValue, Attribute, Element};
use prost::Message;

#[derive(Clone, PartialEq, Message)]
struct XmlNode {
    #[prost(message, optional, tag = "1")]
    element: Option<XmlElement>,
    #[prost(string, optional, tag = "2")]
    text: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct XmlElement {
    #[prost(string, tag = "2")]
    namespace_uri: String,
    #[prost(string, tag = "3")]
    name: String,
    #[prost(message, repeated, tag = "4")]
    attribute: Vec<XmlAttribute>,
    #[prost(message, repeated, tag = "5")]
    child: Vec<XmlNode>,
}

#[derive(Clone, PartialEq, Message)]
struct XmlAttribute {
    #[prost(string, tag = "1")]
    namespace_uri: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    value: String,
    #[prost(uint32, tag = "5")]
    resource_id: u32,
    #[prost(message, optional, tag = "6")]
    compiled_item: Option<Item>,
}

#[derive(Clone, PartialEq, Message)]
struct Item {
    #[prost(message, optional, tag = "1")]
    r#ref: Option<Reference>,
    #[prost(message, optional, tag = "7")]
    prim: Option<Primitive>,
}

#[derive(Clone, PartialEq, Message)]
struct Reference {
    #[prost(uint32, tag = "2")]
    id: u32,
}

#[derive(Clone, PartialEq, Message)]
struct Primitive {
    #[prost(int32, optional, tag = "6")]
    int_decimal_value: Option<i32>,
    #[prost(uint32, optional, tag = "7")]
    int_hexadecimal_value: Option<u32>,
    #[prost(bool, optional, tag = "8")]
    boolean_value: Option<bool>,
}

fn convert(e: &XmlElement, depth: usize) -> Element {
    let attributes = e
        .attribute
        .iter()
        .map(|a| {
            let value = match a.compiled_item.as_ref() {
                Some(Item { prim: Some(p), .. }) => {
                    if let Some(b) = p.boolean_value {
                        AttrValue::Bool(b)
                    } else if let Some(i) = p.int_decimal_value {
                        AttrValue::Int(i as i64)
                    } else if let Some(h) = p.int_hexadecimal_value {
                        AttrValue::Int(h as i32 as i64)
                    } else {
                        AttrValue::String(a.value.clone())
                    }
                }
                Some(Item { r#ref: Some(r), .. }) => AttrValue::Reference(r.id),
                _ => AttrValue::String(a.value.clone()),
            };
            Attribute {
                namespace: Some(a.namespace_uri.clone()).filter(|s| !s.is_empty()),
                name: a.name.clone(),
                resource_id: Some(a.resource_id).filter(|r| *r != 0),
                value,
            }
        })
        .collect();
    let children = if depth < 256 {
        e.child.iter().filter_map(|c| c.element.as_ref()).map(|c| convert(c, depth + 1)).collect()
    } else {
        vec![]
    };
    Element {
        namespace: Some(e.namespace_uri.clone()).filter(|s| !s.is_empty()),
        name: e.name.clone(),
        attributes,
        children,
    }
}

pub fn parse(data: &[u8]) -> Result<Element, String> {
    let node = XmlNode::decode(data).map_err(|e| format!("invalid protobuf XML: {e}"))?;
    node.element
        .as_ref()
        .map(|e| convert(e, 0))
        .ok_or_else(|| "protobuf XML has no root element".into())
}
