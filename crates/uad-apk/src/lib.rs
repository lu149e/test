//! APK, split APK and Android App Bundle processing.
//!
//! * [`axml`]/[`proto_xml`]: manifest decoding (binary XML for APKs, protobuf XML for AABs).
//! * [`manifest`]: typed manifest model.
//! * [`sig`]: signature verification (v1/v2/v3/v3.1), certificates and rotation lineage.
//! * [`analysis`]: single-file analysis and variant classification.
//! * [`splits`]: split-set consistency and dependency validation.
//! * [`apks`]: `.apks` archive writer.

pub mod analysis;
pub mod apks;
pub mod axml;
pub mod manifest;
pub mod proto_xml;
pub mod sig;
pub mod splits;
pub mod zipinfo;

pub use analysis::{analyze, file_digests, peek_manifest, ApkAnalysis, Container};
pub use manifest::ApkManifest;
pub use sig::{verify_apk, SignatureReport, VerifyPolicy};
pub use splits::{validate_split_set, SplitSetReport};
