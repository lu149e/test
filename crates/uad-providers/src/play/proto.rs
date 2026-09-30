//! Minimal protobuf messages of the Google Play device protocol (`/checkin` and `/fdfe/*`).
//!
//! Only the fields this client reads or writes are declared; prost skips everything else.
//! Field numbers follow the community-maintained `GooglePlay.proto` (MIT, used by the
//! googleplay-protobuf crate) which documents the Play Store client's wire format.

#![allow(clippy::enum_variant_names)]

use prost::Message;

// ---- checkin -----------------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct AndroidCheckinRequest {
    #[prost(int64, optional, tag = "2")]
    pub id: Option<i64>,
    #[prost(message, optional, tag = "4")]
    pub checkin: Option<AndroidCheckinProto>,
    #[prost(string, optional, tag = "6")]
    pub locale: Option<String>,
    #[prost(int64, optional, tag = "7")]
    pub logging_id: Option<i64>,
    #[prost(string, repeated, tag = "9")]
    pub mac_addr: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    pub account_cookie: Vec<String>,
    #[prost(string, optional, tag = "12")]
    pub time_zone: Option<String>,
    #[prost(fixed64, optional, tag = "13")]
    pub security_token: Option<u64>,
    #[prost(int32, optional, tag = "14")]
    pub version: Option<i32>,
    #[prost(string, repeated, tag = "15")]
    pub ota_cert: Vec<String>,
    #[prost(message, optional, tag = "18")]
    pub device_configuration: Option<DeviceConfigurationProto>,
    #[prost(string, repeated, tag = "19")]
    pub mac_addr_type: Vec<String>,
    #[prost(int32, optional, tag = "20")]
    pub fragment: Option<i32>,
    #[prost(int32, optional, tag = "22")]
    pub user_serial_number: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AndroidCheckinProto {
    #[prost(message, optional, tag = "1")]
    pub build: Option<AndroidBuildProto>,
    #[prost(int64, optional, tag = "2")]
    pub last_checkin_msec: Option<i64>,
    #[prost(string, optional, tag = "6")]
    pub cell_operator: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub sim_operator: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub roaming: Option<String>,
    #[prost(int32, optional, tag = "9")]
    pub user_number: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AndroidBuildProto {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub product: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub carrier: Option<String>,
    #[prost(string, optional, tag = "4")]
    pub radio: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub bootloader: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub client: Option<String>,
    #[prost(int64, optional, tag = "7")]
    pub timestamp: Option<i64>,
    #[prost(int32, optional, tag = "8")]
    pub google_services: Option<i32>,
    #[prost(string, optional, tag = "9")]
    pub device: Option<String>,
    #[prost(int32, optional, tag = "10")]
    pub sdk_version: Option<i32>,
    #[prost(string, optional, tag = "11")]
    pub model: Option<String>,
    #[prost(string, optional, tag = "12")]
    pub manufacturer: Option<String>,
    #[prost(string, optional, tag = "13")]
    pub build_product: Option<String>,
    #[prost(bool, optional, tag = "14")]
    pub ota_installed: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeviceFeature {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub value: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeviceConfigurationProto {
    #[prost(int32, optional, tag = "1")]
    pub touch_screen: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub keyboard: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    pub navigation: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    pub screen_layout: Option<i32>,
    #[prost(bool, optional, tag = "5")]
    pub has_hard_keyboard: Option<bool>,
    #[prost(bool, optional, tag = "6")]
    pub has_five_way_navigation: Option<bool>,
    #[prost(int32, optional, tag = "7")]
    pub screen_density: Option<i32>,
    #[prost(int32, optional, tag = "8")]
    pub gl_es_version: Option<i32>,
    #[prost(string, repeated, tag = "9")]
    pub system_shared_library: Vec<String>,
    #[prost(string, repeated, tag = "10")]
    pub system_available_feature: Vec<String>,
    #[prost(string, repeated, tag = "11")]
    pub native_platform: Vec<String>,
    #[prost(int32, optional, tag = "12")]
    pub screen_width: Option<i32>,
    #[prost(int32, optional, tag = "13")]
    pub screen_height: Option<i32>,
    #[prost(string, repeated, tag = "14")]
    pub system_supported_locale: Vec<String>,
    #[prost(string, repeated, tag = "15")]
    pub gl_extension: Vec<String>,
    #[prost(int32, optional, tag = "16")]
    pub device_class: Option<i32>,
    #[prost(int32, optional, tag = "17")]
    pub max_apk_download_size_mb: Option<i32>,
    #[prost(int32, optional, tag = "18")]
    pub smallest_screen_width_dp: Option<i32>,
    #[prost(int32, optional, tag = "19")]
    pub low_ram_device: Option<i32>,
    #[prost(int64, optional, tag = "20")]
    pub total_memory_bytes: Option<i64>,
    #[prost(int32, optional, tag = "21")]
    pub max_num_of_cpu_cores: Option<i32>,
    #[prost(message, repeated, tag = "26")]
    pub device_feature: Vec<DeviceFeature>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AndroidCheckinResponse {
    #[prost(bool, optional, tag = "1")]
    pub stats_ok: Option<bool>,
    #[prost(int64, optional, tag = "3")]
    pub time_msec: Option<i64>,
    #[prost(string, optional, tag = "4")]
    pub digest: Option<String>,
    #[prost(bool, optional, tag = "6")]
    pub market_ok: Option<bool>,
    #[prost(fixed64, optional, tag = "7")]
    pub android_id: Option<u64>,
    #[prost(fixed64, optional, tag = "8")]
    pub security_token: Option<u64>,
    #[prost(string, optional, tag = "12")]
    pub device_checkin_consistency_token: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct UploadDeviceConfigRequest {
    #[prost(message, optional, tag = "1")]
    pub device_configuration: Option<DeviceConfigurationProto>,
    #[prost(string, optional, tag = "2")]
    pub manufacturer: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct UploadDeviceConfigResponse {
    #[prost(string, optional, tag = "1")]
    pub upload_device_config_token: Option<String>,
}

// ---- fdfe responses ----------------------------------------------------------------------

#[derive(Clone, PartialEq, Message)]
pub struct ResponseWrapper {
    #[prost(message, optional, tag = "1")]
    pub payload: Option<Payload>,
    #[prost(message, optional, tag = "2")]
    pub commands: Option<ServerCommands>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ServerCommands {
    #[prost(bool, optional, tag = "1")]
    pub clear_cache: Option<bool>,
    #[prost(string, optional, tag = "2")]
    pub display_error_message: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Payload {
    #[prost(message, optional, tag = "2")]
    pub details_response: Option<DetailsResponse>,
    #[prost(message, optional, tag = "4")]
    pub buy_response: Option<BuyResponse>,
    #[prost(message, optional, tag = "6")]
    pub toc_response: Option<TocResponse>,
    #[prost(message, optional, tag = "21")]
    pub delivery_response: Option<DeliveryResponse>,
    #[prost(message, optional, tag = "28")]
    pub upload_device_config_response: Option<UploadDeviceConfigResponse>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TocResponse {
    #[prost(string, optional, tag = "3")]
    pub tos_content: Option<String>,
    #[prost(string, optional, tag = "7")]
    pub tos_token: Option<String>,
    #[prost(bool, optional, tag = "11")]
    pub requires_upload_device_config: Option<bool>,
    #[prost(string, optional, tag = "22")]
    pub cookie: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DetailsResponse {
    #[prost(message, optional, tag = "4")]
    pub item: Option<Item>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Item {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub title: Option<String>,
    #[prost(string, optional, tag = "6")]
    pub creator: Option<String>,
    #[prost(message, repeated, tag = "8")]
    pub offer: Vec<Offer>,
    #[prost(message, optional, tag = "13")]
    pub details: Option<DocumentDetails>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Offer {
    #[prost(int64, optional, tag = "1")]
    pub micros: Option<i64>,
    #[prost(string, optional, tag = "2")]
    pub currency_code: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub formatted_amount: Option<String>,
    #[prost(bool, optional, tag = "5")]
    pub checkout_flow_required: Option<bool>,
    #[prost(int32, optional, tag = "8")]
    pub offer_type: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DocumentDetails {
    #[prost(message, optional, tag = "1")]
    pub app_details: Option<AppDetails>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AppDetails {
    #[prost(string, optional, tag = "1")]
    pub developer_name: Option<String>,
    #[prost(int64, optional, tag = "3")]
    pub version_code: Option<i64>,
    #[prost(string, optional, tag = "4")]
    pub version_string: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub title: Option<String>,
    #[prost(int64, optional, tag = "9")]
    pub info_download_size: Option<i64>,
    #[prost(string, optional, tag = "14")]
    pub package_name: Option<String>,
    #[prost(message, repeated, tag = "17")]
    pub file: Vec<FileMetadata>,
    #[prost(string, repeated, tag = "19")]
    pub certificate_hash: Vec<String>,
    #[prost(message, repeated, tag = "22")]
    pub certificate_set: Vec<CertificateSet>,
    #[prost(string, repeated, tag = "25")]
    pub split_id: Vec<String>,
    #[prost(int32, optional, tag = "32")]
    pub target_sdk_version: Option<i32>,
    #[prost(message, optional, tag = "34")]
    pub dependencies: Option<Dependencies>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FileMetadata {
    #[prost(int32, optional, tag = "1")]
    pub file_type: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub version_code: Option<i32>,
    #[prost(int64, optional, tag = "3")]
    pub size: Option<i64>,
    #[prost(string, optional, tag = "4")]
    pub split_id: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CertificateSet {
    #[prost(string, optional, tag = "1")]
    pub certificate_hash: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub sha256: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Dependencies {
    #[prost(message, repeated, tag = "3")]
    pub dependency: Vec<Dependency>,
    #[prost(string, repeated, tag = "11")]
    pub split_apks: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Dependency {
    #[prost(string, optional, tag = "1")]
    pub package_name: Option<String>,
    #[prost(int32, optional, tag = "2")]
    pub version: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct BuyResponse {
    #[prost(string, optional, tag = "55")]
    pub encoded_delivery_token: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DeliveryResponse {
    #[prost(int32, optional, tag = "1")]
    pub status: Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub app_delivery_data: Option<AndroidAppDeliveryData>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AndroidAppDeliveryData {
    #[prost(int64, optional, tag = "1")]
    pub download_size: Option<i64>,
    #[prost(string, optional, tag = "2")]
    pub sha1: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub download_url: Option<String>,
    #[prost(message, repeated, tag = "4")]
    pub additional_file: Vec<AppFileMetadata>,
    #[prost(message, repeated, tag = "5")]
    pub download_auth_cookie: Vec<HttpCookie>,
    #[prost(message, repeated, tag = "15")]
    pub split_delivery_data: Vec<SplitDeliveryData>,
    #[prost(string, optional, tag = "19")]
    pub sha256: Option<String>,
    #[prost(message, optional, tag = "21")]
    pub dex_metadata: Option<DexMetadata>,
}

#[derive(Clone, PartialEq, Message)]
pub struct AppFileMetadata {
    #[prost(int32, optional, tag = "1")]
    pub file_type: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    pub version_code: Option<i32>,
    #[prost(int64, optional, tag = "3")]
    pub size: Option<i64>,
    #[prost(string, optional, tag = "4")]
    pub download_url: Option<String>,
    #[prost(string, optional, tag = "8")]
    pub sha1: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct HttpCookie {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "2")]
    pub value: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SplitDeliveryData {
    #[prost(string, optional, tag = "1")]
    pub name: Option<String>,
    #[prost(int64, optional, tag = "2")]
    pub download_size: Option<i64>,
    #[prost(string, optional, tag = "4")]
    pub sha1: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub download_url: Option<String>,
    #[prost(string, optional, tag = "9")]
    pub sha256: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DexMetadata {
    #[prost(int64, optional, tag = "1")]
    pub download_size: Option<i64>,
    #[prost(string, optional, tag = "2")]
    pub sha256: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub download_url: Option<String>,
}
