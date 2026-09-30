//! Engine of the Universal APK Downloader: orchestrates providers, downloads, processing,
//! verification, storage and provenance behind a small async API.

pub mod bundletool;
pub mod config;
pub mod download;
pub mod engine;
pub mod provenance;
pub mod report;
pub mod secrets;
pub mod store;

pub use config::Config;
pub use engine::{Engine, EngineError, JobView};
pub use report::JobReport;
