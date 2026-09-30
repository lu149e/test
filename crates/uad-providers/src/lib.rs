//! Acquisition providers. Each provider only *discovers* offers; transfer, verification and
//! storage are performed by the engine.

#[cfg(feature = "emulator")]
pub mod emulator;
pub mod fdroid;
pub mod http;
pub mod local;
pub mod play;
pub mod play_dev;
pub mod play_web;
