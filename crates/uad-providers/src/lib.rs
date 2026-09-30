//! Acquisition providers. Each provider only *discovers* offers; transfer, verification and
//! storage are performed by the engine.

pub mod fdroid;
pub mod http;
pub mod play;
pub mod play_web;
pub mod play_dev;
pub mod local;
#[cfg(feature = "emulator")]
pub mod emulator;
