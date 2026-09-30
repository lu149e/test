//! Core domain of the Universal APK Downloader (UAD).
//!
//! This crate is deliberately free of I/O. It defines:
//! * how user input (Google Play links, `market://` URIs, package names) maps to a [`PackageName`];
//! * the vocabulary for APK variants (ABI, density, language, feature splits) and their
//!   *availability* (known → identified → retrieved);
//! * the contract every acquisition provider implements ([`Provider`]);
//! * the explicit job state machine ([`JobState`]) used by the orchestrator.

pub mod digest;
pub mod input;
pub mod job;
pub mod offer;
pub mod provider;
pub mod secrets;
pub mod variant;

pub use digest::{Sha1Digest, Sha256Digest};
pub use input::{parse_input, AppInput, InputError, InputSource, PackageName};
pub use job::{JobEvent, JobOptions, JobState, TransitionError, VerificationOutcome};
pub use offer::{
    AppMetadata, Discovery, DiscoveryRequest, ExpectedDigests, FileSource, Header, KnownVariant, Offer, OfferLayout, RemoteFile, TrustAnchor,
};
pub use provider::{Provider, ProviderError, ProviderInfo, ProviderKind};
pub use secrets::{MemorySecretStore, SecretStore};
pub use variant::{parse_split_name, Abi, Availability, FileRole, ParsedSplitName, SplitDimension, VariantKind};
