//! Explicit job state machine.
//!
//! ```text
//! Queued ─Start→ Resolving ─Resolved→ Discovering ─OffersFound→ Acquiring ─Acquired→ Processing
//!    ↑                                                                                   │
//!    │                                                                               Processed
//!  Retry                                                                                 ↓
//! Failed / Cancelled / PartiallyCompleted  ←─Verified(Partial|None)─  Verifying ─Verified(All)→ Completed
//! (any non-terminal state) ─Fail→ Failed, ─Cancel→ Cancelled
//! ```
//! Transitions not in the table are rejected, so the orchestrator cannot skip verification.

use crate::variant::Abi;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Resolving,
    Discovering,
    Acquiring,
    Processing,
    Verifying,
    Completed,
    PartiallyCompleted,
    Failed,
    Cancelled,
}

impl JobState {
    pub const ALL: [JobState; 10] = [
        JobState::Queued,
        JobState::Resolving,
        JobState::Discovering,
        JobState::Acquiring,
        JobState::Processing,
        JobState::Verifying,
        JobState::Completed,
        JobState::PartiallyCompleted,
        JobState::Failed,
        JobState::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Resolving => "resolving",
            JobState::Discovering => "discovering",
            JobState::Acquiring => "acquiring",
            JobState::Processing => "processing",
            JobState::Verifying => "verifying",
            JobState::Completed => "completed",
            JobState::PartiallyCompleted => "partially_completed",
            JobState::Failed => "failed",
            JobState::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|st| st.as_str() == s)
    }

    /// No further automatic progress happens from these states.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobState::Completed | JobState::PartiallyCompleted | JobState::Failed | JobState::Cancelled
        )
    }

    /// States that were in flight when a process stopped; they are re-queued on restart.
    pub fn is_active(self) -> bool {
        !self.is_terminal() && self != JobState::Queued
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Every retrieved file passed verification and the preferred result was obtained.
    All,
    /// Something usable was retrieved and verified, but not everything that was identified.
    Partial,
    /// Nothing passed verification.
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEvent {
    Start,
    Resolved,
    OffersFound,
    Acquired,
    Processed,
    Verified(VerificationOutcome),
    Fail,
    Cancel,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid transition: {event:?} in state {from}")]
pub struct TransitionError {
    pub from: JobState,
    pub event: JobEvent,
}

impl JobState {
    pub fn next(self, event: JobEvent) -> Result<JobState, TransitionError> {
        use JobEvent as E;
        use JobState as S;
        let to = match (self, event) {
            (S::Queued, E::Start) => S::Resolving,
            (S::Resolving, E::Resolved) => S::Discovering,
            (S::Discovering, E::OffersFound) => S::Acquiring,
            (S::Acquiring, E::Acquired) => S::Processing,
            (S::Processing, E::Processed) => S::Verifying,
            (S::Verifying, E::Verified(VerificationOutcome::All)) => S::Completed,
            (S::Verifying, E::Verified(VerificationOutcome::Partial)) => S::PartiallyCompleted,
            (S::Verifying, E::Verified(VerificationOutcome::None)) => S::Failed,
            (s, E::Fail) if !s.is_terminal() => S::Failed,
            (s, E::Cancel) if !s.is_terminal() => S::Cancelled,
            (S::Failed | S::Cancelled | S::PartiallyCompleted, E::Retry) => S::Queued,
            // Recovery after a crash: in-flight jobs are restarted from the queue.
            (s, E::Retry) if s.is_active() => S::Queued,
            (from, event) => return Err(TransitionError { from, event }),
        };
        Ok(to)
    }
}

/// Options supplied with a job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobOptions {
    /// Specific version code; `None` = latest.
    #[serde(default)]
    pub version_code: Option<i64>,
    /// Restrict providers (ids). Empty = all enabled providers.
    #[serde(default)]
    pub providers: Vec<String>,
    /// Restrict ABI-specific downloads. Empty = all.
    #[serde(default)]
    pub abis: Vec<Abi>,
    /// Also download every variant, even when a universal APK was obtained.
    #[serde(default)]
    pub all_variants: bool,
    /// Build a universal APK with bundletool when an AAB is obtained (default true).
    #[serde(default = "default_true")]
    pub build_universal_from_aab: bool,
}

fn default_true() -> bool {
    true
}

impl Default for JobOptions {
    fn default() -> Self {
        Self {
            version_code: None,
            providers: vec![],
            abis: vec![],
            all_variants: false,
            build_universal_from_aab: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use JobEvent as E;
    use JobState as S;

    #[test]
    fn happy_path() {
        let mut s = S::Queued;
        for e in [
            E::Start,
            E::Resolved,
            E::OffersFound,
            E::Acquired,
            E::Processed,
            E::Verified(VerificationOutcome::All),
        ] {
            s = s.next(e).unwrap();
        }
        assert_eq!(s, S::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn cannot_skip_verification() {
        assert!(S::Acquiring.next(E::Verified(VerificationOutcome::All)).is_err());
        assert!(S::Processing.next(E::Verified(VerificationOutcome::All)).is_err());
        assert!(S::Queued.next(E::Acquired).is_err());
    }

    #[test]
    fn failure_cancel_and_retry() {
        for s in JobState::ALL {
            let r = s.next(E::Fail);
            assert_eq!(r.is_ok(), !s.is_terminal(), "{s}");
        }
        assert!(S::Completed.next(E::Cancel).is_err());
        assert_eq!(S::Failed.next(E::Retry).unwrap(), S::Queued);
        assert_eq!(S::Acquiring.next(E::Retry).unwrap(), S::Queued);
        assert!(S::Completed.next(E::Retry).is_err());
        assert_eq!(
            S::Verifying.next(E::Verified(VerificationOutcome::Partial)).unwrap(),
            S::PartiallyCompleted
        );
        assert_eq!(S::Verifying.next(E::Verified(VerificationOutcome::None)).unwrap(), S::Failed);
    }

    #[test]
    fn string_roundtrip() {
        for s in JobState::ALL {
            assert_eq!(JobState::parse(s.as_str()), Some(s));
        }
    }

    #[test]
    fn options_defaults() {
        let o: JobOptions = serde_json::from_str("{}").unwrap();
        assert!(o.build_universal_from_aab);
        assert_eq!(o, JobOptions::default());
        assert!(o.version_code.is_none());
    }
}
