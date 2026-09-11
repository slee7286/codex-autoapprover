//! Platform-specific launcher-owned decision brokers.

use anyhow::Error;
use thiserror::Error as ThisError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFailureKind {
    Transport,
    Protocol,
}

#[derive(Debug, ThisError)]
#[error("broker request failed")]
pub struct RequestFailure {
    kind: RequestFailureKind,
}

impl RequestFailure {
    pub const fn new(kind: RequestFailureKind) -> Self {
        Self { kind }
    }

    pub const fn kind(&self) -> RequestFailureKind {
        self.kind
    }
}

pub fn request_failure_kind(error: &Error) -> RequestFailureKind {
    error
        .downcast_ref::<RequestFailure>()
        .map_or(RequestFailureKind::Transport, RequestFailure::kind)
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(windows)]
pub use windows::*;
