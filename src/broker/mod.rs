//! Platform-specific launcher-owned decision brokers.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(windows)]
pub use windows::*;

/// A successful broker decision consumes an invocation even when the peer fails
/// to receive it. Missing unique upstream request IDs require conservative
/// replay rejection; an identical legitimate retry goes to normal approval.
#[derive(Default)]
struct RequestLedger {
    session: Option<String>,
    invocations: std::collections::HashSet<(u32, u64)>,
    requests: std::collections::HashSet<String>,
}

impl RequestLedger {
    fn consume(
        &mut self,
        input: &crate::protocol::HookInput,
        pid: u32,
        started: u64,
        verification: bool,
    ) -> bool {
        use sha2::{Digest, Sha256};
        let Some(session) = input.session_id.as_ref().filter(|s| !s.is_empty()) else {
            return false;
        };
        if self
            .session
            .as_ref()
            .is_some_and(|expected| expected != session)
            || self.invocations.len() >= 4096
            || (verification && !self.invocations.is_empty())
            || self.invocations.contains(&(pid, started))
        {
            return false;
        }
        let Ok(bytes) = serde_json::to_vec(input) else {
            return false;
        };
        let digest = crate::identity::hex(&Sha256::digest(bytes));
        if !self.requests.insert(digest) {
            return false;
        }
        self.session = Some(session.clone());
        self.invocations.insert((pid, started));
        true
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    fn input(session: &str, turn: &str) -> crate::protocol::HookInput {
        crate::protocol::parse(
            serde_json::to_vec(&serde_json::json!({
                "session_id": session, "turn_id": turn, "hook_event_name": "PermissionRequest",
                "cwd": "/synthetic", "tool_name": "Bash", "tool_input": {"command": "true"}
            }))
            .unwrap()
            .as_slice(),
        )
        .unwrap()
    }

    #[test]
    fn a_session_and_invocation_cannot_be_reused_or_rebound() {
        let mut ledger = RequestLedger::default();
        assert!(ledger.consume(&input("s", "t1"), 10, 1, false));
        assert!(!ledger.consume(&input("s", "t1"), 11, 2, false));
        assert!(!ledger.consume(&input("s", "t2"), 10, 1, false));
        assert!(!ledger.consume(&input("other", "t2"), 12, 3, false));
        assert!(ledger.consume(&input("s", "t2"), 12, 3, false));
    }

    #[test]
    fn verifier_consumes_exactly_one_allow_under_concurrency() {
        let ledger = std::sync::Arc::new(std::sync::Mutex::new(RequestLedger::default()));
        let workers: Vec<_> = (1..=16)
            .map(|pid| {
                let ledger = ledger.clone();
                std::thread::spawn(move || {
                    ledger
                        .lock()
                        .unwrap()
                        .consume(&input("s", &format!("t{pid}")), pid, 1, true)
                })
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
}
