//! Platform-specific launcher-owned decision brokers.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

fn reap_finished_workers(workers: &mut Vec<std::thread::JoinHandle<()>>) {
    let mut running = Vec::with_capacity(workers.len());
    for worker in workers.drain(..) {
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            running.push(worker);
        }
    }
    *workers = running;
}

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

#[cfg(test)]
mod worker_tests {
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn reaping_completed_workers_does_not_wait_for_active_connections() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let active = thread::spawn(move || {
            started_tx.send(()).expect("signal active worker");
            release_rx.recv().expect("release active worker");
        });
        started_rx.recv().expect("active worker started");
        let completed = thread::spawn(|| {});
        while !completed.is_finished() {
            thread::yield_now();
        }
        let (result_tx, result_rx) = mpsc::channel();
        let reaper = thread::spawn(move || {
            let mut workers = vec![active, completed];
            super::reap_finished_workers(&mut workers);
            result_tx
                .send(workers.len())
                .expect("report active workers");
            for worker in workers {
                worker.join().expect("join active worker");
            }
        });
        let prompt = result_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).expect("release active worker");
        reaper.join().expect("join reaper");
        assert_eq!(prompt.expect("reaper blocked on an active worker"), 1);
    }
}
