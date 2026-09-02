//! Linux `/proc` process identity and ancestry reader.

use std::{fs, path::PathBuf};

use thiserror::Error;

pub const MAX_ANCESTRY_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
    pub effective_uid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRecord {
    pub identity: ProcessIdentity,
    pub parent_pid: u32,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProcessError {
    #[error("process data is unavailable")]
    Unavailable,
    #[error("process data is malformed")]
    Malformed,
    #[error("process ancestry exceeded the depth limit")]
    DepthExceeded,
    #[error("process ancestry contains a loop")]
    Loop,
    #[error("expected Codex process was not found in ancestry")]
    NotDescendant,
    #[error("process identity changed while it was being inspected")]
    Changed,
}

pub trait ProcessReader: Send + Sync {
    fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcFs;

impl ProcessReader for ProcFs {
    fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        let stat = fs::read_to_string(stat_path(pid)).map_err(|_| ProcessError::Unavailable)?;
        let effective_uid = fs::read_to_string(status_path(pid))
            .map_err(|_| ProcessError::Unavailable)
            .and_then(|status| parse_effective_uid(&status))?;
        parse_stat(&stat, pid).map(|mut record| {
            record.identity.effective_uid = effective_uid;
            record
        })
    }
}

pub fn current_process_identity(pid: u32) -> Result<ProcessIdentity, ProcessError> {
    let reader = ProcFs;
    let first = reader.read_process(pid)?;
    let second = reader.read_process(pid)?;
    if first != second {
        return Err(ProcessError::Changed);
    }
    Ok(first.identity)
}

pub fn validate_ancestry(
    reader: &impl ProcessReader,
    peer_pid: u32,
    expected: ProcessIdentity,
) -> Result<(), ProcessError> {
    let first = collect_ancestry(reader, peer_pid, expected.pid)?;
    let second = collect_ancestry(reader, peer_pid, expected.pid)?;
    if first != second {
        return Err(ProcessError::Changed);
    }
    if first.iter().any(|record| record.identity == expected) {
        Ok(())
    } else {
        Err(ProcessError::NotDescendant)
    }
}

fn collect_ancestry(
    reader: &impl ProcessReader,
    peer_pid: u32,
    expected_pid: u32,
) -> Result<Vec<ProcessRecord>, ProcessError> {
    let mut records: Vec<ProcessRecord> = Vec::new();
    let mut current = peer_pid;
    while records.len() < MAX_ANCESTRY_DEPTH {
        if current == 0 || records.iter().any(|record| record.identity.pid == current) {
            return Err(if current == 0 {
                ProcessError::NotDescendant
            } else {
                ProcessError::Loop
            });
        }
        let record = reader.read_process(current)?;
        if record.identity.pid != current {
            return Err(ProcessError::Malformed);
        }
        records.push(record);
        if record.identity.pid == expected_pid {
            return Ok(records);
        }
        if record.parent_pid == 0 {
            return Err(ProcessError::NotDescendant);
        }
        current = record.parent_pid;
    }
    Err(ProcessError::DepthExceeded)
}

pub fn parse_stat(content: &str, expected_pid: u32) -> Result<ProcessRecord, ProcessError> {
    let open = content.find('(').ok_or(ProcessError::Malformed)?;
    let close = content.rfind(')').ok_or(ProcessError::Malformed)?;
    if close <= open {
        return Err(ProcessError::Malformed);
    }

    let pid = content[..open]
        .trim()
        .parse::<u32>()
        .map_err(|_| ProcessError::Malformed)?;
    if pid != expected_pid {
        return Err(ProcessError::Malformed);
    }

    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    if fields.len() <= 19 || fields[0].len() != 1 {
        return Err(ProcessError::Malformed);
    }
    let parent_pid = fields[1]
        .parse::<u32>()
        .map_err(|_| ProcessError::Malformed)?;
    let start_time = fields[19]
        .parse::<u64>()
        .map_err(|_| ProcessError::Malformed)?;

    Ok(ProcessRecord {
        identity: ProcessIdentity {
            pid,
            start_time,
            effective_uid: 0,
        },
        parent_pid,
    })
}

fn parse_effective_uid(status: &str) -> Result<u32, ProcessError> {
    let line = status
        .lines()
        .find(|line| line.strip_prefix("Uid:").is_some())
        .ok_or(ProcessError::Malformed)?;
    line.split_whitespace()
        .nth(2)
        .ok_or(ProcessError::Malformed)?
        .parse()
        .map_err(|_| ProcessError::Malformed)
}

fn stat_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/stat"))
}

fn status_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/status"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn stat(pid: u32, name: &str, parent: u32, start_time: u64) -> String {
        let mut fields = vec!["0"; 52];
        fields[0] = "R";
        fields[1] = Box::leak(parent.to_string().into_boxed_str());
        fields[19] = Box::leak(start_time.to_string().into_boxed_str());
        format!("{pid} ({name}) {}", fields.join(" "))
    }

    #[test]
    fn parses_names_with_spaces_and_parentheses() {
        for name in ["codex", "codex child", "codex (worker)"] {
            let record = parse_stat(&stat(42, name, 7, 1234), 42).expect("stat parses");
            assert_eq!(record.identity.start_time, 1234);
            assert_eq!(record.parent_pid, 7);
        }
    }

    #[test]
    fn rejects_malformed_stat_content() {
        for content in ["", "42 codex R 7", "42 (codex) R 7", "43 (codex) R 7"] {
            assert!(parse_stat(content, 42).is_err());
        }
    }

    #[derive(Default)]
    struct FakeProc {
        records: HashMap<u32, ProcessRecord>,
    }

    impl ProcessReader for FakeProc {
        fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
            self.records
                .get(&pid)
                .copied()
                .ok_or(ProcessError::Unavailable)
        }
    }

    fn record(pid: u32, parent_pid: u32, start_time: u64) -> ProcessRecord {
        ProcessRecord {
            identity: ProcessIdentity {
                pid,
                start_time,
                effective_uid: 1000,
            },
            parent_pid,
        }
    }

    #[test]
    fn requires_exact_pid_and_start_time() {
        let reader = FakeProc {
            records: HashMap::from([(10, record(10, 20, 11)), (20, record(20, 1, 22))]),
        };
        assert!(
            validate_ancestry(
                &reader,
                10,
                ProcessIdentity {
                    pid: 20,
                    start_time: 22,
                    effective_uid: 1000
                }
            )
            .is_ok()
        );
        assert_eq!(
            validate_ancestry(
                &reader,
                10,
                ProcessIdentity {
                    pid: 20,
                    start_time: 23,
                    effective_uid: 1000
                }
            ),
            Err(ProcessError::NotDescendant)
        );
    }

    #[test]
    fn rejects_loops_and_depth_exhaustion() {
        let loop_reader = FakeProc {
            records: HashMap::from([(10, record(10, 20, 11)), (20, record(20, 10, 22))]),
        };
        assert_eq!(
            validate_ancestry(
                &loop_reader,
                10,
                ProcessIdentity {
                    pid: 99,
                    start_time: 1,
                    effective_uid: 1000
                }
            ),
            Err(ProcessError::Loop)
        );

        let mut records = HashMap::new();
        for pid in 1..=(MAX_ANCESTRY_DEPTH as u32 + 1) {
            records.insert(pid, record(pid, pid + 1, pid as u64));
        }
        records.insert(
            MAX_ANCESTRY_DEPTH as u32 + 2,
            record(MAX_ANCESTRY_DEPTH as u32 + 2, 0, 1),
        );
        assert_eq!(
            validate_ancestry(
                &FakeProc { records },
                1,
                ProcessIdentity {
                    pid: 999,
                    start_time: 1,
                    effective_uid: 1000
                }
            ),
            Err(ProcessError::DepthExceeded)
        );
    }

    #[test]
    fn rejects_missing_processes_and_malformed_parent_relationships() {
        let reader = FakeProc {
            records: HashMap::from([(10, record(10, 0, 11))]),
        };
        assert_eq!(
            validate_ancestry(
                &reader,
                10,
                ProcessIdentity {
                    pid: 99,
                    start_time: 1,
                    effective_uid: 1000
                }
            ),
            Err(ProcessError::NotDescendant)
        );
        assert_eq!(
            validate_ancestry(
                &FakeProc::default(),
                10,
                ProcessIdentity {
                    pid: 99,
                    start_time: 1,
                    effective_uid: 1000
                }
            ),
            Err(ProcessError::Unavailable)
        );
    }
}
