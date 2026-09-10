//! Windows process identity and ancestry validation via Toolhelp and process tokens.

use thiserror::Error;

pub const MAX_ANCESTRY_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time: u64,
    /// Binary SID bytes. Authorization must compare validated SID structures,
    /// never a display/string representation.
    pub user_sid: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Debug, Default, Clone)]
pub struct WinProcess;

impl ProcessReader for WinProcess {
    fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        native::read_process_record(pid)
    }
}

pub fn current_process_identity(pid: u32) -> Result<ProcessIdentity, ProcessError> {
    let reader = WinProcess;
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
    if first
        .iter()
        .any(|record| identity_matches(&record.identity, &expected))
    {
        Ok(())
    } else {
        Err(ProcessError::NotDescendant)
    }
}

pub fn launcher_user_sid() -> Result<Vec<u8>, ProcessError> {
    native::current_user_sid()
}

pub fn peer_user_matches_launcher(peer_pid: u32, launcher_sid: &[u8]) -> bool {
    native::process_user_sid(peer_pid)
        .ok()
        .is_some_and(|sid| native::sid_equal(&sid, launcher_sid))
}

pub fn sid_is_valid(sid: &[u8]) -> bool {
    native::sid_is_valid(sid)
}

fn identity_matches(left: &ProcessIdentity, right: &ProcessIdentity) -> bool {
    left.pid == right.pid
        && left.creation_time == right.creation_time
        && native::sid_equal(&left.user_sid, &right.user_sid)
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
        let parent_pid = record.parent_pid;
        records.push(record);
        if records
            .last()
            .is_some_and(|record| record.identity.pid == expected_pid)
        {
            return Ok(records);
        }
        if parent_pid == 0 {
            return Err(ProcessError::NotDescendant);
        }
        current = parent_pid;
    }
    Err(ProcessError::DepthExceeded)
}

#[cfg(windows)]
mod native {
    use super::{ProcessError, ProcessIdentity, ProcessRecord};
    use std::mem::MaybeUninit;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        EqualSid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn current_user_sid() -> Result<Vec<u8>, ProcessError> {
        process_user_sid(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() })
    }

    pub fn process_user_sid(pid: u32) -> Result<Vec<u8>, ProcessError> {
        let handle = open_process(pid)?;
        let sid = token_user_sid(handle);
        close_handle(handle);
        sid
    }

    pub fn read_process_record(pid: u32) -> Result<ProcessRecord, ProcessError> {
        let handle = open_process(pid)?;
        let process_data = (|| {
            let creation_time = process_creation_time(handle)?;
            let user_sid = token_user_sid(handle)?;
            Ok::<_, ProcessError>((creation_time, user_sid))
        })();
        close_handle(handle);
        let (creation_time, user_sid) = process_data?;
        let parent_pid = parent_process_id(pid)?;
        Ok(ProcessRecord {
            identity: ProcessIdentity {
                pid,
                creation_time,
                user_sid,
            },
            parent_pid,
        })
    }

    fn open_process(pid: u32) -> Result<HANDLE, ProcessError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(ProcessError::Unavailable);
        }
        Ok(handle)
    }

    fn process_creation_time(handle: HANDLE) -> Result<u64, ProcessError> {
        let mut creation = MaybeUninit::uninit();
        let mut exit = MaybeUninit::uninit();
        let mut kernel = MaybeUninit::uninit();
        let mut user = MaybeUninit::uninit();
        let ok = unsafe {
            GetProcessTimes(
                handle,
                creation.as_mut_ptr(),
                exit.as_mut_ptr(),
                kernel.as_mut_ptr(),
                user.as_mut_ptr(),
            )
        };
        if ok == 0 {
            return Err(ProcessError::Unavailable);
        }
        let creation = unsafe { creation.assume_init() };
        Ok(filetime_to_u64(creation))
    }

    fn token_user_sid(process: HANDLE) -> Result<Vec<u8>, ProcessError> {
        let mut token = ptr::null_mut();
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if ok == 0 || token.is_null() {
            return Err(ProcessError::Unavailable);
        }
        let sid = query_token_sid(token);
        close_handle(token);
        sid
    }

    fn query_token_sid(token: HANDLE) -> Result<Vec<u8>, ProcessError> {
        let mut length = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        }
        if length == 0 {
            return Err(ProcessError::Unavailable);
        }
        let buffer_length = usize::try_from(length).map_err(|_| ProcessError::Malformed)?;
        if buffer_length < std::mem::size_of::<TOKEN_USER>() {
            return Err(ProcessError::Malformed);
        }
        let mut buffer = vec![0_u8; buffer_length];
        let buffer_start = buffer.as_ptr() as usize;
        let buffer_end = buffer_start
            .checked_add(buffer.len())
            .ok_or(ProcessError::Malformed)?;
        let mut returned = 0_u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut returned,
            )
        };
        if ok == 0
            || returned as usize > buffer.len()
            || (returned as usize) < std::mem::size_of::<TOKEN_USER>()
        {
            return Err(ProcessError::Unavailable);
        }
        let returned_end = buffer_start
            .checked_add(returned as usize)
            .ok_or(ProcessError::Malformed)?;
        let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
        let sid = unsafe { (*token_user).User.Sid };
        if sid.is_null() {
            return Err(ProcessError::Malformed);
        }
        let sid_start = sid as usize;
        if sid_start < buffer_start
            || sid_start
                .checked_add(8)
                .is_none_or(|header_end| header_end > returned_end)
        {
            return Err(ProcessError::Malformed);
        }
        let header = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
        let sid_length = sid_expected_length(header).ok_or(ProcessError::Malformed)?;
        if sid_start
            .checked_add(sid_length)
            .is_none_or(|sid_end| sid_end > returned_end)
            || unsafe { IsValidSid(sid) } == 0
        {
            return Err(ProcessError::Malformed);
        }
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        let sid_end = sid_start
            .checked_add(sid_length)
            .ok_or(ProcessError::Malformed)?;
        if sid_length == 0 || sid_start < buffer_start || sid_end > buffer_end {
            return Err(ProcessError::Malformed);
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_length) }.to_vec())
    }

    pub fn sid_equal(left: &[u8], right: &[u8]) -> bool {
        if !sid_is_valid(left) || !sid_is_valid(right) {
            return false;
        }
        let left_sid = left.as_ptr().cast_mut().cast();
        let right_sid = right.as_ptr().cast_mut().cast();
        if unsafe { IsValidSid(left_sid) } == 0 || unsafe { IsValidSid(right_sid) } == 0 {
            return false;
        }
        if unsafe { GetLengthSid(left_sid) } as usize != left.len()
            || unsafe { GetLengthSid(right_sid) } as usize != right.len()
        {
            return false;
        }
        unsafe { EqualSid(left_sid, right_sid) != 0 }
    }

    pub fn sid_is_valid(bytes: &[u8]) -> bool {
        if sid_byte_length(bytes) != Some(bytes.len()) || bytes.len() > u32::MAX as usize {
            return false;
        }
        let sid = bytes.as_ptr().cast_mut().cast();
        unsafe { IsValidSid(sid) != 0 && GetLengthSid(sid) as usize == bytes.len() }
    }

    fn sid_byte_length(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 8 || bytes[0] != 1 {
            return None;
        }
        sid_expected_length(&bytes[..8]).filter(|length| *length == bytes.len())
    }

    fn sid_expected_length(header: &[u8]) -> Option<usize> {
        if header.len() < 8 || header[0] != 1 {
            return None;
        }
        let sub_authority_count = usize::from(header[1]);
        if sub_authority_count > 15 {
            return None;
        }
        8usize.checked_add(sub_authority_count.checked_mul(4)?)
    }

    fn parent_process_id(pid: u32) -> Result<u32, ProcessError> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(ProcessError::Unavailable);
        }
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        let mut found = None;
        let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) };
        while ok != 0 {
            if entry.th32ProcessID == pid {
                found = Some(entry.th32ParentProcessID);
                break;
            }
            ok = unsafe { Process32NextW(snapshot, &mut entry) };
        }
        close_handle(snapshot);
        found.ok_or(ProcessError::Unavailable)
    }

    fn filetime_to_u64(filetime: windows_sys::Win32::Foundation::FILETIME) -> u64 {
        ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
    }

    fn close_handle(handle: HANDLE) {
        if !handle.is_null() {
            unsafe { CloseHandle(handle) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default, Clone)]
    struct FakeProc {
        records: HashMap<u32, ProcessRecord>,
    }

    impl ProcessReader for FakeProc {
        fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
            self.records
                .get(&pid)
                .cloned()
                .ok_or(ProcessError::Unavailable)
        }
    }

    fn valid_sid(authority: u8) -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 5, authority, 0, 0, 0]
    }

    fn record(pid: u32, parent_pid: u32, creation_time: u64, user_sid: Vec<u8>) -> ProcessRecord {
        ProcessRecord {
            identity: ProcessIdentity {
                pid,
                creation_time,
                user_sid,
            },
            parent_pid,
        }
    }

    #[test]
    fn requires_exact_pid_and_creation_time_and_sid() {
        let reader = FakeProc {
            records: HashMap::from([
                (10, record(10, 20, 11, valid_sid(18))),
                (20, record(20, 1, 22, valid_sid(18))),
            ]),
        };
        assert!(
            validate_ancestry(
                &reader,
                10,
                ProcessIdentity {
                    pid: 20,
                    creation_time: 22,
                    user_sid: valid_sid(18),
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
                    creation_time: 23,
                    user_sid: valid_sid(18),
                }
            ),
            Err(ProcessError::NotDescendant)
        );
    }

    #[test]
    fn rejects_loops_depth_and_missing_processes() {
        let loop_reader = FakeProc {
            records: HashMap::from([
                (10, record(10, 20, 11, valid_sid(18))),
                (20, record(20, 10, 22, valid_sid(18))),
            ]),
        };
        assert_eq!(
            validate_ancestry(
                &loop_reader,
                10,
                ProcessIdentity {
                    pid: 99,
                    creation_time: 1,
                    user_sid: valid_sid(18),
                }
            ),
            Err(ProcessError::Loop)
        );

        let depth_reader = FakeProc {
            records: (1..=MAX_ANCESTRY_DEPTH as u32)
                .map(|pid| (pid, record(pid, pid + 1, u64::from(pid), valid_sid(18))))
                .collect(),
        };
        assert_eq!(
            validate_ancestry(
                &depth_reader,
                1,
                ProcessIdentity {
                    pid: 99,
                    creation_time: 1,
                    user_sid: valid_sid(18),
                }
            ),
            Err(ProcessError::DepthExceeded)
        );

        let unrelated_reader = FakeProc {
            records: HashMap::from([
                (10, record(10, 20, 11, valid_sid(18))),
                (20, record(20, 0, 22, valid_sid(18))),
            ]),
        };
        assert_eq!(
            validate_ancestry(
                &unrelated_reader,
                10,
                ProcessIdentity {
                    pid: 30,
                    creation_time: 22,
                    user_sid: valid_sid(18),
                }
            ),
            Err(ProcessError::NotDescendant)
        );
    }

    struct ChangingProc(Mutex<u32>);

    impl ProcessReader for ChangingProc {
        fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
            let mut reads = self.0.lock().expect("read counter");
            *reads += 1;
            Ok(record(
                pid,
                if pid == 10 { 20 } else { 0 },
                if pid == 20 { u64::from(*reads) } else { 11 },
                valid_sid(18),
            ))
        }
    }

    #[test]
    fn unstable_two_pass_ancestry_is_rejected() {
        assert_eq!(
            validate_ancestry(
                &ChangingProc(Mutex::new(0)),
                10,
                ProcessIdentity {
                    pid: 20,
                    creation_time: 2,
                    user_sid: valid_sid(18),
                }
            ),
            Err(ProcessError::Changed)
        );
    }

    #[test]
    fn binary_sid_equality_rejects_malformed_and_mismatched_data() {
        let sid = valid_sid(18);
        assert!(native::sid_equal(&sid, &sid));
        assert!(!native::sid_equal(&sid, &valid_sid(19)));
        assert!(!native::sid_equal(&sid[..sid.len() - 1], &sid));
        assert!(!native::sid_equal(&[], &sid));
    }

    #[test]
    fn current_user_sid_matches_current_process_only_by_binary_equality() {
        let sid = native::current_user_sid().expect("current user SID");
        assert!(peer_user_matches_launcher(
            unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() },
            &sid
        ));
        assert!(!peer_user_matches_launcher(0, &sid));
    }
}
