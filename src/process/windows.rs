//! Windows process identity and ancestry validation via Toolhelp and process tokens.

use thiserror::Error;

pub const MAX_ANCESTRY_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time: u64,
    pub user_sid: String,
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
    if first.iter().any(|record| record.identity == expected) {
        Ok(())
    } else {
        Err(ProcessError::NotDescendant)
    }
}

pub fn launcher_user_sid() -> Result<String, ProcessError> {
    native::current_user_sid()
}

pub fn peer_user_matches_launcher(peer_pid: u32, launcher_sid: &str) -> bool {
    native::process_user_sid(peer_pid)
        .ok()
        .is_some_and(|sid| sid == launcher_sid)
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
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn current_user_sid() -> Result<String, ProcessError> {
        process_user_sid(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() })
    }

    pub fn process_user_sid(pid: u32) -> Result<String, ProcessError> {
        let handle = open_process(pid)?;
        let sid = token_user_sid(handle)?;
        close_handle(handle);
        Ok(sid)
    }

    pub fn read_process_record(pid: u32) -> Result<ProcessRecord, ProcessError> {
        let handle = open_process(pid)?;
        let creation_time = process_creation_time(handle)?;
        let user_sid = token_user_sid(handle)?;
        close_handle(handle);
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

    fn token_user_sid(process: HANDLE) -> Result<String, ProcessError> {
        let mut token = ptr::null_mut();
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if ok == 0 || token.is_null() {
            return Err(ProcessError::Unavailable);
        }
        let sid = query_token_sid(token);
        close_handle(token);
        sid
    }

    fn query_token_sid(token: HANDLE) -> Result<String, ProcessError> {
        let mut length = 0_u32;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
        }
        if length == 0 {
            return Err(ProcessError::Unavailable);
        }
        let mut buffer = vec![0_u8; length as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            )
        };
        if ok == 0 {
            return Err(ProcessError::Unavailable);
        }
        let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
        let sid = unsafe { (*token_user).User.Sid };
        sid_to_string(sid)
    }

    fn sid_to_string(sid: *mut std::ffi::c_void) -> Result<String, ProcessError> {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut string = ptr::null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut string) };
        if ok == 0 || string.is_null() {
            return Err(ProcessError::Malformed);
        }
        let mut chars = Vec::new();
        let mut index = 0;
        loop {
            let value = unsafe { *string.add(index) };
            if value == 0 {
                break;
            }
            chars.push(value);
            index += 1;
        }
        unsafe { LocalFree(string.cast()) };
        String::from_utf16(&chars).map_err(|_| ProcessError::Malformed)
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
    use std::collections::HashMap;

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

    fn record(pid: u32, parent_pid: u32, creation_time: u64, user_sid: &str) -> ProcessRecord {
        ProcessRecord {
            identity: ProcessIdentity {
                pid,
                creation_time,
                user_sid: user_sid.into(),
            },
            parent_pid,
        }
    }

    #[test]
    fn requires_exact_pid_and_creation_time_and_sid() {
        let reader = FakeProc {
            records: HashMap::from([
                (10, record(10, 20, 11, "S-1-1-0")),
                (20, record(20, 1, 22, "S-1-1-0")),
            ]),
        };
        assert!(
            validate_ancestry(
                &reader,
                10,
                ProcessIdentity {
                    pid: 20,
                    creation_time: 22,
                    user_sid: "S-1-1-0".into(),
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
                    user_sid: "S-1-1-0".into(),
                }
            ),
            Err(ProcessError::NotDescendant)
        );
    }

    #[test]
    fn rejects_loops_depth_and_missing_processes() {
        let loop_reader = FakeProc {
            records: HashMap::from([
                (10, record(10, 20, 11, "S-1-1-0")),
                (20, record(20, 10, 22, "S-1-1-0")),
            ]),
        };
        assert_eq!(
            validate_ancestry(
                &loop_reader,
                10,
                ProcessIdentity {
                    pid: 99,
                    creation_time: 1,
                    user_sid: "S-1-1-0".into(),
                }
            ),
            Err(ProcessError::Loop)
        );
    }
}
