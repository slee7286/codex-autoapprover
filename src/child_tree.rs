use std::process::{Child, Command};

use anyhow::{Context, Result};

/// Owns the boundary around a short-lived probe or verification child.
/// Dropping a Windows job also kills any descendants still in that job.
pub struct ChildTree {
    #[cfg(unix)]
    group: u32,
    #[cfg(windows)]
    job: std::os::windows::io::OwnedHandle,
}

impl ChildTree {
    pub fn spawn(command: &mut Command) -> Result<(Child, Self)> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            command.process_group(0);
            let child = command
                .spawn()
                .context("spawn isolated child process group")?;
            let tree = Self { group: child.id() };
            Ok((child, tree))
        }
        #[cfg(windows)]
        {
            windows::spawn(command)
        }
    }

    pub fn stop(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use rustix::process::{Pid, Signal, kill_process_group};

            if let Some(group) = Pid::from_raw(self.group as i32) {
                match kill_process_group(group, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
                    Err(error) => Err(error).context("stop isolated child process group"),
                }
            } else {
                anyhow::bail!("invalid isolated child process group")
            }
        }
        #[cfg(windows)]
        {
            windows::stop(&self.job)
        }
    }

    pub fn stop_and_reap(&self, child: &mut Child) -> Result<()> {
        let stop = self.stop();
        let reap = (|| {
            if child
                .try_wait()
                .context("check isolated child status")?
                .is_none()
                && let Err(error) = child.kill()
                && child
                    .try_wait()
                    .context("recheck isolated child status")?
                    .is_none()
            {
                return Err(error).context("kill isolated child");
            }
            child.wait().context("reap isolated child")?;
            Ok(())
        })();
        match (stop, reap) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(reap)) => {
                Err(error.context(format!("isolated child reaping also failed: {reap:#}")))
            }
        }
    }

    /// Releases the job handle before caller-owned temporary state is removed.
    pub fn close(self) {}
}

#[cfg(windows)]
mod windows {
    use std::{
        io,
        mem::{offset_of, size_of, zeroed},
        os::windows::{
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
            process::CommandExt,
        },
        process::{Child, Command},
        ptr,
    };

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject,
            },
            Threading::{
                CREATE_SUSPENDED, GetProcessIdOfThread, OpenThread, ResumeThread,
                THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
            },
        },
    };

    use super::ChildTree;

    pub(super) fn spawn(command: &mut Command) -> Result<(Child, ChildTree)> {
        let job = create_job()?;
        // The initial thread cannot run before it joins the job. This closes
        // the spawn/assignment gap in which descendants could otherwise escape.
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn().context("spawn suspended isolated child")?;
        let prepared = (|| {
            let process = child.as_raw_handle() as HANDLE;
            check(
                unsafe { AssignProcessToJobObject(job.as_raw_handle() as HANDLE, process) },
                "assign suspended child to job",
            )?;
            let thread = initial_thread(child.id())?;
            let previous = unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) };
            if previous != 1 {
                bail!("resume isolated child: expected suspend count 1, got {previous}")
            }
            Ok(())
        })();
        if let Err(error) = prepared {
            // This also covers assignment failure, before the job owns the child.
            let cleanup: Result<()> = (|| {
                child.kill().context("kill unprepared suspended child")?;
                child.wait().context("reap unprepared suspended child")?;
                Ok(())
            })();
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => {
                    error.context(format!("suspended child cleanup also failed: {cleanup:#}"))
                }
            });
        }
        Ok((child, ChildTree { job }))
    }

    fn create_job() -> Result<OwnedHandle> {
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error()).context("create isolated child job");
        }
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        check(
            unsafe {
                SetInformationJobObject(
                    job.as_raw_handle() as HANDLE,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            },
            "set kill-on-close child job limit",
        )?;
        Ok(job)
    }

    fn initial_thread(process_id: u32) -> Result<OwnedHandle> {
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error()).context("snapshot isolated child threads");
        }
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry: THREADENTRY32 = unsafe { zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut found = None;
        let mut present = unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        loop {
            if present == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(error).context("enumerate isolated child threads");
                }
                break;
            }
            if entry.dwSize
                < (offset_of!(THREADENTRY32, th32OwnerProcessID) + size_of::<u32>()) as u32
            {
                bail!("isolated child thread snapshot entry is incomplete")
            }
            if entry.th32OwnerProcessID == process_id && found.replace(entry.th32ThreadID).is_some()
            {
                bail!("isolated child has more than one initial thread")
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            present = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        }
        let thread_id = found.context("find suspended child initial thread")?;
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                thread_id,
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error()).context("open suspended child thread");
        }
        let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
        let owner = unsafe { GetProcessIdOfThread(thread.as_raw_handle() as HANDLE) };
        if owner == 0 {
            return Err(io::Error::last_os_error()).context("verify suspended child thread owner");
        }
        if owner != process_id {
            bail!("suspended child thread owner changed")
        }
        Ok(thread)
    }

    pub(super) fn stop(job: &OwnedHandle) -> Result<()> {
        check(
            unsafe { TerminateJobObject(job.as_raw_handle() as HANDLE, 1) },
            "stop isolated child job",
        )
    }

    fn check(value: i32, action: &'static str) -> Result<()> {
        if value == 0 {
            return Err(io::Error::last_os_error()).context(action);
        }
        Ok(())
    }
}
