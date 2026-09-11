//! Bounded user-scoped update state and startup-check coordination.
//!
//! This module deliberately has no network, installer, hook, or compatibility
//! authorization behavior. It stores only version/check metadata and uses an
//! OS advisory lock whose ownership is released by the kernel when the owning
//! process exits. Callers must hold a `CheckLease` across a read/modify/write
//! transaction; lock contention is an explicit recoverable result.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{manifest::StableVersion, manifest::reject_duplicate_json_keys};

pub const STATE_SCHEMA_VERSION: u32 = 1;
pub const MAX_STATE_BYTES: usize = 64 * 1024;
pub const MAX_VALIDATOR_BYTES: usize = 512;
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_millis(250);

const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateState {
    pub schema_version: u32,
    pub installed_autoapprover_version: Option<StableVersion>,
    pub last_codex_version: Option<StableVersion>,
    pub last_successful_check: Option<SuccessfulCheck>,
    pub metadata_validators: Option<MetadataValidators>,
    pub skip_scope: Option<SkipScope>,
    pub backoff: Option<BackoffState>,
    pub last_failure: Option<FailureCategory>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            installed_autoapprover_version: None,
            last_codex_version: None,
            last_successful_check: None,
            metadata_validators: None,
            skip_scope: None,
            backoff: None,
            last_failure: None,
        }
    }
}

impl UpdateState {
    pub fn validate(&self) -> Result<(), StateError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(StateError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: STATE_SCHEMA_VERSION,
            });
        }
        if let Some(check) = &self.last_successful_check {
            check.validate()?;
        }
        if let Some(validators) = &self.metadata_validators {
            validators.validate()?;
        }
        if let Some(backoff) = &self.backoff {
            backoff.validate()?;
        }
        Ok(())
    }

    pub fn record_successful_check<C: Clock>(
        &mut self,
        codex_version: StableVersion,
        metadata_version: Option<u64>,
        validators: MetadataValidators,
        clock: &C,
    ) -> Result<(), StateError> {
        validators.validate()?;
        self.last_codex_version = Some(codex_version.clone());
        self.last_successful_check = Some(SuccessfulCheck {
            observed_at_unix_seconds: clock.now_unix_seconds(),
            codex_version,
            metadata_version,
        });
        self.metadata_validators = Some(validators);
        self.last_failure = None;
        self.validate()
    }

    pub fn is_backoff_active(&self, now_unix_seconds: u64) -> bool {
        self.backoff
            .as_ref()
            .is_some_and(|backoff| backoff.until_unix_seconds > now_unix_seconds)
    }

    pub fn is_skipped_for(
        &self,
        codex_version: &StableVersion,
        release_version: &StableVersion,
    ) -> bool {
        self.skip_scope.as_ref().is_some_and(|skip| {
            &skip.codex_version == codex_version && &skip.release_version == release_version
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessfulCheck {
    pub observed_at_unix_seconds: u64,
    pub codex_version: StableVersion,
    pub metadata_version: Option<u64>,
}

impl SuccessfulCheck {
    fn validate(&self) -> Result<(), StateError> {
        if self.observed_at_unix_seconds == 0 {
            return Err(StateError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl MetadataValidators {
    pub fn validate(&self) -> Result<(), StateError> {
        validate_bounded_text(self.etag.as_deref())?;
        validate_bounded_text(self.last_modified.as_deref())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkipScope {
    pub codex_version: StableVersion,
    pub release_version: StableVersion,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackoffState {
    pub until_unix_seconds: u64,
    pub reason: BackoffReason,
}

impl BackoffState {
    fn validate(&self) -> Result<(), StateError> {
        if self.until_unix_seconds == 0 {
            return Err(StateError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackoffReason {
    ServerDirected,
    TransportFailure,
    MetadataFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    StorageUnavailable,
    StateCorrupt,
    UnsupportedStateVersion,
    LockContended,
    CheckUnavailable,
    MetadataInvalid,
    NoApplicableRelease,
    InstallationFailed,
    CompatibilityUnresolved,
}

pub trait Clock {
    fn now_unix_seconds(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadState {
    Missing,
    Present(Box<UpdateState>),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StateError {
    #[error("state file is too large")]
    TooLarge,
    #[error("state file is corrupt")]
    Corrupt,
    #[error("state schema version is unsupported")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("state value is invalid")]
    Invalid,
    #[error("state path is unsafe")]
    UnsafePath,
    #[error("state storage is unavailable during {operation:?}")]
    StorageUnavailable {
        operation: StateOperation,
        kind: io::ErrorKind,
    },
    #[error("startup check coordination lock was contended until the bounded deadline")]
    LockContended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateOperation {
    Inspect,
    Read,
    CreateDirectory,
    WriteTemporary,
    Sync,
    Replace,
    OpenLock,
    AcquireLock,
}

pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|value| value.to_os_string())
            .unwrap_or_else(|| "state".into());
        name.push(".lock");
        self.path.with_file_name(name)
    }

    pub fn load(&self) -> Result<LoadState, StateError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(LoadState::Missing),
            Err(error) => return Err(storage_error(StateOperation::Inspect, error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StateError::UnsafePath);
        }
        if metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(StateError::TooLarge);
        }

        let file =
            File::open(&self.path).map_err(|error| storage_error(StateOperation::Read, error))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_STATE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| storage_error(StateOperation::Read, error))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateError::TooLarge);
        }
        reject_duplicate_json_keys(&bytes).map_err(|_| StateError::Corrupt)?;
        let state =
            serde_json::from_slice::<UpdateState>(&bytes).map_err(|_| StateError::Corrupt)?;
        state.validate()?;
        Ok(LoadState::Present(Box::new(state)))
    }

    pub fn save(&self, state: &UpdateState) -> Result<(), StateError> {
        self.save_inner(state, None)
    }

    pub fn save_with_lease(
        &self,
        state: &UpdateState,
        lease: &CheckLease,
    ) -> Result<(), StateError> {
        if lease.lock_path != self.lock_path() {
            return Err(StateError::Invalid);
        }
        self.save_inner(state, Some(lease))
    }

    fn save_inner(
        &self,
        state: &UpdateState,
        _lease: Option<&CheckLease>,
    ) -> Result<(), StateError> {
        state.validate()?;
        let bytes = serde_json::to_vec(state).map_err(|_| StateError::Invalid)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateError::TooLarge);
        }

        let parent = self.ensure_parent()?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(StateError::UnsafePath);
        }

        let temp_path = temporary_path(&self.path);
        let write_result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|error| storage_error(StateOperation::WriteTemporary, error))?;
            restrict_file_permissions(&file)?;
            file.write_all(&bytes)
                .map_err(|error| storage_error(StateOperation::WriteTemporary, error))?;
            file.sync_all()
                .map_err(|error| storage_error(StateOperation::Sync, error))?;
            drop(file);
            atomic_replace(&temp_path, &self.path)
                .map_err(|error| storage_error(StateOperation::Replace, error))?;
            sync_parent(&parent).map_err(|error| storage_error(StateOperation::Sync, error))
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }

    fn ensure_parent(&self) -> Result<PathBuf, StateError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| storage_error(StateOperation::CreateDirectory, error))?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|error| storage_error(StateOperation::Inspect, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StateError::UnsafePath);
        }
        Ok(parent.to_path_buf())
    }
}

pub struct CheckCoordinator {
    lock_path: PathBuf,
}

impl CheckCoordinator {
    pub fn new(lock_path: impl Into<PathBuf>) -> Self {
        Self {
            lock_path: lock_path.into(),
        }
    }

    pub fn for_state(store: &StateStore) -> Self {
        Self::new(store.lock_path())
    }

    pub fn acquire(&self, timeout: Duration) -> Result<CheckLease, StateError> {
        let parent = self.lock_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| storage_error(StateOperation::CreateDirectory, error))?;
        if let Ok(metadata) = fs::symlink_metadata(&self.lock_path)
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(StateError::UnsafePath);
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|error| storage_error(StateOperation::OpenLock, error))?;
        restrict_file_permissions(&file)?;

        let deadline = Instant::now() + timeout;
        loop {
            match try_lock(&file) {
                Ok(()) => {
                    return Ok(CheckLease {
                        file,
                        lock_path: self.lock_path.clone(),
                    });
                }
                Err(error) if is_lock_contention(&error) => {
                    if Instant::now() >= deadline {
                        return Err(StateError::LockContended);
                    }
                    thread::sleep(
                        LOCK_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(error) => return Err(storage_error(StateOperation::AcquireLock, error)),
            }
        }
    }
}

#[derive(Debug)]
pub struct CheckLease {
    file: File,
    lock_path: PathBuf,
}

impl CheckLease {
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn release(self) {
        drop(self);
    }
}

fn validate_bounded_text(value: Option<&str>) -> Result<(), StateError> {
    if value.is_some_and(|value| {
        value.is_empty() || value.len() > MAX_VALIDATOR_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(StateError::Invalid);
    }
    Ok(())
}

fn storage_error(operation: StateOperation, error: io::Error) -> StateError {
    StateError::StorageUnavailable {
        operation,
        kind: error.kind(),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(".{name}.tmp.{}.{}", std::process::id(), counter))
}

#[cfg(unix)]
fn restrict_file_permissions(file: &File) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = file
        .metadata()
        .map_err(|error| storage_error(StateOperation::WriteTemporary, error))?
        .permissions();
    permissions.set_mode(0o600);
    file.set_permissions(permissions)
        .map_err(|error| storage_error(StateOperation::WriteTemporary, error))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_file: &File) -> Result<(), StateError> {
    Ok(())
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(io::Error::from)
}

#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{BOOL, HANDLE},
        Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx},
        System::IO::OVERLAPPED,
    };

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result: BOOL = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn is_lock_contention(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(unix)]
fn atomic_replace(temp: &Path, target: &Path) -> io::Result<()> {
    fs::rename(temp, target)
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, target: &Path) -> io::Result<()> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = temp.as_os_str().encode_wide().chain(once(0)).collect();
    let destination: Vec<u16> = target.as_os_str().encode_wide().chain(once(0)).collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, Stdio},
        sync::{Arc, Barrier},
    };

    use tempfile::TempDir;

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> u64 {
            self.0
        }
    }

    fn versions() -> (StableVersion, StableVersion) {
        (
            StableVersion::parse("0.154.0").expect("Codex version"),
            StableVersion::parse("0.2.0").expect("release version"),
        )
    }

    fn state_with_check() -> UpdateState {
        let (codex_version, release_version) = versions();
        let mut state = UpdateState {
            installed_autoapprover_version: Some(release_version),
            ..UpdateState::default()
        };
        state
            .record_successful_check(
                codex_version,
                Some(17),
                MetadataValidators {
                    etag: Some("etag-17".into()),
                    last_modified: Some("Wed, 01 Jan 2025 00:00:00 GMT".into()),
                },
                &FixedClock(1_735_689_600),
            )
            .expect("valid check");
        state.skip_scope = Some(SkipScope {
            codex_version: StableVersion::parse("0.154.0").expect("Codex version"),
            release_version: StableVersion::parse("0.3.0").expect("release version"),
        });
        state.backoff = Some(BackoffState {
            until_unix_seconds: 1_735_689_900,
            reason: BackoffReason::ServerDirected,
        });
        state.last_failure = Some(FailureCategory::CompatibilityUnresolved);
        state
    }

    #[test]
    fn state_round_trips_and_preserves_minimal_preferences() {
        let directory = TempDir::new().expect("state directory");
        let store = StateStore::new(directory.path().join("state.json"));
        let expected = state_with_check();
        store.save(&expected).expect("save state");
        assert_eq!(
            store.load().expect("load state"),
            LoadState::Present(Box::new(expected))
        );
        assert!(store.path().is_file());
    }

    #[test]
    fn validation_rejects_unsupported_version_invalid_timestamp_and_unbounded_validator() {
        let state = UpdateState {
            schema_version: STATE_SCHEMA_VERSION + 1,
            ..UpdateState::default()
        };
        assert!(matches!(
            state.validate(),
            Err(StateError::UnsupportedSchemaVersion { .. })
        ));

        let state = UpdateState {
            last_successful_check: Some(SuccessfulCheck {
                observed_at_unix_seconds: 0,
                codex_version: StableVersion::parse("0.154.0").expect("Codex version"),
                metadata_version: None,
            }),
            ..UpdateState::default()
        };
        assert_eq!(state.validate(), Err(StateError::Invalid));

        let state = UpdateState {
            metadata_validators: Some(MetadataValidators {
                etag: Some("x".repeat(MAX_VALIDATOR_BYTES + 1)),
                last_modified: None,
            }),
            ..UpdateState::default()
        };
        assert_eq!(state.validate(), Err(StateError::Invalid));
    }

    #[test]
    fn corrupt_duplicate_unknown_and_oversized_state_is_rejected_without_reset() {
        let directory = TempDir::new().expect("state directory");
        let path = directory.path().join("state.json");
        let store = StateStore::new(&path);
        let expected = state_with_check();
        store.save(&expected).expect("save state");
        fs::write(&path, br#"{"schema_version":1,"schema_version":1}"#).expect("corrupt state");
        assert_eq!(store.load(), Err(StateError::Corrupt));

        fs::write(&path, br#"{"schema_version":1,"unknown":true}"#).expect("unknown state");
        assert_eq!(store.load(), Err(StateError::Corrupt));

        fs::write(&path, vec![b'x'; MAX_STATE_BYTES + 1]).expect("oversized state");
        assert_eq!(store.load(), Err(StateError::TooLarge));
        assert!(
            !serde_json::to_vec(&expected)
                .expect("state JSON")
                .is_empty()
        );
    }

    #[test]
    fn interrupted_temporary_write_leaves_previous_valid_state() {
        let directory = TempDir::new().expect("state directory");
        let store = StateStore::new(directory.path().join("state.json"));
        let expected = state_with_check();
        store.save(&expected).expect("save state");
        let interrupted = store.path().with_file_name(".state.json.tmp.interrupted");
        fs::write(&interrupted, b"{\"schema_version\":").expect("partial temporary state");
        assert_eq!(
            store.load().expect("load previous state"),
            LoadState::Present(Box::new(expected))
        );
        assert!(interrupted.is_file());
    }

    #[test]
    fn unavailable_storage_is_explicit_and_does_not_fallback() {
        let directory = TempDir::new().expect("state directory");
        let parent_file = directory.path().join("not-a-directory");
        fs::write(&parent_file, b"owned file").expect("parent fixture");
        let store = StateStore::new(parent_file.join("state.json"));
        assert!(matches!(
            store.save(&UpdateState::default()),
            Err(StateError::StorageUnavailable { .. })
        ));
    }

    #[test]
    fn directory_state_and_lock_paths_are_rejected() {
        let directory = TempDir::new().expect("state directory");
        let state_path = directory.path().join("state.json");
        fs::create_dir(&state_path).expect("directory state fixture");
        let store = StateStore::new(&state_path);
        assert_eq!(store.load(), Err(StateError::UnsafePath));

        let lock_path = directory.path().join("check.lock");
        fs::create_dir(&lock_path).expect("directory lock fixture");
        assert!(matches!(
            CheckCoordinator::new(lock_path).acquire(Duration::from_millis(10)),
            Err(StateError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_state_path_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("state directory");
        let real_path = directory.path().join("real.json");
        let link_path = directory.path().join("state.json");
        fs::write(
            &real_path,
            serde_json::to_vec(&state_with_check()).expect("state JSON"),
        )
        .expect("real state");
        symlink(&real_path, &link_path).expect("state symlink");
        assert_eq!(
            StateStore::new(link_path).load(),
            Err(StateError::UnsafePath)
        );
    }

    #[test]
    fn concurrent_read_modify_write_transactions_remain_valid() {
        let directory = TempDir::new().expect("state directory");
        let store = Arc::new(StateStore::new(directory.path().join("state.json")));
        store.save(&UpdateState::default()).expect("initial state");
        let barrier = Arc::new(Barrier::new(4));
        let mut writers = Vec::new();
        for version in ["0.151.0", "0.153.2", "0.154.0"] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let version = version.to_owned();
            writers.push(std::thread::spawn(move || {
                barrier.wait();
                let coordinator = CheckCoordinator::for_state(&store);
                let lease = coordinator.acquire(Duration::from_secs(2)).expect("lock");
                let mut state = match store.load().expect("load") {
                    LoadState::Missing => UpdateState::default(),
                    LoadState::Present(state) => *state,
                };
                state.last_codex_version = Some(StableVersion::parse(&version).expect("version"));
                store
                    .save_with_lease(&state, &lease)
                    .expect("save with lease");
                lease.release();
            }));
        }
        let store_for_reader = Arc::clone(&store);
        let barrier_for_reader = Arc::clone(&barrier);
        writers.push(std::thread::spawn(move || {
            barrier_for_reader.wait();
            let coordinator = CheckCoordinator::for_state(&store_for_reader);
            let lease = coordinator
                .acquire(Duration::from_secs(2))
                .expect("reader lock");
            let state = store_for_reader.load().expect("load");
            assert!(matches!(state, LoadState::Present(_)));
            lease.release();
        }));
        for writer in writers {
            writer.join().expect("writer thread");
        }
        assert!(matches!(
            store.load().expect("final state"),
            LoadState::Present(_)
        ));
    }

    #[test]
    fn bounded_contention_returns_recoverable_category() {
        let directory = TempDir::new().expect("state directory");
        let store = StateStore::new(directory.path().join("state.json"));
        let first = CheckCoordinator::for_state(&store)
            .acquire(Duration::from_millis(100))
            .expect("first lock");
        let started = Instant::now();
        let error = CheckCoordinator::for_state(&store)
            .acquire(Duration::from_millis(50))
            .expect_err("second lock must be bounded");
        assert_eq!(error, StateError::LockContended);
        assert!(started.elapsed() < Duration::from_secs(1));
        first.release();
    }

    #[test]
    fn lock_release_after_process_termination_is_not_a_stale_file_decision() {
        let directory = TempDir::new().expect("state directory");
        let lock_path = directory.path().join("check.lock");
        let ready_path = directory.path().join("ready");
        fs::write(&lock_path, b"").expect("create lock fixture");
        let mut child = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "update::state::tests::lock_holder_process",
                "--nocapture",
            ])
            .env("CODEX_AUTOAPPROVER_LOCK_CHILD", "1")
            .env(
                "CODEX_AUTOAPPROVER_LOCK_PATH",
                lock_path.to_string_lossy().as_ref(),
            )
            .env(
                "CODEX_AUTOAPPROVER_READY_PATH",
                ready_path.to_string_lossy().as_ref(),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn lock holder");
        let started = Instant::now();
        while !ready_path.is_file() && started.elapsed() < Duration::from_secs(2) {
            if child.try_wait().expect("poll lock holder").is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready_path.is_file(), "lock holder did not become ready");
        child.kill().expect("terminate lock holder");
        child.wait().expect("wait lock holder");
        CheckCoordinator::new(lock_path)
            .acquire(Duration::from_secs(1))
            .expect("terminated process releases kernel lock")
            .release();
    }

    #[test]
    fn lock_holder_process() {
        if env::var_os("CODEX_AUTOAPPROVER_LOCK_CHILD").is_none() {
            return;
        }
        let path = PathBuf::from(env::var_os("CODEX_AUTOAPPROVER_LOCK_PATH").expect("lock path"));
        let coordinator = CheckCoordinator::new(path);
        let _lease = coordinator
            .acquire(Duration::from_secs(1))
            .expect("child lock");
        let ready_path =
            PathBuf::from(env::var_os("CODEX_AUTOAPPROVER_READY_PATH").expect("ready path"));
        fs::write(ready_path, b"ready").expect("write readiness");
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn state_shape_cannot_contain_sensitive_runtime_data() {
        let state = state_with_check();
        let encoded = String::from_utf8(serde_json::to_vec(&state).expect("state JSON"))
            .expect("UTF-8 state JSON");
        for forbidden in [
            "command",
            "hook_input",
            "session_secret",
            "password",
            "token",
            "environment",
        ] {
            assert!(!encoded.contains(forbidden), "state contains {forbidden}");
        }
        assert_eq!(
            state.last_failure,
            Some(FailureCategory::CompatibilityUnresolved)
        );
    }
}
