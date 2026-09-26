//! Bounded user-scoped update state and startup-check coordination.
//!
//! This module deliberately has no network, installer, hook, or compatibility
//! authorization behavior. It stores only version/check metadata and uses an
//! OS advisory lock whose ownership is released by the kernel when the owning
//! process exits. Callers must hold a `CheckLease` across a read/modify/write
//! transaction; lock contention is an explicit recoverable result.

use std::{
    env, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::{
    fs::{self, File},
    io::{Read, Write},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::compatibility::{OperatingSystem, Surface};

#[cfg(unix)]
use super::manifest::reject_duplicate_json_keys;
use super::{
    manifest::StableVersion,
    outcome::{CommandOutcome, HookOutcome, HookOutcomeCounts, MAX_OUTCOME_COUNT, SessionOutcome},
};

pub const STATE_SCHEMA_VERSION: u32 = 1;
pub const MAX_STATE_BYTES: usize = 64 * 1024;
pub const MAX_VALIDATOR_BYTES: usize = 512;
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_millis(250);
pub const MAX_COMPATIBILITY_OBSERVATIONS: usize = 8;

#[cfg(unix)]
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(unix)]
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
    #[serde(default)]
    pub compatibility_observations: Vec<CompatibilityObservation>,
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
            compatibility_observations: Vec::new(),
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
        if self.compatibility_observations.len() > MAX_COMPATIBILITY_OBSERVATIONS {
            return Err(StateError::Invalid);
        }
        for observation in &self.compatibility_observations {
            observation.validate()?;
        }
        Ok(())
    }

    pub fn record_compatibility_observation<C: Clock>(
        &mut self,
        observation: CompatibilityObservation,
        clock: &C,
    ) -> Result<(), StateError> {
        let mut observation = observation;
        if observation.observed_at_unix_seconds == 0 {
            observation.observed_at_unix_seconds = clock.now_unix_seconds();
        }
        observation.validate()?;
        if let Some(existing) = self
            .compatibility_observations
            .iter_mut()
            .find(|existing| existing.same_identity(&observation))
        {
            // These are bounded historical indicators, not lifetime totals. Once a
            // category reaches the audit cap it remains at the cap; failures stay
            // visible to the conservative aggregate.
            for (left, right) in [
                (
                    &mut existing.counts.entry_count,
                    observation.counts.entry_count,
                ),
                (
                    &mut existing.counts.validated_request_count,
                    observation.counts.validated_request_count,
                ),
                (
                    &mut existing.counts.allow_count,
                    observation.counts.allow_count,
                ),
                (
                    &mut existing.counts.no_decision_count,
                    observation.counts.no_decision_count,
                ),
                (
                    &mut existing.counts.structured_emission_count,
                    observation.counts.structured_emission_count,
                ),
                (
                    &mut existing.counts.stdout_error_count,
                    observation.counts.stdout_error_count,
                ),
                (
                    &mut existing.counts.successful_exchange_count,
                    observation.counts.successful_exchange_count,
                ),
                (
                    &mut existing.counts.broker_allow_unconfirmed_count,
                    observation.counts.broker_allow_unconfirmed_count,
                ),
                (
                    &mut existing.counts.compatibility_rejection_count,
                    observation.counts.compatibility_rejection_count,
                ),
                (
                    &mut existing.counts.transport_failure_count,
                    observation.counts.transport_failure_count,
                ),
                (
                    &mut existing.counts.protocol_failure_count,
                    observation.counts.protocol_failure_count,
                ),
            ] {
                *left = left.saturating_add(right).min(MAX_OUTCOME_COUNT);
            }
            existing.hook_outcome = existing.counts.aggregate_hook_outcome();
            existing.command_outcome =
                merge_command_outcomes(existing.command_outcome, observation.command_outcome);
            existing.observed_at_unix_seconds = clock.now_unix_seconds();
        } else {
            observation.observed_at_unix_seconds = clock.now_unix_seconds();
            if self.compatibility_observations.len() >= MAX_COMPATIBILITY_OBSERVATIONS {
                let Some((oldest_index, _)) =
                    self.compatibility_observations.iter().enumerate().min_by(
                        |(_, left), (_, right)| {
                            observation_order(left).cmp(&observation_order(right))
                        },
                    )
                else {
                    return Err(StateError::Invalid);
                };
                if observation_order(&observation)
                    <= observation_order(&self.compatibility_observations[oldest_index])
                {
                    return self.validate();
                }
                self.compatibility_observations.remove(oldest_index);
            }
            self.compatibility_observations.push(observation);
            self.compatibility_observations
                .sort_by(|left, right| observation_order(left).cmp(&observation_order(right)));
        }
        self.validate()
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
pub struct CompatibilityObservation {
    pub observed_at_unix_seconds: u64,
    pub autoapprover_version: StableVersion,
    pub codex_version: StableVersion,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_outcome: HookOutcome,
    pub command_outcome: CommandOutcome,
    pub counts: HookOutcomeCounts,
}

impl CompatibilityObservation {
    pub fn from_session(
        autoapprover_version: StableVersion,
        codex_version: StableVersion,
        operating_system: OperatingSystem,
        surface: Surface,
        session: SessionOutcome,
    ) -> Self {
        Self {
            observed_at_unix_seconds: 0,
            autoapprover_version,
            codex_version,
            operating_system,
            surface,
            hook_outcome: session.hook_outcome,
            command_outcome: session.command_outcome,
            counts: session.counts,
        }
    }

    fn validate(&self) -> Result<(), StateError> {
        if self.observed_at_unix_seconds == 0 {
            return Err(StateError::Invalid);
        }
        self.counts.validate().map_err(|_| StateError::Invalid)?;
        if self.hook_outcome != self.counts.aggregate_hook_outcome() {
            return Err(StateError::Invalid);
        }
        Ok(())
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.autoapprover_version == other.autoapprover_version
            && self.codex_version == other.codex_version
            && self.operating_system == other.operating_system
            && self.surface == other.surface
    }
}

fn merge_command_outcomes(left: CommandOutcome, right: CommandOutcome) -> CommandOutcome {
    match (left, right) {
        (CommandOutcome::Failed, _) | (_, CommandOutcome::Failed) => CommandOutcome::Failed,
        (CommandOutcome::Unknown, _) | (_, CommandOutcome::Unknown) => CommandOutcome::Unknown,
        _ => CommandOutcome::Succeeded,
    }
}

fn observation_order(
    observation: &CompatibilityObservation,
) -> (&StableVersion, &StableVersion, OperatingSystem, Surface) {
    (
        &observation.codex_version,
        &observation.autoapprover_version,
        observation.operating_system,
        observation.surface,
    )
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
    #[error("state persistence is disabled on this platform because path races cannot be excluded")]
    UnsafePersistence,
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

    #[cfg(unix)]
    pub fn load(&self) -> Result<LoadState, StateError> {
        let parent = match open_parent(&self.path, false) {
            Ok(parent) => parent,
            Err(StateError::StorageUnavailable {
                kind: io::ErrorKind::NotFound,
                ..
            }) => return Ok(LoadState::Missing),
            Err(error) => return Err(error),
        };
        self.load_at(&parent)
    }

    #[cfg(not(unix))]
    pub fn load(&self) -> Result<LoadState, StateError> {
        Err(StateError::UnsafePersistence)
    }

    #[cfg(unix)]
    fn load_at(&self, parent: &File) -> Result<LoadState, StateError> {
        use rustix::fs::{Mode, OFlags, openat};
        let name = state_name(&self.path)?;
        let file = match openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(LoadState::Missing),
            Err(rustix::io::Errno::LOOP) => return Err(StateError::UnsafePath),
            Err(error) => return Err(storage_error(StateOperation::Read, error.into())),
        };
        let metadata = safe_regular_file(&file)?;
        if metadata.len() > MAX_STATE_BYTES as u64 {
            return Err(StateError::TooLarge);
        }
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

    pub fn record_compatibility_observation<C: Clock>(
        &self,
        observation: CompatibilityObservation,
        clock: &C,
    ) -> Result<(), StateError> {
        let lease = CheckCoordinator::for_state(self).acquire(DEFAULT_LOCK_TIMEOUT)?;
        #[cfg(unix)]
        let mut state = match self.load_at(&lease.parent)? {
            LoadState::Missing => UpdateState::default(),
            LoadState::Present(state) => *state,
        };
        #[cfg(not(unix))]
        let mut state = match self.load()? {
            LoadState::Missing => UpdateState::default(),
            LoadState::Present(state) => *state,
        };
        state.record_compatibility_observation(observation, clock)?;
        self.save_with_lease(&state, &lease)
    }

    pub fn save_with_lease(
        &self,
        state: &UpdateState,
        lease: &CheckLease,
    ) -> Result<(), StateError> {
        if lease.lock_path != self.lock_path() {
            return Err(StateError::Invalid);
        }
        #[cfg(unix)]
        {
            verify_lock_entry(&lease.parent, &lease.lock_path, &lease.file)?;
            self.save_at(state, lease)
        }
        #[cfg(not(unix))]
        {
            let _ = state;
            Err(StateError::UnsafePersistence)
        }
    }

    #[cfg(unix)]
    fn save_at(&self, state: &UpdateState, lease: &CheckLease) -> Result<(), StateError> {
        use rustix::fs::{AtFlags, Mode, OFlags, openat, renameat, unlinkat};
        state.validate()?;
        let bytes = serde_json::to_vec(state).map_err(|_| StateError::Invalid)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateError::TooLarge);
        }
        let parent = &lease.parent;
        let name = state_name(&self.path)?;
        check_existing_entry(parent, name)?;
        let temporary = temporary_path(&self.path);
        let temp_name = state_name(&temporary)?;
        let write_result = (|| {
            let mut file = File::from(
                openat(
                    parent,
                    temp_name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|error| storage_error(StateOperation::WriteTemporary, error.into()))?,
            );
            file.write_all(&bytes)
                .map_err(|error| storage_error(StateOperation::WriteTemporary, error))?;
            file.sync_all()
                .map_err(|error| storage_error(StateOperation::Sync, error))?;
            // Detect replacement of the lock inode and unsafe target just before commit.
            verify_lock_entry(parent, &lease.lock_path, &lease.file)?;
            check_existing_entry(parent, name)?;
            renameat(parent, temp_name, parent, name)
                .map_err(|error| storage_error(StateOperation::Replace, error.into()))?;
            parent
                .sync_all()
                .map_err(|error| storage_error(StateOperation::Sync, error))
        })();
        if write_result.is_err() {
            let _ = unlinkat(parent, temp_name, AtFlags::empty());
        }
        write_result
    }
}

pub fn user_state_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        return env::var_os("LOCALAPPDATA").map(PathBuf::from).map(|root| {
            root.join("codex-autoapprover")
                .join("state")
                .join("update-state.json")
        });
    }
    #[cfg(unix)]
    {
        return env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
            .map(|root| root.join("codex-autoapprover").join("update-state.json"));
    }
    #[allow(unreachable_code)]
    None
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

    #[cfg(unix)]
    pub fn acquire(&self, timeout: Duration) -> Result<CheckLease, StateError> {
        use rustix::fs::{Mode, OFlags, openat};
        let parent = open_parent(&self.lock_path, true)?;
        let name = state_name(&self.lock_path)?;
        check_existing_entry(&parent, name)?;
        let file = File::from(
            openat(
                &parent,
                name,
                OFlags::RDWR
                    | OFlags::CREATE
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::LOOP {
                    StateError::UnsafePath
                } else {
                    storage_error(StateOperation::OpenLock, error.into())
                }
            })?,
        );
        safe_regular_file(&file)?;
        let deadline = Instant::now() + timeout;
        loop {
            match try_lock(&file) {
                Ok(()) => {
                    verify_lock_entry(&parent, &self.lock_path, &file)?;
                    return Ok(CheckLease {
                        file,
                        parent,
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

    #[cfg(not(unix))]
    pub fn acquire(&self, _timeout: Duration) -> Result<CheckLease, StateError> {
        Err(StateError::UnsafePersistence)
    }
}

#[derive(Debug)]
pub struct CheckLease {
    #[cfg(unix)]
    parent: File,
    #[cfg(unix)]
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

#[cfg(unix)]
fn state_name(path: &Path) -> Result<&std::ffi::OsStr, StateError> {
    use std::path::Component;
    let name = path.file_name().ok_or(StateError::UnsafePath)?;
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(StateError::UnsafePath);
    }
    Ok(name)
}

#[cfg(unix)]
fn open_parent(path: &Path, create: bool) -> Result<File, StateError> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};
    use std::path::Component;
    state_name(path)?;
    let root = if path.is_absolute() { "/" } else { "." };
    let mut dir =
        File::open(root).map_err(|error| storage_error(StateOperation::Inspect, error))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for part in parent.components() {
        let component = match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(component) => component,
            _ => return Err(StateError::UnsafePath),
        };
        if create {
            match mkdirat(&dir, component, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => {
                    return Err(storage_error(StateOperation::CreateDirectory, error.into()));
                }
            }
        }
        dir = File::from(
            openat(
                &dir,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| match error {
                rustix::io::Errno::LOOP => StateError::UnsafePath,
                // A symlink to a directory can appear as NOTDIR on some kernels.
                rustix::io::Errno::NOTDIR => StateError::UnsafePath,
                _ => storage_error(StateOperation::Inspect, error.into()),
            })?,
        );
    }
    use std::os::unix::fs::MetadataExt;
    let metadata = dir
        .metadata()
        .map_err(|error| storage_error(StateOperation::Inspect, error))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(StateError::UnsafePath);
    }
    Ok(dir)
}

#[cfg(unix)]
fn safe_regular_file(file: &File) -> Result<fs::Metadata, StateError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| storage_error(StateOperation::Inspect, error))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(StateError::UnsafePath);
    }
    Ok(metadata)
}

#[cfg(unix)]
fn check_existing_entry(parent: &File, name: &std::ffi::OsStr) -> Result<(), StateError> {
    use rustix::fs::{AtFlags, FileType, statat};
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat)
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
                || stat.st_nlink != 1 =>
        {
            Err(StateError::UnsafePath)
        }
        Ok(_) => {
            use rustix::fs::{Mode, OFlags, openat};
            let file = File::from(
                openat(
                    parent,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| StateError::UnsafePath)?,
            );
            safe_regular_file(&file).map(|_| ())
        }
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(storage_error(StateOperation::Inspect, error.into())),
    }
}

#[cfg(unix)]
fn verify_lock_entry(parent: &File, path: &Path, held: &File) -> Result<(), StateError> {
    use rustix::fs::{AtFlags, statat};
    use std::os::unix::fs::MetadataExt;
    let stat = statat(parent, state_name(path)?, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| StateError::UnsafePath)?;
    let metadata = safe_regular_file(held)?;
    if stat.st_ino != metadata.ino() || stat.st_dev != metadata.dev() || stat.st_nlink != 1 {
        return Err(StateError::UnsafePath);
    }
    Ok(())
}

fn validate_bounded_text(value: Option<&str>) -> Result<(), StateError> {
    if value.is_some_and(|value| {
        value.is_empty() || value.len() > MAX_VALIDATOR_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(StateError::Invalid);
    }
    Ok(())
}

#[cfg(unix)]
fn storage_error(operation: StateOperation, error: io::Error) -> StateError {
    StateError::StorageUnavailable {
        operation,
        kind: error.kind(),
    }
}

#[cfg(unix)]
fn temporary_path(path: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    path.with_file_name(format!(".{name}.tmp.{}.{}", std::process::id(), counter))
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(io::Error::from)
}

#[cfg(unix)]
fn is_lock_contention(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        process::{Command, Stdio},
        sync::{Arc, Barrier},
    };
    #[cfg(unix)]
    use tempfile::TempDir;

    use super::*;

    #[cfg(unix)]
    fn private_dir() -> TempDir {
        use std::os::unix::fs::PermissionsExt;
        let directory = TempDir::new().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[cfg(unix)]
    fn save_for_test(store: &StateStore, state: &UpdateState) -> Result<(), StateError> {
        let lease = CheckCoordinator::for_state(store).acquire(Duration::from_secs(1))?;
        store.save_with_lease(state, &lease)
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_persistence_fails_closed_without_creating_paths() {
        let store = StateStore::new(std::env::temp_dir().join("never-created-update-state.json"));
        assert_eq!(store.load(), Err(StateError::UnsafePersistence));
        assert!(matches!(
            CheckCoordinator::for_state(&store).acquire(Duration::ZERO),
            Err(StateError::UnsafePersistence)
        ));
    }

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

    #[cfg(unix)]
    #[test]
    fn state_round_trips_and_preserves_minimal_preferences() {
        let directory = private_dir();
        let store = StateStore::new(directory.path().join("state.json"));
        let expected = state_with_check();
        save_for_test(&store, &expected).expect("save state");
        assert_eq!(
            store.load().expect("load state"),
            LoadState::Present(Box::new(expected))
        );
        assert!(store.path().is_file());
    }

    #[cfg(unix)]
    #[test]
    fn replacing_lock_inode_invalidates_held_lease_before_write() {
        let directory = private_dir();
        let store = StateStore::new(directory.path().join("state.json"));
        let lease = CheckCoordinator::for_state(&store)
            .acquire(Duration::ZERO)
            .unwrap();
        fs::remove_file(store.lock_path()).unwrap();
        let replacement = store.lock_path();
        fs::write(&replacement, b"").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.save_with_lease(&UpdateState::default(), &lease),
            Err(StateError::UnsafePath)
        );
        assert!(!store.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn nested_state_directory_is_created_private_on_first_observation() {
        use crate::update::outcome::SessionOutcomeAccumulator;
        use std::os::unix::fs::PermissionsExt;
        let directory = private_dir();
        let store = StateStore::new(directory.path().join("nested/state/state.json"));
        let observation = CompatibilityObservation::from_session(
            StableVersion::parse("0.1.0").unwrap(),
            StableVersion::parse("0.154.0").unwrap(),
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            SessionOutcomeAccumulator::default().finish(),
        );
        store
            .record_compatibility_observation(observation, &FixedClock(1))
            .unwrap();
        assert!(store.path().is_file());
        assert_eq!(
            fs::metadata(store.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn state_write_requires_matching_held_lease() {
        let directory = private_dir();
        let store = StateStore::new(directory.path().join("state.json"));
        let unrelated = StateStore::new(directory.path().join("other.json"));
        let lease = CheckCoordinator::for_state(&unrelated)
            .acquire(Duration::from_secs(1))
            .expect("unrelated lease");
        assert_eq!(
            store.save_with_lease(&UpdateState::default(), &lease),
            Err(StateError::Invalid)
        );
        assert!(!store.path().exists());
    }

    #[test]
    fn repeated_compatibility_observations_saturate_without_losing_failure_signal() {
        use crate::update::outcome::{MAX_OUTCOME_COUNT, SessionOutcomeAccumulator};
        let mut accumulator = SessionOutcomeAccumulator::default();
        accumulator
            .record_hook_outcome(HookOutcome::ProtocolFailure)
            .expect("outcome");
        let observation = CompatibilityObservation::from_session(
            StableVersion::parse("0.1.0").unwrap(),
            StableVersion::parse("0.154.0").unwrap(),
            OperatingSystem::Windows,
            Surface::LocalCliLauncher,
            accumulator.finish(),
        );
        let mut state = UpdateState::default();
        for timestamp in 1..=MAX_OUTCOME_COUNT + 2 {
            state
                .record_compatibility_observation(
                    observation.clone(),
                    &FixedClock(timestamp as u64),
                )
                .expect("bounded cumulative count");
        }
        let stored = &state.compatibility_observations[0];
        assert_eq!(stored.counts.protocol_failure_count, MAX_OUTCOME_COUNT);
        assert_eq!(stored.hook_outcome, HookOutcome::ProtocolFailure);
        assert_eq!(
            stored.observed_at_unix_seconds,
            (MAX_OUTCOME_COUNT + 2) as u64
        );
    }

    #[test]
    fn unconfirmed_broker_allow_remains_visible_after_success() {
        use crate::update::outcome::SessionOutcomeAccumulator;
        let mut state = UpdateState::default();
        for (outcome, time) in [
            (HookOutcome::SuccessfulExchange, 1),
            (HookOutcome::BrokerAllowUnconfirmed, 2),
        ] {
            let mut session = SessionOutcomeAccumulator::default();
            session.record_hook_outcome(outcome).unwrap();
            state
                .record_compatibility_observation(
                    CompatibilityObservation::from_session(
                        StableVersion::parse("0.1.0").unwrap(),
                        StableVersion::parse("0.154.0").unwrap(),
                        OperatingSystem::Linux,
                        Surface::LocalCliLauncher,
                        session.finish(),
                    ),
                    &FixedClock(time),
                )
                .unwrap();
        }
        let stored = &state.compatibility_observations[0];
        assert_eq!(stored.counts.broker_allow_unconfirmed_count, 1);
        assert_eq!(stored.hook_outcome, HookOutcome::BrokerAllowUnconfirmed);
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_and_lock_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;
        let directory = TempDir::new().unwrap();
        let real = directory.path().join("real");
        fs::create_dir(&real).unwrap();
        let linked = directory.path().join("linked");
        symlink(&real, &linked).unwrap();
        let store = StateStore::new(linked.join("state.json"));
        assert_eq!(store.load(), Err(StateError::UnsafePath));
        let lock = directory.path().join("lock");
        let victim = directory.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &lock).unwrap();
        assert!(matches!(
            CheckCoordinator::new(lock).acquire(Duration::ZERO),
            Err(StateError::UnsafePath)
        ));
        assert_eq!(fs::read(victim).unwrap(), b"untouched");
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

    #[cfg(unix)]
    #[test]
    fn corrupt_duplicate_unknown_and_oversized_state_is_rejected_without_reset() {
        let directory = private_dir();
        let path = directory.path().join("state.json");
        let store = StateStore::new(&path);
        let expected = state_with_check();
        save_for_test(&store, &expected).expect("save state");
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

    #[cfg(unix)]
    #[test]
    fn interrupted_temporary_write_leaves_previous_valid_state() {
        let directory = private_dir();
        let store = StateStore::new(directory.path().join("state.json"));
        let expected = state_with_check();
        save_for_test(&store, &expected).expect("save state");
        let interrupted = store.path().with_file_name(".state.json.tmp.interrupted");
        fs::write(&interrupted, b"{\"schema_version\":").expect("partial temporary state");
        assert_eq!(
            store.load().expect("load previous state"),
            LoadState::Present(Box::new(expected))
        );
        assert!(interrupted.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_storage_is_explicit_and_does_not_fallback() {
        let directory = private_dir();
        let parent_file = directory.path().join("not-a-directory");
        fs::write(&parent_file, b"owned file").expect("parent fixture");
        let store = StateStore::new(parent_file.join("state.json"));
        assert!(matches!(
            save_for_test(&store, &UpdateState::default()),
            Err(StateError::UnsafePath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn directory_state_and_lock_paths_are_rejected() {
        let directory = private_dir();
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

        let directory = private_dir();
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

    #[cfg(unix)]
    #[test]
    fn concurrent_read_modify_write_transactions_remain_valid() {
        let directory = private_dir();
        let store = Arc::new(StateStore::new(directory.path().join("state.json")));
        save_for_test(&store, &UpdateState::default()).expect("initial state");
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

    #[cfg(unix)]
    #[test]
    fn bounded_contention_returns_recoverable_category() {
        let directory = private_dir();
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

    #[cfg(unix)]
    #[test]
    fn lock_release_after_process_termination_is_not_a_stale_file_decision() {
        let directory = private_dir();
        let lock_path = directory.path().join("check.lock");
        let ready_path = directory.path().join("ready");
        fs::write(&lock_path, b"").expect("create lock fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
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

    #[cfg(unix)]
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

    #[cfg(unix)]
    #[test]
    fn compatibility_observations_are_bounded_and_older_versions_cannot_overwrite_newer() {
        use crate::update::outcome::SessionOutcomeAccumulator;

        fn observation(codex: &str, hook: HookOutcome) -> CompatibilityObservation {
            let mut accumulator = SessionOutcomeAccumulator::default();
            accumulator.record_hook_outcome(hook).expect("hook outcome");
            CompatibilityObservation::from_session(
                StableVersion::parse("0.1.0").expect("autoapprover version"),
                StableVersion::parse(codex).expect("Codex version"),
                OperatingSystem::Windows,
                Surface::LocalCliLauncher,
                accumulator.finish(),
            )
        }

        let directory = private_dir();
        let store = StateStore::new(directory.path().join("state.json"));
        let newer = observation("0.154.0", HookOutcome::SuccessfulExchange);
        let older = observation("0.153.2", HookOutcome::CompatibilityRejection);
        store
            .record_compatibility_observation(newer, &FixedClock(100))
            .expect("newer observation");
        store
            .record_compatibility_observation(older, &FixedClock(101))
            .expect("older observation remains separate");
        store
            .record_compatibility_observation(
                observation("0.154.0", HookOutcome::SuccessfulExchange),
                &FixedClock(102),
            )
            .expect("same identity merges");

        let LoadState::Present(state) = store.load().expect("load state") else {
            panic!("expected state")
        };
        assert_eq!(state.compatibility_observations.len(), 2);
        let latest = state
            .compatibility_observations
            .iter()
            .find(|value| value.codex_version == StableVersion::parse("0.154.0").unwrap())
            .expect("newer observation");
        assert_eq!(latest.hook_outcome, HookOutcome::SuccessfulExchange);
        assert_eq!(latest.counts.successful_exchange_count, 2);
        assert!(
            state
                .compatibility_observations
                .iter()
                .any(|value| value.codex_version == StableVersion::parse("0.153.2").unwrap())
        );
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
