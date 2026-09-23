//! A certificate identifies bytes, never a self-reported version banner.
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

const MAX_IDENTITY_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Executable {
    requested: PathBuf,
    pub path: PathBuf,
    pub sha256: String,
    stamp: Stamp,
    // Holding a Windows read-only share denies replacement and in-place writes.
    // Linux checks the executed inode; the kernel denies writing an active image.
    file: Arc<File>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Stamp(Vec<u64>);

#[derive(Debug, Clone)]
pub(crate) struct BoundFile {
    path: PathBuf,
    stamp: Stamp,
    file: Arc<File>,
    pub sha256: String,
    pub size: u64,
}

impl BoundFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn open_limited(path: &Path, limit: u64) -> Result<Self> {
        check_trusted_directory_chain(path.parent().context("bundle file has no parent")?)?;
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            bail!("bundle file is a symlink")
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(path).context("open bundle file")?;
        let before = stamp(&file)?;
        let size = file.metadata()?.len();
        if size > limit {
            bail!("bundle file exceeds the inspection size limit")
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut read_bytes = 0u64;
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            read_bytes = read_bytes
                .checked_add(length as u64)
                .context("bundle file size overflow")?;
            if read_bytes > limit {
                bail!("bundle file exceeds the inspection size limit")
            }
            hash.update(&buffer[..length]);
        }
        if read_bytes != size || before != stamp(&file)? || fs::canonicalize(path)? != path {
            bail!("bundle file changed during inspection")
        }
        Ok(Self {
            path: path.into(),
            stamp: before,
            file: Arc::new(file),
            sha256: hex(&hash.finalize()),
            size,
        })
    }

    pub fn recheck(&self) -> Result<()> {
        check_trusted_directory_chain(self.path.parent().context("bundle file has no parent")?)?;
        if fs::canonicalize(&self.path)? != self.path
            || stamp(&self.file)? != self.stamp
            || stamp(&File::open(&self.path)?)? != self.stamp
        {
            bail!("Codex bundle file was replaced or modified")
        }
        Ok(())
    }
}

impl Executable {
    pub fn open(requested: &Path) -> Result<Self> {
        let path = fs::canonicalize(requested).context("resolve executable identity")?;
        check_trusted_directory_chain(path.parent().context("executable has no parent")?)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            };
            options
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options
            .open(&path)
            .context("open native Codex executable")?;
        let before = stamp(&file)?;
        let size = file.metadata()?.len();
        if size > MAX_IDENTITY_FILE_BYTES {
            bail!("Codex executable exceeds the inspection size limit")
        }
        let mut prefix = [0u8; 4];
        file.read_exact(&mut prefix)
            .context("read executable header")?;
        let native = if cfg!(target_os = "linux") {
            prefix == *b"\x7fELF"
        } else if cfg!(windows) {
            prefix[..2] == *b"MZ"
        } else {
            false
        };
        if !native {
            bail!(
                "resolved Codex is a shim, script or unsupported image; native executable identity is required"
            )
        }
        let mut hash = Sha256::new();
        hash.update(prefix);
        let mut buffer = [0u8; 64 * 1024];
        let mut read_bytes = prefix.len() as u64;
        loop {
            let length = file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            read_bytes = read_bytes
                .checked_add(length as u64)
                .context("Codex executable size overflow")?;
            if read_bytes > MAX_IDENTITY_FILE_BYTES {
                bail!("Codex executable exceeds the inspection size limit")
            }
            hash.update(&buffer[..length]);
        }
        if read_bytes != size || before != stamp(&file)? || fs::canonicalize(requested)? != path {
            bail!("Codex executable changed during identity inspection")
        }
        Ok(Self {
            requested: requested.to_owned(),
            path,
            sha256: hex(&hash.finalize()),
            stamp: before,
            file: Arc::new(file),
        })
    }

    pub fn recheck(&self) -> Result<()> {
        check_trusted_directory_chain(self.path.parent().context("executable has no parent")?)?;
        if fs::canonicalize(&self.requested)? != self.path
            || stamp(&self.file)? != self.stamp
            || stamp(&File::open(&self.path)?)? != self.stamp
        {
            bail!("Codex executable was replaced or modified; automatic approval is disabled")
        }
        Ok(())
    }

    pub fn command(&self) -> std::process::Command {
        #[cfg(target_os = "linux")]
        {
            use std::os::{fd::AsRawFd, unix::process::CommandExt};
            // The kernel opens this held inode before closing CLOEXEC handles.
            // A rename between recheck and exec cannot substitute new bytes.
            let mut command =
                std::process::Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
            command.arg0(&self.path);
            command
        }
        #[cfg(windows)]
        {
            // The held file denies FILE_SHARE_WRITE and FILE_SHARE_DELETE.
            std::process::Command::new(&self.path)
        }
    }

    pub fn verify_process(&self, pid: u32) -> Result<()> {
        self.recheck()?;
        #[cfg(target_os = "linux")]
        if stamp(&File::open(format!("/proc/{pid}/exe"))?)? != self.stamp {
            bail!("running process does not use the certified Codex executable")
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::Threading::{
                    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
                },
            };
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if handle.is_null() {
                bail!("cannot inspect running Codex executable")
            }
            let mut buffer = vec![0u16; 32768];
            let mut length = buffer.len() as u32;
            let result =
                unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) };
            unsafe {
                CloseHandle(handle);
            }
            if result == 0 {
                bail!("cannot read running Codex executable path")
            }
            let actual = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize]));
            if stamp(&File::open(actual)?)? != self.stamp {
                bail!("running process does not use the certified Codex executable")
            }
        }
        Ok(())
    }
}

/// Files in a writable directory can be swapped without changing their own
/// permissions. A system-owned sticky directory such as /tmp is safe for an
/// owner-controlled immediate child; all later path components must be
/// unwritable by other principals. This does not isolate malicious same-UID
/// processes or the owner of the filesystem root, which are outside the
/// security boundary. Root ownership can be UID-mapped inside containers.
pub(crate) fn check_trusted_directory_chain(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = rustix::process::geteuid().as_raw() as u32;
        let system_owner = fs::symlink_metadata("/")?.uid();
        let mut current = Some(path);
        while let Some(directory) = current {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("native artifact directory is not a plain directory")
            }
            let mode = metadata.mode();
            if metadata.uid() != owner && metadata.uid() != system_owner {
                bail!("native artifact directory has an untrusted owner")
            }
            if mode & 0o022 != 0 && !(metadata.uid() == system_owner && mode & 0o1000 != 0) {
                bail!(
                    "native artifact directory is writable by another principal: {} (mode {:o}, owner {})",
                    directory.display(),
                    mode & 0o7777,
                    metadata.uid()
                )
            }
            current = directory.parent();
        }
    }
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn stamp(file: &File) -> Result<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
        || m.uid() != rustix::process::geteuid().as_raw() as u32
    {
        bail!(
            "native artifact must be a regular, singly linked, owner-controlled file without group or world write permission"
        )
    }
    Ok(Stamp(vec![
        m.dev(),
        m.ino(),
        m.len(),
        m.mode() as u64,
        m.uid() as u64,
        m.mtime() as u64,
        m.mtime_nsec() as u64,
        m.ctime() as u64,
        m.ctime_nsec() as u64,
    ]))
}

#[cfg(windows)]
fn stamp(file: &File) -> Result<Stamp> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        bail!("cannot inspect executable file identity")
    }
    if info.nNumberOfLinks != 1
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        bail!("native executable must be a regular file without hardlinks or reparse points")
    }
    Ok(Stamp(vec![
        info.dwVolumeSerialNumber as u64,
        info.nFileIndexHigh as u64,
        info.nFileIndexLow as u64,
        info.nFileSizeHigh as u64,
        info.nFileSizeLow as u64,
        info.ftLastWriteTime.dwHighDateTime as u64,
        info.ftLastWriteTime.dwLowDateTime as u64,
        info.dwFileAttributes as u64,
    ]))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn digest_and_running_image_are_bound_and_replacement_disarms() {
        let temp = private_tempdir();
        let path = temp.path().join("sleep");
        fs::copy("/bin/sleep", &path).unwrap();
        let image = Executable::open(&path).unwrap();
        assert_eq!(image.sha256, hex(&Sha256::digest(fs::read(&path).unwrap())));
        let mut child = image.command().arg("30").spawn().unwrap();
        let result = image.verify_process(child.id());
        assert!(child.try_wait().unwrap().is_none());
        assert!(image.verify_process(std::process::id()).is_err());
        fs::rename(&path, temp.path().join("old")).unwrap();
        fs::copy("/bin/sleep", &path).unwrap();
        let changed = image.verify_process(child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(changed.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scripts_hardlinks_and_symlink_retargeting_cannot_borrow_identity() {
        use std::os::unix::fs::symlink;
        let temp = private_tempdir();
        let path = temp.path().join("sleep");
        fs::write(&path, b"#!/bin/sh\necho codex-cli 0.151.0").unwrap();
        assert!(Executable::open(&path).is_err());
        fs::copy("/bin/sleep", &path).unwrap();
        let link = temp.path().join("link");
        fs::hard_link(&path, &link).unwrap();
        assert!(Executable::open(&path).is_err());
        fs::remove_file(&link).unwrap();
        symlink(&path, &link).unwrap();
        let image = Executable::open(&link).unwrap();
        fs::remove_file(&link).unwrap();
        symlink("/bin/true", &link).unwrap();
        assert!(image.recheck().is_err());
    }
}
