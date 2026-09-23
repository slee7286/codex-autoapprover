//! Explicit configuration repair; never called by `run` or by an approval hook.
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, Value};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

pub fn render(original: &str, mode: &str) -> Result<String> {
    if !matches!(mode, "elevated" | "unelevated") {
        bail!("unsupported Windows sandbox mode")
    }
    let mut document: DocumentMut = original
        .trim_start_matches('\u{feff}')
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TOML; configuration was not changed"))?;
    if !document.contains_key("windows") {
        document.insert("windows", Item::Table(Table::new()));
    }
    let windows = document
        .get_mut("windows")
        .and_then(Item::as_table_like_mut)
        .context("windows must be a TOML table; configuration was not changed")?;
    if let Some(current) = windows.get("sandbox") {
        let current = current
            .as_str()
            .context("windows.sandbox must be a string")?;
        if !matches!(current, "elevated" | "unelevated") {
            bail!("unrecognized windows.sandbox value; configuration was not changed")
        }
        if current == mode {
            return Ok(original.to_owned());
        }
    }
    let mut value = Value::from(mode);
    if let Some(previous) = windows.get("sandbox").and_then(Item::as_value) {
        *value.decor_mut() = previous.decor().clone();
    }
    windows.insert("sandbox", Item::Value(value));
    Ok(document.to_string())
}

pub fn run(directory: &Path, mode: &str) -> Result<i32> {
    if !cfg!(windows) {
        bail!("Windows sandbox configuration requires native Windows")
    }
    update(directory, mode)?;
    println!("Configured windows.sandbox={mode:?}. This affects ordinary Codex and the launcher.");
    if mode == "unelevated" {
        println!("The unelevated fallback provides weaker isolation than the elevated sandbox.");
    }
    Ok(0)
}

fn update(directory: &Path, mode: &str) -> Result<()> {
    check_plain_directory_chain(directory)?;
    fs::create_dir_all(directory).context("create Codex configuration directory")?;
    check_plain_directory_chain(directory)?;
    #[cfg(windows)]
    crate::identity::check_trusted_directory_chain(&std::path::absolute(directory)?)
        .context("Codex configuration directory is not owner-controlled")?;
    let lock_path = directory.join(".autoapprover-config.lock");
    let lock = fs::OpenOptions::new().write(true).create_new(true).open(&lock_path)
        .context("configuration lock exists or is inaccessible; close other installers, and remove a stale .autoapprover-config.lock only after confirming none is running")?;
    let result = update_locked(directory, mode);
    drop(lock);
    let cleanup = fs::remove_file(lock_path).context("remove configuration lock");
    result.and(cleanup)
}

fn check_plain_directory_chain(directory: &Path) -> Result<()> {
    let absolute = std::path::absolute(directory).context("resolve Codex configuration path")?;
    for parent in absolute.ancestors() {
        let metadata = match fs::symlink_metadata(parent) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("inspect Codex configuration directory"),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("Codex configuration path contains a non-directory or symlink")
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                bail!("Codex configuration path contains a reparse point")
            }
        }
    }
    Ok(())
}

fn update_locked(directory: &Path, mode: &str) -> Result<()> {
    let path = directory.join("config.toml");
    let original = read_config(&path)?;
    let updated = render(original.as_deref().unwrap_or_default(), mode)?;
    if original.as_deref() == Some(updated.as_str()) {
        return Ok(());
    }
    let mut staged = tempfile::NamedTempFile::new_in(directory)?;
    staged.write_all(updated.as_bytes())?;
    staged.as_file().sync_all()?;
    if let Some(original) = original {
        if read_config(&path)?.as_deref() != Some(original.as_str()) {
            bail!("config.toml changed during installation; configuration was not replaced")
        }
        #[allow(unused_mut)]
        let mut backup = tempfile::Builder::new()
            .prefix("config.toml.autoapprover-")
            .suffix(".bak")
            .tempfile_in(directory)?;
        // On Windows ReplaceFile moves the original file to the backup name,
        // preserving its security metadata. Do not copy sensitive config into a
        // separately inherited ACL before that operation.
        #[cfg(not(windows))]
        {
            backup.write_all(original.as_bytes())?;
            fs::set_permissions(backup.path(), fs::metadata(&path)?.permissions())?;
            backup.as_file().sync_all()?;
        }
        let (backup_file, backup_path) = backup.keep()?;
        drop(backup_file);
        let staged_path = staged.into_temp_path(); // Close the Windows file handle before ReplaceFileW.
        replace_existing(&staged_path, &path, &backup_path).with_context(|| {
            format!(
                "replacement failed; inspect config.toml and backup {} before retrying",
                backup_path.display()
            )
        })?;
        println!("Previous configuration saved to {}", backup_path.display());
    } else {
        // Do not replace a config created by another process since the initial read.
        staged
            .persist_noclobber(&path)
            .context("create configuration without overwriting another writer")?;
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Codex configuration"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("config.toml must be a regular file; configuration was not changed")
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
    let file = options.open(path).context("open Codex configuration")?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > MAX_CONFIG_BYTES {
        bail!("config.toml is not a bounded regular file; configuration was not changed")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 {
            bail!("hardlinked config.toml is not safe to replace")
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, GetFileInformationByHandle,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("inspect Codex configuration file");
        }
        if info.nNumberOfLinks != 1 || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("hardlinked or reparse-point config.toml is not safe to replace")
        }
        crate::identity::check_trusted_file_acl(&file)
            .context("config.toml owner or DACL is not safe for replacement")?;
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .context("read UTF-8 Codex configuration")?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        bail!("config.toml exceeds the configuration size limit")
    }
    Ok(Some(text))
}

#[cfg(windows)]
fn replace_existing(staged: &Path, destination: &Path, backup: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
    let wide = |path: &Path| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>()
    };
    // Rust canonicalization supplies extended-length Windows paths to the raw
    // API, including when CODEX_HOME itself exceeds MAX_PATH.
    let destination = fs::canonicalize(destination)?;
    let staged = fs::canonicalize(staged)?;
    let backup = fs::canonicalize(backup)?;
    // ReplaceFile preserves the destination's Windows ACLs. Both files share a directory.
    let result = unsafe {
        ReplaceFileW(
            wide(&destination).as_ptr(),
            wide(&staged).as_ptr(),
            wide(&backup).as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("atomically replace Codex configuration");
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_existing(staged: &Path, destination: &Path, _backup: &Path) -> Result<()> {
    fs::set_permissions(staged, fs::metadata(destination)?.permissions())?;
    fs::rename(staged, destination).context("atomically replace configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_layouts_preserve_values_comments_and_are_idempotent() {
        for original in [
            "",
            "[windows]\nsandbox = 'elevated' # keep me\n",
            "windows.sandbox = 'elevated'\n",
            "windows = { sandbox = 'elevated', sandbox_private_desktop = false }\n",
            "[\"windows\"]\n\"sandbox\" = 'elevated'\n",
            "note = '''\n[windows]\nsandbox = 'text, not configuration'\n'''\nitems = [\n'one',\n['two'],\n]\n",
        ] {
            let rendered = render(original, "unelevated").unwrap();
            let parsed: DocumentMut = rendered.parse().unwrap();
            assert_eq!(parsed["windows"]["sandbox"].as_str(), Some("unelevated"));
            if original.contains("# keep me") {
                assert!(rendered.contains("# keep me"));
            }
            if original.contains("note =") {
                assert!(rendered.contains("sandbox = 'text, not configuration'"));
            }
            assert_eq!(render(&rendered, "unelevated").unwrap(), rendered);
        }
    }

    #[test]
    fn invalid_or_unknown_configuration_is_not_rewritten() {
        for original in [
            "[windows",
            "windows = 3",
            "[windows]\nsandbox = 3",
            "[windows]\nsandbox = 'future'",
            "[windows]\n[windows]",
        ] {
            assert!(render(original, "unelevated").is_err());
        }
    }

    #[test]
    fn update_creates_exact_backup_and_no_redundant_backup() {
        let directory = tempfile::tempdir().unwrap();
        let original = "model = 'keep'\r\n[windows]\r\nsandbox = 'elevated'\r\n";
        fs::write(directory.path().join("config.toml"), original).unwrap();
        update(directory.path(), "unelevated").unwrap();
        update(directory.path(), "unelevated").unwrap();
        let backups: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "bak"))
            .collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(fs::read_to_string(backups[0].path()).unwrap(), original);
    }

    #[test]
    fn existing_lock_prevents_changes() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(".autoapprover-config.lock"), "").unwrap();
        assert!(update(directory.path(), "unelevated").is_err());
        assert!(!directory.path().join("config.toml").exists());
    }

    #[test]
    fn linked_configuration_is_rejected_without_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let alias = directory.path().join("alias.toml");
        let original = "[windows]\nsandbox = 'elevated'\n";
        fs::write(&path, original).unwrap();
        fs::hard_link(&path, &alias).unwrap();
        assert!(update(directory.path(), "unelevated").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(fs::read_to_string(&alias).unwrap(), original);
        fs::remove_file(&alias).unwrap();
        #[cfg(unix)]
        {
            fs::write(&alias, original).unwrap();
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&alias, &path).unwrap();
            assert!(update(directory.path(), "unelevated").is_err());
            assert_eq!(fs::read_to_string(&alias).unwrap(), original);
        }
    }

    #[test]
    fn oversized_configuration_is_rejected_without_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let body = vec![b' '; MAX_CONFIG_BYTES as usize + 1];
        fs::write(&path, &body).unwrap();
        assert!(update(directory.path(), "unelevated").is_err());
        assert_eq!(fs::read(&path).unwrap(), body);
    }

    #[cfg(windows)]
    #[test]
    fn broad_write_acl_on_directory_or_file_is_rejected_before_replacement() {
        use std::process::Command;

        let root = tempfile::tempdir().unwrap();
        for broad_directory in [true, false] {
            let directory = root.path().join(if broad_directory {
                "broad-directory"
            } else {
                "broad-file"
            });
            fs::create_dir(&directory).unwrap();
            let path = directory.join("config.toml");
            let original = "[windows]\nsandbox = 'elevated'\n";
            fs::write(&path, original).unwrap();
            let target = if broad_directory { &directory } else { &path };
            let grant = if broad_directory {
                "*S-1-5-32-545:(OI)(CI)M"
            } else {
                "*S-1-5-32-545:M"
            };
            assert!(
                Command::new("icacls")
                    .arg(target)
                    .args(["/grant", grant])
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(update(&directory, "unelevated").is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
            assert!(!directory.join(".autoapprover-config.lock").exists());
            assert!(
                fs::read_dir(&directory)
                    .unwrap()
                    .flatten()
                    .all(|entry| entry.path().extension().is_none_or(|ext| ext != "bak"))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_configuration_directory_is_rejected_before_creation() {
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = root.path().join("redirected");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(update(&link, "unelevated").is_err());
        assert!(!real.join("config.toml").exists());
        assert!(!real.join(".autoapprover-config.lock").exists());
    }
}
