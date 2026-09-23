//! Explicit configuration repair; never called by `run` or by an approval hook.
use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, bail};
use toml_edit::{DocumentMut, Item, Table, Value};

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
    fs::create_dir_all(directory).context("create Codex configuration directory")?;
    let lock_path = directory.join(".autoapprover-config.lock");
    let lock = fs::OpenOptions::new().write(true).create_new(true).open(&lock_path)
        .context("configuration lock exists or is inaccessible; close other installers, and remove a stale .autoapprover-config.lock only after confirming none is running")?;
    let result = update_locked(directory, mode);
    drop(lock);
    let cleanup = fs::remove_file(lock_path).context("remove configuration lock");
    result.and(cleanup)
}

fn update_locked(directory: &Path, mode: &str) -> Result<()> {
    let path = directory.join("config.toml");
    let original = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("config.toml must be a regular file; configuration was not changed")
            }
            Some(fs::read_to_string(&path).context("read UTF-8 Codex configuration")?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect Codex configuration"),
    };
    let updated = render(original.as_deref().unwrap_or_default(), mode)?;
    if original.as_deref() == Some(updated.as_str()) {
        return Ok(());
    }
    let mut staged = tempfile::NamedTempFile::new_in(directory)?;
    staged.write_all(updated.as_bytes())?;
    staged.as_file().sync_all()?;
    if let Some(original) = original {
        if fs::read_to_string(&path)? != original {
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
}
