//! Identify the native Codex package that a PATH shim would launch. The shim
//! itself is never executed in an armed session. Helpers and resources are
//! bound to the same certificate as the native executable.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::identity::{BoundFile, Executable, check_trusted_directory_chain};

const MAX_FILES: usize = 256;
const MAX_DIRECTORIES: usize = 512;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_LAUNCH_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Bundle {
    pub executable: Executable,
    pub bundle_sha256: String,
    pub launch_kind: String,
    pub launch_sha256: String,
    pub launch_package_sha256: String,
    package_root: PathBuf,
    requested: PathBuf,
    launch_file: Option<BoundFile>,
    launch_package_file: Option<BoundFile>,
    files: Vec<BoundFile>,
    file_names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageMetadata {
    layout_version: u32,
    version: String,
    target: String,
    variant: String,
    entrypoint: String,
    resources_dir: String,
    path_dir: String,
}

struct Location {
    root: PathBuf,
    executable: PathBuf,
    kind: &'static str,
    shim: Option<PathBuf>,
    npm_package_json: Option<PathBuf>,
}

impl Bundle {
    pub fn configure_child(&self, command: &mut Command) -> Result<()> {
        for marker in [
            "CODEX_MANAGED_BY_NPM",
            "CODEX_MANAGED_BY_BUN",
            "CODEX_MANAGED_BY_PNPM",
            "CODEX_MANAGED_BY_VITE_PLUS",
            "CODEX_MANAGED_PACKAGE_ROOT",
        ] {
            command.env_remove(marker);
        }
        if self.launch_kind.starts_with("npm-") {
            let root = self
                .launch_package_file
                .as_ref()
                .and_then(|file| file.path().parent())
                .context("npm launch package root is unavailable")?;
            command
                .env("CODEX_MANAGED_BY_NPM", "1")
                .env("CODEX_MANAGED_PACKAGE_ROOT", root);
        }
        Ok(())
    }

    pub fn discover(requested: &Path, version: &str) -> Result<Self> {
        let location = locate(requested, version)?;
        let executable = Executable::open(&location.executable)?;
        let launch_file = location
            .shim
            .as_deref()
            .map(|path| BoundFile::open_limited(path, MAX_LAUNCH_BYTES))
            .transpose()?;
        let launch_package_file = location
            .npm_package_json
            .as_deref()
            .map(|path| BoundFile::open_limited(path, MAX_METADATA_BYTES as u64))
            .transpose()?;
        let launch_sha256 = launch_file
            .as_ref()
            .map_or_else(|| executable.sha256.clone(), |file| file.sha256.clone());
        let launch_package_sha256 = launch_package_file.as_ref().map_or_else(
            || {
                BoundFile::open_limited(
                    &location.root.join("codex-package.json"),
                    MAX_METADATA_BYTES as u64,
                )
                .map(|file| file.sha256)
            },
            |file| Ok(file.sha256.clone()),
        )?;
        let file_names = list_files(&location.root)?;
        let mut files = Vec::new();
        let mut digest = Sha256::new();
        digest.update(b"codex-autoapprover-bundle-v1\0");
        let mut bytes = 0u64;
        for name in &file_names {
            let path = location.root.join(name);
            let expected_size = fs::metadata(&path)?.len();
            let remaining = MAX_BYTES - bytes;
            if expected_size > remaining {
                bail!("Codex bundle exceeds the inspection limit")
            }
            let (sha256, size) = if path == executable.path {
                (executable.sha256.clone(), expected_size)
            } else {
                let file = BoundFile::open_limited(&path, remaining)?;
                let result = (file.sha256.clone(), file.size);
                files.push(file);
                result
            };
            if size != expected_size {
                bail!("Codex bundle file changed during inspection")
            }
            bytes += size;
            digest.update(name.as_bytes());
            digest.update([0]);
            digest.update(size.to_be_bytes());
            digest.update(sha256.as_bytes());
        }
        let result = Self {
            executable,
            bundle_sha256: crate::identity::hex(&digest.finalize()),
            launch_kind: location.kind.into(),
            launch_sha256,
            launch_package_sha256,
            package_root: location.root,
            requested: requested.into(),
            launch_file,
            launch_package_file,
            files,
            file_names,
        };
        result.recheck()?;
        Ok(result)
    }

    pub fn recheck(&self) -> Result<()> {
        let located = locate(&self.requested, &self.version()?)?;
        if located.root != self.package_root
            || located.executable != self.executable.path
            || located.kind != self.launch_kind
            || located.shim.as_deref() != self.launch_file.as_ref().map(BoundFile::path)
            || located.npm_package_json.as_deref()
                != self.launch_package_file.as_ref().map(BoundFile::path)
            || list_files(&self.package_root)? != self.file_names
        {
            bail!("Codex package location or contents changed")
        }
        self.executable.recheck()?;
        if let Some(shim) = &self.launch_file {
            shim.recheck()?;
        }
        if let Some(package) = &self.launch_package_file {
            package.recheck()?;
        }
        for file in &self.files {
            file.recheck()?;
        }
        Ok(())
    }

    fn version(&self) -> Result<String> {
        let metadata: PackageMetadata = read_package_metadata(&self.package_root)?;
        Ok(metadata.version)
    }
}

/// Locate a tagged native bundle without interpreting or executing an npm
/// entrypoint. Unknown layouts are deliberately ineligible for certification.
pub fn native_path(requested: &Path) -> Result<PathBuf> {
    let location = locate(requested, "")?;
    Ok(location.executable)
}

fn locate(requested: &Path, version: &str) -> Result<Location> {
    let canonical = fs::canonicalize(requested).context("resolve Codex launch path")?;
    let name = canonical
        .file_name()
        .context("Codex launch path has no filename")?;
    let requested_name = requested
        .file_name()
        .context("Codex launch path has no filename")?;
    let (root, kind, shim, npm_version, npm_package_json) = if name == OsStr::new("codex.js") {
        if cfg!(windows)
            && (requested_name == OsStr::new("codex.cmd")
                || requested_name == OsStr::new("codex.ps1"))
        {
            bail!("a Windows command shim cannot alias the JavaScript entrypoint")
        }
        let npm_root = canonical
            .parent()
            .and_then(Path::parent)
            .context("npm entrypoint has no package root")?;
        if !npm_root.join("package.json").is_file() {
            bail!("npm Codex package metadata is missing")
        }
        check_trusted_directory_chain(npm_root)?;
        let package: serde_json::Value = read_json(&npm_root.join("package.json"))?;
        if package.get("name").and_then(|v| v.as_str()) != Some("@openai/codex")
            || package.get("version").and_then(|v| v.as_str()).is_none()
            || !canonical.ends_with("bin/codex.js")
        {
            bail!("unrecognized npm Codex entrypoint")
        }
        let (package_name, triple) = native_target()?;
        let root = npm_root
            .join("node_modules/@openai")
            .join(package_name)
            .join("vendor")
            .join(triple);
        let kind = if requested_name == OsStr::new("codex.cmd") {
            "npm-cmd"
        } else if requested_name == OsStr::new("codex.ps1") {
            "npm-ps1"
        } else {
            "npm-bin"
        };
        (
            root,
            kind,
            Some(canonical.clone()),
            package["version"].as_str().map(str::to_owned),
            Some(npm_root.join("package.json")),
        )
    } else if cfg!(windows)
        && matches!(
            requested.extension().and_then(OsStr::to_str),
            Some("cmd" | "ps1")
        )
    {
        let npm_root = requested
            .parent()
            .context("shim has no parent")?
            .join("node_modules/@openai/codex");
        let npm_root = fs::canonicalize(npm_root).context("resolve npm Codex package")?;
        check_trusted_directory_chain(&npm_root)?;
        let package: serde_json::Value = read_json(&npm_root.join("package.json"))?;
        if package.get("name").and_then(|v| v.as_str()) != Some("@openai/codex") {
            bail!("unrecognized npm Codex package")
        }
        let (package_name, triple) = native_target()?;
        let root = npm_root
            .join("node_modules/@openai")
            .join(package_name)
            .join("vendor")
            .join(triple);
        let kind = if requested_name == OsStr::new("codex.cmd") {
            "npm-cmd"
        } else if requested_name == OsStr::new("codex.ps1") {
            "npm-ps1"
        } else {
            bail!("unrecognized npm Codex shim")
        };
        (
            root,
            kind,
            Some(canonical.clone()),
            package["version"].as_str().map(str::to_owned),
            Some(npm_root.join("package.json")),
        )
    } else {
        let parent = canonical
            .parent()
            .context("native Codex path has no parent")?;
        let root = if parent.file_name() == Some(OsStr::new("bin")) {
            parent
                .parent()
                .context("native Codex package has no root")?
                .to_path_buf()
        } else {
            parent.to_path_buf()
        };
        (root, "native", None, None, None)
    };
    let root = fs::canonicalize(&root).context("resolve native Codex bundle")?;
    check_trusted_directory_chain(&root)?;
    let metadata = read_package_metadata(&root)?;
    if metadata.layout_version != 1
        || metadata.variant != "codex"
        || metadata.resources_dir != "codex-resources"
        || metadata.path_dir != "codex-path"
        || metadata.target != native_target()?.1
        || (!version.is_empty() && metadata.version != version)
        || (kind != "native" && npm_version.as_deref() != Some(metadata.version.as_str()))
    {
        bail!("native Codex bundle metadata does not match the expected target")
    }
    let entrypoint = Path::new(&metadata.entrypoint);
    let triple = native_target()?.1;
    let allowed = if cfg!(windows) {
        vec![
            "bin/codex.exe".to_owned(),
            "codex.exe".to_owned(),
            format!("codex-{triple}.exe"),
        ]
    } else {
        vec![
            "bin/codex".to_owned(),
            "codex".to_owned(),
            format!("codex-{triple}"),
        ]
    };
    if !allowed.iter().any(|value| entrypoint == Path::new(value)) {
        bail!("unrecognized native Codex bundle entrypoint")
    }
    let executable = root.join(entrypoint);
    let executable = fs::canonicalize(&executable).context("resolve native Codex executable")?;
    if !executable.starts_with(&root) || (kind == "native" && executable != canonical) {
        bail!("native Codex entrypoint does not belong to the expected bundle")
    }
    if !root.join("codex-resources").is_dir() || !root.join("codex-path").is_dir() {
        bail!("native Codex bundle is missing its resources or path directory")
    }
    if let Some(shim) = &shim
        && shim == &executable
    {
        bail!("npm shim unexpectedly resolves to the native executable")
    }
    Ok(Location {
        root,
        executable,
        kind,
        shim,
        npm_package_json,
    })
}

fn native_target() -> Result<(&'static str, &'static str)> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok(("codex-linux-x64", "x86_64-unknown-linux-musl")),
        ("linux", "aarch64") => Ok(("codex-linux-arm64", "aarch64-unknown-linux-musl")),
        ("windows", "x86_64") => Ok(("codex-win32-x64", "x86_64-pc-windows-msvc")),
        ("windows", "aarch64") => Ok(("codex-win32-arm64", "aarch64-pc-windows-msvc")),
        _ => bail!("unsupported native Codex bundle target"),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let body = fs::read(path)?;
    if body.len() > MAX_METADATA_BYTES {
        bail!("Codex package metadata is too large")
    }
    let value = crate::protocol::parse_unique_object(&body)
        .map_err(|_| anyhow::anyhow!("ambiguous Codex package metadata"))?;
    serde_json::from_value(value).context("decode Codex package metadata")
}

fn read_package_metadata(root: &Path) -> Result<PackageMetadata> {
    read_json(&root.join("codex-package.json"))
}

fn list_files(root: &Path) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut directories = 0usize;
    while let Some(directory) = stack.pop() {
        directories += 1;
        if directories > MAX_DIRECTORIES {
            bail!("Codex bundle has too many directories")
        }
        check_trusted_directory_chain(&directory)?;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("Codex bundle contains a symlink")
            }
            if metadata.is_dir() {
                if stack.len() + directories >= MAX_DIRECTORIES {
                    bail!("Codex bundle has too many directories")
                }
                stack.push(path);
            } else if metadata.is_file() {
                let relative = path.strip_prefix(root)?;
                let name = relative
                    .to_str()
                    .context("bundle filename is not Unicode")?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                result.push(name);
                if result.len() > MAX_FILES {
                    bail!("Codex bundle has too many files")
                }
            } else {
                bail!("Codex bundle contains a non-regular entry")
            }
        }
    }
    result.sort();
    if result.is_empty() {
        bail!("Codex bundle is empty")
    }
    Ok(result)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn secure_write(path: &Path, content: impl AsRef<[u8]>) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn secure_test_directories(path: &Path) {
        let temp_root = fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(path.starts_with(&temp_root));
        for directory in path.ancestors().take_while(|entry| *entry != temp_root) {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn synthetic_bundle(root: &Path) {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("codex-resources")).unwrap();
        fs::create_dir(root.join("codex-path")).unwrap();
        secure_test_directories(&root.join("bin"));
        secure_test_directories(&root.join("codex-resources"));
        secure_test_directories(&root.join("codex-path"));
        let metadata = serde_json::json!({
            "layoutVersion": 1,
            "version": "0.156.0",
            "target": native_target().unwrap().1,
            "variant": "codex",
            "entrypoint": "bin/codex",
            "resourcesDir": "codex-resources",
            "pathDir": "codex-path",
        });
        secure_write(&root.join("codex-package.json"), metadata.to_string());
        fs::copy("/bin/true", root.join("bin/codex")).unwrap();
    }

    #[test]
    fn helper_replacement_and_added_files_invalidate_the_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        synthetic_bundle(root);
        let helper = root.join("codex-resources/bwrap");
        secure_write(&helper, b"synthetic helper");
        let bundle = Bundle::discover(&root.join("bin/codex"), "0.156.0").unwrap();
        assert!(bundle.recheck().is_ok());
        fs::write(&helper, b"changed helper").unwrap();
        assert!(bundle.recheck().is_err());
        fs::write(&helper, b"synthetic helper").unwrap();
        let bundle = Bundle::discover(&root.join("bin/codex"), "0.156.0").unwrap();
        fs::write(root.join("codex-resources/added"), b"extra").unwrap();
        assert!(bundle.recheck().is_err());
    }

    #[test]
    fn npm_launch_chain_is_bound_and_version_mismatch_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path().join("node_modules/@openai/codex");
        let (package_name, triple) = native_target().unwrap();
        let root = package
            .join("node_modules/@openai")
            .join(package_name)
            .join("vendor")
            .join(triple);
        fs::create_dir_all(package.join("bin")).unwrap();
        secure_test_directories(&package.join("bin"));
        synthetic_bundle(&root);
        let npm_metadata = package.join("package.json");
        secure_write(
            &npm_metadata,
            r#"{"name":"@openai/codex","version":"0.156.0"}"#,
        );
        let shim = package.join("bin/codex.js");
        secure_write(&shim, b"synthetic npm launcher");
        let bundle = Bundle::discover(&shim, "0.156.0").unwrap();
        assert_eq!(bundle.launch_kind, "npm-bin");
        assert!(bundle.recheck().is_ok());
        let mut command = Command::new("/bin/true");
        command.env("CODEX_MANAGED_BY_PNPM", "untrusted-parent");
        bundle.configure_child(&mut command).unwrap();
        let managed_root = command
            .get_envs()
            .find(|(name, _)| *name == "CODEX_MANAGED_PACKAGE_ROOT")
            .and_then(|(_, value)| value);
        assert_eq!(managed_root, Some(package.as_os_str()));
        assert!(
            command
                .get_envs()
                .any(|(name, value)| { name == "CODEX_MANAGED_BY_PNPM" && value.is_none() })
        );
        assert!(Bundle::discover(&shim, "0.155.0").is_err());
        fs::write(
            &npm_metadata,
            r#"{"name":"@openai/codex","version":"0.156.0"} "#,
        )
        .unwrap();
        assert!(bundle.recheck().is_err());
        let bundle = Bundle::discover(&shim, "0.156.0").unwrap();
        fs::write(&shim, b"modified synthetic npm launcher").unwrap();
        assert!(bundle.recheck().is_err());
        fs::OpenOptions::new()
            .write(true)
            .open(&shim)
            .unwrap()
            .set_len(MAX_LAUNCH_BYTES + 1)
            .unwrap();
        assert!(Bundle::discover(&shim, "0.156.0").is_err());
    }

    #[test]
    fn group_writable_executable_is_never_certifiable() {
        let temp = tempfile::tempdir().unwrap();
        synthetic_bundle(temp.path());
        let executable = temp.path().join("bin/codex");
        assert!(Bundle::discover(&executable, "0.156.0").is_ok());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(Bundle::discover(&executable, "0.156.0").is_err());
    }

    #[test]
    fn group_writable_bundle_directory_is_never_certifiable() {
        let temp = tempfile::tempdir().unwrap();
        synthetic_bundle(temp.path());
        let executable = temp.path().join("bin/codex");
        assert!(Bundle::discover(&executable, "0.156.0").is_ok());
        fs::set_permissions(
            temp.path().join("codex-resources"),
            fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        assert!(Bundle::discover(&executable, "0.156.0").is_err());
    }
}
