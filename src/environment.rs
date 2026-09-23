//! Conservative native-host observation. Missing facts never mean native support.
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::env;
#[cfg(target_os = "linux")]
use std::fs;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Host {
    pub os: String,
    pub arch: String,
    pub os_release: String,
    pub os_build: String,
    pub surface: String,
}

pub fn surface() -> Result<&'static str> {
    for key in ["WSL_DISTRO_NAME", "WSL_INTEROP"] {
        if env::var_os(key).is_some() {
            return Ok("wsl");
        }
    }
    for key in [
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "SSH_TTY",
        "CODESPACES",
        "CLOUD_SHELL",
    ] {
        if env::var_os(key).is_some() {
            return Ok("remote");
        }
    }
    for key in [
        "VSCODE_PID",
        "VSCODE_IPC_HOOK_CLI",
        "CURSOR_TRACE_ID",
        "REMOTE_CONTAINERS",
    ] {
        if env::var_os(key).is_some() {
            return Ok("ide");
        }
    }
    if env::var("TERM_PROGRAM")
        .is_ok_and(|v| matches!(v.to_lowercase().as_str(), "vscode" | "cursor"))
    {
        return Ok("ide");
    }
    if env::var("CODEX_INTERNAL_ORIGINATOR_OVERRIDE").is_ok_and(|v| v != "codex_cli_rs") {
        return Ok("hosted");
    }
    #[cfg(target_os = "linux")]
    {
        let kernel =
            fs::read_to_string("/proc/sys/kernel/osrelease").context("read kernel environment")?;
        if kernel.to_ascii_lowercase().contains("microsoft") {
            return Ok("wsl");
        }
        for path in [
            "/.dockerenv",
            "/run/.containerenv",
            "/run/systemd/container",
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => return Ok("container"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).context("inspect container boundary"),
            }
        }
        if env::var_os("container").is_some() {
            return Ok("container");
        }
        let cgroups = fs::read_to_string("/proc/1/cgroup").context("inspect host cgroups")?;
        if ["docker", "kubepods", "containerd", "lxc", "libpod"]
            .iter()
            .any(|word| cgroups.contains(word))
        {
            return Ok("container");
        }
        // A mount/user namespace distinct from PID 1 is an isolated execution
        // surface, even when /etc/os-release looks like the native host.
        for namespace in ["mnt", "user", "pid"] {
            if fs::read_link(format!("/proc/self/ns/{namespace}"))?
                != fs::read_link(format!("/proc/1/ns/{namespace}"))?
            {
                return Ok("isolated-namespace");
            }
        }
    }
    Ok("native-cli")
}

pub fn observe() -> Result<Host> {
    let surface = surface()?.to_owned();
    #[cfg(target_os = "linux")]
    {
        let uname = rustix::system::uname();
        let arch = uname
            .machine()
            .to_str()
            .context("read native architecture")?
            .to_owned();
        if arch != env::consts::ARCH {
            bail!("emulated or mismatched executable architecture")
        }
        let release = fs::read("/etc/os-release").context("read exact distro identity")?;
        let text = std::str::from_utf8(&release)?;
        let id = release_field(text, "ID").context("missing distro ID")?;
        let version = release_field(text, "VERSION_ID").context("missing distro version")?;
        let build = fs::read_to_string("/proc/sys/kernel/version")?;
        Ok(Host {
            os: "linux".into(),
            arch,
            os_release: format!(
                "{id}:{version}:sha256:{}",
                crate::identity::hex(&Sha256::digest(&release))
            ),
            os_build: format!("{} {}", uname.release().to_str()?, build.trim()),
            surface,
        })
    }
    #[cfg(windows)]
    {
        let (arch, release, build) = windows_identity()?;
        Ok(Host {
            os: "windows".into(),
            arch,
            os_release: release,
            os_build: build,
            surface,
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    bail!("this native OS is not supported")
}

#[cfg(target_os = "linux")]
fn release_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut values = text
        .lines()
        .filter_map(|line| line.strip_prefix(key)?.strip_prefix('='));
    let value = values.next()?.trim_matches('"');
    if value.is_empty()
        || values.next().is_some()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return None;
    }
    Some(value)
}

#[cfg(windows)]
fn windows_identity() -> Result<(String, String, String)> {
    use windows_sys::Win32::System::{
        Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY, RegGetValueW},
        SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO},
    };
    #[repr(C)]
    struct OsVersion {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform: u32,
        service_pack: [u16; 128],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(version: *mut OsVersion) -> i32;
    }
    let mut v = OsVersion {
        size: std::mem::size_of::<OsVersion>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    if unsafe { RtlGetVersion(&mut v) } != 0 {
        bail!("cannot read exact Windows build")
    }
    let mut system: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe {
        GetNativeSystemInfo(&mut system);
    }
    let arch = match unsafe { system.Anonymous.Anonymous.wProcessorArchitecture } {
        9 => "x86_64",
        12 => "aarch64",
        _ => bail!("unsupported native Windows architecture"),
    };
    if arch != env::consts::ARCH {
        bail!("emulated Windows architecture is not certified")
    }
    let key: Vec<u16> = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0"
        .encode_utf16()
        .collect();
    let name: Vec<u16> = "UBR\0".encode_utf16().collect();
    let mut revision = 0u32;
    let mut length = 4u32;
    if unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            std::ptr::null_mut(),
            (&mut revision as *mut u32).cast(),
            &mut length,
        )
    } != 0
        || length != 4
    {
        bail!("cannot read Windows update build revision")
    }
    Ok((
        arch.into(),
        format!("windows:{}.{}", v.major, v.minor),
        format!("{}.{revision}", v.build),
    ))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn distro_identity_requires_unambiguous_literal_values() {
        assert_eq!(
            super::release_field("ID=ubuntu\nVERSION_ID=\"26.04\"", "ID"),
            Some("ubuntu")
        );
        assert_eq!(super::release_field("ID=ubuntu\nID=debian", "ID"), None);
        assert_eq!(super::release_field("ID=$(uname)", "ID"), None);
    }
}
