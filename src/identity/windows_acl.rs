//! Conservative NTFS owner/DACL validation for protected paths.
//! A current-user, SYSTEM or Administrators owner may change its own DACL.
//! Other principals may only create new names in an ancestor. The protected
//! leaf itself must grant them no create, write, delete or ACL rights.
//! Unknown ACE forms fail closed until they have native review coverage.

use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    mem::size_of,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path, Prefix},
    ptr::{addr_of, null_mut},
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{GENERIC_ALL, GENERIC_WRITE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, IsValidAcl, IsValidSid, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WinBuiltinAdministratorsSid,
        WinCreatorOwnerSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA, GetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const INHERIT_ONLY_ACE: u8 = 0x08;
const UNTRUSTED_WRITE: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;
const UNTRUSTED_REPLACEMENT: u32 = UNTRUSTED_WRITE & !(FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY);

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

pub(super) fn check_trusted_directory_chain(path: &Path) -> Result<()> {
    let mut components = path.components();
    if !path.is_absolute()
        || !matches!(
            components.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        )
    {
        bail!("protected Windows path must use a local absolute drive path")
    }
    let user_sid = crate::process::launcher_user_sid().context("read Windows launcher user SID")?;
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    // Keep each ancestor open without write/delete sharing while inspecting
    // later components. Directory ACL changes through preexisting handles
    // still require native review; an ACL snapshot alone cannot close races.
    let mut held = Vec::with_capacity(ancestors.len());
    let last = ancestors.len() - 1;
    for (index, directory) in ancestors.into_iter().enumerate() {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(directory)
            .with_context(|| format!("open protected directory: {}", directory.display()))?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            bail!("protected directory is not plain: {}", directory.display())
        }
        check_acl(&file, &user_sid, index == last)
            .with_context(|| format!("unsafe protected directory: {}", directory.display()))?;
        held.push(file);
    }
    Ok(())
}

pub(super) fn check_trusted_file_acl(file: &File) -> Result<()> {
    let user_sid = crate::process::launcher_user_sid().context("read Windows launcher user SID")?;
    check_acl(file, &user_sid, true)
}

fn check_acl(object: &File, user_sid: &[u8], protected_leaf: bool) -> Result<()> {
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = SecurityDescriptor(descriptor);
    if code != 0 || owner.is_null() || dacl.is_null() {
        // A null DACL grants everyone full access, not zero access.
        bail!("cannot read a bounded Windows owner and DACL")
    }
    if unsafe { IsValidSid(owner) } == 0 || !trusted_owner(owner, user_sid) {
        bail!("protected path has an untrusted owner")
    }
    if unsafe { IsValidAcl(dacl) } == 0 {
        bail!("protected path has an invalid DACL")
    }
    let acl_size = unsafe { (*dacl).AclSize as usize };
    let acl_start = dacl as usize;
    let acl_end = acl_start
        .checked_add(acl_size)
        .context("Windows ACL size overflow")?;
    for index in 0..unsafe { (*dacl).AceCount as u32 } {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            bail!("cannot inspect Windows directory ACE")
        }
        let ace_start = ace as usize;
        let header_end = ace_start
            .checked_add(size_of::<ACE_HEADER>())
            .context("Windows ACE size overflow")?;
        if ace_start
            < acl_start
                .checked_add(size_of::<ACL>())
                .context("Windows ACL size overflow")?
            || header_end > acl_end
        {
            bail!("Windows directory ACE is outside its DACL")
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let ace_end = ace_start
            .checked_add(header.AceSize as usize)
            .context("Windows ACE size overflow")?;
        if ace_end > acl_end || ace_end < header_end {
            bail!("Windows directory ACE has invalid bounds")
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            bail!("unsupported Windows directory ACE type")
        }
        // Inherit-only entries do not grant rights on this directory. Any
        // effective inherited grant is checked on the child in the same walk.
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if ace_end - ace_start < size_of::<ACCESS_ALLOWED_ACE>() {
            bail!("short Windows access-allowed ACE")
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid_start = addr_of!(allowed.SidStart) as usize;
        let sid_header_end = sid_start
            .checked_add(8)
            .context("Windows SID size overflow")?;
        if sid_header_end > ace_end {
            bail!("short Windows directory ACE SID")
        }
        let subauthorities = unsafe { *(sid_start as *const u8).add(1) as usize };
        let sid_end = sid_header_end
            .checked_add(
                subauthorities
                    .checked_mul(4)
                    .context("Windows SID size overflow")?,
            )
            .context("Windows SID size overflow")?;
        if sid_end > ace_end || unsafe { IsValidSid(sid_start as PSID) } == 0 {
            bail!("invalid Windows directory ACE SID")
        }
        let forbidden = if protected_leaf {
            UNTRUSTED_WRITE
        } else {
            // Creating another name in an ancestor cannot replace this path
            // component; write, delete and ACL/owner changes still fail.
            UNTRUSTED_REPLACEMENT
        };
        if allowed.Mask & forbidden != 0 && !trusted_grantee(sid_start as PSID, user_sid) {
            bail!("protected path grants write access to another principal")
        }
    }
    Ok(())
}

fn trusted_owner(sid: PSID, user_sid: &[u8]) -> bool {
    same_user(sid, user_sid)
        || (unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }) != 0
        || (unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }) != 0
}

fn trusted_grantee(sid: PSID, user_sid: &[u8]) -> bool {
    trusted_owner(sid, user_sid) || (unsafe { IsWellKnownSid(sid, WinCreatorOwnerSid) }) != 0
}

fn same_user(sid: PSID, user_sid: &[u8]) -> bool {
    (unsafe { EqualSid(sid, user_sid.as_ptr() as PSID) }) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    #[test]
    fn owner_controlled_chain_rejects_broad_write_acl() {
        let temp = tempfile::tempdir().unwrap();
        let nested = temp.path().join("space & unicode-测试");
        fs::create_dir(&nested).unwrap();
        check_trusted_directory_chain(&nested).unwrap();

        let status = Command::new("icacls")
            .arg(&nested)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "could not add disposable Users modify ACE"
        );
        assert!(check_trusted_directory_chain(&nested).is_err());
    }
}
