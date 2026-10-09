//! Data directory security checks (TASK-005C-1).
//!
//! Unix V1 requirements for the bastion data directory:
//! - Owned by the current effective user.
//! - Mode `0700` or stricter (no group/other permission bits).
//! - The directory itself is not a symlink; neither is its parent.
//! - The parent directory is owned by the current user or root and is
//!   not writable by group/other (otherwise an untrusted user could
//!   replace the data directory with their own).
//! - `bastion.db` and `bastion.lock` are owned by the current user with
//!   mode `0600` or stricter and are not symlinks.
//! - Existing permissions are **never** repaired automatically: a
//!   violation is a startup failure (`STARTUP_FAILED`), never a silent
//!   fix and never a fallback to legacy mode.
//!
//! Non-Unix platforms: bastion mode refuses to start. We cannot
//! guarantee equivalent filesystem isolation there, and silently
//! skipping these checks would be worse than refusing.

use std::path::Path;

/// Check the bastion data directory itself (ownership, mode, symlinks,
/// parent safety). Called after the directory exists.
pub fn check_data_dir_security(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        check_data_dir_unix(dir)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err("bastion startup failed: bastion mode requires Unix filesystem permission \
             checks (ownership + 0700); refusing to start on this platform rather than \
             silently skipping the security checks"
            .to_string())
    }
}

/// Check a bastion data file (`bastion.db`, `bastion.lock`): not a
/// symlink, owned by the current user, mode `0600` or stricter.
pub fn check_data_file_security(path: &Path, what: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        check_file_unix(path, what)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, what);
        Err("bastion startup failed: bastion mode requires Unix filesystem permission \
             checks; refusing to start on this platform rather than silently skipping \
             the security checks"
            .to_string())
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid is async-signal-safe and has no failure mode.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn check_data_dir_unix(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    // 1. The path itself must not be a symlink. `symlink_metadata`
    //    does not follow the final component.
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("bastion startup failed: cannot stat bastion dir {}: {e}", dir.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "bastion startup failed: bastion dir {} is a symlink; refusing to follow untrusted links",
            dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!("bastion startup failed: bastion dir {} is not a directory", dir.display()));
    }

    // 2. Owned by the current effective user.
    let euid = current_uid();
    if meta.uid() != euid {
        return Err(format!(
            "bastion startup failed: bastion dir {} is owned by uid {} (expected euid {euid}); \
             refusing to use a directory owned by another user",
            dir.display(),
            meta.uid()
        ));
    }

    // 3. Mode 0700 or stricter: no group/other permission bits at all.
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "bastion startup failed: bastion dir {} has insecure permissions {mode:04o}; \
             require 0700 or stricter (no group/other access). Permissions are not repaired \
             automatically — fix them and restart",
            dir.display()
        ));
    }

    // 4. Parent directory: must not be a symlink, must be owned by us
    //    or root, and must not be writable by group/other. Otherwise
    //    an untrusted user could replace the data directory.
    let parent = dir
        .parent()
        .ok_or_else(|| format!("bastion startup failed: bastion dir {} has no parent; refusing", dir.display()))?;
    // A relative dir like "bastion" has parent ""; resolve against ".".
    let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let pmeta = std::fs::symlink_metadata(parent).map_err(|e| {
        format!("bastion startup failed: cannot stat parent dir {} of bastion dir: {e}", parent.display())
    })?;
    if pmeta.file_type().is_symlink() {
        return Err(format!(
            "bastion startup failed: parent dir {} of bastion dir is a symlink; refusing",
            parent.display()
        ));
    }
    if !pmeta.is_dir() {
        return Err(format!(
            "bastion startup failed: parent {} of bastion dir is not a directory; refusing",
            parent.display()
        ));
    }
    let p_uid = pmeta.uid();
    if p_uid != euid && p_uid != 0 {
        return Err(format!(
            "bastion startup failed: parent dir {} of bastion dir is owned by uid {p_uid} \
             (expected euid {euid} or root); an untrusted owner could replace the data directory",
            parent.display()
        ));
    }
    let p_mode = pmeta.mode() & 0o777;
    if p_mode & 0o022 != 0 {
        return Err(format!(
            "bastion startup failed: parent dir {} of bastion dir is writable by group/other \
             ({p_mode:04o}); untrusted users could replace the data directory",
            parent.display()
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn check_file_unix(path: &Path, what: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("bastion startup failed: cannot stat {what} {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("bastion startup failed: {what} {} is a symlink; refusing", path.display()));
    }
    if !meta.is_file() {
        return Err(format!("bastion startup failed: {what} {} is not a regular file", path.display()));
    }
    let euid = current_uid();
    if meta.uid() != euid {
        return Err(format!(
            "bastion startup failed: {what} {} is owned by uid {} (expected euid {euid}); refusing",
            path.display(),
            meta.uid()
        ));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "bastion startup failed: {what} {} has insecure permissions {mode:04o}; \
             require 0600 or stricter. Permissions are not repaired automatically",
            path.display()
        ));
    }
    Ok(())
}

/// Create a directory (and parents) with secure permissions when it
/// does not already exist. Existing directories are never
/// re-permissioned — use [`check_data_dir_security`] to validate.
#[cfg(unix)]
pub fn create_dir_secure(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    if std::fs::symlink_metadata(dir).is_ok() {
        return Ok(()); // exists (or is a symlink) — caller validates
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("bastion startup failed: cannot create bastion dir {}: {e}", dir.display()))?;
    // Newly created: establish 0700 at creation time. This is not a
    // repair of existing permissions.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("bastion startup failed: cannot set 0700 on new bastion dir {}: {e}", dir.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn create_dir_secure(dir: &Path) -> Result<(), String> {
    let _ = dir;
    Err("bastion startup failed: bastion mode requires Unix; refusing to start".to_string())
}

/// Restrict a newly created data file to `0600`. Only call for files
/// this process created — existing files are validated, never fixed.
#[cfg(unix)]
pub fn secure_new_file(path: &Path, what: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("bastion startup failed: cannot set 0600 on new {what} {}: {e}", path.display()))
}

#[cfg(not(unix))]
pub fn secure_new_file(path: &Path, what: &str) -> Result<(), String> {
    let _ = (path, what);
    Err("bastion startup failed: bastion mode requires Unix; refusing to start".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn make_temp_case(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("bastion-fs-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[cfg(unix)]
    #[test]
    fn secure_dir_passes() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("ok");
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_data_dir_security(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn dir_0755_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("755");
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = check_data_dir_security(&dir).unwrap_err();
        assert!(err.contains("insecure permissions"), "unexpected: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn dir_0777_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("777");
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_data_dir_security(&dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn dir_0700_stricter_variants_pass() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o700, 0o500, 0o400] {
            let base = make_temp_case(&format!("m{mode:o}"));
            let dir = base.join("data");
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(check_data_dir_security(&dir).is_ok(), "mode {mode:o} should pass");
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_dir_rejected() {
        let base = make_temp_case("symlink");
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = check_data_dir_security(&link).unwrap_err();
        assert!(err.contains("symlink"), "unexpected: {err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_parent_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("wwparent");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = check_data_dir_security(&dir).unwrap_err();
        assert!(err.contains("writable by group/other"), "unexpected: {err}");
        // Restore so cleanup works.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn other_owner_dir_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("owner");
        let dir = base.join("data");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Try to give the dir to another uid. Only works as root;
        // skip the test otherwise.
        let changed = unsafe {
            libc::chown(std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap().as_ptr(), 65534, 65534)
        } == 0;
        if !changed {
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        let err = check_data_dir_security(&dir).unwrap_err();
        assert!(err.contains("owned by uid"), "unexpected: {err}");
        // Restore ownership for cleanup.
        unsafe {
            libc::chown(
                std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap().as_ptr(),
                libc::geteuid(),
                libc::getegid(),
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn data_file_perms_checked() {
        use std::os::unix::fs::PermissionsExt;
        let base = make_temp_case("file");
        let f = base.join("bastion.db");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_data_file_security(&f, "test file").is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_data_file_security(&f, "test file").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
