//! Secure directory handling for bastion data (Unix).
//!
//! Single source of truth for the bastion directory security policy,
//! used by [`crate::storage::SqliteStore::open`], [`crate::auth::AdminBootstrap`],
//! and (via delegation) dbx-web's startup checks. The policy:
//!
//! - New directories are created with mode `0700` **at creation time**
//!   (`DirBuilder::mode`), so there is never a window where the
//!   directory exists with looser permissions. The mode is passed to
//!   `mkdir(2)` directly; it does not depend on the process umask
//!   (`0700` has no group/other bits for the umask to mask).
//! - Existing directories are **validated, never repaired**: they must
//!   not be symlinks, must be owned by the current euid, must be
//!   `0700` or stricter, and their parent must not be a symlink, must
//!   be owned by euid or root, and must not be group/other-writable.
//!   Insecure existing directories are refused with a diagnosable error.
//!
//! This module has no dependency on dbx-web; dbx-web delegates to it.

use std::path::Path;

use crate::error::{BastionError, Result};

/// Required mode for bastion data directories: owner-only.
const SECURE_DIR_MODE: u32 = 0o700;

/// Ensure `dir` exists as a secure bastion directory.
///
/// - Missing: created (recursively) with `0700` at creation time.
/// - Present: validated (symlink / ownership / permissions / parent);
///   insecure directories are refused, never silently repaired.
///
/// Non-Unix platforms are refused outright: the permission model
/// below is Unix-specific.
pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        // Fast path: if the path already exists (and is not a symlink),
        // validate it. `symlink_metadata` does not follow the final
        // component, so a symlink is detected rather than followed.
        match std::fs::symlink_metadata(dir) {
            Ok(_) => validate_existing_dir(dir),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_secure_dir(dir),
            Err(e) => Err(BastionError::Migration(format!("cannot stat bastion dir {}: {e}", dir.display()))),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(BastionError::Migration("bastion directory security requires Unix; refusing".to_string()))
    }
}

/// Create `dir` (and missing parents) with `0700` at creation time.
///
/// `DirBuilder::mode` passes the mode to `mkdir(2)` directly — the
/// directory never exists with umask-derived looser permissions.
/// (`0700 & !umask == 0700` for any umask, since 0700 has no
/// group/other bits.)
#[cfg(unix)]
fn create_secure_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(SECURE_DIR_MODE)
        .create(dir)
        .map_err(|e| BastionError::Migration(format!("cannot create bastion dir {}: {e}", dir.display())))?;
    // Validate what we created (defense in depth: confirms the mode
    // actually landed as 0700 and the path is not a symlink).
    validate_existing_dir(dir)
}

/// Validate an existing directory: no symlinks, owned by euid,
/// `0700` or stricter, trustworthy parent. Never repairs.
#[cfg(unix)]
fn validate_existing_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| BastionError::Migration(format!("cannot stat bastion dir {}: {e}", dir.display())))?;
    if meta.file_type().is_symlink() {
        return Err(BastionError::Migration(format!(
            "bastion dir {} is a symlink; refusing to follow untrusted links",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(BastionError::Migration(format!("bastion dir {} is not a directory", dir.display())));
    }

    let euid = current_uid();
    if meta.uid() != euid {
        return Err(BastionError::Migration(format!(
            "bastion dir {} is owned by uid {} (expected euid {euid}); refusing to use a directory owned by another user",
            dir.display(),
            meta.uid()
        )));
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(BastionError::Migration(format!(
            "bastion dir {} has insecure permissions {mode:04o}; require 0700 or stricter \
             (no group/other access). Permissions are not repaired automatically",
            dir.display()
        )));
    }

    // Parent: must not be a symlink, must be owned by euid or root,
    // and must not be writable by group/other.
    let parent = dir
        .parent()
        .ok_or_else(|| BastionError::Migration(format!("bastion dir {} has no parent; refusing", dir.display())))?;
    let parent = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let pmeta = std::fs::symlink_metadata(parent).map_err(|e| {
        BastionError::Migration(format!("cannot stat parent dir {} of bastion dir: {e}", parent.display()))
    })?;
    if pmeta.file_type().is_symlink() {
        return Err(BastionError::Migration(format!(
            "parent dir {} of bastion dir is a symlink; refusing",
            parent.display()
        )));
    }
    if !pmeta.is_dir() {
        return Err(BastionError::Migration(format!(
            "parent {} of bastion dir is not a directory; refusing",
            parent.display()
        )));
    }
    let p_uid = pmeta.uid();
    if p_uid != euid && p_uid != 0 {
        return Err(BastionError::Migration(format!(
            "parent dir {} of bastion dir is owned by uid {p_uid} (expected euid {euid} or root)",
            parent.display()
        )));
    }
    let p_mode = pmeta.mode() & 0o777;
    // World-writable parent without the sticky bit: untrusted users
    // could rename/replace the bastion directory. The sticky bit
    // (e.g. /tmp at 1777) restricts rename/delete to the owner, so it
    // is accepted.
    let has_sticky = pmeta.mode() & 0o1000 != 0;
    if p_mode & 0o022 != 0 && !has_sticky {
        return Err(BastionError::Migration(format!(
            "parent dir {} of bastion dir is writable by group/other ({p_mode:04o}) without the sticky bit",
            parent.display()
        )));
    }

    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: geteuid is async-signal-safe and has no failure mode.
    unsafe { libc::geteuid() }
}

/// Pre-create a new database file with `0600` before the SQLite
/// connection opens it, so the file never exists with looser
/// permissions. Existing files are left untouched (validated
/// elsewhere, never repaired).
#[cfg(unix)]
pub fn precreate_secure_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(BastionError::Migration(format!("cannot pre-create bastion db file {}: {e}", path.display()))),
    }
}

#[cfg(not(unix))]
pub fn precreate_secure_file(path: &Path) -> Result<()> {
    let _ = path;
    Err(BastionError::Migration("bastion file security requires Unix; refusing".to_string()))
}

/// Validate an existing database file BEFORE SQLite opens it.
/// Rejects symlinks, non-regular files, wrong ownership, and insecure
/// permissions. Never repairs: an untrusted old file is refused with
/// a diagnosable error.
#[cfg(unix)]
pub(crate) fn validate_existing_file(path: &Path, what: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| BastionError::Migration(format!("cannot stat {what} {}: {e}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Err(BastionError::Migration(format!(
            "{what} {} is a symlink; refusing to follow untrusted links",
            path.display()
        )));
    }
    if !meta.file_type().is_file() {
        return Err(BastionError::Migration(format!("{what} {} is not a regular file; refusing", path.display())));
    }
    let euid = current_uid();
    if meta.uid() != euid {
        return Err(BastionError::Migration(format!(
            "{what} {} is owned by uid {} (expected euid {euid}); refusing",
            path.display(),
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(BastionError::Migration(format!(
            "{what} {} has insecure permissions {mode:04o}; require 0600 or stricter. \
             Permissions are not repaired automatically",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn validate_existing_file(path: &Path, what: &str) -> Result<()> {
    let _ = (path, what);
    Err(BastionError::Migration("bastion file security requires Unix; refusing".to_string()))
}

/// Anti-TOCTOU guard: open an existing file with `O_NOFOLLOW` so a
/// symlink swap between validation and the SQLite open fails instead
/// of being followed. The parent directory is already `0700`/
/// euid-owned at this point, so no other user can swap the file —
/// this is defense in depth for the check→open window.
///
/// Returns `Ok(())` when the file does not exist (caller will create
/// it securely).
#[cfg(unix)]
pub(crate) fn nofollow_open_check(path: &Path, what: &str) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let file = match std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // ELOOP or any other open failure: refuse.
        Err(e) => {
            return Err(BastionError::Migration(format!(
                "{what} {} cannot be opened without following symlinks ({e}); refusing",
                path.display()
            )))
        }
    };
    // Confirm via fstat on the open fd: must still be a regular file
    // owned by euid (the fd cannot be swapped under us).
    let fd = file.as_raw_fd();
    let stat: libc::stat = unsafe {
        let mut s = std::mem::zeroed();
        if libc::fstat(fd, &mut s) != 0 {
            return Err(BastionError::Migration(format!("{what} {}: fstat failed; refusing", path.display())));
        }
        s
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(BastionError::Migration(format!(
            "{what} {} is not a regular file (fstat); refusing",
            path.display()
        )));
    }
    if stat.st_uid != current_uid() {
        return Err(BastionError::Migration(format!(
            "{what} {} changed ownership after validation; refusing",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn nofollow_open_check(path: &Path, what: &str) -> Result<()> {
    let _ = (path, what);
    Err(BastionError::Migration("bastion file security requires Unix; refusing".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn unique_base(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("bastion-secured-dir-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    #[cfg(unix)]
    #[test]
    fn new_dir_is_0700_under_umask_0022() {
        use std::os::unix::fs::PermissionsExt;

        // Set umask 0022 for this thread/process during the test.
        // SAFETY: umask is process-global; tests in this module run on
        // the default test harness which may run tests in parallel.
        // We set and restore it immediately around the creation.
        let old = unsafe { libc::umask(0o022) };
        let dir = unique_base("umask").join("bastion");
        let r = ensure_secure_dir(&dir);
        unsafe { libc::umask(old) };
        r.unwrap();

        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "new dir must be 0700 even under umask 0022");
    }

    #[cfg(unix)]
    #[test]
    fn existing_insecure_dir_is_refused_not_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_base("insecure");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = ensure_secure_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("insecure permissions"), "unexpected: {err}");

        // Not silently repaired: still 0755.
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_dir_is_refused() {
        let base = unique_base("symlink");
        let target = base.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = ensure_secure_dir(&link).unwrap_err();
        assert!(err.to_string().contains("symlink"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn precreate_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_base("file");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("bastion.db");
        precreate_secure_file(&file).unwrap();

        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new db file must be 0600");
        // Idempotent: existing file is left alone.
        precreate_secure_file(&file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_file_is_rejected() {
        let base = unique_base("symlink-file");
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("real.db");
        std::fs::write(&target, b"sqlite").unwrap();
        let link = base.join("bastion.db");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = validate_existing_file(&link, "bastion database").unwrap_err();
        assert!(err.to_string().contains("symlink"), "unexpected: {err}");
        // The O_NOFOLLOW guard also rejects it.
        let err = nofollow_open_check(&link, "bastion database").unwrap_err();
        assert!(err.to_string().contains("symlink") || err.to_string().contains("ELOOP"), "unexpected: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn existing_insecure_file_is_rejected_not_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_base("insecure-file");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("bastion.db");
        std::fs::write(&file, b"sqlite").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = validate_existing_file(&file, "bastion database").unwrap_err();
        assert!(err.to_string().contains("insecure permissions"), "unexpected: {err}");

        // Not silently repaired: still 0644.
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn existing_secure_file_passes() {
        use std::os::unix::fs::PermissionsExt;

        let base = unique_base("secure-file");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("bastion.db");
        std::fs::write(&file, b"sqlite").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();

        validate_existing_file(&file, "bastion database").unwrap();
        nofollow_open_check(&file, "bastion database").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn non_regular_file_is_rejected() {
        let base = unique_base("dir-as-file");
        let dir_as_file = base.join("bastion.db");
        std::fs::create_dir_all(&dir_as_file).unwrap();

        let err = validate_existing_file(&dir_as_file, "bastion database").unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "unexpected: {err}");
    }
}
