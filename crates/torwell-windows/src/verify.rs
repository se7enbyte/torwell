//! Executable verification: absolute, canonical, regular file (no links/junction redirection),
//! parent directory not writable by unprivileged users, and SHA-256 equal to the pinned digest.
//! Authenticode is not checked here (requires WinVerifyTrust); the digest pin is the trust root.
//! Residual risk: a TOCTOU window between this check and process creation is closed only by
//! the directory ACL requirement.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};
use crate::sha256::{sha256, to_hex};

pub trait PathGuard {
    /// Creates `dir` if missing and restricts it to Administrators and SYSTEM, then verifies.
    fn ensure_secure_dir(&self, dir: &Path) -> Result<()>;
    /// `dir` and ownership are Administrators/SYSTEM only (state directory).
    fn verify_admin_only(&self, path: &Path) -> Result<()>;
    /// Nobody but admins/SYSTEM/TrustedInstaller can modify `dir` (executable directories).
    fn verify_not_user_writable(&self, dir: &Path) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub path: PathBuf,
    pub sha256: [u8; 32],
}

pub const MAX_EXE_BYTES: u64 = 256 * 1024 * 1024;

fn strip_verbatim(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(r) => PathBuf::from(r),
        None => p.to_path_buf(),
    }
}

pub fn verify_executable(p: &Pinned, guard: &dyn PathGuard) -> Result<()> {
    let name = p.path.display();
    let bad = |m: &str| Error::Preflight(vec![format!("{name}: {m}")]);
    if !p.path.is_absolute()
        || p.path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(bad("must be an absolute path without '.'/'..'"));
    }
    let meta = fs::symlink_metadata(&p.path).map_err(|e| bad(&format!("not readable: {e}")))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(bad("must be a regular file (not a link)"));
    }
    if meta.len() > MAX_EXE_BYTES {
        return Err(bad("unexpectedly large"));
    }
    let canon = fs::canonicalize(&p.path).map_err(|e| bad(&format!("cannot canonicalize: {e}")))?;
    let canon = strip_verbatim(&canon);
    if !crate::proc::same_image(&canon, &p.path) {
        return Err(bad(&format!(
            "path traverses a link or alias (resolves to {})",
            canon.display()
        )));
    }
    let parent = p.path.parent().ok_or_else(|| bad("no parent directory"))?;
    guard
        .verify_not_user_writable(parent)
        .map_err(|e| bad(&format!("directory not protected: {e}")))?;
    let mut data = Vec::new();
    fs::File::open(&p.path)
        .and_then(|f| f.take(MAX_EXE_BYTES).read_to_end(&mut data))
        .map_err(|e| bad(&format!("read failed: {e}")))?;
    let got = sha256(&data);
    if got != p.sha256 {
        return Err(bad(&format!(
            "digest mismatch (got {}, pinned {})",
            to_hex(&got),
            to_hex(&p.sha256)
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testutil::{temp_dir, FakeGuard};

    fn pinned(path: &Path, data: &[u8]) -> Pinned {
        Pinned {
            path: path.to_path_buf(),
            sha256: sha256(data),
        }
    }

    #[test]
    fn accepts_matching_digest_in_protected_dir() {
        let d = temp_dir("verify-ok");
        let f = d.join("tor.exe");
        fs::write(&f, b"tor-bytes").unwrap();
        verify_executable(&pinned(&f, b"tor-bytes"), &FakeGuard::default()).unwrap();
    }

    #[test]
    fn rejects_digest_mismatch_unprotected_dir_symlink_and_relative() {
        let d = temp_dir("verify-bad");
        let f = d.join("tor.exe");
        fs::write(&f, b"evil").unwrap();
        assert!(verify_executable(&pinned(&f, b"tor-bytes"), &FakeGuard::default()).is_err());
        assert!(verify_executable(
            &pinned(&f, b"evil"),
            &FakeGuard {
                writable: true,
                ..Default::default()
            }
        )
        .is_err());
        let link = d.join("link.exe");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(verify_executable(&pinned(&link, b"evil"), &FakeGuard::default()).is_err());
        let rel = Pinned {
            path: PathBuf::from("tor.exe"),
            sha256: sha256(b"evil"),
        };
        assert!(verify_executable(&rel, &FakeGuard::default()).is_err());
        let dots = Pinned {
            path: d.join("..").join("x"),
            sha256: sha256(b""),
        };
        assert!(verify_executable(&dots, &FakeGuard::default()).is_err());
    }

    #[test]
    fn directory_symlink_in_path_is_rejected() {
        let d = temp_dir("verify-dirlink");
        let real = d.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("tor.exe"), b"x").unwrap();
        let alias = d.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert!(
            verify_executable(&pinned(&alias.join("tor.exe"), b"x"), &FakeGuard::default())
                .is_err()
        );
    }
}
