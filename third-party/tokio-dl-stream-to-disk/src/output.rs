use std::io;
use std::path::{Path, PathBuf};

/// An existing output directory pinned to an open Linux directory descriptor.
///
/// `open` rejects symlinks in every component, parent traversal and untrusted
/// directory ownership/write modes. Ancestors must be owned by root or the
/// effective user and not group/other writable (sticky ancestors are allowed).
/// The final directory must be owned by the effective user and not group/other
/// writable, even if sticky. `open` never creates directories or changes modes;
/// `create`/`create_child` create missing components privately (0700).
///
/// Keep this owner alive for ALL operations through `path()`, including temporary
/// file cleanup and publication. Use only validated single filenames or trusted
/// child directories: joining an absolute path, `..` or an untrusted symlink
/// beneath this path defeats the protection. Do not canonicalize before opening.
///
/// This prevents ancestor replacement from redirecting operations; it does not
/// isolate root, same-UID code, a malicious directory owner or a process allowed
/// to change permissions/ACLs. Such actors can still delete/replace entries,
/// including tempfiles and published files. This is not a filesystem sandbox or
/// a no-clobber publication primitive. Caller-specific file checks still apply.
/// Linux procfs must be available at `/proc`; other platforms fail closed.
#[derive(Debug)]
pub struct OutputDirectory {
    #[cfg(target_os = "linux")]
    directory: std::os::fd::OwnedFd,
    path: PathBuf,
}

impl OutputDirectory {
    /// Create missing components with private modes through pinned parents.
    pub fn create(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::open_create(path, true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::open(path)
        }
    }

    /// Create and pin a relative child tree without following symlinks.
    pub fn create_child(&self, path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::open_child_create(&self.directory, path, true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.open_child(path)
        }
    }

    /// Open and pin an existing absolute or current-directory-relative path.
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::open(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned output directories require Linux procfs",
            ))
        }
    }

    /// Pin an existing relative child without reopening the procfs path.
    /// Absolute paths, parent traversal and symlink components are rejected.
    /// The returned guard owns its descriptor independently of the parent.
    pub fn open_child(&self, path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::open_child(&self.directory, path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned output directories require Linux procfs",
            ))
        }
    }

    /// Stable descriptor path, valid only while this guard remains alive.
    /// Do not pass it back to `open`: procfs descriptor entries are symlinks.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    const FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;

    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a safe directory path",
        )
    }

    fn open_at(parent: RawFd, name: &OsStr, nofollow: bool) -> io::Result<OwnedFd> {
        let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        let flags = FLAGS | if nofollow { libc::O_NOFOLLOW } else { 0 };
        // SAFETY: name is NUL-terminated, parent is AT_FDCWD or a live directory
        // descriptor, and no mode argument is needed without O_CREAT.
        let fd = unsafe { libc::openat(parent, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returned a new descriptor owned only here.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn stat(directory: &OwnedFd) -> io::Result<libc::stat> {
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the descriptor is live and metadata points to writable storage.
        if unsafe { libc::fstat(directory.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized metadata completely.
        Ok(unsafe { metadata.assume_init() })
    }

    fn trusted(directory: &OwnedFd, final_directory: bool) -> io::Result<()> {
        let metadata = stat(directory)?;
        // SAFETY: geteuid has no arguments or memory safety preconditions.
        let user = unsafe { libc::geteuid() };
        let owned = metadata.st_uid == user;
        let writable = metadata.st_mode & 0o022 != 0;
        let sticky = metadata.st_mode & libc::S_ISVTX != 0;
        let allowed = if final_directory {
            owned && !writable
        } else {
            (owned || metadata.st_uid == 0) && (!writable || sticky)
        };
        if !allowed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe output directory ownership or write permissions",
            ));
        }
        Ok(())
    }

    pub(super) fn open(path: &Path) -> io::Result<OutputDirectory> {
        open_create(path, false)
    }

    fn child_at(parent: &OwnedFd, name: &OsStr, create: bool) -> io::Result<OwnedFd> {
        match open_at(parent.as_raw_fd(), name, true) {
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                let name_c = CString::new(name.as_bytes()).map_err(|_| invalid())?;
                // SAFETY: parent is live, name is one NUL-terminated component.
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_at(parent.as_raw_fd(), name, true)
            }
            result => result,
        }
    }

    pub(super) fn open_create(path: &Path, create: bool) -> io::Result<OutputDirectory> {
        if path.as_os_str().is_empty() {
            return Err(invalid());
        }
        let mut directory = open_at(
            libc::AT_FDCWD,
            OsStr::new(if path.is_absolute() { "/" } else { "." }),
            true,
        )?;
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    trusted(&directory, false)?;
                    directory = child_at(&directory, name, create)?;
                }
                Component::RootDir | Component::CurDir => {}
                _ => return Err(invalid()),
            }
        }
        finish(directory)
    }

    pub(super) fn open_child(parent: &OwnedFd, path: &Path) -> io::Result<OutputDirectory> {
        open_child_create(parent, path, false)
    }

    pub(super) fn open_child_create(
        parent: &OwnedFd,
        path: &Path,
        create: bool,
    ) -> io::Result<OutputDirectory> {
        if path.as_os_str().is_empty() || path.is_absolute() {
            return Err(invalid());
        }
        trusted(parent, true)?;
        let mut directory = open_at(parent.as_raw_fd(), OsStr::new("."), true)?;
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    trusted(&directory, false)?;
                    directory = child_at(&directory, name, create)?;
                }
                Component::CurDir => {}
                _ => return Err(invalid()),
            }
        }
        finish(directory)
    }

    fn finish(directory: OwnedFd) -> io::Result<OutputDirectory> {
        finish_at(directory, Path::new("/proc/self/fd"))
    }

    // Private explicit seam for unavailable/non-procfs fixtures. Production
    // always uses the fixed procfs path above, never environment configuration.
    pub(super) fn finish_at(directory: OwnedFd, proc_path: &Path) -> io::Result<OutputDirectory> {
        trusted(&directory, true)?;
        // Intentionally follow procfs's own `self` link, never user path links.
        let proc = open_at(libc::AT_FDCWD, proc_path.as_os_str(), true)?;
        let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: proc is live and filesystem points to writable statfs storage.
        if unsafe { libc::fstatfs(proc.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized filesystem completely.
        if unsafe { filesystem.assume_init() }.f_type != libc::PROC_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux procfs is required",
            ));
        }
        let name = directory.as_raw_fd().to_string();
        // Descriptor entries are intentionally followed, only after verifying
        // the parent is procfs; the reopened inode must match our owned handle.
        let reopened = open_at(proc.as_raw_fd(), OsStr::new(&name), false)?;
        let expected = stat(&directory)?;
        let actual = stat(&reopened)?;
        if expected.st_dev != actual.st_dev || expected.st_ino != actual.st_ino {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unavailable pinned directory path",
            ));
        }
        Ok(OutputDirectory {
            directory,
            path: proc_path.join(name),
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "output_tests.rs"]
mod tests;
