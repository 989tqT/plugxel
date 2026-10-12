// p1.5 atomic filesystem containment module
// provide kernel level atomic containment primitive

pub mod linux;
pub mod windows;

// wasi preview 1 error code from wasi libc errno values h
pub const WASI_ESUCCESS: i32 = 0;
pub const WASI_E2BIG: i32 = 1;
pub const WASI_EACCES: i32 = 2;
pub const WASI_EAGAIN: i32 = 6;
pub const WASI_EBADF: i32 = 8;
pub const WASI_EEXIST: i32 = 20;
pub const WASI_EINVAL: i32 = 28;
pub const WASI_EIO: i32 = 29;
pub const WASI_EISCONN: i32 = 30;
pub const WASI_EISDIR: i32 = 31;
pub const WASI_ELOOP: i32 = 32;
pub const WASI_ENOENT: i32 = 44;
pub const WASI_ENOSYS: i32 = 52;
pub const WASI_ENOTDIR: i32 = 54;
pub const WASI_ENOTEMPTY: i32 = 55;
pub const WASI_EPERM: i32 = 63;
pub const WASI_EROFS: i32 = 69;
pub const WASI_EXDEV: i32 = 75;
pub const WASI_ENOTCAPABLE: i32 = 76;

// map linux openat2 raw error to wasi preview 1 errno
pub fn map_linux_openat2_err(err: i32) -> i32 {
    match err {
        // boundary breach or symlink policy breach map to capability violation
        libc::EXDEV | libc::ELOOP => WASI_ENOTCAPABLE,
        // standard access or permission rejection
        libc::EACCES => WASI_EACCES,
        libc::EPERM => WASI_EPERM,
        libc::ENOENT => WASI_ENOENT,
        libc::EEXIST => WASI_EEXIST,
        libc::EISDIR => WASI_EISDIR,
        libc::ENOTDIR => WASI_ENOTDIR,
        libc::EINVAL => WASI_EINVAL,
        libc::ENOSYS => WASI_ENOTCAPABLE,
        // generic io fallback
        _ => WASI_EIO,
    }
}

// map linux leaf operation error to wasi preview 1 errno
pub fn map_linux_leaf_err(err: i32) -> i32 {
    match err {
        libc::EEXIST => WASI_EEXIST,
        libc::ENOENT => WASI_ENOENT,
        libc::EACCES => WASI_EACCES,
        libc::EPERM => WASI_EPERM,
        libc::EISDIR => WASI_EISDIR,
        libc::ENOTDIR => WASI_ENOTDIR,
        libc::ENOTEMPTY => WASI_ENOTEMPTY,
        _ => WASI_EIO,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub directory: bool,
    pub follow_symlinks: bool,
}

impl Default for OpenFlags {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        }
    }
}

pub trait AtomicContainmentEngine {
    // open file or directory strictly beneath root descriptor
    fn open_beneath(&self, root_fd: i32, rel_path: &str, flags: OpenFlags) -> Result<i32, i32>;

    // create directory leaf beneath root descriptor
    fn mkdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32>;

    // unlink file leaf beneath root descriptor
    fn unlink_file_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32>;

    // remove directory leaf beneath root descriptor
    fn rmdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasi_errno_values() {
        assert_eq!(WASI_EACCES, 2);
        assert_eq!(WASI_EAGAIN, 6);
        assert_eq!(WASI_EINVAL, 28);
        assert_eq!(WASI_EIO, 29);
        assert_eq!(WASI_EISCONN, 30);
        assert_eq!(WASI_EISDIR, 31);
        assert_eq!(WASI_ELOOP, 32);
        assert_eq!(WASI_ENOENT, 44);
        assert_eq!(WASI_ENOSYS, 52);
        assert_eq!(WASI_ENOTDIR, 54);
        assert_eq!(WASI_EPERM, 63);
        assert_eq!(WASI_EROFS, 69);
        assert_eq!(WASI_EXDEV, 75);
        assert_eq!(WASI_ENOTCAPABLE, 76);
    }

    #[test]
    fn test_openat2_err_mapping() {
        assert_eq!(map_linux_openat2_err(libc::EXDEV), WASI_ENOTCAPABLE);
        assert_eq!(map_linux_openat2_err(libc::ELOOP), WASI_ENOTCAPABLE);
        assert_eq!(map_linux_openat2_err(libc::EACCES), WASI_EACCES);
        assert_eq!(map_linux_openat2_err(libc::EPERM), WASI_EPERM);
        assert_eq!(map_linux_openat2_err(libc::ENOENT), WASI_ENOENT);
        assert_eq!(map_linux_openat2_err(libc::EEXIST), WASI_EEXIST);
        assert_eq!(map_linux_openat2_err(libc::EISDIR), WASI_EISDIR);
        assert_eq!(map_linux_openat2_err(libc::ENOTDIR), WASI_ENOTDIR);
        assert_eq!(map_linux_openat2_err(libc::EINVAL), WASI_EINVAL);
        assert_eq!(map_linux_openat2_err(libc::ENOSYS), WASI_ENOTCAPABLE);
        assert_eq!(map_linux_openat2_err(999), WASI_EIO);
    }

    #[test]
    fn test_leaf_err_mapping() {
        assert_eq!(map_linux_leaf_err(libc::EEXIST), WASI_EEXIST);
        assert_eq!(map_linux_leaf_err(libc::ENOENT), WASI_ENOENT);
        assert_eq!(map_linux_leaf_err(libc::EACCES), WASI_EACCES);
        assert_eq!(map_linux_leaf_err(libc::EPERM), WASI_EPERM);
        assert_eq!(map_linux_leaf_err(libc::EISDIR), WASI_EISDIR);
        assert_eq!(map_linux_leaf_err(libc::ENOTDIR), WASI_ENOTDIR);
        assert_eq!(map_linux_leaf_err(libc::ENOTEMPTY), WASI_ENOTEMPTY);
        assert_eq!(map_linux_leaf_err(999), WASI_EIO);
    }
}
