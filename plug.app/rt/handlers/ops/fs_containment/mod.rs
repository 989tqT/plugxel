// p1.5 atomic filesystem containment module
// provide kernel level atomic containment primitive

pub mod linux;
#[cfg(windows)]
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

pub type WasiErrno = i32;

// wasi preview 1 open flag bitmask
pub const WASI_O_CREAT: i32 = 1 << 0;
pub const WASI_O_DIRECTORY: i32 = 1 << 1;
pub const WASI_O_EXCL: i32 = 1 << 2;
pub const WASI_O_TRUNC: i32 = 1 << 3;

// complete wasi snapshot preview 1 right bitmask definition
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasiRights(pub u64);

impl WasiRights {
    pub const EMPTY: Self = Self(0);

    pub const FD_DATASYNC: u64 = 1 << 0;
    pub const FD_READ: u64 = 1 << 1;
    pub const FD_SEEK: u64 = 1 << 2;
    pub const FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
    pub const FD_SYNC: u64 = 1 << 4;
    pub const FD_TELL: u64 = 1 << 5;
    pub const FD_WRITE: u64 = 1 << 6;
    pub const FD_ADVISE: u64 = 1 << 7;
    pub const FD_ALLOCATE: u64 = 1 << 8;
    pub const PATH_CREATE_DIRECTORY: u64 = 1 << 9;
    pub const PATH_CREATE_FILE: u64 = 1 << 10;
    pub const PATH_LINK_SOURCE: u64 = 1 << 11;
    pub const PATH_LINK_TARGET: u64 = 1 << 12;
    pub const PATH_OPEN: u64 = 1 << 13;
    pub const FD_READDIR: u64 = 1 << 14;
    pub const PATH_READLINK: u64 = 1 << 15;
    pub const PATH_RENAME_SOURCE: u64 = 1 << 16;
    pub const PATH_RENAME_TARGET: u64 = 1 << 17;
    pub const PATH_FILESTAT_GET: u64 = 1 << 18;
    pub const PATH_FILESTAT_SET_SIZE: u64 = 1 << 19;
    pub const PATH_FILESTAT_SET_TIMES: u64 = 1 << 20;
    pub const FD_FILESTAT_GET: u64 = 1 << 21;
    pub const FD_FILESTAT_SET_SIZE: u64 = 1 << 22;
    pub const FD_FILESTAT_SET_TIMES: u64 = 1 << 23;
    pub const PATH_SYMLINK: u64 = 1 << 24;
    pub const PATH_REMOVE_DIRECTORY: u64 = 1 << 25;
    pub const PATH_UNLINK_FILE: u64 = 1 << 26;
    pub const POLL_FD_READWRITE: u64 = 1 << 27;
    pub const SOCK_SHUTDOWN: u64 = 1 << 28;

    // all 29 protocol valid right bit in wasi snapshot preview 1
    pub const ALL_VALID: u64 = (1 << 29) - 1;

    // plugxel compatibility sentinel for test plugin requesting maximum inherited right
    pub const PLUGXEL_COMPAT_MAX_RIGHTS: u64 = u64::MAX;

    // right actually supported by plugxel for directory descriptor
    // exclude unsupported symlink hardlink rename path_filestat and socket operation
    pub const SUPPORTED_DIRECTORY_BASE: Self = Self(
        Self::FD_DATASYNC
            | Self::FD_FDSTAT_SET_FLAGS
            | Self::FD_SYNC
            | Self::FD_ADVISE
            | Self::PATH_CREATE_DIRECTORY
            | Self::PATH_CREATE_FILE
            | Self::PATH_OPEN
            | Self::FD_READDIR
            | Self::PATH_FILESTAT_SET_SIZE
            | Self::FD_FILESTAT_GET
            | Self::FD_FILESTAT_SET_TIMES
            | Self::PATH_REMOVE_DIRECTORY
            | Self::PATH_UNLINK_FILE,
    );

    // right actually supported by plugxel for regular file descriptor
    pub const SUPPORTED_REGULAR_FILE_BASE: Self = Self(
        Self::FD_DATASYNC
            | Self::FD_READ
            | Self::FD_SEEK
            | Self::FD_FDSTAT_SET_FLAGS
            | Self::FD_SYNC
            | Self::FD_TELL
            | Self::FD_WRITE
            | Self::FD_ADVISE
            | Self::FD_ALLOCATE
            | Self::FD_FILESTAT_GET
            | Self::FD_FILESTAT_SET_SIZE
            | Self::FD_FILESTAT_SET_TIMES
            | Self::POLL_FD_READWRITE,
    );

    // right supported for inheritance from directory descriptor to child descriptor
    pub const SUPPORTED_DIRECTORY_INHERITING: Self =
        Self(Self::SUPPORTED_DIRECTORY_BASE.0 | Self::SUPPORTED_REGULAR_FILE_BASE.0);

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, required: u64) -> bool {
        (self.0 & required) == required
    }

    pub const fn is_protocol_valid(raw: u64) -> bool {
        (raw & !Self::ALL_VALID) == 0
    }

    // apply implicit right relation where fd_seek include fd_tell
    pub const fn with_implications(self) -> Self {
        if (self.0 & Self::FD_SEEK) != 0 {
            Self(self.0 | Self::FD_TELL)
        } else {
            self
        }
    }

    pub const fn permits_read(self) -> bool {
        self.contains(Self::FD_READ)
    }

    pub const fn permits_write(self) -> bool {
        self.contains(Self::FD_WRITE)
    }

    pub const fn permits_seek(self) -> bool {
        self.contains(Self::FD_SEEK)
    }

    // fd_seek imply fd_tell in wasi preview 1
    pub const fn permits_tell(self) -> bool {
        self.contains(Self::FD_TELL) || self.contains(Self::FD_SEEK)
    }

    // fd_read together with fd_seek permit fd_pread
    pub const fn permits_pread(self) -> bool {
        self.contains(Self::FD_READ | Self::FD_SEEK)
    }

    // fd_write together with fd_seek permit fd_pwrite
    pub const fn permits_pwrite(self) -> bool {
        self.contains(Self::FD_WRITE | Self::FD_SEEK)
    }

    pub const fn permits_filestat_get(self) -> bool {
        self.contains(Self::FD_FILESTAT_GET)
    }

    pub const fn permits_filestat_set_size(self) -> bool {
        self.contains(Self::FD_FILESTAT_SET_SIZE)
    }

    // verify parent directory base right before execute path_open creation or truncation
    // dsync require both fd_datasync and fd_sync per wasi preview 1 right definition
    // rsync require fd_sync and sync use fd_sync under plugxel compatibility policy
    pub const fn permits_path_open(
        self,
        create: bool,
        truncate: bool,
        fd_flags: DescriptorFlags,
    ) -> bool {
        if !self.contains(Self::PATH_OPEN) {
            return false;
        }
        if create && !self.contains(Self::PATH_CREATE_FILE) {
            return false;
        }
        if truncate && !self.contains(Self::PATH_FILESTAT_SET_SIZE) {
            return false;
        }
        if fd_flags.contains(DescriptorFlags::DSYNC)
            && !self.contains(Self::FD_DATASYNC | Self::FD_SYNC)
        {
            return false;
        }
        if fd_flags.contains(DescriptorFlags::RSYNC) && !self.contains(Self::FD_SYNC) {
            return false;
        }
        // plugxel compatibility policy require fd_sync for fdflag sync
        if fd_flags.contains(DescriptorFlags::SYNC) && !self.contains(Self::FD_SYNC) {
            return false;
        }
        true
    }
}

// wasi preview 1 descriptor flag bitmask
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorFlags(pub u16);

impl DescriptorFlags {
    pub const EMPTY: Self = Self(0);

    pub const APPEND: u16 = 1 << 0;
    pub const DSYNC: u16 = 1 << 1;
    pub const NONBLOCK: u16 = 1 << 2;
    pub const RSYNC: u16 = 1 << 3;
    pub const SYNC: u16 = 1 << 4;

    pub const ALL_VALID: u16 = (1 << 5) - 1;

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, flag: u16) -> bool {
        (self.0 & flag) == flag
    }

    pub const fn from_raw_validated(raw: u16) -> Result<Self, WasiErrno> {
        if (raw & !Self::ALL_VALID) != 0 {
            Err(WASI_EINVAL)
        } else {
            Ok(Self(raw))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorRights {
    pub base: WasiRights,
    pub inheriting: WasiRights,
}

impl DescriptorRights {
    // default capability right for preopened sandbox root directory
    pub const fn preopen_directory_default() -> Self {
        Self {
            base: WasiRights::SUPPORTED_DIRECTORY_BASE,
            inheriting: WasiRights::SUPPORTED_DIRECTORY_INHERITING,
        }
    }

    // construct validated right for directory descriptor
    pub const fn for_directory(base: WasiRights, inheriting: WasiRights) -> Result<Self, WasiErrno> {
        if (base.0 & !WasiRights::SUPPORTED_DIRECTORY_BASE.0) != 0 {
            return Err(WASI_ENOTCAPABLE);
        }
        if (inheriting.0 & !WasiRights::SUPPORTED_DIRECTORY_INHERITING.0) != 0 {
            return Err(WASI_ENOTCAPABLE);
        }
        Ok(Self { base, inheriting })
    }

    // construct validated right for regular file descriptor
    pub const fn for_regular_file(base: WasiRights) -> Result<Self, WasiErrno> {
        if (base.0 & !WasiRights::SUPPORTED_REGULAR_FILE_BASE.0) != 0 {
            return Err(WASI_ENOTCAPABLE);
        }
        Ok(Self {
            base: base.with_implications(),
            inheriting: WasiRights::EMPTY,
        })
    }

    // monotonically attenuate right via fd_fdstat_set_rights
    // reject unknown bit or any attempt to expand current base or inheriting right
    pub fn attenuate(&mut self, new_base_raw: u64, new_inheriting_raw: u64) -> Result<(), WasiErrno> {
        if !WasiRights::is_protocol_valid(new_base_raw)
            || !WasiRights::is_protocol_valid(new_inheriting_raw)
        {
            return Err(WASI_ENOTCAPABLE);
        }
        if (new_base_raw & !self.base.0) != 0 || (new_inheriting_raw & !self.inheriting.0) != 0 {
            return Err(WASI_ENOTCAPABLE);
        }
        self.base = WasiRights(new_base_raw);
        self.inheriting = WasiRights(new_inheriting_raw);
        Ok(())
    }

    // verify parent descriptor base and inheriting right for path_open operation
    pub const fn permits_path_open(
        &self,
        create: bool,
        truncate: bool,
        fd_flags: DescriptorFlags,
    ) -> bool {
        if !self.base.permits_path_open(create, truncate, fd_flags) {
            return false;
        }
        if fd_flags.contains(DescriptorFlags::DSYNC)
            && !self
                .inheriting
                .contains(WasiRights::FD_DATASYNC | WasiRights::FD_SYNC)
        {
            return false;
        }
        if fd_flags.contains(DescriptorFlags::RSYNC)
            && !self.inheriting.contains(WasiRights::FD_SYNC)
        {
            return false;
        }
        // plugxel compatibility policy require fd_sync in inheriting mask for fdflag sync
        if fd_flags.contains(DescriptorFlags::SYNC)
            && !self.inheriting.contains(WasiRights::FD_SYNC)
        {
            return false;
        }
        true
    }

    // validate parent capability right and derive child descriptor right for path_open
    // preserve exact u64 max compatibility extension while reject explicit escalation
    pub fn derive_child_rights(
        &self,
        create: bool,
        truncate: bool,
        directory: bool,
        fd_flags: DescriptorFlags,
        requested_base_raw: u64,
        requested_inheriting_raw: u64,
    ) -> Result<DescriptorRights, WasiErrno> {
        if !self.permits_path_open(create, truncate, fd_flags) {
            return Err(WASI_ENOTCAPABLE);
        }

        if directory {
            let derived_base = if requested_base_raw == WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS {
                WasiRights(self.inheriting.0 & WasiRights::SUPPORTED_DIRECTORY_BASE.0)
            } else {
                if !WasiRights::is_protocol_valid(requested_base_raw) {
                    return Err(WASI_ENOTCAPABLE);
                }
                if (requested_base_raw & !self.inheriting.0) != 0 {
                    return Err(WASI_ENOTCAPABLE);
                }
                if (requested_base_raw & !WasiRights::SUPPORTED_DIRECTORY_BASE.0) != 0 {
                    return Err(WASI_ENOTCAPABLE);
                }
                WasiRights(requested_base_raw)
            };

            let derived_inheriting =
                if requested_inheriting_raw == WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS {
                    WasiRights(self.inheriting.0 & WasiRights::SUPPORTED_DIRECTORY_INHERITING.0)
                } else {
                    if !WasiRights::is_protocol_valid(requested_inheriting_raw) {
                        return Err(WASI_ENOTCAPABLE);
                    }
                    if (requested_inheriting_raw & !self.inheriting.0) != 0 {
                        return Err(WASI_ENOTCAPABLE);
                    }
                    if (requested_inheriting_raw & !WasiRights::SUPPORTED_DIRECTORY_INHERITING.0) != 0 {
                        return Err(WASI_ENOTCAPABLE);
                    }
                    WasiRights(requested_inheriting_raw)
                };

            Self::for_directory(derived_base, derived_inheriting)
        } else {
            let derived_base = if requested_base_raw == WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS {
                WasiRights(self.inheriting.0 & WasiRights::SUPPORTED_REGULAR_FILE_BASE.0)
            } else {
                if !WasiRights::is_protocol_valid(requested_base_raw) {
                    return Err(WASI_ENOTCAPABLE);
                }
                if (requested_base_raw & !self.inheriting.0) != 0 {
                    return Err(WASI_ENOTCAPABLE);
                }
                if (requested_base_raw & !WasiRights::SUPPORTED_REGULAR_FILE_BASE.0) != 0 {
                    return Err(WASI_ENOTCAPABLE);
                }
                WasiRights(requested_base_raw)
            };

            if requested_inheriting_raw != WasiRights::PLUGXEL_COMPAT_MAX_RIGHTS {
                if !WasiRights::is_protocol_valid(requested_inheriting_raw) {
                    return Err(WASI_ENOTCAPABLE);
                }
                if (requested_inheriting_raw & !self.inheriting.0) != 0 {
                    return Err(WASI_ENOTCAPABLE);
                }
            }

            Self::for_regular_file(derived_base)
        }
    }
}

// shared runtime filesystem synchronization context
// guarantee single filelocktable instance across all runtime environment and descriptor
pub struct RuntimeFsContext {
    #[cfg(windows)]
    file_lock_table: std::sync::Arc<windows::FileLockTable>,
}

impl RuntimeFsContext {
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            file_lock_table: std::sync::Arc::new(windows::FileLockTable::new()),
        }
    }

    // return process wide shared runtime filesystem context
    pub fn shared() -> std::sync::Arc<Self> {
        static SHARED_CTX: std::sync::OnceLock<std::sync::Arc<RuntimeFsContext>> =
            std::sync::OnceLock::new();
        std::sync::Arc::clone(SHARED_CTX.get_or_init(|| std::sync::Arc::new(Self::new())))
    }

    #[cfg(windows)]
    pub fn file_lock_table(&self) -> &std::sync::Arc<windows::FileLockTable> {
        &self.file_lock_table
    }

    #[cfg(windows)]
    pub fn windows_engine(&self) -> windows::WindowsContainmentEngine {
        windows::WindowsContainmentEngine::with_lock_table(std::sync::Arc::clone(
            &self.file_lock_table,
        ))
    }

    pub fn linux_engine(&self) -> linux::LinuxContainmentEngine {
        linux::LinuxContainmentEngine::new()
    }
}

// handle based descriptor kind without host pathname authority
pub enum DescriptorKind {
    PreopenDir {
        dir_file: std::fs::File,
        guest_path: &'static str,
    },
    Directory {
        dir_file: std::fs::File,
    },
    RegularFile {
        // single source of truth for sequential descriptor file pointer
        file: std::sync::Mutex<std::fs::File>,
        #[cfg(windows)]
        file_id: windows::NtfsFileIdentity,
    },
}

// runtime descriptor state managed via arc in descriptor table
pub struct DescriptorState {
    kind: DescriptorKind,
    rights: std::sync::Mutex<DescriptorRights>,
    fd_flags: std::sync::Mutex<DescriptorFlags>,
}

impl DescriptorState {
    // construct preopened capability root directory descriptor
    pub fn new_preopen_dir(dir_file: std::fs::File, guest_path: &'static str) -> Self {
        Self {
            kind: DescriptorKind::PreopenDir {
                dir_file,
                guest_path,
            },
            rights: std::sync::Mutex::new(DescriptorRights::preopen_directory_default()),
            fd_flags: std::sync::Mutex::new(DescriptorFlags::EMPTY),
        }
    }

    // construct verified subdirectory descriptor
    pub fn new_directory(
        dir_file: std::fs::File,
        rights: DescriptorRights,
        fd_flags: DescriptorFlags,
    ) -> Result<Self, WasiErrno> {
        let validated_rights = DescriptorRights::for_directory(rights.base, rights.inheriting)?;
        let validated_flags = DescriptorFlags::from_raw_validated(fd_flags.0)?;
        Ok(Self {
            kind: DescriptorKind::Directory { dir_file },
            rights: std::sync::Mutex::new(validated_rights),
            fd_flags: std::sync::Mutex::new(validated_flags),
        })
    }

    // construct verified regular file descriptor with mandatory ntfs identity on windows
    pub fn new_regular_file(
        file: std::fs::File,
        rights: DescriptorRights,
        fd_flags: DescriptorFlags,
    ) -> Result<Self, WasiErrno> {
        let validated_rights = DescriptorRights::for_regular_file(rights.base)?;
        if rights.inheriting != WasiRights::EMPTY {
            return Err(WASI_ENOTCAPABLE);
        }
        let validated_flags = DescriptorFlags::from_raw_validated(fd_flags.0)?;
        #[cfg(windows)]
        let file_id = windows::query_file_identity(&file)?;

        Ok(Self {
            kind: DescriptorKind::RegularFile {
                file: std::sync::Mutex::new(file),
                #[cfg(windows)]
                file_id,
            },
            rights: std::sync::Mutex::new(validated_rights),
            fd_flags: std::sync::Mutex::new(validated_flags),
        })
    }

    pub fn kind(&self) -> &DescriptorKind {
        &self.kind
    }

    pub fn rights(&self) -> DescriptorRights {
        *self.rights.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_rights(&self, new_base_raw: u64, new_inheriting_raw: u64) -> Result<(), WasiErrno> {
        let mut guard = self.rights.lock().unwrap_or_else(|e| e.into_inner());
        guard.attenuate(new_base_raw, new_inheriting_raw)
    }

    pub fn fd_flags(&self) -> DescriptorFlags {
        *self.fd_flags.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_fd_flags(&self, new_flags_raw: u16) -> Result<(), WasiErrno> {
        let current_rights = self.rights();
        if !current_rights.base.contains(WasiRights::FD_FDSTAT_SET_FLAGS) {
            return Err(WASI_ENOTCAPABLE);
        }
        let validated = DescriptorFlags::from_raw_validated(new_flags_raw)?;
        let mut guard = self.fd_flags.lock().unwrap_or_else(|e| e.into_inner());
        *guard = validated;
        Ok(())
    }
}

// runtime containment contract with owned file handle lifecycle
pub trait RuntimeContainmentEngine {
    // open file or directory strictly beneath root directory handle and return owned file
    fn open_file_beneath(
        &self,
        root_dir: &std::fs::File,
        rel_path: &str,
        flags: OpenFlags,
    ) -> Result<std::fs::File, WasiErrno>;

    // create directory leaf beneath root directory handle
    fn mkdir_file_beneath(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno>;

    // unlink file leaf beneath root directory handle
    fn unlink_file_beneath_handle(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno>;

    // remove directory leaf beneath root directory handle
    fn rmdir_beneath_handle(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno>;
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

    #[test]
    fn test_wasi_rights_protocol_bits_and_kind_supported_masks() {
        assert_eq!(WasiRights::SOCK_SHUTDOWN, 1u64 << 28);
        assert_eq!(WasiRights::ALL_VALID, (1u64 << 29) - 1);
        assert!(WasiRights::is_protocol_valid(WasiRights::ALL_VALID));
        assert!(!WasiRights::is_protocol_valid(1u64 << 29));
        assert!(!WasiRights::is_protocol_valid(u64::MAX));

        // verify supported mask never include unsupported operation even when protocol valid
        let unsupported = WasiRights::SOCK_SHUTDOWN
            | WasiRights::PATH_SYMLINK
            | WasiRights::PATH_READLINK
            | WasiRights::PATH_RENAME_SOURCE
            | WasiRights::PATH_RENAME_TARGET
            | WasiRights::PATH_LINK_SOURCE
            | WasiRights::PATH_LINK_TARGET;
        assert_eq!(WasiRights::SUPPORTED_DIRECTORY_BASE.0 & unsupported, 0);
        assert_eq!(WasiRights::SUPPORTED_REGULAR_FILE_BASE.0 & unsupported, 0);
        assert_eq!(WasiRights::SUPPORTED_DIRECTORY_INHERITING.0 & unsupported, 0);

        // verify directory base exclude regular file io right
        assert!(!WasiRights::SUPPORTED_DIRECTORY_BASE.contains(WasiRights::FD_READ));
        assert!(!WasiRights::SUPPORTED_DIRECTORY_BASE.contains(WasiRights::FD_WRITE));
        assert!(!WasiRights::SUPPORTED_DIRECTORY_BASE.contains(WasiRights::FD_SEEK));
        assert!(!WasiRights::SUPPORTED_DIRECTORY_BASE.contains(WasiRights::FD_TELL));
        assert!(!WasiRights::SUPPORTED_DIRECTORY_BASE.contains(WasiRights::FD_FILESTAT_SET_SIZE));

        // verify regular file base exclude path operation right
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::PATH_OPEN));
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::PATH_CREATE_FILE));
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::PATH_CREATE_DIRECTORY));
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::PATH_UNLINK_FILE));
        assert!(!WasiRights::SUPPORTED_REGULAR_FILE_BASE.contains(WasiRights::PATH_REMOVE_DIRECTORY));
    }

    #[test]
    fn test_wasi_rights_implications_and_path_open_flags() {
        // fd_seek imply fd_tell
        let seek_only = WasiRights(WasiRights::FD_SEEK);
        assert!(seek_only.permits_seek());
        assert!(seek_only.permits_tell());
        assert!(seek_only.with_implications().contains(WasiRights::FD_TELL));

        let tell_only = WasiRights(WasiRights::FD_TELL);
        assert!(!tell_only.permits_seek());
        assert!(tell_only.permits_tell());

        // fd_pread require both fd_read and fd_seek
        assert!(!WasiRights(WasiRights::FD_READ).permits_pread());
        assert!(!WasiRights(WasiRights::FD_SEEK).permits_pread());
        assert!(WasiRights(WasiRights::FD_READ | WasiRights::FD_SEEK).permits_pread());

        // fd_pwrite require both fd_write and fd_seek
        assert!(!WasiRights(WasiRights::FD_WRITE).permits_pwrite());
        assert!(!WasiRights(WasiRights::FD_SEEK).permits_pwrite());
        assert!(WasiRights(WasiRights::FD_WRITE | WasiRights::FD_SEEK).permits_pwrite());

        // path_open permission check for o_creat and o_trunc and sync flag
        let base_open_only = WasiRights(WasiRights::PATH_OPEN);
        assert!(base_open_only.permits_path_open(false, false, DescriptorFlags::EMPTY));
        assert!(!base_open_only.permits_path_open(true, false, DescriptorFlags::EMPTY));
        assert!(!base_open_only.permits_path_open(false, true, DescriptorFlags::EMPTY));
        assert!(!base_open_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert!(!base_open_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::RSYNC)
        ));
        assert!(!base_open_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));

        let base_with_create = WasiRights(WasiRights::PATH_OPEN | WasiRights::PATH_CREATE_FILE);
        assert!(base_with_create.permits_path_open(true, false, DescriptorFlags::EMPTY));
        assert!(!base_with_create.permits_path_open(true, true, DescriptorFlags::EMPTY));

        let base_with_trunc = WasiRights(WasiRights::PATH_OPEN | WasiRights::PATH_FILESTAT_SET_SIZE);
        assert!(base_with_trunc.permits_path_open(false, true, DescriptorFlags::EMPTY));
        assert!(!base_with_trunc.permits_path_open(true, true, DescriptorFlags::EMPTY));

        let base_with_datasync_only = WasiRights(WasiRights::PATH_OPEN | WasiRights::FD_DATASYNC);
        assert!(!base_with_datasync_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert!(!base_with_datasync_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));

        let base_with_sync_only = WasiRights(WasiRights::PATH_OPEN | WasiRights::FD_SYNC);
        assert!(!base_with_sync_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert!(base_with_sync_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::RSYNC)
        ));
        assert!(base_with_sync_only.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));

        let base_with_both_sync =
            WasiRights(WasiRights::PATH_OPEN | WasiRights::FD_DATASYNC | WasiRights::FD_SYNC);
        assert!(base_with_both_sync.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
    }

    #[test]
    fn test_path_open_dsync_rsync_sync_capability_matrix() {
        let full_parent = DescriptorRights::preopen_directory_default();

        // 1. dsync with fd_datasync but without fd_sync must be denied
        let mut dsync_no_sync_base = full_parent;
        dsync_no_sync_base
            .attenuate(
                full_parent.base.0 & !WasiRights::FD_SYNC,
                full_parent.inheriting.0,
            )
            .unwrap();
        assert!(!dsync_no_sync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert_eq!(
            dsync_no_sync_base.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::DSYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        let mut dsync_no_sync_inh = full_parent;
        dsync_no_sync_inh
            .attenuate(
                full_parent.base.0,
                full_parent.inheriting.0 & !WasiRights::FD_SYNC,
            )
            .unwrap();
        assert!(!dsync_no_sync_inh.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert_eq!(
            dsync_no_sync_inh.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::DSYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // 2. dsync with fd_sync but without fd_datasync must be denied
        let mut dsync_no_datasync_base = full_parent;
        dsync_no_datasync_base
            .attenuate(
                full_parent.base.0 & !WasiRights::FD_DATASYNC,
                full_parent.inheriting.0,
            )
            .unwrap();
        assert!(!dsync_no_datasync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert_eq!(
            dsync_no_datasync_base.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::DSYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        let mut dsync_no_datasync_inh = full_parent;
        dsync_no_datasync_inh
            .attenuate(
                full_parent.base.0,
                full_parent.inheriting.0 & !WasiRights::FD_DATASYNC,
            )
            .unwrap();
        assert!(!dsync_no_datasync_inh.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert_eq!(
            dsync_no_datasync_inh.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::DSYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // 3. dsync with both fd_datasync and fd_sync must succeed
        assert!(full_parent.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::DSYNC)
        ));
        assert!(full_parent
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::DSYNC),
                WasiRights::FD_READ,
                0,
            )
            .is_ok());

        // 4. rsync without fd_sync must be denied and rsync with fd_sync must succeed
        assert!(!dsync_no_sync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::RSYNC)
        ));
        assert_eq!(
            dsync_no_sync_base.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::RSYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert!(dsync_no_datasync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::RSYNC)
        ));
        assert!(dsync_no_datasync_base
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::RSYNC),
                WasiRights::FD_READ,
                0,
            )
            .is_ok());

        // 5. sync compatibility policy require fd_sync on base and inheriting
        assert!(!dsync_no_sync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));
        assert_eq!(
            dsync_no_sync_base.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::SYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert!(!dsync_no_sync_inh.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));
        assert_eq!(
            dsync_no_sync_inh.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::SYNC),
                WasiRights::FD_READ,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert!(dsync_no_datasync_base.permits_path_open(
            false,
            false,
            DescriptorFlags(DescriptorFlags::SYNC)
        ));
        assert!(dsync_no_datasync_base
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags(DescriptorFlags::SYNC),
                WasiRights::FD_READ,
                0,
            )
            .is_ok());
    }

    #[test]
    fn test_descriptor_rights_inheritance_u64_max_compat_and_attenuation() {
        let mut parent = DescriptorRights::preopen_directory_default();

        // u64 max compatibility sentinel derive full supported regular file right
        let child_file = parent
            .derive_child_rights(
                true,
                true,
                false,
                DescriptorFlags::EMPTY,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert_eq!(child_file.base, WasiRights::SUPPORTED_REGULAR_FILE_BASE);
        assert_eq!(child_file.inheriting, WasiRights::EMPTY);

        // u64 max compatibility sentinel derive full supported directory right
        let child_dir = parent
            .derive_child_rights(
                false,
                false,
                true,
                DescriptorFlags::EMPTY,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert_eq!(child_dir.base, WasiRights::SUPPORTED_DIRECTORY_BASE);
        assert_eq!(child_dir.inheriting, WasiRights::SUPPORTED_DIRECTORY_INHERITING);

        // explicit right with fd_seek automatically imply fd_tell on regular file
        let seek_read_file = parent
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ | WasiRights::FD_SEEK,
                0,
            )
            .unwrap();
        assert!(seek_read_file.base.permits_pread());
        assert!(seek_read_file.base.permits_tell());
        assert!(!seek_read_file.base.permits_write());

        // reject unsupported protocol valid right such as sock_shutdown or path_symlink
        assert_eq!(
            parent.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ | WasiRights::SOCK_SHUTDOWN,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            parent.derive_child_rights(
                false,
                false,
                true,
                DescriptorFlags::EMPTY,
                WasiRights::PATH_OPEN | WasiRights::PATH_SYMLINK,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // reject wrong descriptor kind right such as path_open on regular file or fd_write on directory
        assert_eq!(
            parent.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ | WasiRights::PATH_OPEN,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            parent.derive_child_rights(
                false,
                false,
                true,
                DescriptorFlags::EMPTY,
                WasiRights::PATH_OPEN | WasiRights::FD_WRITE,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // attenuate parent inheriting right to remove fd_write and path_filestat_set_size
        let narrowed_inheriting = parent.inheriting.0 & !WasiRights::FD_WRITE;
        let narrowed_base = parent.base.0 & !WasiRights::PATH_FILESTAT_SET_SIZE;
        parent.attenuate(narrowed_base, narrowed_inheriting).unwrap();

        // attempt to re-add removed right via attenuate must fail with enotcapable
        assert_eq!(
            parent.attenuate(
                parent.base.0 | WasiRights::PATH_FILESTAT_SET_SIZE,
                parent.inheriting.0
            ),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            parent.attenuate(parent.base.0, parent.inheriting.0 | WasiRights::FD_WRITE),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(parent.attenuate(u64::MAX, 0), Err(WASI_ENOTCAPABLE));

        // o_trunc must now fail because parent base lack path_filestat_set_size
        assert_eq!(
            parent.derive_child_rights(
                false,
                true,
                false,
                DescriptorFlags::EMPTY,
                u64::MAX,
                u64::MAX,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // explicit request for fd_write must fail because parent inheriting lack fd_write
        assert_eq!(
            parent.derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ | WasiRights::FD_WRITE,
                0,
            ),
            Err(WASI_ENOTCAPABLE)
        );

        // u64 max compatibility request succeed but clamp out fd_write
        let ro_child = parent
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert!(ro_child.base.permits_read());
        assert!(!ro_child.base.permits_write());
    }

    #[test]
    fn test_descriptor_state_ownership_lifecycle_and_shared_runtime_context() {
        let ctx_a = RuntimeFsContext::shared();
        let ctx_b = RuntimeFsContext::shared();
        assert!(std::sync::Arc::ptr_eq(&ctx_a, &ctx_b));

        #[cfg(windows)]
        {
            let eng_a = ctx_a.windows_engine();
            let eng_b = ctx_b.windows_engine();
            assert!(std::sync::Arc::ptr_eq(eng_a.lock_table(), eng_b.lock_table()));
            assert!(std::sync::Arc::ptr_eq(
                ctx_a.file_lock_table(),
                eng_a.lock_table()
            ));
        }

        let temp_dir =
            std::env::temp_dir().join(format!("plug_desc_state_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        #[cfg(windows)]
        let root_file = windows::open_directory_for_containment(&temp_dir).unwrap();
        #[cfg(not(windows))]
        let root_file = std::fs::File::open(&temp_dir).unwrap();

        let preopen_desc = std::sync::Arc::new(DescriptorState::new_preopen_dir(root_file, "/data"));
        match preopen_desc.kind() {
            DescriptorKind::PreopenDir { guest_path, .. } => assert_eq!(*guest_path, "/data"),
            _ => panic!("expected preopen directory descriptor"),
        }

        let file_path = temp_dir.join("state_test.bin");
        std::fs::write(&file_path, b"hello").unwrap();
        let reg_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        let child_rights = preopen_desc
            .rights()
            .derive_child_rights(
                false,
                false,
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ
                    | WasiRights::FD_WRITE
                    | WasiRights::FD_SEEK
                    | WasiRights::FD_FDSTAT_SET_FLAGS,
                0,
            )
            .unwrap();

        let file_desc = std::sync::Arc::new(
            DescriptorState::new_regular_file(reg_handle, child_rights, DescriptorFlags::EMPTY)
                .unwrap(),
        );
        assert!(file_desc.rights().base.permits_read());
        assert!(file_desc.rights().base.permits_write());
        assert!(file_desc.rights().base.permits_tell());

        // validate fd_flags update and unknown flag rejection
        assert_eq!(file_desc.set_fd_flags(1 << 9), Err(WASI_EINVAL));
        file_desc.set_fd_flags(DescriptorFlags::APPEND).unwrap();
        assert_eq!(file_desc.fd_flags(), DescriptorFlags(DescriptorFlags::APPEND));

        // attenuate regular file descriptor to drop write and fdstat_set_flags right
        file_desc
            .set_rights(WasiRights::FD_READ | WasiRights::FD_SEEK, 0)
            .unwrap();
        assert!(!file_desc.rights().base.permits_write());
        assert_eq!(
            file_desc.set_fd_flags(DescriptorFlags::EMPTY.0),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            file_desc.set_rights(WasiRights::FD_READ | WasiRights::FD_WRITE, 0),
            Err(WASI_ENOTCAPABLE)
        );

        drop(file_desc);
        drop(preopen_desc);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
