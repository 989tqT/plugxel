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
pub const WASI_EMFILE: i32 = 33;
pub const WASI_ENOENT: i32 = 44;
pub const WASI_ENOSYS: i32 = 52;
pub const WASI_ENOTDIR: i32 = 54;
pub const WASI_ENOTEMPTY: i32 = 55;
pub const WASI_ENOTSUP: i32 = 58;
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
    // exclude poll_fd_readwrite because poll_oneoff readiness polling is not implemented
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
            | Self::FD_FILESTAT_SET_TIMES,
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

    // fdflag actually honored by active runtime io path
    // empty until b3.2 wire append into fd_write path
    pub const RUNTIME_SUPPORTED: u16 = 0;

    // validate fdflag at syscall boundary and reject protocol valid but unhonored flag
    pub const fn from_raw_runtime_supported(raw: u16) -> Result<Self, WasiErrno> {
        if (raw & !Self::ALL_VALID) != 0 {
            return Err(WASI_EINVAL);
        }
        if (raw & !Self::RUNTIME_SUPPORTED) != 0 {
            return Err(WASI_ENOTSUP);
        }
        Ok(Self(raw))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorRights {
    pub base: WasiRights,
    pub inheriting: WasiRights,
}

impl DescriptorRights {
    pub const PACKED_INHERITING_SHIFT: u32 = 29;
    // bit 0..58 carry base and inheriting while bit 58..64 must stay zero
    pub const PACKED_VALID_MASK: u64 = (1 << 58) - 1;

    // pack 29 bit base and 29 bit inheriting mask into single 64 bit word
    // guarantee coherent atomic snapshot without torn base or inheriting state
    pub const fn to_packed_u64(self) -> u64 {
        (self.base.0 & WasiRights::ALL_VALID)
            | ((self.inheriting.0 & WasiRights::ALL_VALID) << Self::PACKED_INHERITING_SHIFT)
    }

    // unpack coherent base and inheriting right snapshot from single 64 bit word
    pub const fn from_packed_u64(packed: u64) -> Self {
        Self {
            base: WasiRights(packed & WasiRights::ALL_VALID),
            inheriting: WasiRights(
                (packed >> Self::PACKED_INHERITING_SHIFT) & WasiRights::ALL_VALID,
            ),
        }
    }

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
// capability right linearize at single packed atomicu64 load on syscall entry
pub struct DescriptorState {
    kind: DescriptorKind,
    packed_rights: std::sync::atomic::AtomicU64,
    fd_flags: std::sync::atomic::AtomicU16,
}

impl DescriptorState {
    // construct preopened capability root directory descriptor
    pub fn new_preopen_dir(dir_file: std::fs::File, guest_path: &'static str) -> Self {
        Self {
            kind: DescriptorKind::PreopenDir {
                dir_file,
                guest_path,
            },
            packed_rights: std::sync::atomic::AtomicU64::new(
                DescriptorRights::preopen_directory_default().to_packed_u64(),
            ),
            fd_flags: std::sync::atomic::AtomicU16::new(DescriptorFlags::EMPTY.0),
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
            packed_rights: std::sync::atomic::AtomicU64::new(validated_rights.to_packed_u64()),
            fd_flags: std::sync::atomic::AtomicU16::new(validated_flags.0),
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
            packed_rights: std::sync::atomic::AtomicU64::new(validated_rights.to_packed_u64()),
            fd_flags: std::sync::atomic::AtomicU16::new(validated_flags.0),
        })
    }

    pub fn kind(&self) -> &DescriptorKind {
        &self.kind
    }

    // load coherent base and inheriting right snapshot in single atomic instruction
    pub fn rights(&self) -> DescriptorRights {
        DescriptorRights::from_packed_u64(
            self.packed_rights.load(std::sync::atomic::Ordering::Acquire),
        )
    }

    // atomically attenuate both base and inheriting right via compare exchange loop
    // linearize before subsequent syscall entry check while allow in flight io to finish
    pub fn set_rights(&self, new_base_raw: u64, new_inheriting_raw: u64) -> Result<(), WasiErrno> {
        attenuate_packed_rights(&self.packed_rights, new_base_raw, new_inheriting_raw)
    }

    pub fn fd_flags(&self) -> DescriptorFlags {
        DescriptorFlags(self.fd_flags.load(std::sync::atomic::Ordering::Acquire))
    }

    // reject flag not honored by active io path with wasi_enotsup instead of silent accept
    pub fn set_fd_flags(&self, new_flags_raw: u16) -> Result<(), WasiErrno> {
        let current_rights = self.rights();
        if !current_rights.base.contains(WasiRights::FD_FDSTAT_SET_FLAGS) {
            return Err(WASI_ENOTCAPABLE);
        }
        let validated = DescriptorFlags::from_raw_runtime_supported(new_flags_raw)?;
        self.fd_flags
            .store(validated.0, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    // snapshot wasi preview 1 fdstat metadata for descriptor
    pub fn fd_fdstat_get(&self) -> WasiFdstat {
        let fs_filetype = match &self.kind {
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                WASI_FILETYPE_DIRECTORY
            }
            DescriptorKind::RegularFile { .. } => WASI_FILETYPE_REGULAR_FILE,
        };
        let rights = self.rights();
        let fs_flags = self.fd_flags();
        WasiFdstat {
            fs_filetype,
            fs_flags,
            fs_rights_base: rights.base,
            fs_rights_inheriting: rights.inheriting,
        }
    }

    // seek sequential kernel file pointer under descriptor mutex only
    // fd_tell alone permit whence cur with offset zero since position stay unchanged
    pub fn fd_seek(&self, offset: i64, whence: u8) -> Result<u64, WasiErrno> {
        use std::io::{Seek, SeekFrom};

        let current_rights = self.rights();
        let is_position_query = whence == 1 && offset == 0;
        if !current_rights.base.permits_seek()
            && !(is_position_query && current_rights.base.permits_tell())
        {
            return Err(WASI_ENOTCAPABLE);
        }
        let file_mutex = match &self.kind {
            DescriptorKind::RegularFile { file, .. } => file,
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                return Err(WASI_EBADF)
            }
        };
        let seek_from = match whence {
            0 => {
                let start = u64::try_from(offset).map_err(|_| WASI_EINVAL)?;
                SeekFrom::Start(start)
            }
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Err(WASI_EINVAL),
        };
        let mut guard = file_mutex.lock().unwrap_or_else(|e| e.into_inner());
        guard.seek(seek_from).map_err(|_| WASI_EINVAL)
    }

    // query sequential kernel file pointer under descriptor mutex only
    pub fn fd_tell(&self) -> Result<u64, WasiErrno> {
        use std::io::Seek;

        let current_rights = self.rights();
        if !current_rights.base.permits_tell() {
            return Err(WASI_ENOTCAPABLE);
        }
        let file_mutex = match &self.kind {
            DescriptorKind::RegularFile { file, .. } => file,
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                return Err(WASI_EBADF)
            }
        };
        let mut guard = file_mutex.lock().unwrap_or_else(|e| e.into_inner());
        guard.stream_position().map_err(|_| WASI_EIO)
    }

    // execute sequential read closure under shared file lock then descriptor mutex
    pub fn read_with_lock<F, R>(&self, ctx: &RuntimeFsContext, f: F) -> Result<R, WasiErrno>
    where
        F: FnOnce(&mut std::fs::File) -> Result<R, WasiErrno>,
    {
        let current_rights = self.rights();
        if !current_rights.base.permits_read() {
            return Err(WASI_ENOTCAPABLE);
        }
        match &self.kind {
            DescriptorKind::RegularFile {
                file,
                #[cfg(windows)]
                file_id,
            } => {
                #[cfg(windows)]
                {
                    ctx.file_lock_table().with_shared_lock(*file_id, || {
                        let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                        f(&mut guard)
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = ctx;
                    let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                    f(&mut guard)
                }
            }
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                Err(WASI_EBADF)
            }
        }
    }

    // execute sequential write closure under exclusive file lock then descriptor mutex
    pub fn write_with_lock<F, R>(&self, ctx: &RuntimeFsContext, f: F) -> Result<R, WasiErrno>
    where
        F: FnOnce(&mut std::fs::File) -> Result<R, WasiErrno>,
    {
        let current_rights = self.rights();
        if !current_rights.base.permits_write() {
            return Err(WASI_ENOTCAPABLE);
        }
        match &self.kind {
            DescriptorKind::RegularFile {
                file,
                #[cfg(windows)]
                file_id,
            } => {
                #[cfg(windows)]
                {
                    ctx.file_lock_table().with_exclusive_lock(*file_id, || {
                        let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                        f(&mut guard)
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = ctx;
                    let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
                    f(&mut guard)
                }
            }
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                Err(WASI_EBADF)
            }
        }
    }

    // resize file under exclusive file lock then descriptor mutex
    pub fn set_size_with_lock(&self, ctx: &RuntimeFsContext, size: u64) -> Result<(), WasiErrno> {
        let current_rights = self.rights();
        if !current_rights.base.permits_filestat_set_size() {
            return Err(WASI_ENOTCAPABLE);
        }
        match &self.kind {
            DescriptorKind::RegularFile {
                file,
                #[cfg(windows)]
                file_id,
            } => {
                #[cfg(windows)]
                {
                    ctx.file_lock_table().with_exclusive_lock(*file_id, || {
                        let guard = file.lock().unwrap_or_else(|e| e.into_inner());
                        windows::set_file_end_of_file_unlocked(&guard, size)
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = ctx;
                    let guard = file.lock().unwrap_or_else(|e| e.into_inner());
                    guard.set_len(size).map_err(|_| WASI_EIO)
                }
            }
            DescriptorKind::PreopenDir { .. } | DescriptorKind::Directory { .. } => {
                Err(WASI_EBADF)
            }
        }
    }
}

// wasi preview 1 filetype constant
pub const WASI_FILETYPE_DIRECTORY: u8 = 3;
pub const WASI_FILETYPE_REGULAR_FILE: u8 = 4;

// wasi preview 1 fdstat snapshot structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasiFdstat {
    pub fs_filetype: u8,
    pub fs_flags: DescriptorFlags,
    pub fs_rights_base: WasiRights,
    pub fs_rights_inheriting: WasiRights,
}

impl WasiFdstat {
    // serialize into 24 byte wasi preview 1 fdstat binary layout
    pub const fn to_wasi_bytes(self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0] = self.fs_filetype;
        let flags_le = self.fs_flags.0.to_le_bytes();
        buf[2] = flags_le[0];
        buf[3] = flags_le[1];
        let base_le = self.fs_rights_base.0.to_le_bytes();
        buf[8] = base_le[0];
        buf[9] = base_le[1];
        buf[10] = base_le[2];
        buf[11] = base_le[3];
        buf[12] = base_le[4];
        buf[13] = base_le[5];
        buf[14] = base_le[6];
        buf[15] = base_le[7];
        let inh_le = self.fs_rights_inheriting.0.to_le_bytes();
        buf[16] = inh_le[0];
        buf[17] = inh_le[1];
        buf[18] = inh_le[2];
        buf[19] = inh_le[3];
        buf[20] = inh_le[4];
        buf[21] = inh_le[5];
        buf[22] = inh_le[6];
        buf[23] = inh_le[7];
        buf
    }
}

struct DescriptorTableInner {
    entries: std::collections::HashMap<i32, std::sync::Arc<DescriptorState>>,
    // monotonic descriptor allocator starting at 4 to prevent aba descriptor id reuse
    // none indicate descriptor id space is permanently exhausted
    next_fd: Option<i32>,
}

// concurrency safe descriptor table enforcing clone arc and release lock immediately invariant
pub struct DescriptorTable {
    inner: std::sync::Mutex<DescriptorTableInner>,
}

impl DescriptorTable {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(DescriptorTableInner {
                entries: std::collections::HashMap::new(),
                next_fd: Some(4),
            }),
        }
    }

    // construct table with preopened capability root directory at fd 3
    pub fn new_with_preopen(dir_file: std::fs::File, guest_path: &'static str) -> Self {
        let mut entries = std::collections::HashMap::new();
        entries.insert(
            3,
            std::sync::Arc::new(DescriptorState::new_preopen_dir(dir_file, guest_path)),
        );
        Self {
            inner: std::sync::Mutex::new(DescriptorTableInner {
                entries,
                next_fd: Some(4),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_start_fd_for_test(start_fd: i32) -> Self {
        Self {
            inner: std::sync::Mutex::new(DescriptorTableInner {
                entries: std::collections::HashMap::new(),
                next_fd: if start_fd >= 4 { Some(start_fd) } else { None },
            }),
        }
    }

    // allocate monotonic descriptor id without reuse closed id
    // return wasi_emfile when descriptor id space reach i32 max without wraparound
    pub fn insert(&self, state: DescriptorState) -> Result<i32, WasiErrno> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let assigned_fd = match guard.next_fd {
            Some(fd) if fd >= 4 => fd,
            _ => return Err(WASI_EMFILE),
        };
        guard.next_fd = assigned_fd.checked_add(1);
        guard.entries.insert(assigned_fd, std::sync::Arc::new(state));
        Ok(assigned_fd)
    }

    // lookup descriptor and clone arc while release table lock before return
    pub fn get(&self, fd: i32) -> Result<std::sync::Arc<DescriptorState>, WasiErrno> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .get(&fd)
            .map(std::sync::Arc::clone)
            .ok_or(WASI_EBADF)
    }

    // remove descriptor from table and drop arc outside table lock
    // preopen fd 3 closable per wasi preview 1 fd_close since guest only lose own capability
    // fd 3 never reallocated because monotonic allocator start at 4
    pub fn close(&self, fd: i32) -> Result<(), WasiErrno> {
        let removed = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.entries.remove(&fd)
        };
        match removed {
            Some(arc_desc) => {
                drop(arc_desc);
                Ok(())
            }
            None => Err(WASI_EBADF),
        }
    }
}

// convert allocated descriptor id to 4 byte little endian wasi abi representation
// reject negative id or reserved stdio and preopen id below 4
pub fn encode_abi_fd(fd: i32) -> Result<[u8; 4], WasiErrno> {
    if fd < 4 {
        return Err(WASI_EBADF);
    }
    let raw = u32::try_from(fd).map_err(|_| WASI_EBADF)?;
    Ok(raw.to_le_bytes())
}

// monotonic cas attenuation over packed right word shared by file and stdio descriptor
// any reserved bit set mean slot closed and yield wasi_ebadf
fn attenuate_packed_rights(
    cell: &std::sync::atomic::AtomicU64,
    new_base_raw: u64,
    new_inheriting_raw: u64,
) -> Result<(), WasiErrno> {
    use std::sync::atomic::Ordering;

    let mut current_packed = cell.load(Ordering::Acquire);
    loop {
        if (current_packed & !DescriptorRights::PACKED_VALID_MASK) != 0 {
            return Err(WASI_EBADF);
        }
        let mut candidate = DescriptorRights::from_packed_u64(current_packed);
        candidate.attenuate(new_base_raw, new_inheriting_raw)?;
        let next_packed = candidate.to_packed_u64();
        match cell.compare_exchange_weak(
            current_packed,
            next_packed,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current_packed = observed,
        }
    }
}

pub const WASI_FILETYPE_CHARACTER_DEVICE: u8 = 2;

// wasi preview 1 standard stream at fd 0 1 2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioStream {
    Stdin,
    Stdout,
    Stderr,
}

impl StdioStream {
    pub const fn from_fd(fd: i32) -> Option<Self> {
        match fd {
            0 => Some(Self::Stdin),
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            _ => None,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Stdin => 0,
            Self::Stdout => 1,
            Self::Stderr => 2,
        }
    }

    // initial right for stream without seek tell setflag or unimplemented poll_oneoff readiness
    const fn default_rights(self) -> DescriptorRights {
        let base = match self {
            Self::Stdin => WasiRights::FD_READ,
            Self::Stdout | Self::Stderr => WasiRights::FD_WRITE,
        };
        DescriptorRights {
            base: WasiRights(base),
            inheriting: WasiRights::EMPTY,
        }
    }
}

// host owned per instance standard stream descriptor managed outside descriptortable
// keep stdio separate from filesystem capability so stdio never alias preopen or file handle
// stdin use explicit no host stream policy and return eof zero byte until closed
pub struct StdioDescriptors {
    slots: [std::sync::atomic::AtomicU64; 3],
    stdout_sink: std::sync::Mutex<Box<dyn std::io::Write + Send>>,
    stderr_sink: std::sync::Mutex<Box<dyn std::io::Write + Send>>,
}

impl StdioDescriptors {
    // reserved bit 58..64 all set mark closed slot and never collide with valid packed right
    const CLOSED_SENTINEL: u64 = u64::MAX;

    pub fn new() -> Self {
        Self::with_sinks(Box::new(std::io::sink()), Box::new(std::io::sink()))
    }

    pub fn with_sinks(
        stdout_sink: Box<dyn std::io::Write + Send>,
        stderr_sink: Box<dyn std::io::Write + Send>,
    ) -> Self {
        Self {
            slots: [
                std::sync::atomic::AtomicU64::new(
                    StdioStream::Stdin.default_rights().to_packed_u64(),
                ),
                std::sync::atomic::AtomicU64::new(
                    StdioStream::Stdout.default_rights().to_packed_u64(),
                ),
                std::sync::atomic::AtomicU64::new(
                    StdioStream::Stderr.default_rights().to_packed_u64(),
                ),
            ],
            stdout_sink: std::sync::Mutex::new(stdout_sink),
            stderr_sink: std::sync::Mutex::new(stderr_sink),
        }
    }

    // load coherent right snapshot or wasi_ebadf when stream closed
    pub fn rights(&self, stream: StdioStream) -> Result<DescriptorRights, WasiErrno> {
        let packed = self.slots[stream.index()].load(std::sync::atomic::Ordering::Acquire);
        if packed == Self::CLOSED_SENTINEL {
            return Err(WASI_EBADF);
        }
        Ok(DescriptorRights::from_packed_u64(packed))
    }

    // verify stream open and base right contain required mask
    pub fn require(&self, stream: StdioStream, required: u64) -> Result<(), WasiErrno> {
        if self.rights(stream)?.base.contains(required) {
            Ok(())
        } else {
            Err(WASI_ENOTCAPABLE)
        }
    }

    // read from standard stream where stdin return eof zero byte by default policy
    pub fn read_stream(&self, stream: StdioStream) -> Result<usize, WasiErrno> {
        self.require(stream, WasiRights::FD_READ)?;
        match stream {
            StdioStream::Stdin => Ok(0),
            StdioStream::Stdout | StdioStream::Stderr => Err(WASI_ENOTCAPABLE),
        }
    }

    // write vectored slice to configured per instance stdout or stderr sink
    // honor partial write count and map underlying sink failure to wasi_eio
    pub fn write_stream(&self, stream: StdioStream, slices: &[&[u8]]) -> Result<usize, WasiErrno> {
        self.require(stream, WasiRights::FD_WRITE)?;
        let sink_mutex = match stream {
            StdioStream::Stdout => &self.stdout_sink,
            StdioStream::Stderr => &self.stderr_sink,
            StdioStream::Stdin => return Err(WASI_ENOTCAPABLE),
        };
        let mut sink = sink_mutex.lock().unwrap_or_else(|e| e.into_inner());
        let mut total_written = 0usize;
        for slice in slices {
            if slice.is_empty() {
                continue;
            }
            match sink.write(slice) {
                Ok(0) => break,
                Ok(n) => {
                    let actual = n.min(slice.len());
                    total_written = total_written.checked_add(actual).ok_or(WASI_EINVAL)?;
                    if actual < slice.len() {
                        break;
                    }
                }
                Err(_) => {
                    if total_written > 0 {
                        break;
                    }
                    return Err(WASI_EIO);
                }
            }
        }
        Ok(total_written)
    }

    // stdio fdflag stay empty because runtime honor no settable flag on stream
    pub fn fd_fdstat_get(&self, stream: StdioStream) -> Result<WasiFdstat, WasiErrno> {
        let rights = self.rights(stream)?;
        Ok(WasiFdstat {
            fs_filetype: WASI_FILETYPE_CHARACTER_DEVICE,
            fs_flags: DescriptorFlags::EMPTY,
            fs_rights_base: rights.base,
            fs_rights_inheriting: rights.inheriting,
        })
    }

    pub fn set_rights(
        &self,
        stream: StdioStream,
        new_base_raw: u64,
        new_inheriting_raw: u64,
    ) -> Result<(), WasiErrno> {
        attenuate_packed_rights(&self.slots[stream.index()], new_base_raw, new_inheriting_raw)
    }

    // flag never stored since runtime_supported is empty and clearing is no op
    pub fn set_fd_flags(&self, stream: StdioStream, new_flags_raw: u16) -> Result<(), WasiErrno> {
        self.require(stream, WasiRights::FD_FDSTAT_SET_FLAGS)?;
        DescriptorFlags::from_raw_runtime_supported(new_flags_raw)?;
        Ok(())
    }

    // close stream slot once and reject double close with wasi_ebadf
    pub fn close(&self, stream: StdioStream) -> Result<(), WasiErrno> {
        let previous = self.slots[stream.index()]
            .swap(Self::CLOSED_SENTINEL, std::sync::atomic::Ordering::AcqRel);
        if previous == Self::CLOSED_SENTINEL {
            Err(WASI_EBADF)
        } else {
            Ok(())
        }
    }
}

// open host directory handle for descriptor table initialization without follow symlink
pub fn open_directory_handle(path: &std::path::Path) -> Result<std::fs::File, WasiErrno> {
    #[cfg(windows)]
    {
        windows::open_directory_for_containment(path)
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| match e.raw_os_error() {
                Some(libc::ENOENT) => WASI_ENOENT,
                Some(libc::EACCES) => WASI_EACCES,
                Some(libc::EPERM) => WASI_EPERM,
                Some(libc::ENOTDIR) => WASI_ENOTDIR,
                Some(libc::ELOOP) => WASI_ENOTCAPABLE,
                _ => WASI_EIO,
            })
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
        assert_eq!(WASI_EMFILE, 33);
        assert_eq!(WASI_ENOENT, 44);
        assert_eq!(WASI_ENOSYS, 52);
        assert_eq!(WASI_ENOTDIR, 54);
        assert_eq!(WASI_ENOTSUP, 58);
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
            | WasiRights::POLL_FD_READWRITE
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

        // reject unsupported protocol valid right such as sock_shutdown poll_fd_readwrite or path_symlink
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
                false,
                DescriptorFlags::EMPTY,
                WasiRights::FD_READ | WasiRights::POLL_FD_READWRITE,
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
        // append not honored by active write path until b3.2 so reject with enotsup
        assert_eq!(file_desc.set_fd_flags(DescriptorFlags::APPEND), Err(WASI_ENOTSUP));
        file_desc.set_fd_flags(DescriptorFlags::EMPTY.0).unwrap();
        assert_eq!(file_desc.fd_flags(), DescriptorFlags::EMPTY);

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

    #[test]
    fn test_b2_2_descriptor_id_monotonic_non_reuse_and_preopen_close() {
        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_mono_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        #[cfg(windows)]
        let root_file = windows::open_directory_for_containment(&temp_dir).unwrap();
        #[cfg(not(windows))]
        let root_file = std::fs::File::open(&temp_dir).unwrap();

        let table = DescriptorTable::new_with_preopen(root_file, "/data");

        // guest may close preopen fd 3 per wasi preview 1 and only lose own capability
        // in flight arc keep root handle alive after removal from table
        let inflight_preopen = table.get(3).unwrap();
        assert_eq!(table.close(3), Ok(()));
        assert_eq!(table.get(3).err(), Some(WASI_EBADF));
        assert_eq!(table.close(3), Err(WASI_EBADF));
        assert!(matches!(
            inflight_preopen.kind(),
            DescriptorKind::PreopenDir { guest_path: "/data", .. }
        ));
        drop(inflight_preopen);

        let file_path = temp_dir.join("mono.bin");
        std::fs::write(&file_path, b"abc").unwrap();

        let make_reg = || {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let rights = DescriptorRights::for_regular_file(WasiRights(
                WasiRights::FD_READ | WasiRights::FD_WRITE | WasiRights::FD_SEEK,
            ))
            .unwrap();
            DescriptorState::new_regular_file(f, rights, DescriptorFlags::EMPTY).unwrap()
        };

        // closed fd 3 never reallocated since allocator start at 4
        let fd4 = table.insert(make_reg()).unwrap();
        let fd5 = table.insert(make_reg()).unwrap();
        let fd6 = table.insert(make_reg()).unwrap();
        assert_eq!((fd4, fd5, fd6), (4, 5, 6));

        // close fd 4 and fd 5 then verify next allocation receive fd 7 without reuse
        assert_eq!(table.close(4), Ok(()));
        assert_eq!(table.close(4), Err(WASI_EBADF));
        assert_eq!(table.get(4).err(), Some(WASI_EBADF));
        assert_eq!(table.close(5), Ok(()));

        let fd7 = table.insert(make_reg()).unwrap();
        assert_eq!(fd7, 7);
        assert_eq!(table.close(6), Ok(()));
        assert_eq!(table.close(7), Ok(()));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_concurrent_fd_close_while_inflight_operation_holds_arc() {
        use std::io::Write;
        use std::sync::{Arc, Barrier};

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_close_race_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let ctx = Arc::new(RuntimeFsContext::new());
        let table = Arc::new(DescriptorTable::new());

        let file_path = temp_dir.join("inflight.bin");
        std::fs::write(&file_path, b"").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let rights = DescriptorRights::for_regular_file(WasiRights(
            WasiRights::FD_READ | WasiRights::FD_WRITE | WasiRights::FD_SEEK,
        ))
        .unwrap();
        let fd = table
            .insert(DescriptorState::new_regular_file(f, rights, DescriptorFlags::EMPTY).unwrap())
            .unwrap();
        assert_eq!(fd, 4);

        let bar_acquired = Arc::new(Barrier::new(2));
        let bar_closed = Arc::new(Barrier::new(2));

        let table_worker = Arc::clone(&table);
        let ctx_worker = Arc::clone(&ctx);
        let bar_acq_w = Arc::clone(&bar_acquired);
        let bar_cls_w = Arc::clone(&bar_closed);

        // worker thread clone arc from table then enter write_with_lock while main thread close fd
        let worker = std::thread::spawn(move || {
            let desc = table_worker.get(fd).unwrap();
            desc.write_with_lock(&ctx_worker, |file_ref| {
                bar_acq_w.wait();
                bar_cls_w.wait();
                file_ref.write_all(b"inflight_payload_survives_close").map_err(|_| WASI_EIO)?;
                Ok(())
            })
            .unwrap();
            assert_eq!(desc.fd_tell().unwrap(), 31);
        });

        // wait until worker hold arc and file lock
        bar_acquired.wait();

        // close fd 4 while worker operation still in flight
        assert_eq!(table.close(fd), Ok(()));
        assert_eq!(table.get(fd).err(), Some(WASI_EBADF));

        // open another descriptor while fd 4 still in flight and verify id is 5 not 4
        let f2 = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let fd_new = table
            .insert(DescriptorState::new_regular_file(f2, rights, DescriptorFlags::EMPTY).unwrap())
            .unwrap();
        assert_eq!(fd_new, 5);

        // release worker to finish write on cloned arc
        bar_closed.wait();
        worker.join().unwrap();

        assert_eq!(table.close(fd_new), Ok(()));
        #[cfg(windows)]
        assert_eq!(ctx.file_lock_table().active_entry_count(), 0);
        assert_eq!(
            std::fs::read(&file_path).unwrap(),
            b"inflight_payload_survives_close"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_multithreaded_fd_seek_and_fd_tell_on_shared_descriptor() {
        use std::sync::{Arc, Barrier};

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_seek_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("seek_target.bin");
        std::fs::write(&file_path, vec![0x42u8; 4096]).unwrap();

        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let rights = DescriptorRights::for_regular_file(WasiRights(
            WasiRights::FD_READ | WasiRights::FD_SEEK,
        ))
        .unwrap();
        let desc = Arc::new(
            DescriptorState::new_regular_file(f, rights, DescriptorFlags::EMPTY).unwrap(),
        );

        let threads = 4usize;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::new();

        for tid in 0..threads {
            let d = Arc::clone(&desc);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                for step in 0..50u64 {
                    let target = ((tid as u64) * 128 + step * 8) % 4096;
                    let pos = d.fd_seek(target as i64, 0).unwrap();
                    assert_eq!(pos, target);
                    let told = d.fd_tell().unwrap();
                    assert!(told <= 4096);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // verify final deterministic seek from start current and end
        assert_eq!(desc.fd_seek(100, 0).unwrap(), 100);
        assert_eq!(desc.fd_tell().unwrap(), 100);
        assert_eq!(desc.fd_seek(28, 1).unwrap(), 128);
        assert_eq!(desc.fd_tell().unwrap(), 128);
        assert_eq!(desc.fd_seek(-96, 2).unwrap(), 4000);
        assert_eq!(desc.fd_tell().unwrap(), 4000);
        assert_eq!(desc.fd_seek(-10, 0), Err(WASI_EINVAL));
        assert_eq!(desc.fd_seek(0, 9), Err(WASI_EINVAL));

        drop(desc);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_concurrent_fdstat_get_and_monotonic_set_rights() {
        use std::sync::{Arc, Barrier};

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_fdstat_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("fdstat.bin");
        std::fs::write(&file_path, b"stat").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let initial_mask = WasiRights::FD_READ
            | WasiRights::FD_WRITE
            | WasiRights::FD_SEEK
            | WasiRights::FD_TELL
            | WasiRights::FD_FILESTAT_GET
            | WasiRights::FD_FILESTAT_SET_SIZE;
        let rights = DescriptorRights::for_regular_file(WasiRights(initial_mask)).unwrap();
        let desc = Arc::new(
            DescriptorState::new_regular_file(
                f,
                rights,
                DescriptorFlags(DescriptorFlags::APPEND),
            )
            .unwrap(),
        );

        let barrier = Arc::new(Barrier::new(2));
        let d_attenuate = Arc::clone(&desc);
        let b_attenuate = Arc::clone(&barrier);

        let attenuator = std::thread::spawn(move || {
            b_attenuate.wait();
            // step 1 drop fd_filestat_set_size
            let m1 = initial_mask & !WasiRights::FD_FILESTAT_SET_SIZE;
            d_attenuate.set_rights(m1, 0).unwrap();
            assert_eq!(d_attenuate.set_rights(initial_mask, 0), Err(WASI_ENOTCAPABLE));

            // step 2 drop fd_write
            let m2 = m1 & !WasiRights::FD_WRITE;
            d_attenuate.set_rights(m2, 0).unwrap();
            assert_eq!(d_attenuate.set_rights(m1, 0), Err(WASI_ENOTCAPABLE));
        });

        let d_reader = Arc::clone(&desc);
        let b_reader = Arc::clone(&barrier);
        let reader = std::thread::spawn(move || {
            b_reader.wait();
            let mut saw_write_dropped = false;
            for _ in 0..200 {
                let st = d_reader.fd_fdstat_get();
                assert_eq!(st.fs_filetype, WASI_FILETYPE_REGULAR_FILE);
                assert_eq!(st.fs_flags, DescriptorFlags(DescriptorFlags::APPEND));
                assert_eq!(st.fs_rights_inheriting, WasiRights::EMPTY);
                assert_eq!(st.fs_rights_base.0 & !initial_mask, 0);
                if !st.fs_rights_base.contains(WasiRights::FD_WRITE) {
                    saw_write_dropped = true;
                } else if saw_write_dropped {
                    panic!("monotonic right violation observed in concurrent fd_fdstat_get");
                }
                let raw_bytes = st.to_wasi_bytes();
                assert_eq!(raw_bytes[0], WASI_FILETYPE_REGULAR_FILE);
                assert_eq!(
                    u16::from_le_bytes([raw_bytes[2], raw_bytes[3]]),
                    DescriptorFlags::APPEND
                );
            }
        });

        attenuator.join().unwrap();
        reader.join().unwrap();

        let final_st = desc.fd_fdstat_get();
        assert!(final_st.fs_rights_base.permits_read());
        assert!(final_st.fs_rights_base.permits_seek());
        assert!(!final_st.fs_rights_base.permits_write());
        assert!(!final_st.fs_rights_base.permits_filestat_set_size());

        drop(desc);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_lock_ordering_no_deadlock_multi_descriptor_same_file() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::sync::{Arc, Barrier};

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_lock_order_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let ctx = Arc::new(RuntimeFsContext::new());
        let table = Arc::new(DescriptorTable::new());

        let file_path = temp_dir.join("shared_lock_order.bin");
        std::fs::write(&file_path, vec![0x11u8; 256]).unwrap();

        let rights = DescriptorRights::for_regular_file(WasiRights(
            WasiRights::FD_READ
                | WasiRights::FD_WRITE
                | WasiRights::FD_SEEK
                | WasiRights::FD_TELL
                | WasiRights::FD_FILESTAT_SET_SIZE,
        ))
        .unwrap();

        let f_a = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let f_b = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        let fd_a = table
            .insert(DescriptorState::new_regular_file(f_a, rights, DescriptorFlags::EMPTY).unwrap())
            .unwrap();
        let fd_b = table
            .insert(DescriptorState::new_regular_file(f_b, rights, DescriptorFlags::EMPTY).unwrap())
            .unwrap();

        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();

        for idx in 0..4usize {
            let t = Arc::clone(&table);
            let c = Arc::clone(&ctx);
            let b = Arc::clone(&barrier);
            let target_fd = if idx % 2 == 0 { fd_a } else { fd_b };

            workers.push(std::thread::spawn(move || {
                b.wait();
                for round in 0..50usize {
                    let desc = t.get(target_fd).unwrap();
                    match (idx + round) % 4 {
                        0 => {
                            desc.write_with_lock(&c, |f| {
                                f.seek(SeekFrom::Start(0)).map_err(|_| WASI_EIO)?;
                                f.write_all(&[0x33u8; 128]).map_err(|_| WASI_EIO)?;
                                Ok(())
                            })
                            .unwrap();
                        }
                        1 => {
                            desc.read_with_lock(&c, |f| {
                                f.seek(SeekFrom::Start(0)).map_err(|_| WASI_EIO)?;
                                let mut buf = [0u8; 64];
                                let _ = f.read(&mut buf).map_err(|_| WASI_EIO)?;
                                Ok(())
                            })
                            .unwrap();
                        }
                        2 => {
                            desc.set_size_with_lock(&c, 256).unwrap();
                        }
                        _ => {
                            let _ = desc.fd_seek(0, 0).unwrap();
                            let _ = desc.fd_tell().unwrap();
                            let _ = desc.fd_fdstat_get();
                        }
                    }
                }
            }));
        }

        for w in workers {
            w.join().unwrap();
        }

        assert_eq!(table.close(fd_a), Ok(()));
        assert_eq!(table.close(fd_b), Ok(()));
        #[cfg(windows)]
        assert_eq!(ctx.file_lock_table().active_entry_count(), 0);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_packed_atomic_rights_coherent_snapshot_no_torn_read() {
        use std::sync::{Arc, Barrier};

        // verify 58 bit packing boundary roundtrip for full 29 bit masks
        let max_pair = DescriptorRights {
            base: WasiRights(WasiRights::ALL_VALID),
            inheriting: WasiRights(WasiRights::ALL_VALID),
        };
        let packed = max_pair.to_packed_u64();
        assert_eq!(packed, (1u64 << 58) - 1);
        assert_eq!(DescriptorRights::from_packed_u64(packed), max_pair);

        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_packed_rights_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        #[cfg(windows)]
        let root_file = windows::open_directory_for_containment(&temp_dir).unwrap();
        #[cfg(not(windows))]
        let root_file = std::fs::File::open(&temp_dir).unwrap();

        let dir_desc = Arc::new(DescriptorState::new_preopen_dir(root_file, "/data"));

        let s0 = DescriptorRights::preopen_directory_default();
        let s1 = DescriptorRights {
            base: WasiRights(s0.base.0 & !WasiRights::PATH_UNLINK_FILE),
            inheriting: WasiRights(s0.inheriting.0 & !WasiRights::FD_FILESTAT_SET_SIZE),
        };
        let s2 = DescriptorRights {
            base: WasiRights(s1.base.0 & !WasiRights::PATH_REMOVE_DIRECTORY),
            inheriting: WasiRights(s1.inheriting.0 & !WasiRights::FD_WRITE),
        };
        let s3 = DescriptorRights {
            base: WasiRights(s2.base.0 & !WasiRights::PATH_CREATE_FILE),
            inheriting: WasiRights(s2.inheriting.0 & !WasiRights::FD_SEEK),
        };
        let valid_states = [s0, s1, s2, s3];

        let barrier = Arc::new(Barrier::new(5));
        let mut readers = Vec::new();

        for _ in 0..4usize {
            let d = Arc::clone(&dir_desc);
            let b = Arc::clone(&barrier);
            readers.push(std::thread::spawn(move || {
                b.wait();
                let mut prev_idx = 0usize;
                for _ in 0..500usize {
                    let st = d.fd_fdstat_get();
                    let observed = DescriptorRights {
                        base: st.fs_rights_base,
                        inheriting: st.fs_rights_inheriting,
                    };
                    // snapshot must match one exact step and never mix base from step i with inheriting from step j
                    let idx = valid_states
                        .iter()
                        .position(|candidate| *candidate == observed)
                        .expect("torn base and inheriting right snapshot observed");
                    assert!(
                        idx >= prev_idx,
                        "non monotonic right snapshot progression observed"
                    );
                    prev_idx = idx;
                }
            }));
        }

        let d_writer = Arc::clone(&dir_desc);
        let b_writer = Arc::clone(&barrier);
        let writer = std::thread::spawn(move || {
            b_writer.wait();
            d_writer.set_rights(s1.base.0, s1.inheriting.0).unwrap();
            d_writer.set_rights(s2.base.0, s2.inheriting.0).unwrap();
            d_writer.set_rights(s3.base.0, s3.inheriting.0).unwrap();
        });

        writer.join().unwrap();
        for r in readers {
            r.join().unwrap();
        }

        assert_eq!(dir_desc.rights(), s3);
        drop(dir_desc);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b2_2_descriptor_id_exhaustion_near_i32_max_no_wraparound_or_reuse() {
        let temp_dir =
            std::env::temp_dir().join(format!("plug_b22_fd_exhaust_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("exhaust.bin");
        std::fs::write(&file_path, b"x").unwrap();

        let make_reg = || {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file_path)
                .unwrap();
            let rights =
                DescriptorRights::for_regular_file(WasiRights(WasiRights::FD_READ)).unwrap();
            DescriptorState::new_regular_file(f, rights, DescriptorFlags::EMPTY).unwrap()
        };

        let table = DescriptorTable::new_with_start_fd_for_test(i32::MAX - 1);

        let fd_penultimate = table.insert(make_reg()).unwrap();
        assert_eq!(fd_penultimate, i32::MAX - 1);

        let fd_max = table.insert(make_reg()).unwrap();
        assert_eq!(fd_max, i32::MAX);

        // id space now exhausted so further allocation must fail with wasi_emfile
        assert_eq!(table.insert(make_reg()), Err(WASI_EMFILE));

        // closing existing descriptor must not re enable allocation or reuse closed id
        assert_eq!(table.close(fd_penultimate), Ok(()));
        assert_eq!(table.insert(make_reg()), Err(WASI_EMFILE));

        assert_eq!(table.close(fd_max), Ok(()));
        assert_eq!(table.insert(make_reg()), Err(WASI_EMFILE));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b3_1_encode_abi_fd_checked_conversion() {
        assert_eq!(encode_abi_fd(i32::MIN), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(-1), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(0), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(1), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(2), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(3), Err(WASI_EBADF));
        assert_eq!(encode_abi_fd(4), Ok(4u32.to_le_bytes()));
        assert_eq!(encode_abi_fd(i32::MAX), Ok((i32::MAX as u32).to_le_bytes()));
    }

    #[test]
    fn test_b3_1_fd_seek_tell_only_permit_cur_zero_query() {
        let temp_dir =
            std::env::temp_dir().join(format!("plug_b31_tell_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("tell.bin");
        std::fs::write(&file_path, b"0123456789").unwrap();

        let open_with = |mask: u64| {
            let f = std::fs::OpenOptions::new().read(true).open(&file_path).unwrap();
            let rights = DescriptorRights::for_regular_file(WasiRights(mask)).unwrap();
            DescriptorState::new_regular_file(f, rights, DescriptorFlags::EMPTY).unwrap()
        };

        // fd_tell alone permit only position query whence cur offset zero
        let tell_only = open_with(WasiRights::FD_READ | WasiRights::FD_TELL);
        assert_eq!(tell_only.fd_seek(0, 1), Ok(0));
        assert_eq!(tell_only.fd_tell(), Ok(0));
        assert_eq!(tell_only.fd_seek(3, 1), Err(WASI_ENOTCAPABLE));
        assert_eq!(tell_only.fd_seek(-1, 1), Err(WASI_ENOTCAPABLE));
        assert_eq!(tell_only.fd_seek(0, 0), Err(WASI_ENOTCAPABLE));
        assert_eq!(tell_only.fd_seek(0, 2), Err(WASI_ENOTCAPABLE));

        // fd_seek imply fd_tell and permit all whence
        let seek_only = open_with(WasiRights::FD_READ | WasiRights::FD_SEEK);
        assert_eq!(seek_only.fd_seek(4, 0), Ok(4));
        assert_eq!(seek_only.fd_seek(2, 1), Ok(6));
        assert_eq!(seek_only.fd_seek(0, 1), Ok(6));
        assert_eq!(seek_only.fd_tell(), Ok(6));
        assert_eq!(seek_only.fd_seek(-1, 2), Ok(9));

        // attenuate seek while keep tell then only position query remain
        seek_only
            .set_rights(WasiRights::FD_READ | WasiRights::FD_TELL, 0)
            .unwrap();
        assert_eq!(seek_only.fd_seek(0, 1), Ok(9));
        assert_eq!(seek_only.fd_seek(0, 0), Err(WASI_ENOTCAPABLE));

        // neither seek nor tell reject every positioning call
        let neither = open_with(WasiRights::FD_READ);
        assert_eq!(neither.fd_seek(0, 1), Err(WASI_ENOTCAPABLE));
        assert_eq!(neither.fd_tell(), Err(WASI_ENOTCAPABLE));

        drop((tell_only, seek_only, neither));
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_b3_1_fdflags_runtime_supported_policy() {
        assert_eq!(DescriptorFlags::from_raw_runtime_supported(0), Ok(DescriptorFlags::EMPTY));
        for flag in [
            DescriptorFlags::APPEND,
            DescriptorFlags::DSYNC,
            DescriptorFlags::NONBLOCK,
            DescriptorFlags::RSYNC,
            DescriptorFlags::SYNC,
        ] {
            assert_eq!(DescriptorFlags::from_raw_runtime_supported(flag), Err(WASI_ENOTSUP));
        }
        assert_eq!(DescriptorFlags::from_raw_runtime_supported(1 << 5), Err(WASI_EINVAL));
        assert_eq!(DescriptorFlags::from_raw_runtime_supported(u16::MAX), Err(WASI_EINVAL));
    }

    #[test]
    fn test_b3_1_stdio_descriptor_lifecycle_rights_and_fdstat() {
        let stdio = StdioDescriptors::new();

        assert_eq!(StdioStream::from_fd(0), Some(StdioStream::Stdin));
        assert_eq!(StdioStream::from_fd(1), Some(StdioStream::Stdout));
        assert_eq!(StdioStream::from_fd(2), Some(StdioStream::Stderr));
        assert_eq!(StdioStream::from_fd(3), None);
        assert_eq!(StdioStream::from_fd(-1), None);

        // stdin read only and stdout stderr write only without seek tell setflag or poll_fd_readwrite
        let stdin_st = stdio.fd_fdstat_get(StdioStream::Stdin).unwrap();
        assert_eq!(stdin_st.fs_filetype, WASI_FILETYPE_CHARACTER_DEVICE);
        assert_eq!(stdin_st.fs_flags, DescriptorFlags::EMPTY);
        assert_eq!(stdin_st.fs_rights_base, WasiRights(WasiRights::FD_READ));
        assert!(!stdin_st.fs_rights_base.contains(WasiRights::POLL_FD_READWRITE));
        assert_eq!(stdin_st.fs_rights_inheriting, WasiRights::EMPTY);
        for stream in [StdioStream::Stdout, StdioStream::Stderr] {
            let st = stdio.fd_fdstat_get(stream).unwrap();
            assert_eq!(st.fs_filetype, WASI_FILETYPE_CHARACTER_DEVICE);
            assert_eq!(st.fs_rights_base, WasiRights(WasiRights::FD_WRITE));
            assert!(!st.fs_rights_base.contains(WasiRights::POLL_FD_READWRITE));
        }
        assert_eq!(stdio.require(StdioStream::Stdin, WasiRights::FD_READ), Ok(()));
        assert_eq!(stdio.require(StdioStream::Stdin, WasiRights::FD_WRITE), Err(WASI_ENOTCAPABLE));
        assert_eq!(stdio.require(StdioStream::Stdin, WasiRights::POLL_FD_READWRITE), Err(WASI_ENOTCAPABLE));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::FD_WRITE), Ok(()));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::FD_READ), Err(WASI_ENOTCAPABLE));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::POLL_FD_READWRITE), Err(WASI_ENOTCAPABLE));
        assert_eq!(stdio.require(StdioStream::Stderr, WasiRights::FD_SEEK), Err(WASI_ENOTCAPABLE));

        // stdio lack fdstat_set_flags right
        assert_eq!(stdio.set_fd_flags(StdioStream::Stdout, 0), Err(WASI_ENOTCAPABLE));

        // monotonic attenuation and escalation rejection on stdio
        assert_eq!(
            stdio.set_rights(StdioStream::Stderr, WasiRights::FD_WRITE | WasiRights::FD_SEEK, 0),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(
            stdio.set_rights(StdioStream::Stderr, WasiRights::FD_WRITE | WasiRights::POLL_FD_READWRITE, 0),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(stdio.set_rights(StdioStream::Stderr, 0, 0), Ok(()));
        assert_eq!(stdio.require(StdioStream::Stderr, WasiRights::FD_WRITE), Err(WASI_ENOTCAPABLE));
        assert_eq!(
            stdio.set_rights(StdioStream::Stderr, WasiRights::FD_WRITE, 0),
            Err(WASI_ENOTCAPABLE)
        );

        // close once then every operation yield ebadf while sibling stream stay open
        assert_eq!(stdio.close(StdioStream::Stdout), Ok(()));
        assert_eq!(stdio.close(StdioStream::Stdout), Err(WASI_EBADF));
        assert_eq!(stdio.fd_fdstat_get(StdioStream::Stdout).err(), Some(WASI_EBADF));
        assert_eq!(stdio.rights(StdioStream::Stdout).err(), Some(WASI_EBADF));
        assert_eq!(stdio.require(StdioStream::Stdout, WasiRights::FD_WRITE), Err(WASI_EBADF));
        assert_eq!(stdio.set_rights(StdioStream::Stdout, 0, 0), Err(WASI_EBADF));
        assert_eq!(stdio.set_fd_flags(StdioStream::Stdout, 0), Err(WASI_EBADF));
        assert!(stdio.fd_fdstat_get(StdioStream::Stdin).is_ok());
        assert!(stdio.fd_fdstat_get(StdioStream::Stderr).is_ok());
    }

    #[test]
    fn test_b3_1_stdio_sink_io_partial_write_error_and_instance_isolation() {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SharedTestSink {
            buf: Arc<Mutex<Vec<u8>>>,
            max_write_per_call: Option<usize>,
            fail_on_call: Option<usize>,
            calls: Arc<Mutex<usize>>,
        }

        impl SharedTestSink {
            fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
                let buf = Arc::new(Mutex::new(Vec::new()));
                (
                    Self {
                        buf: Arc::clone(&buf),
                        max_write_per_call: None,
                        fail_on_call: None,
                        calls: Arc::new(Mutex::new(0)),
                    },
                    buf,
                )
            }
        }

        impl std::io::Write for SharedTestSink {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                let mut calls = self.calls.lock().unwrap();
                *calls += 1;
                if self.fail_on_call == Some(*calls) {
                    return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sink io fail"));
                }
                let take = match self.max_write_per_call {
                    Some(limit) => data.len().min(limit),
                    None => data.len(),
                };
                self.buf.lock().unwrap().extend_from_slice(&data[..take]);
                Ok(take)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // 1. two independent plugin instances with distinct stdout and stderr sink
        let (out_a_sink, out_a_buf) = SharedTestSink::new();
        let (err_a_sink, err_a_buf) = SharedTestSink::new();
        let inst_a = StdioDescriptors::with_sinks(Box::new(out_a_sink), Box::new(err_a_sink));

        let (out_b_sink, out_b_buf) = SharedTestSink::new();
        let (err_b_sink, err_b_buf) = SharedTestSink::new();
        let inst_b = StdioDescriptors::with_sinks(Box::new(out_b_sink), Box::new(err_b_sink));

        // verify stdout and stderr write to their respective sink with exact byte count
        let n_out_a = inst_a
            .write_stream(StdioStream::Stdout, &[b"alpha-", b"stdout"])
            .unwrap();
        assert_eq!(n_out_a, 12);
        assert_eq!(out_a_buf.lock().unwrap().as_slice(), b"alpha-stdout");
        assert!(err_a_buf.lock().unwrap().is_empty());

        let n_err_a = inst_a
            .write_stream(StdioStream::Stderr, &[b"alpha-stderr"])
            .unwrap();
        assert_eq!(n_err_a, 12);
        assert_eq!(err_a_buf.lock().unwrap().as_slice(), b"alpha-stderr");

        // verify stdin return eof zero byte and reject write
        assert_eq!(inst_a.read_stream(StdioStream::Stdin), Ok(0));
        assert_eq!(
            inst_a.write_stream(StdioStream::Stdin, &[b"x"]),
            Err(WASI_ENOTCAPABLE)
        );
        assert_eq!(inst_a.read_stream(StdioStream::Stdout), Err(WASI_ENOTCAPABLE));
        assert_eq!(inst_a.read_stream(StdioStream::Stderr), Err(WASI_ENOTCAPABLE));

        // 2. closing fd 0 1 2 in instance a must not affect instance b
        assert_eq!(inst_a.close(StdioStream::Stdin), Ok(()));
        assert_eq!(inst_a.close(StdioStream::Stdout), Ok(()));
        assert_eq!(inst_a.close(StdioStream::Stderr), Ok(()));
        assert_eq!(inst_a.close(StdioStream::Stdin), Err(WASI_EBADF));
        assert_eq!(inst_a.close(StdioStream::Stdout), Err(WASI_EBADF));
        assert_eq!(inst_a.close(StdioStream::Stderr), Err(WASI_EBADF));
        assert_eq!(inst_a.read_stream(StdioStream::Stdin), Err(WASI_EBADF));
        assert_eq!(inst_a.write_stream(StdioStream::Stdout, &[b"x"]), Err(WASI_EBADF));
        assert_eq!(inst_a.write_stream(StdioStream::Stderr, &[b"x"]), Err(WASI_EBADF));

        assert_eq!(inst_b.read_stream(StdioStream::Stdin), Ok(0));
        assert_eq!(
            inst_b.write_stream(StdioStream::Stdout, &[b"bravo-out"]),
            Ok(9)
        );
        assert_eq!(
            inst_b.write_stream(StdioStream::Stderr, &[b"bravo-err"]),
            Ok(9)
        );
        assert_eq!(out_b_buf.lock().unwrap().as_slice(), b"bravo-out");
        assert_eq!(err_b_buf.lock().unwrap().as_slice(), b"bravo-err");

        // 3. partial write stop at short write boundary and report exact nwritten
        let (mut partial_out_sink, partial_out_buf) = SharedTestSink::new();
        partial_out_sink.max_write_per_call = Some(4);
        let (dummy_err_sink, _) = SharedTestSink::new();
        let inst_partial =
            StdioDescriptors::with_sinks(Box::new(partial_out_sink), Box::new(dummy_err_sink));
        let n_partial = inst_partial
            .write_stream(StdioStream::Stdout, &[b"12345678", b"90"])
            .unwrap();
        assert_eq!(n_partial, 4);
        assert_eq!(partial_out_buf.lock().unwrap().as_slice(), b"1234");

        // 4. sink io error on first chunk return wasi_eio and on second chunk return prior nwritten
        let (mut fail_first_sink, _) = SharedTestSink::new();
        fail_first_sink.fail_on_call = Some(1);
        let (mut fail_second_sink, fail_second_buf) = SharedTestSink::new();
        fail_second_sink.fail_on_call = Some(2);
        let inst_err =
            StdioDescriptors::with_sinks(Box::new(fail_first_sink), Box::new(fail_second_sink));
        assert_eq!(
            inst_err.write_stream(StdioStream::Stdout, &[b"boom"]),
            Err(WASI_EIO)
        );
        assert_eq!(
            inst_err.write_stream(StdioStream::Stderr, &[b"ok-first", b"fail-second"]),
            Ok(8)
        );
        assert_eq!(fail_second_buf.lock().unwrap().as_slice(), b"ok-first");
    }
}
