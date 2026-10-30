// windows nt containment engine feasibility spike
// implement native handle walking and handle direct delete

#![allow(unused_imports, dead_code)]
use super::*;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};

// nt status code
const STATUS_SUCCESS: i32 = 0;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = -1073741772; // 0xc0000034
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = -1073741766; // 0xc000003a
const STATUS_ACCESS_DENIED: i32 = -1073741790; // 0xc0000022
const STATUS_OBJECT_NAME_COLLISION: i32 = -1073741771; // 0xc0000035
const STATUS_SHARING_VIOLATION: i32 = -1073741757; // 0xc0000043
const STATUS_DELETE_PENDING: i32 = -1073741738; // 0xc0000056
const STATUS_PRIVILEGE_NOT_HELD: i32 = -1073741727; // 0xc0000061
const STATUS_DIRECTORY_NOT_EMPTY: i32 = -1073741567; // 0xc0000101
const STATUS_NOT_A_DIRECTORY: i32 = -1073741565; // 0xc0000103
const STATUS_NAME_TOO_LONG: i32 = -1073741562; // 0xc0000106
const STATUS_FILE_IS_A_DIRECTORY: i32 = -1073741638; // 0xc00000ba
const STATUS_CANNOT_DELETE: i32 = -1073741535; // 0xc0000121
const STATUS_REPARSE_POINT_ENCOUNTERED: i32 = -1073741195; // 0xc0000275
const STATUS_STOPPED_ON_SYMLINK: i32 = -2147483603; // 0x8000002d

// access right
const FILE_READ_DATA: u32 = 0x0001;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_ADD_FILE: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const FILE_TRAVERSE: u32 = 0x0020;
const DELETE: u32 = 0x00010000;
const SYNCHRONIZE: u32 = 0x00100000;
const FILE_GENERIC_READ: u32 = 0x00120089;
const FILE_GENERIC_WRITE: u32 = 0x00120116;

// share access
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const FILE_SHARE_DELETE: u32 = 0x00000004;

// create disposition
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;

// create option
const FILE_DIRECTORY_FILE: u32 = 0x00000001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x00004000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x00200000;

// file attribute
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;

// object attribute flag
const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

// file info class
const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
const FILE_END_OF_FILE_INFO_CLASS: u32 = 6;
const FILE_CASE_SENSITIVE_INFO_CLASS: u32 = 71;

// case sensitivity flag
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 0x00000001;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut std::ffi::c_void,
    security_quality_of_service: *mut std::ffi::c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoStatusBlock {
    pub status: i32,
    pub information: usize,
}

#[repr(C)]
struct ByHandleFileInformation {
    dw_file_attributes: u32,
    ft_creation_time_low: u32,
    ft_creation_time_high: u32,
    ft_last_access_time_low: u32,
    ft_last_access_time_high: u32,
    ft_last_write_time_low: u32,
    ft_last_write_time_high: u32,
    dw_volume_serial_number: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    n_number_of_links: u32,
    n_file_index_high: u32,
    n_file_index_low: u32,
}

#[repr(C)]
struct FileDispositionInfo {
    delete_file: u8,
}

#[repr(C)]
struct FileEndOfFileInfo {
    end_of_file: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCaseSensitiveInfo {
    pub flags: u32,
}

// ntfs file identity key from by handle file information
// note refs use 128 bit file id and require file id info query in production
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtfsFileIdentity {
    pub volume_serial_number: u32,
    pub file_index_high: u32,
    pub file_index_low: u32,
}

impl NtfsFileIdentity {
    fn from_info(info: &ByHandleFileInformation) -> Self {
        Self {
            volume_serial_number: info.dw_volume_serial_number,
            file_index_high: info.n_file_index_high,
            file_index_low: info.n_file_index_low,
        }
    }
}

// per file lock table keyed by verified ntfs file identity
// two level lock structure avoid hold global table lock during io wait
pub struct FileLockTable {
    entries: std::sync::Mutex<std::collections::HashMap<NtfsFileIdentity, std::sync::Arc<std::sync::RwLock<()>>>>,
}

struct LockEntryReleaseGuard<'a> {
    table: &'a FileLockTable,
    id: NtfsFileIdentity,
    handle: Option<std::sync::Arc<std::sync::RwLock<()>>>,
}

impl<'a> Drop for LockEntryReleaseGuard<'a> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.table.release_lock_handle(self.id, handle);
        }
    }
}

impl FileLockTable {
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    // acquire per file lock handle while hold table mutex briefly
    pub fn acquire_lock_handle(&self, id: NtfsFileIdentity) -> std::sync::Arc<std::sync::RwLock<()>> {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        std::sync::Arc::clone(
            map.entry(id)
                .or_insert_with(|| std::sync::Arc::new(std::sync::RwLock::new(()))),
        )
    }

    // release per file lock handle and prune entry only when no other contender exist
    pub fn release_lock_handle(&self, id: NtfsFileIdentity, handle: std::sync::Arc<std::sync::RwLock<()>>) {
        let mut map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        drop(handle);
        if let Some(existing) = map.get(&id) {
            if std::sync::Arc::strong_count(existing) == 1 {
                map.remove(&id);
            }
        }
    }

    // execute closure under exclusive per file lock with unwind safe entry release
    pub fn with_exclusive_lock<F, R>(&self, id: NtfsFileIdentity, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let entry_guard = LockEntryReleaseGuard {
            table: self,
            id,
            handle: Some(self.acquire_lock_handle(id)),
        };
        let lock_ref = entry_guard.handle.as_ref().unwrap();
        let _write_guard = lock_ref.write().unwrap_or_else(|e| e.into_inner());
        f()
    }

    // execute closure under shared per file lock with unwind safe entry release
    pub fn with_shared_lock<F, R>(&self, id: NtfsFileIdentity, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let entry_guard = LockEntryReleaseGuard {
            table: self,
            id,
            handle: Some(self.acquire_lock_handle(id)),
        };
        let lock_ref = entry_guard.handle.as_ref().unwrap();
        let _read_guard = lock_ref.read().unwrap_or_else(|e| e.into_inner());
        f()
    }

    // return count of active file identity entry in table
    pub fn active_entry_count(&self) -> usize {
        let map = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        map.len()
    }
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut std::ffi::c_void,
        ea_length: u32,
    ) -> i32;

    fn NtClose(handle: *mut std::ffi::c_void) -> i32;

    fn NtQueryInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;

    #[cfg(test)]
    fn NtSetInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: u32,
    ) -> i32;
}

extern "system" {
    fn GetFileInformationByHandle(
        h_file: *mut std::ffi::c_void,
        lp_file_information: *mut ByHandleFileInformation,
    ) -> i32;

    fn SetFileInformationByHandle(
        h_file: *mut std::ffi::c_void,
        file_information_class: u32,
        lp_file_information: *mut std::ffi::c_void,
        dw_buffer_size: u32,
    ) -> i32;

    fn GetFinalPathNameByHandleW(
        h_file: *mut std::ffi::c_void,
        lpsz_file_path: *mut u16,
        cch_file_path: u32,
        dw_flags: u32,
    ) -> u32;

    #[cfg(test)]
    fn WriteFile(
        h_file: *mut std::ffi::c_void,
        lp_buffer: *const std::ffi::c_void,
        n_number_of_bytes_to_write: u32,
        lp_number_of_bytes_written: *mut u32,
        lp_overlapped: *mut std::ffi::c_void,
    ) -> i32;

    #[cfg(test)]
    fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
}

#[cfg(test)]
extern "C" {
    fn _open_osfhandle(osfhandle: isize, flags: i32) -> i32;
    fn _get_osfhandle(fd: i32) -> isize;
}

// map ntstatus to wasi preview 1 errno
pub fn map_ntstatus_to_wasi(status: i32) -> i32 {
    match status {
        STATUS_SUCCESS => WASI_ESUCCESS,
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND | STATUS_DELETE_PENDING => WASI_ENOENT,
        STATUS_ACCESS_DENIED | STATUS_SHARING_VIOLATION => WASI_EACCES,
        STATUS_PRIVILEGE_NOT_HELD | STATUS_CANNOT_DELETE => WASI_EPERM,
        STATUS_OBJECT_NAME_COLLISION => WASI_EEXIST,
        STATUS_NOT_A_DIRECTORY => WASI_ENOTDIR,
        STATUS_FILE_IS_A_DIRECTORY => WASI_EISDIR,
        STATUS_DIRECTORY_NOT_EMPTY => WASI_ENOTEMPTY,
        STATUS_NAME_TOO_LONG => WASI_EINVAL,
        STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_STOPPED_ON_SYMLINK => WASI_ENOTCAPABLE,
        _ => WASI_EIO,
    }
}

// resolve raw handle from crt descriptor in test harness
#[cfg(test)]
fn resolve_raw_handle(root_fd: i32) -> Result<*mut std::ffi::c_void, i32> {
    if root_fd < 0 {
        return Err(WASI_EBADF);
    }
    let os_handle = unsafe { _get_osfhandle(root_fd) };
    if os_handle != -1 && os_handle != 0 {
        Ok(os_handle as *mut std::ffi::c_void)
    } else {
        let direct = root_fd as isize as *mut std::ffi::c_void;
        if !direct.is_null() {
            Ok(direct)
        } else {
            Err(WASI_EBADF)
        }
    }
}

// query canonical final path for handle
fn get_canonical_handle_path(handle: *mut std::ffi::c_void) -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let len = unsafe { GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0) };
    if len == 0 || len >= buf.len() as u32 {
        return None;
    }
    let s = OsString::from_wide(&buf[..len as usize]);
    let mut p = PathBuf::from(s);
    if let Ok(stripped) = p.strip_prefix(r"\\?\") {
        p = stripped.to_path_buf();
    }
    Some(p)
}

// verify canonical containment using directory boundary aware exact ordinal comparison
pub fn verify_canonical_containment(root_path: &Path, leaf_path: &Path) -> bool {
    let root_comps: Vec<_> = root_path.components().collect();
    let leaf_comps: Vec<_> = leaf_path.components().collect();

    // strict child or self invariant leaf must have at least as many component as root
    if leaf_comps.len() < root_comps.len() {
        return false;
    }

    // exact binary ordinal comparison across all root prefix component
    for (r, l) in root_comps.iter().zip(leaf_comps.iter()) {
        if r.as_os_str() != l.as_os_str() {
            return false;
        }
    }

    true
}

// evaluate nt query information result for case sensitivity with strict fail closed policy
pub fn evaluate_case_sensitive_info(
    status: i32,
    io_status: &IoStatusBlock,
    info: &FileCaseSensitiveInfo,
) -> Result<(), i32> {
    // fail closed on any nt query failure or unsupported information class
    if status != STATUS_SUCCESS {
        return Err(WASI_ENOTCAPABLE);
    }

    // fail closed if io status block indicate error
    if io_status.status != STATUS_SUCCESS {
        return Err(WASI_ENOTCAPABLE);
    }

    // fail closed if buffer size return by kernel is insufficient
    if io_status.information < std::mem::size_of::<FileCaseSensitiveInfo>() {
        return Err(WASI_ENOTCAPABLE);
    }

    // reject directory when case sensitive flag is set
    if (info.flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0 {
        return Err(WASI_ENOTCAPABLE);
    }

    Ok(())
}

// query parent directory case sensitivity state and enforce fail closed policy
pub fn check_parent_case_sensitivity(parent_handle: *mut std::ffi::c_void) -> Result<(), i32> {
    check_parent_case_sensitivity_with_query(parent_handle, |h, ios, inf, len, cls| unsafe {
        NtQueryInformationFile(h, ios, inf, len, cls)
    })
}

// query parent directory case sensitivity state with query runner seam
pub fn check_parent_case_sensitivity_with_query<F>(
    parent_handle: *mut std::ffi::c_void,
    mut query_fn: F,
) -> Result<(), i32>
where
    F: FnMut(*mut std::ffi::c_void, *mut IoStatusBlock, *mut std::ffi::c_void, u32, u32) -> i32,
{
    if parent_handle.is_null() {
        return Err(WASI_EBADF);
    }

    let mut info = FileCaseSensitiveInfo { flags: 0xFFFFFFFF };
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };

    let status = query_fn(
        parent_handle,
        &mut io_status,
        &mut info as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<FileCaseSensitiveInfo>() as u32,
        FILE_CASE_SENSITIVE_INFO_CLASS,
    );

    evaluate_case_sensitive_info(status, &io_status, &info)
}

#[cfg(test)]
pub fn set_directory_case_sensitive(dir_handle: *mut std::ffi::c_void, enable: bool) -> i32 {
    let mut info = FileCaseSensitiveInfo {
        flags: if enable { FILE_CS_FLAG_CASE_SENSITIVE_DIR } else { 0 },
    };
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    unsafe {
        NtSetInformationFile(
            dir_handle,
            &mut io_status,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<FileCaseSensitiveInfo>() as u32,
            FILE_CASE_SENSITIVE_INFO_CLASS,
        )
    }
}

// validate single path component
pub fn validate_component_token(comp: &str) -> Result<(), i32> {
    if comp.is_empty() || comp == "." || comp == ".." {
        return Err(WASI_ENOTCAPABLE);
    }
    if comp.contains('/') || comp.contains('\\') || comp.contains(':') {
        return Err(WASI_ENOTCAPABLE);
    }
    if comp.contains('\0') || comp.contains('*') || comp.contains('?') {
        return Err(WASI_EINVAL);
    }
    Ok(())
}

// parse and validate relative path
pub fn parse_relative_components(rel_path: &str) -> Result<Vec<&str>, i32> {
    let trimmed = rel_path.trim_start_matches("./");
    if trimmed.is_empty() {
        return Err(WASI_EINVAL);
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err(WASI_ENOTCAPABLE);
    }
    if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
        return Err(WASI_ENOTCAPABLE);
    }
    let mut components = Vec::new();
    for part in trimmed.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(WASI_ENOTCAPABLE);
        }
        validate_component_token(part)?;
        components.push(part);
    }
    if components.is_empty() {
        return Err(WASI_EINVAL);
    }
    Ok(components)
}

// open single component relative to verified parent handle via ntcreatefile
fn open_relative_nt_component_with_check<F>(
    parent_handle: *mut std::ffi::c_void,
    component_name: &str,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
    check_case: &F,
) -> Result<*mut std::ffi::c_void, i32>
where
    F: Fn(*mut std::ffi::c_void) -> Result<(), i32>,
{
    validate_component_token(component_name)?;

    // pre-open inspection verify parent directory case sensitivity before resolve child
    check_case(parent_handle)?;

    let mut utf16: Vec<u16> = component_name.encode_utf16().collect();
    let length_bytes = (utf16.len() * 2) as u16;
    let mut ustr = UnicodeString {
        length: length_bytes,
        maximum_length: length_bytes,
        buffer: utf16.as_mut_ptr(),
    };

    let mut obj_attr = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent_handle,
        object_name: &mut ustr,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };

    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut child_handle: *mut std::ffi::c_void = std::ptr::null_mut();

    let status = unsafe {
        NtCreateFile(
            &mut child_handle,
            desired_access | SYNCHRONIZE,
            &mut obj_attr,
            &mut io_status,
            std::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            create_disposition,
            create_options | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null_mut(),
            0,
        )
    };

    if status != STATUS_SUCCESS {
        return Err(map_ntstatus_to_wasi(status));
    }

    Ok(child_handle)
}

fn open_relative_nt_component(
    parent_handle: *mut std::ffi::c_void,
    component_name: &str,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<*mut std::ffi::c_void, i32> {
    open_relative_nt_component_with_check(
        parent_handle,
        component_name,
        desired_access,
        create_disposition,
        create_options,
        &check_parent_case_sensitivity,
    )
}

// walk parent directory handle chain safely
fn walk_parent_directory_handles<F>(
    root_handle: *mut std::ffi::c_void,
    components: &[&str],
    check_case: &F,
) -> Result<*mut std::ffi::c_void, i32>
where
    F: Fn(*mut std::ffi::c_void) -> Result<(), i32>,
{
    let mut current_handle = root_handle;
    let mut handles_to_close: Vec<*mut std::ffi::c_void> = Vec::new();

    for comp in components {
        // pre-open inspection verify current parent directory case sensitivity
        if let Err(e) = check_case(current_handle) {
            for h in handles_to_close {
                unsafe { NtClose(h) };
            }
            return Err(e);
        }

        let child = match open_relative_nt_component_with_check(
            current_handle,
            comp,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            check_case,
        ) {
            Ok(h) => h,
            Err(e) => {
                for h in handles_to_close {
                    unsafe { NtClose(h) };
                }
                return Err(e);
            }
        };

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(child, info.as_mut_ptr()) };
        if ok == 0 {
            unsafe { NtClose(child) };
            for h in handles_to_close {
                unsafe { NtClose(h) };
            }
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            unsafe { NtClose(child) };
            for h in handles_to_close {
                unsafe { NtClose(h) };
            }
            return Err(WASI_ENOTCAPABLE);
        }

        if info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            unsafe { NtClose(child) };
            for h in handles_to_close {
                unsafe { NtClose(h) };
            }
            return Err(WASI_ENOTDIR);
        }

        handles_to_close.push(child);
        current_handle = child;
    }

    if handles_to_close.len() > 1 {
        let len = handles_to_close.len();
        for h in handles_to_close[..len - 1].iter() {
            unsafe { NtClose(*h) };
        }
        Ok(handles_to_close[len - 1])
    } else if handles_to_close.len() == 1 {
        Ok(handles_to_close[0])
    } else {
        Ok(root_handle)
    }
}

// query verified ntfs file identity from raw handle
fn query_ntfs_file_identity(handle: *mut std::ffi::c_void) -> Result<NtfsFileIdentity, i32> {
    if handle.is_null() {
        return Err(WASI_EBADF);
    }
    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) };
    if ok == 0 {
        return Err(WASI_EIO);
    }
    let info = unsafe { info.assume_init() };
    Ok(NtfsFileIdentity::from_info(&info))
}

// set verified handle end of file via fileendoffileinfo class under exclusive lock
fn set_verified_handle_end_of_file(handle: *mut std::ffi::c_void, size: u64) -> Result<(), WasiErrno> {
    let eof = i64::try_from(size).map_err(|_| WASI_EINVAL)?;
    let mut eof_info = FileEndOfFileInfo { end_of_file: eof };
    let ok = unsafe {
        SetFileInformationByHandle(
            handle,
            FILE_END_OF_FILE_INFO_CLASS,
            &mut eof_info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<FileEndOfFileInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(WASI_EIO);
    }
    Ok(())
}

// truncate verified handle to zero via fileendoffileinfo class under exclusive lock
fn truncate_verified_handle_to_zero(handle: *mut std::ffi::c_void) -> Result<(), WasiErrno> {
    set_verified_handle_end_of_file(handle, 0)
}

// open host directory handle for containment root without follow reparse point
pub fn open_directory_for_containment(path: &Path) -> Result<std::fs::File, WasiErrno> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    // 0x02000000 backup semantic flag and 0x00200000 open reparse point flag
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x02000000 | 0x00200000)
        .open(path)
        .map_err(|_| WASI_ENOENT)?;

    let raw_handle = file.as_raw_handle() as *mut std::ffi::c_void;

    let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(raw_handle, info.as_mut_ptr()) };
    if ok == 0 {
        return Err(WASI_EIO);
    }
    let info = unsafe { info.assume_init() };

    if info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(WASI_ENOTDIR);
    }
    if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(WASI_ENOTCAPABLE);
    }

    check_parent_case_sensitivity(raw_handle)?;

    Ok(file)
}

// query verified ntfs file identity for owned runtime file handle
pub fn query_file_identity(file: &std::fs::File) -> Result<NtfsFileIdentity, WasiErrno> {
    use std::os::windows::io::AsRawHandle;
    let handle = file.as_raw_handle() as *mut std::ffi::c_void;
    if handle.is_null() || handle as isize == -1 {
        return Err(WASI_EBADF);
    }
    query_ntfs_file_identity(handle)
}

#[derive(Clone)]
pub struct WindowsContainmentEngine {
    lock_table: std::sync::Arc<FileLockTable>,
    #[cfg(test)]
    case_query_override: Option<std::sync::Arc<dyn Fn(*mut std::ffi::c_void) -> Result<(), i32> + Send + Sync>>,
}

impl WindowsContainmentEngine {
    pub fn new() -> Self {
        Self::with_lock_table(std::sync::Arc::new(FileLockTable::new()))
    }

    // construct engine bound to shared runtime file lock table
    pub fn with_lock_table(lock_table: std::sync::Arc<FileLockTable>) -> Self {
        Self {
            lock_table,
            #[cfg(test)]
            case_query_override: None,
        }
    }

    pub fn lock_table(&self) -> &std::sync::Arc<FileLockTable> {
        &self.lock_table
    }

    // query verified ntfs file identity for owned runtime file handle
    pub fn file_identity_for_file(&self, file: &std::fs::File) -> Result<NtfsFileIdentity, WasiErrno> {
        query_file_identity(file)
    }

    // execute coordinated size update on owned runtime file handle through per file exclusive lock
    pub fn set_file_size_for_file(&self, file: &std::fs::File, size: u64) -> Result<(), WasiErrno> {
        use std::os::windows::io::AsRawHandle;
        let handle = file.as_raw_handle() as *mut std::ffi::c_void;
        if handle.is_null() || handle as isize == -1 {
            return Err(WASI_EBADF);
        }
        let file_id = query_ntfs_file_identity(handle)?;
        self.lock_table
            .with_exclusive_lock(file_id, || set_verified_handle_end_of_file(handle, size))
    }

    // query verified ntfs file identity for open descriptor in spike test
    #[cfg(test)]
    pub fn file_identity_for_fd(&self, fd: i32) -> Result<NtfsFileIdentity, i32> {
        let handle = resolve_raw_handle(fd)?;
        query_ntfs_file_identity(handle)
    }

    // execute coordinated truncate on open descriptor through per file exclusive lock in spike test
    #[cfg(test)]
    pub fn truncate_synchronized(&self, fd: i32) -> Result<(), i32> {
        let handle = resolve_raw_handle(fd)?;
        let file_id = query_ntfs_file_identity(handle)?;
        self.lock_table
            .with_exclusive_lock(file_id, || truncate_verified_handle_to_zero(handle))
    }

    // execute coordinated write on open descriptor through per file exclusive lock in spike test
    // preserve descriptor file pointer without implicit offset relocation
    #[cfg(test)]
    pub fn write_synchronized(&self, fd: i32, data: &[u8]) -> Result<usize, i32> {
        let handle = resolve_raw_handle(fd)?;
        let file_id = query_ntfs_file_identity(handle)?;
        self.lock_table.with_exclusive_lock(file_id, || {
            let mut total_written: usize = 0;
            while total_written < data.len() {
                let remaining = &data[total_written..];
                let chunk_len = remaining.len().min(u32::MAX as usize) as u32;
                let mut written: u32 = 0;
                let ok = unsafe {
                    WriteFile(
                        handle,
                        remaining.as_ptr() as *const std::ffi::c_void,
                        chunk_len,
                        &mut written,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    return Err(WASI_EIO);
                }
                if written == 0 {
                    break;
                }
                total_written += written as usize;
            }
            Ok(total_written)
        })
    }

    #[cfg(test)]
    pub fn new_with_case_hook<F>(hook: F) -> Self
    where
        F: Fn(*mut std::ffi::c_void) -> Result<(), i32> + Send + Sync + 'static,
    {
        Self {
            lock_table: std::sync::Arc::new(FileLockTable::new()),
            case_query_override: Some(std::sync::Arc::new(hook)),
        }
    }

    fn check_case(&self, handle: *mut std::ffi::c_void) -> Result<(), i32> {
        #[cfg(test)]
        if let Some(ref hook) = self.case_query_override {
            return hook(handle);
        }
        check_parent_case_sensitivity(handle)
    }

    fn open_owned_handle_beneath(
        &self,
        root_handle: *mut std::ffi::c_void,
        rel_path: &str,
        flags: OpenFlags,
    ) -> Result<std::os::windows::io::OwnedHandle, WasiErrno> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

        if root_handle.is_null() || root_handle as isize == -1 {
            return Err(WASI_EBADF);
        }
        let components = parse_relative_components(rel_path)?;

        let mut root_info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let root_ok = unsafe { GetFileInformationByHandle(root_handle, root_info.as_mut_ptr()) };
        if root_ok == 0 {
            return Err(WASI_EBADF);
        }
        let root_info = unsafe { root_info.assume_init() };

        // verify root handle itself is directory
        if root_info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(WASI_ENOTDIR);
        }

        // verify root handle is not reparse point
        if root_info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WASI_ENOTCAPABLE);
        }

        // pre-open inspection verify root directory case sensitivity before resolve any child
        self.check_case(root_handle)?;

        let check_fn = |h| self.check_case(h);

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1], &check_fn)?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        // pre-open inspection verify parent handle before resolve leaf component
        if let Err(e) = self.check_case(parent_handle) {
            if should_close_parent {
                unsafe { NtClose(parent_handle) };
            }
            return Err(e);
        }

        let (desired_access, create_disposition, create_options) = if flags.directory {
            (
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            )
        } else {
            let mut acc = FILE_READ_ATTRIBUTES;
            if flags.read {
                acc |= FILE_GENERIC_READ;
            }
            if flags.write || flags.create || flags.truncate {
                acc |= FILE_GENERIC_WRITE;
            }

            let disp = if flags.create {
                FILE_OPEN_IF
            } else {
                FILE_OPEN
            };

            (acc, disp, FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT)
        };

        let leaf_res = open_relative_nt_component_with_check(
            parent_handle,
            leaf_name,
            desired_access,
            create_disposition,
            create_options,
            &check_fn,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        // transfer raw handle ownership to ownedhandle immediately before fallible check
        let raw_leaf = leaf_res?;
        let owned_leaf = unsafe { OwnedHandle::from_raw_handle(raw_leaf as _) };
        let leaf_handle = owned_leaf.as_raw_handle() as *mut std::ffi::c_void;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        // reject reparse point
        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WASI_ENOTCAPABLE);
        }

        // hard link containment policy check
        // reject file with multiple hard link to prevent external alias write
        if !flags.directory && info.n_number_of_links > 1 {
            return Err(WASI_ENOTCAPABLE);
        }

        // volume cross device check
        if info.dw_volume_serial_number != root_info.dw_volume_serial_number {
            return Err(WASI_ENOTCAPABLE);
        }

        // canonical boundary verification with exact ordinal component comparison
        if let Some(root_path) = get_canonical_handle_path(root_handle) {
            if let Some(leaf_path) = get_canonical_handle_path(leaf_handle) {
                if !verify_canonical_containment(&root_path, &leaf_path) {
                    return Err(WASI_ENOTCAPABLE);
                }
            } else {
                return Err(WASI_ENOTCAPABLE);
            }
        }

        // coordinated truncate execution on verified handle under per file exclusive lock
        if flags.truncate && !flags.directory {
            let file_id = NtfsFileIdentity::from_info(&info);
            self.lock_table
                .with_exclusive_lock(file_id, || truncate_verified_handle_to_zero(leaf_handle))?;
        }

        Ok(owned_leaf)
    }

    fn mkdir_raw_handle_beneath(&self, root_handle: *mut std::ffi::c_void, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};

        if root_handle.is_null() || root_handle as isize == -1 {
            return Err(WASI_EBADF);
        }
        let components = parse_relative_components(rel_path)?;

        // pre-open inspection verify root directory case sensitivity before resolve any child
        self.check_case(root_handle)?;

        let check_fn = |h| self.check_case(h);

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1], &check_fn)?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        // pre-open inspection verify parent handle before resolve leaf component
        if let Err(e) = self.check_case(parent_handle) {
            if should_close_parent {
                unsafe { NtClose(parent_handle) };
            }
            return Err(e);
        }

        let res = open_relative_nt_component_with_check(
            parent_handle,
            leaf_name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            &check_fn,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        let raw_dir = res?;
        let _owned_dir = unsafe { OwnedHandle::from_raw_handle(raw_dir as _) };
        Ok(())
    }

    fn unlink_raw_handle_beneath(&self, root_handle: *mut std::ffi::c_void, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

        if root_handle.is_null() || root_handle as isize == -1 {
            return Err(WASI_EBADF);
        }
        let components = parse_relative_components(rel_path)?;

        // pre-open inspection verify root directory case sensitivity before resolve any child
        self.check_case(root_handle)?;

        let check_fn = |h| self.check_case(h);

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1], &check_fn)?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        // pre-open inspection verify parent handle before resolve leaf component
        if let Err(e) = self.check_case(parent_handle) {
            if should_close_parent {
                unsafe { NtClose(parent_handle) };
            }
            return Err(e);
        }

        let res = open_relative_nt_component_with_check(
            parent_handle,
            leaf_name,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            &check_fn,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        // transfer raw handle ownership to ownedhandle immediately before fallible check
        let raw_leaf = res?;
        let owned_leaf = unsafe { OwnedHandle::from_raw_handle(raw_leaf as _) };
        let leaf_handle = owned_leaf.as_raw_handle() as *mut std::ffi::c_void;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WASI_ENOTCAPABLE);
        }

        if info.n_number_of_links > 1 {
            return Err(WASI_ENOTCAPABLE);
        }

        let mut disp = FileDispositionInfo { delete_file: 1 };
        let ok = unsafe {
            SetFileInformationByHandle(
                leaf_handle,
                FILE_DISPOSITION_INFO_CLASS,
                &mut disp as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<FileDispositionInfo>() as u32,
            )
        };

        if ok == 0 {
            Err(WASI_EIO)
        } else {
            Ok(())
        }
    }

    fn rmdir_raw_handle_beneath(&self, root_handle: *mut std::ffi::c_void, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

        if root_handle.is_null() || root_handle as isize == -1 {
            return Err(WASI_EBADF);
        }
        let components = parse_relative_components(rel_path)?;

        // pre-open inspection verify root directory case sensitivity before resolve any child
        self.check_case(root_handle)?;

        let check_fn = |h| self.check_case(h);

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1], &check_fn)?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        // pre-open inspection verify parent handle before resolve leaf component
        if let Err(e) = self.check_case(parent_handle) {
            if should_close_parent {
                unsafe { NtClose(parent_handle) };
            }
            return Err(e);
        }

        let res = open_relative_nt_component_with_check(
            parent_handle,
            leaf_name,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
            &check_fn,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        // transfer raw handle ownership to ownedhandle immediately before fallible check
        let raw_leaf = res?;
        let owned_leaf = unsafe { OwnedHandle::from_raw_handle(raw_leaf as _) };
        let leaf_handle = owned_leaf.as_raw_handle() as *mut std::ffi::c_void;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(WASI_ENOTCAPABLE);
        }

        let mut disp = FileDispositionInfo { delete_file: 1 };
        let ok = unsafe {
            SetFileInformationByHandle(
                leaf_handle,
                FILE_DISPOSITION_INFO_CLASS,
                &mut disp as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<FileDispositionInfo>() as u32,
            )
        };

        if ok == 0 {
            Err(WASI_ENOTEMPTY)
        } else {
            Ok(())
        }
    }
}

impl RuntimeContainmentEngine for WindowsContainmentEngine {
    fn open_file_beneath(
        &self,
        root_dir: &std::fs::File,
        rel_path: &str,
        flags: OpenFlags,
    ) -> Result<std::fs::File, WasiErrno> {
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_dir.as_raw_handle() as *mut std::ffi::c_void;
        let owned = self.open_owned_handle_beneath(root_handle, rel_path, flags)?;
        Ok(std::fs::File::from(owned))
    }

    fn mkdir_file_beneath(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_dir.as_raw_handle() as *mut std::ffi::c_void;
        self.mkdir_raw_handle_beneath(root_handle, rel_path)
    }

    fn unlink_file_beneath_handle(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_dir.as_raw_handle() as *mut std::ffi::c_void;
        self.unlink_raw_handle_beneath(root_handle, rel_path)
    }

    fn rmdir_beneath_handle(&self, root_dir: &std::fs::File, rel_path: &str) -> Result<(), WasiErrno> {
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_dir.as_raw_handle() as *mut std::ffi::c_void;
        self.rmdir_raw_handle_beneath(root_handle, rel_path)
    }
}

#[cfg(test)]
impl AtomicContainmentEngine for WindowsContainmentEngine {
    fn open_beneath(&self, root_fd: i32, rel_path: &str, flags: OpenFlags) -> Result<i32, i32> {
        use std::os::windows::io::IntoRawHandle;
        let root_handle = resolve_raw_handle(root_fd)?;
        let owned_leaf = self.open_owned_handle_beneath(root_handle, rel_path, flags)?;
        let leaf_handle = owned_leaf.into_raw_handle() as *mut std::ffi::c_void;
        let crt_flags = if flags.write || flags.create || flags.truncate { 0x0002 | 0x8000 } else { 0x0000 | 0x8000 };
        let fd = unsafe { _open_osfhandle(leaf_handle as isize, crt_flags) };
        if fd < 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_EIO);
        }
        Ok(fd)
    }

    fn mkdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        self.mkdir_raw_handle_beneath(root_handle, rel_path)
    }

    fn unlink_file_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        self.unlink_raw_handle_beneath(root_handle, rel_path)
    }

    fn rmdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        self.rmdir_raw_handle_beneath(root_handle, rel_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_component_validation() {
        assert_eq!(validate_component_token(""), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token("."), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token(".."), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token("foo/bar"), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token("foo\\bar"), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token("C:"), Err(WASI_ENOTCAPABLE));
        assert_eq!(validate_component_token("file*"), Err(WASI_EINVAL));
        assert_eq!(validate_component_token("valid_name.txt"), Ok(()));
    }

    #[test]
    fn test_windows_relative_path_parsing() {
        assert_eq!(parse_relative_components(""), Err(WASI_EINVAL));
        assert_eq!(parse_relative_components("/abs/path"), Err(WASI_ENOTCAPABLE));
        assert_eq!(parse_relative_components("\\abs\\path"), Err(WASI_ENOTCAPABLE));
        assert_eq!(parse_relative_components("C:/path"), Err(WASI_ENOTCAPABLE));
        assert_eq!(parse_relative_components("a/../b"), Err(WASI_ENOTCAPABLE));

        let res = parse_relative_components("a/b/c.txt").unwrap();
        assert_eq!(res, vec!["a", "b", "c.txt"]);

        let res2 = parse_relative_components("./sub\\file.txt").unwrap();
        assert_eq!(res2, vec!["sub", "file.txt"]);
    }

    #[test]
    fn test_windows_ntstatus_mapping() {
        assert_eq!(map_ntstatus_to_wasi(STATUS_SUCCESS), WASI_ESUCCESS);
        assert_eq!(map_ntstatus_to_wasi(STATUS_OBJECT_NAME_NOT_FOUND), WASI_ENOENT);
        assert_eq!(map_ntstatus_to_wasi(STATUS_OBJECT_PATH_NOT_FOUND), WASI_ENOENT);
        assert_eq!(map_ntstatus_to_wasi(STATUS_ACCESS_DENIED), WASI_EACCES);
        assert_eq!(map_ntstatus_to_wasi(STATUS_SHARING_VIOLATION), WASI_EACCES);
        assert_eq!(map_ntstatus_to_wasi(STATUS_PRIVILEGE_NOT_HELD), WASI_EPERM);
        assert_eq!(map_ntstatus_to_wasi(STATUS_OBJECT_NAME_COLLISION), WASI_EEXIST);
        assert_eq!(map_ntstatus_to_wasi(STATUS_NOT_A_DIRECTORY), WASI_ENOTDIR);
        assert_eq!(map_ntstatus_to_wasi(STATUS_FILE_IS_A_DIRECTORY), WASI_EISDIR);
        assert_eq!(map_ntstatus_to_wasi(STATUS_DIRECTORY_NOT_EMPTY), WASI_ENOTEMPTY);
        assert_eq!(map_ntstatus_to_wasi(STATUS_REPARSE_POINT_ENCOUNTERED), WASI_ENOTCAPABLE);
        assert_eq!(map_ntstatus_to_wasi(STATUS_STOPPED_ON_SYMLINK), WASI_ENOTCAPABLE);
        assert_eq!(map_ntstatus_to_wasi(99999), WASI_EIO);
    }

    #[test]
    fn test_windows_truncate_semantics_deterministic() {
        let temp_dir = std::env::temp_dir().join(format!("plug_win_trunc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let target_file = temp_dir.join("existing_large.bin");
        std::fs::write(&target_file, vec![0xAAu8; 512]).unwrap();
        assert_eq!(std::fs::metadata(&target_file).unwrap().len(), 512);

        use std::os::windows::fs::OpenOptionsExt;
        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&temp_dir)
            .unwrap();
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = WindowsContainmentEngine::new();
        let open_flags = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: true,
            directory: false,
            follow_symlinks: false,
        };

        let fd = engine.open_beneath(root_fd, "existing_large.bin", open_flags).expect("truncate open fail");
        assert!(fd >= 0);

        unsafe { libc::write(fd, b"ABCDE".as_ptr() as *const _, 5) };
        unsafe { libc::close(fd) };

        let file_bytes = std::fs::read(&target_file).unwrap();
        assert_eq!(file_bytes.len(), 5, "file was not truncated to zero before write");
        assert_eq!(file_bytes, b"ABCDE");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_ntfs_containment_gates() {
        let temp_dir = std::env::temp_dir().join(format!("plug_win_spike_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let outside_dir = temp_dir.join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let sentinel_path = outside_dir.join("sentinel.txt");
        std::fs::write(&sentinel_path, b"sentinel original content").unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = WindowsContainmentEngine::new();

        // WIN-GATE 1: standard in-capability write and read
        let open_flags_create = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        };
        let file_fd = engine.open_beneath(root_fd, "test_file.txt", open_flags_create).expect("gate 1 open fail");
        assert!(file_fd >= 0);
        unsafe { libc::write(file_fd, b"hello world".as_ptr() as *const _, 11) };
        unsafe { libc::close(file_fd) };
        assert_eq!(std::fs::read(sandbox_dir.join("test_file.txt")).unwrap(), b"hello world");

        // WIN-GATE 2: rooted path and .. traversal rejected
        assert_eq!(engine.open_beneath(root_fd, "../outside/sentinel.txt", OpenFlags::default()), Err(WASI_ENOTCAPABLE));
        assert_eq!(engine.open_beneath(root_fd, "/sentinel.txt", OpenFlags::default()), Err(WASI_ENOTCAPABLE));
        assert_eq!(engine.open_beneath(root_fd, "C:/sentinel.txt", OpenFlags::default()), Err(WASI_ENOTCAPABLE));

        // WIN-GATE 5: handle-based unlink
        assert!(sandbox_dir.join("test_file.txt").exists());
        engine.unlink_file_beneath(root_fd, "test_file.txt").expect("gate 5 unlink fail");
        assert!(!sandbox_dir.join("test_file.txt").exists());

        // WIN-GATE 7: HARD-LINK REJECTION
        let hardlink_in_sandbox = sandbox_dir.join("hardlinked_sentinel.txt");
        std::fs::hard_link(&sentinel_path, &hardlink_in_sandbox).expect("create hard link fail");
        assert!(hardlink_in_sandbox.exists());

        let open_flags_write = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: true,
            directory: false,
            follow_symlinks: false,
        };
        let open_res = engine.open_beneath(root_fd, "hardlinked_sentinel.txt", open_flags_write);
        assert_eq!(open_res, Err(WASI_ENOTCAPABLE), "hard link must be rejected by containment policy");

        let sentinel_content = std::fs::read(&sentinel_path).unwrap();
        assert_eq!(sentinel_content, b"sentinel original content", "outside sentinel was modified by hard link alias");

        let unlink_res = engine.unlink_file_beneath(root_fd, "hardlinked_sentinel.txt");
        assert_eq!(unlink_res, Err(WASI_ENOTCAPABLE), "unlink hard link must fail-closed");
        assert_eq!(std::fs::read(&sentinel_path).unwrap(), b"sentinel original content");

        // cleanup
        let _ = std::fs::remove_file(&hardlink_in_sandbox);
        let _ = std::fs::remove_file(&sentinel_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_ntfs_junction_rejection() {
        let temp_dir = std::env::temp_dir().join(format!("plug_win_junc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let outside_dir = temp_dir.join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let sentinel_path = outside_dir.join("sentinel.txt");
        std::fs::write(&sentinel_path, b"outside secret data").unwrap();

        let junction_path = sandbox_dir.join("junction_escape");
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("New-Item -ItemType Junction -Path '{}' -Target '{}' -Force -Confirm:$false", junction_path.display(), outside_dir.display())])
            .status()
            .expect("invoke powershell junction fail");
        assert!(status.success(), "failed to create test junction");

        use std::os::windows::fs::OpenOptionsExt;
        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = WindowsContainmentEngine::new();

        // attempt to walk through junction to read sentinel
        let res = engine.open_beneath(root_fd, "junction_escape/sentinel.txt", OpenFlags::default());
        assert_eq!(res, Err(WASI_ENOTCAPABLE), "junction escape must be denied by handle walking");

        // attempt to open junction itself
        let junc_open = engine.open_beneath(root_fd, "junction_escape", OpenFlags { directory: true, ..OpenFlags::default() });
        assert_eq!(junc_open, Err(WASI_ENOTCAPABLE), "junction opening must be denied by reparse check");

        // outside sentinel verified intact
        assert_eq!(std::fs::read(&sentinel_path).unwrap(), b"outside secret data");

        let _ = std::fs::remove_dir(&junction_path);
        let _ = std::fs::remove_file(&sentinel_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_concurrent_namespace_mutation() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = std::env::temp_dir().join(format!("plug_win_stress_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir).unwrap();

        let outside_dir = temp_dir.join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let sentinel_path = outside_dir.join("sentinel.txt");
        std::fs::write(&sentinel_path, b"unmodified stress sentinel").unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        use std::os::windows::io::AsRawHandle;
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = Arc::new(WindowsContainmentEngine::new());
        let mut handles = Vec::new();

        for tid in 0..4 {
            let engine_clone = Arc::clone(&engine);
            let handle = thread::spawn(move || {
                for i in 0..50 {
                    let filename = format!("file_{}_{}.txt", tid, i);
                    let open_flags = OpenFlags {
                        read: true,
                        write: true,
                        create: true,
                        truncate: false,
                        directory: false,
                        follow_symlinks: false,
                    };
                    if let Ok(fd) = engine_clone.open_beneath(root_fd, &filename, open_flags) {
                        unsafe { libc::write(fd, b"thread payload".as_ptr() as *const _, 14) };
                        unsafe { libc::close(fd) };
                        let _ = engine_clone.unlink_file_beneath(root_fd, &filename);
                    }
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(std::fs::read(&sentinel_path).unwrap(), b"unmodified stress sentinel");
        let _ = std::fs::remove_file(&sentinel_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_case_sensitive_evaluation_rules() {
        // test evaluate case sensitive info strict fail closed rule
        let success_io = IoStatusBlock {
            status: STATUS_SUCCESS,
            information: std::mem::size_of::<FileCaseSensitiveInfo>(),
        };

        // ordinary case insensitive directory succeed
        let normal_info = FileCaseSensitiveInfo { flags: 0 };
        assert_eq!(evaluate_case_sensitive_info(STATUS_SUCCESS, &success_io, &normal_info), Ok(()));

        // case sensitive directory flag reject
        let cs_info = FileCaseSensitiveInfo { flags: FILE_CS_FLAG_CASE_SENSITIVE_DIR };
        assert_eq!(evaluate_case_sensitive_info(STATUS_SUCCESS, &success_io, &cs_info), Err(WASI_ENOTCAPABLE));

        // multi-flag with bit 0 set reject
        let multi_flag_info = FileCaseSensitiveInfo { flags: 0x00000003 };
        assert_eq!(evaluate_case_sensitive_info(STATUS_SUCCESS, &success_io, &multi_flag_info), Err(WASI_ENOTCAPABLE));

        // nt query failure reject
        assert_eq!(evaluate_case_sensitive_info(STATUS_ACCESS_DENIED, &success_io, &normal_info), Err(WASI_ENOTCAPABLE));
        assert_eq!(evaluate_case_sensitive_info(-1073741821, &success_io, &normal_info), Err(WASI_ENOTCAPABLE)); // STATUS_INVALID_INFO_CLASS
        assert_eq!(evaluate_case_sensitive_info(-1073741637, &success_io, &normal_info), Err(WASI_ENOTCAPABLE)); // STATUS_NOT_SUPPORTED

        // io status block failure reject
        let err_io = IoStatusBlock {
            status: STATUS_ACCESS_DENIED,
            information: std::mem::size_of::<FileCaseSensitiveInfo>(),
        };
        assert_eq!(evaluate_case_sensitive_info(STATUS_SUCCESS, &err_io, &normal_info), Err(WASI_ENOTCAPABLE));

        // truncated information length reject
        let trunc_io = IoStatusBlock {
            status: STATUS_SUCCESS,
            information: 2,
        };
        assert_eq!(evaluate_case_sensitive_info(STATUS_SUCCESS, &trunc_io, &normal_info), Err(WASI_ENOTCAPABLE));
    }

    #[test]
    fn test_windows_case_sensitivity_query_real_ntfs() {
        // test native case sensitivity query on real ntfs fixture
        let temp_dir = std::env::temp_dir().join(format!("plug_win_cs_real_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&temp_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle();

        // real ntfs ordinary directory query succeed
        let query_res = check_parent_case_sensitivity(root_handle);
        assert_eq!(query_res, Ok(()));

        // query with null handle fail closed with ebadf
        assert_eq!(check_parent_case_sensitivity(std::ptr::null_mut()), Err(WASI_EBADF));

        // query with invalid handle fail closed with enotcapable
        assert_eq!(check_parent_case_sensitivity(!0 as *mut std::ffi::c_void), Err(WASI_ENOTCAPABLE));

        // query with closed handle produce kernel query failure and fail closed with enotcapable
        let test_bin = temp_dir.join("test_write_only.bin");
        std::fs::write(&test_bin, b"sample").unwrap();
        let query_fail_file = std::fs::OpenOptions::new()
            .read(true)
            .open(&test_bin)
            .unwrap();
        let query_fail_handle = query_fail_file.as_raw_handle();
        unsafe { CloseHandle(query_fail_handle) };
        std::mem::forget(query_fail_file);
        assert_eq!(check_parent_case_sensitivity(query_fail_handle), Err(WASI_ENOTCAPABLE));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_case_sensitive_sandbox_root_rejection_fail_closed() {
        // test case sensitive sandbox root reject before open child
        let temp_dir = std::env::temp_dir().join(format!("plug_win_cs_root_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        std::fs::create_dir_all(&sandbox_dir).unwrap();
        let sentinel_file = sandbox_dir.join("sentinel.txt");
        std::fs::write(&sentinel_file, b"intact root sentinel").unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle();
        let root_addr = root_handle as usize;
        let root_fd = unsafe { _open_osfhandle(root_handle as isize, 0x8000) };
        assert!(root_fd >= 0);

        // hook simulate case sensitive root directory
        let engine = WindowsContainmentEngine::new_with_case_hook(move |h| {
            if h as usize == root_addr {
                Err(WASI_ENOTCAPABLE)
            } else {
                check_parent_case_sensitivity(h)
            }
        });

        // case sensitive root reject open with enotcapable
        let open_flags_create = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        };
        let res = engine.open_beneath(root_fd, "new_file.txt", open_flags_create);
        assert_eq!(res, Err(WASI_ENOTCAPABLE));

        // verify zero unintended file create
        assert!(!sandbox_dir.join("new_file.txt").exists());

        // case sensitive root reject mkdir with enotcapable
        let mkdir_res = engine.mkdir_beneath(root_fd, "new_sub_dir");
        assert_eq!(mkdir_res, Err(WASI_ENOTCAPABLE));

        // verify zero unintended directory create
        assert!(!sandbox_dir.join("new_sub_dir").exists());

        // case sensitive root reject unlink with enotcapable
        let unlink_res = engine.unlink_file_beneath(root_fd, "sentinel.txt");
        assert_eq!(unlink_res, Err(WASI_ENOTCAPABLE));

        // verify pre-existing file intact
        assert_eq!(std::fs::read(&sentinel_file).unwrap(), b"intact root sentinel");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_case_sensitive_intermediate_parent_rejection() {
        // test case sensitive intermediate parent reject before open child
        let temp_dir = std::env::temp_dir().join(format!("plug_win_cs_inter_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        let parent_dir = sandbox_dir.join("intermediate");
        std::fs::create_dir_all(&parent_dir).unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle();
        let root_addr = root_handle as usize;
        let root_fd = unsafe { _open_osfhandle(root_handle as isize, 0x8000) };
        assert!(root_fd >= 0);

        // hook permit root but reject intermediate directory
        let engine = WindowsContainmentEngine::new_with_case_hook(move |h| {
            if h as usize == root_addr {
                Ok(())
            } else {
                Err(WASI_ENOTCAPABLE)
            }
        });

        // case sensitive intermediate parent reject file open
        let open_flags_create = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        };
        let res = engine.open_beneath(root_fd, "intermediate/blocked_child.txt", open_flags_create);
        assert_eq!(res, Err(WASI_ENOTCAPABLE));

        // verify zero unintended file create in intermediate directory
        assert!(!parent_dir.join("blocked_child.txt").exists());

        // case sensitive intermediate parent reject mkdir
        let mkdir_res = engine.mkdir_beneath(root_fd, "intermediate/blocked_sub");
        assert_eq!(mkdir_res, Err(WASI_ENOTCAPABLE));

        // verify zero unintended directory create in intermediate directory
        assert!(!parent_dir.join("blocked_sub").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_case_sensitivity_query_failure_fail_closed() {
        // test query failure produce fail closed behavior
        let temp_dir = std::env::temp_dir().join(format!("plug_win_cs_fail_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let sandbox_dir = temp_dir.join("sandbox");
        let intermediate_dir = sandbox_dir.join("sub");
        std::fs::create_dir_all(&intermediate_dir).unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&sandbox_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle();
        let root_addr = root_handle as usize;
        let root_fd = unsafe { _open_osfhandle(root_handle as isize, 0x8000) };
        assert!(root_fd >= 0);

        // hook simulate query failure on intermediate handle
        let engine = WindowsContainmentEngine::new_with_case_hook(move |h| {
            if h as usize == root_addr {
                Ok(())
            } else {
                // simulate ntqueryinformationfile failure e.g. status_invalid_info_class
                Err(WASI_ENOTCAPABLE)
            }
        });

        // query failure fail closed with enotcapable
        let res = engine.open_beneath(root_fd, "sub/target.txt", OpenFlags { create: true, write: true, ..OpenFlags::default() });
        assert_eq!(res, Err(WASI_ENOTCAPABLE));
        assert!(!intermediate_dir.join("target.txt").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_real_ntfs_case_sensitive_attribute_gating() {
        // test real ntfs case sensitive root and intermediate parent gating
        let temp_dir = std::env::temp_dir().join(format!("plug_win_cs_attr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let cs_root_dir = temp_dir.join("cs_root");
        std::fs::create_dir_all(&cs_root_dir).unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_dir_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x02000000)
            .open(&cs_root_dir)
            .unwrap();
        let root_dir_handle = root_dir_file.as_raw_handle();

        // attempt enable case sensitive attribute on real ntfs directory
        let status = set_directory_case_sensitive(root_dir_handle, true);
        println!("[NTFS CASE SENSITIVE FIXTURE] NtSetInformationFile status: 0x{:08X}", status);

        if status == STATUS_SUCCESS {
            // test 1: real case sensitive root rejection
            let root_fd = unsafe { _open_osfhandle(root_dir_handle as isize, 0x8000) };
            assert!(root_fd >= 0);

            let engine = WindowsContainmentEngine::new();
            let open_flags_create = OpenFlags {
                read: true,
                write: true,
                create: true,
                truncate: false,
                directory: false,
                follow_symlinks: false,
            };

            // real case sensitive root reject open with enotcapable
            let res = engine.open_beneath(root_fd, "new_file.txt", open_flags_create);
            assert_eq!(res, Err(WASI_ENOTCAPABLE));
            // verify zero unintended file create in real case sensitive root
            assert!(!cs_root_dir.join("new_file.txt").exists());

            // real case sensitive root reject mkdir with enotcapable
            let res_mkdir = engine.mkdir_beneath(root_fd, "sub_dir");
            assert_eq!(res_mkdir, Err(WASI_ENOTCAPABLE));
            // verify zero unintended directory create in real case sensitive root
            assert!(!cs_root_dir.join("sub_dir").exists());

            // test 2: real case sensitive intermediate parent rejection
            let norm_sandbox = temp_dir.join("norm_sandbox");
            let cs_inter_dir = norm_sandbox.join("cs_inter");
            std::fs::create_dir_all(&cs_inter_dir).unwrap();

            let inter_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(0x02000000)
                .open(&cs_inter_dir)
                .unwrap();
            let inter_handle = inter_file.as_raw_handle();
            let inter_status = set_directory_case_sensitive(inter_handle, true);
            assert_eq!(inter_status, STATUS_SUCCESS);

            let norm_root_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(0x02000000)
                .open(&norm_sandbox)
                .unwrap();
            let norm_root_handle = norm_root_file.as_raw_handle();
            let norm_root_fd = unsafe { _open_osfhandle(norm_root_handle as isize, 0x8000) };
            assert!(norm_root_fd >= 0);

            // real case sensitive intermediate parent reject open with enotcapable
            let res_inter = engine.open_beneath(norm_root_fd, "cs_inter/blocked.txt", open_flags_create);
            assert_eq!(res_inter, Err(WASI_ENOTCAPABLE));
            // verify zero unintended file create in real case sensitive parent
            assert!(!cs_inter_dir.join("blocked.txt").exists());

            // real case sensitive intermediate parent reject mkdir with enotcapable
            let res_inter_mkdir = engine.mkdir_beneath(norm_root_fd, "cs_inter/blocked_sub");
            assert_eq!(res_inter_mkdir, Err(WASI_ENOTCAPABLE));
            // verify zero unintended directory create in real case sensitive parent
            assert!(!cs_inter_dir.join("blocked_sub").exists());

            // cleanup case sensitive flag on real ntfs directory
            let _ = set_directory_case_sensitive(root_dir_handle, false);
            let _ = set_directory_case_sensitive(inter_handle, false);
        } else {
            // report unsupported test environment when privilege missing
            println!(
                "[UNSUPPORTED ENVIRONMENT] real NTFS case-sensitive attribute could not be set: status 0x{:08X} (requires administrator privileges or developer mode policy)",
                status
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_canonical_ordinal_containment() {
        // test canonical path exact ordinal containment verification
        let root = Path::new(r"C:\sandbox\data");

        // exact identical match valid
        assert!(verify_canonical_containment(root, Path::new(r"C:\sandbox\data")));

        // child beneath root valid
        assert!(verify_canonical_containment(root, Path::new(r"C:\sandbox\data\file.txt")));
        assert!(verify_canonical_containment(root, Path::new(r"C:\sandbox\data\sub\leaf.bin")));

        // traversal above root reject
        assert!(!verify_canonical_containment(root, Path::new(r"C:\sandbox")));
        assert!(!verify_canonical_containment(root, Path::new(r"C:\")));

        // sibling directory prefix collision reject
        assert!(!verify_canonical_containment(root, Path::new(r"C:\sandbox\data-evil\file.txt")));
        assert!(!verify_canonical_containment(root, Path::new(r"C:\sandbox\database\file.txt")));

        // ancestor casing divergence reject under exact ordinal policy
        assert!(!verify_canonical_containment(Path::new(r"C:\Sandbox\data"), Path::new(r"C:\sandbox\data\file.txt")));
        assert!(!verify_canonical_containment(root, Path::new(r"C:\sandbox\DATA\file.txt")));
    }

    #[test]
    fn test_windows_file_lock_table_identity_and_lifecycle() {
        // verify two handle to same ntfs file share identity and lock instance
        let temp_dir = std::env::temp_dir().join(format!("plug_win_lock_id_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&temp_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = WindowsContainmentEngine::new();
        let create_flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        };

        let fd1 = engine.open_beneath(root_fd, "same_file.bin", create_flags).unwrap();
        let fd2 = engine.open_beneath(root_fd, "same_file.bin", create_flags).unwrap();
        let fd_other = engine.open_beneath(root_fd, "other_file.bin", create_flags).unwrap();

        let id1 = engine.file_identity_for_fd(fd1).unwrap();
        let id2 = engine.file_identity_for_fd(fd2).unwrap();
        let id_other = engine.file_identity_for_fd(fd_other).unwrap();

        assert_eq!(id1, id2);
        assert_ne!(id1, id_other);

        let table = engine.lock_table();
        assert_eq!(table.active_entry_count(), 0);

        // acquire two handle for same file identity and verify single shared arc
        let lock_a = table.acquire_lock_handle(id1);
        let lock_b = table.acquire_lock_handle(id2);
        assert!(std::sync::Arc::ptr_eq(&lock_a, &lock_b));
        assert_eq!(table.active_entry_count(), 1);

        // release first handle while second handle remain active
        table.release_lock_handle(id1, lock_a);
        assert_eq!(table.active_entry_count(), 1);

        // third contender must receive exact same active lock instance
        let lock_c = table.acquire_lock_handle(id1);
        assert!(std::sync::Arc::ptr_eq(&lock_b, &lock_c));

        // release remaining handle and verify table prune entry
        table.release_lock_handle(id2, lock_b);
        assert_eq!(table.active_entry_count(), 1);
        table.release_lock_handle(id1, lock_c);
        assert_eq!(table.active_entry_count(), 0);

        // verify error return and panic unwind release lock and prune entry cleanly
        let err_res: Result<(), i32> = table.with_exclusive_lock(id1, || Err(WASI_EIO));
        assert_eq!(err_res, Err(WASI_EIO));
        assert_eq!(table.active_entry_count(), 0);

        let unwind_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            table.with_exclusive_lock(id1, || {
                panic!("simulated panic inside exclusive lock");
            });
        }));
        assert!(unwind_res.is_err());
        assert_eq!(table.active_entry_count(), 0);

        let post_panic_res: Result<u32, i32> = table.with_exclusive_lock(id1, || Ok(42));
        assert_eq!(post_panic_res, Ok(42));
        assert_eq!(table.active_entry_count(), 0);

        // stress concurrent acquire and release to verify zero split lock under contention
        let active_writers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut threads = Vec::new();

        for _ in 0..4 {
            let eng = engine.clone();
            let aw = std::sync::Arc::clone(&active_writers);
            let bar = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                bar.wait();
                for _ in 0..200 {
                    eng.lock_table().with_exclusive_lock(id1, || {
                        let prev = aw.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        assert_eq!(prev, 0, "split lock detected for active file identity");
                        std::thread::yield_now();
                        aw.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    });
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(table.active_entry_count(), 0);

        unsafe {
            libc::close(fd1);
            libc::close(fd2);
            libc::close(fd_other);
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_truncate_write_concurrency_two_handles() {
        // verify coordinated truncate and write across two independent handle on ntfs
        let temp_dir = std::env::temp_dir().join(format!("plug_win_tw_conc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let target_path = temp_dir.join("shared_conc.bin");

        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let root_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000)
            .open(&temp_dir)
            .unwrap();
        let root_handle = root_file.as_raw_handle() as isize;
        let root_fd = unsafe { _open_osfhandle(root_handle, 0x8000) };
        assert!(root_fd >= 0);

        let engine = WindowsContainmentEngine::new();
        let rw_flags = OpenFlags {
            read: true,
            write: true,
            create: true,
            truncate: false,
            directory: false,
            follow_symlinks: false,
        };
        let trunc_open_flags = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: true,
            directory: false,
            follow_symlinks: false,
        };

        let fd_writer = engine.open_beneath(root_fd, "shared_conc.bin", rw_flags).unwrap();
        let fd_trunc = engine.open_beneath(root_fd, "shared_conc.bin", rw_flags).unwrap();
        assert_eq!(
            engine.file_identity_for_fd(fd_writer).unwrap(),
            engine.file_identity_for_fd(fd_trunc).unwrap()
        );

        // order check 1 write followed by truncate produce zero byte file
        let written = engine.write_synchronized(fd_writer, &[0x41u8; 256]).unwrap();
        assert_eq!(written, 256);
        assert_eq!(std::fs::metadata(&target_path).unwrap().len(), 256);

        engine.truncate_synchronized(fd_trunc).unwrap();
        assert_eq!(std::fs::metadata(&target_path).unwrap().len(), 0);

        // order check 2 write on first handle after truncate on second handle preserve descriptor offset
        // descriptor offset remain at 256 so write of 64 byte extend file to 320 byte
        let written_after = engine.write_synchronized(fd_writer, &[0x5Au8; 64]).unwrap();
        assert_eq!(written_after, 64);
        let after_bytes = std::fs::read(&target_path).unwrap();
        assert_eq!(after_bytes.len(), 256 + 64);
        assert!(after_bytes[..256].iter().all(|&b| b == 0));
        assert!(after_bytes[256..].iter().all(|&b| b == 0x5A));

        // order check 3 open with truncate flag reset file to zero and write from initial offset zero
        let transient_trunc_fd = engine
            .open_beneath(root_fd, "shared_conc.bin", trunc_open_flags)
            .unwrap();
        assert_eq!(std::fs::metadata(&target_path).unwrap().len(), 0);
        engine.write_synchronized(transient_trunc_fd, &[0x33u8; 128]).unwrap();
        unsafe { libc::close(transient_trunc_fd) };
        let fresh_bytes = std::fs::read(&target_path).unwrap();
        assert_eq!(fresh_bytes.len(), 128);
        assert!(fresh_bytes.iter().all(|&b| b == 0x33));

        unsafe { libc::close(fd_writer) };

        // concurrent stress rounds with deterministic barrier synchronization
        let fd_writer_stress = engine.open_beneath(root_fd, "shared_conc.bin", trunc_open_flags).unwrap();
        let rounds = 40usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let eng_writer = engine.clone();
        let bar_writer = std::sync::Arc::clone(&barrier);
        let writer_thread = std::thread::spawn(move || {
            for r in 0..rounds {
                bar_writer.wait();
                let tag = ((r % 200) as u8).saturating_add(1);
                let frame = [tag; 256];
                for _ in 0..4 {
                    eng_writer.write_synchronized(fd_writer_stress, &frame).unwrap();
                }
                bar_writer.wait();
            }
        });

        let eng_trunc = engine.clone();
        let bar_trunc = std::sync::Arc::clone(&barrier);
        let trunc_thread = std::thread::spawn(move || {
            for r in 0..rounds {
                bar_trunc.wait();
                if r % 2 == 0 {
                    eng_trunc.truncate_synchronized(fd_trunc).unwrap();
                } else {
                    let tfd = eng_trunc
                        .open_beneath(root_fd, "shared_conc.bin", trunc_open_flags)
                        .unwrap();
                    unsafe { libc::close(tfd) };
                }
                bar_trunc.wait();

                // validate file state after each round match valid sequential execution
                let data = std::fs::read(&target_path).unwrap();
                let expected_tag = ((r % 200) as u8).saturating_add(1);
                assert_eq!(data.len() % 256, 0, "torn frame size detected");
                if !data.is_empty() {
                    assert_eq!(
                        data.len(),
                        (r + 1) * 1024,
                        "unexpected file length for sequential write offset"
                    );
                    let mut seen_written_frame = false;
                    for chunk in data.chunks_exact(256) {
                        let first = chunk[0];
                        assert!(
                            chunk.iter().all(|&b| b == first),
                            "interleaved write or partial frame corruption detected"
                        );
                        if first != 0 {
                            seen_written_frame = true;
                            assert_eq!(first, expected_tag, "unexpected frame tag after truncate");
                        } else if seen_written_frame {
                            panic!("zero hole detected after post-truncate write frame");
                        }
                    }
                    assert!(seen_written_frame, "non-empty file after write must contain final frame");
                }
            }
        });

        writer_thread.join().unwrap();
        trunc_thread.join().unwrap();
        assert_eq!(engine.lock_table().active_entry_count(), 0);

        unsafe {
            libc::close(fd_writer_stress);
            libc::close(fd_trunc);
        }
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_windows_runtime_owned_handle_and_shared_lock_contract() {
        use std::io::{Read, Seek, SeekFrom, Write};

        let temp_dir = std::env::temp_dir().join(format!("plug_win_rt_owned_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        // open root directory via production owned handle helper
        let root_dir = open_directory_for_containment(&temp_dir).unwrap();
        let engine = WindowsContainmentEngine::new();

        // verify runtime directory creation and file creation without crt fd wrapper
        engine.mkdir_file_beneath(&root_dir, "sub").unwrap();
        let mut f1 = engine
            .open_file_beneath(
                &root_dir,
                "sub/data.bin",
                OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                    truncate: true,
                    directory: false,
                    follow_symlinks: false,
                },
            )
            .unwrap();

        let mut f2 = engine
            .open_file_beneath(
                &root_dir,
                "sub/data.bin",
                OpenFlags {
                    read: true,
                    write: false,
                    create: false,
                    truncate: false,
                    directory: false,
                    follow_symlinks: false,
                },
            )
            .unwrap();

        let id1 = engine.file_identity_for_file(&f1).unwrap();
        let id2 = engine.file_identity_for_file(&f2).unwrap();
        assert_eq!(id1, id2);

        // write payload under exclusive lock and resize via runtime file helper
        engine.lock_table().with_exclusive_lock(id1, || {
            f1.write_all(&[0x5Au8; 64]).unwrap();
        });
        assert_eq!(engine.lock_table().active_entry_count(), 0);

        engine.set_file_size_for_file(&f1, 32).unwrap();
        assert_eq!(engine.lock_table().active_entry_count(), 0);

        // read payload under shared lock and verify panic unwind release
        let read_bytes = engine.lock_table().with_shared_lock(id2, || {
            f2.seek(SeekFrom::Start(0)).unwrap();
            let mut buf = Vec::new();
            f2.read_to_end(&mut buf).unwrap();
            buf
        });
        assert_eq!(read_bytes, vec![0x5Au8; 32]);
        assert_eq!(engine.lock_table().active_entry_count(), 0);

        let unwind_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            engine.lock_table().with_shared_lock(id2, || -> Result<(), i32> {
                panic!("simulated panic inside shared lock closure");
            })
        }));
        assert!(unwind_res.is_err());
        assert_eq!(engine.lock_table().active_entry_count(), 0);

        drop(f1);
        drop(f2);

        // verify runtime unlink and rmdir via owned directory handle
        engine.unlink_file_beneath_handle(&root_dir, "sub/data.bin").unwrap();
        engine.rmdir_beneath_handle(&root_dir, "sub").unwrap();
        drop(root_dir);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
