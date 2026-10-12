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
struct IoStatusBlock {
    status: i32,
    information: usize,
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

    fn SetFilePointer(
        h_file: *mut std::ffi::c_void,
        l_distance_to_move: i32,
        lp_distance_to_move_high: *mut i32,
        dw_move_method: u32,
    ) -> u32;

    fn SetEndOfFile(h_file: *mut std::ffi::c_void) -> i32;
    fn CloseHandle(h_object: *mut std::ffi::c_void) -> i32;
}

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

// resolve raw handle from root descriptor
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

// normalize path for comparison with lowercasing and separator canonicalization
fn normalize_path_for_compare(p: &Path) -> PathBuf {
    let s = p.to_string_lossy().to_lowercase();
    let stripped = if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest
    } else {
        &s
    };
    PathBuf::from(stripped.replace('/', "\\"))
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
fn open_relative_nt_component(
    parent_handle: *mut std::ffi::c_void,
    component_name: &str,
    desired_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<*mut std::ffi::c_void, i32> {
    validate_component_token(component_name)?;

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

// walk parent directory handle chain safely
fn walk_parent_directory_handles(
    root_handle: *mut std::ffi::c_void,
    components: &[&str],
) -> Result<*mut std::ffi::c_void, i32> {
    let mut current_handle = root_handle;
    let mut handles_to_close: Vec<*mut std::ffi::c_void> = Vec::new();

    for comp in components {
        let child = match open_relative_nt_component(
            current_handle,
            comp,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
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

pub struct WindowsContainmentEngine;

impl WindowsContainmentEngine {
    pub fn new() -> Self {
        Self
    }
}

impl AtomicContainmentEngine for WindowsContainmentEngine {
    fn open_beneath(&self, root_fd: i32, rel_path: &str, flags: OpenFlags) -> Result<i32, i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        let components = parse_relative_components(rel_path)?;

        let mut root_info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let root_ok = unsafe { GetFileInformationByHandle(root_handle, root_info.as_mut_ptr()) };
        if root_ok == 0 {
            return Err(WASI_EBADF);
        }
        let root_info = unsafe { root_info.assume_init() };

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1])?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

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

        let leaf_res = open_relative_nt_component(
            parent_handle,
            leaf_name,
            desired_access,
            create_disposition,
            create_options,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        let leaf_handle = leaf_res?;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        // reject reparse point
        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_ENOTCAPABLE);
        }

        // hard link containment policy check
        // reject file with multiple hard links to prevent external alias write
        if !flags.directory && info.n_number_of_links > 1 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_ENOTCAPABLE);
        }

        // volume cross device check
        if info.dw_volume_serial_number != root_info.dw_volume_serial_number {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_ENOTCAPABLE);
        }

        // canonical boundary verification with lowercased path comparison
        if let Some(root_path) = get_canonical_handle_path(root_handle) {
            if let Some(leaf_path) = get_canonical_handle_path(leaf_handle) {
                let norm_root = normalize_path_for_compare(&root_path);
                let norm_leaf = normalize_path_for_compare(&leaf_path);
                if !norm_leaf.starts_with(&norm_root) {
                    unsafe { NtClose(leaf_handle) };
                    return Err(WASI_ENOTCAPABLE);
                }
            } else {
                unsafe { NtClose(leaf_handle) };
                return Err(WASI_ENOTCAPABLE);
            }
        }

        // deterministic truncate execution on verified handle
        // move file pointer to offset 0 before setting end of file
        if flags.truncate && !flags.directory {
            let move_res = unsafe { SetFilePointer(leaf_handle, 0, std::ptr::null_mut(), 0) };
            if move_res == 0xFFFFFFFF {
                unsafe { NtClose(leaf_handle) };
                return Err(WASI_EIO);
            }
            let ok = unsafe { SetEndOfFile(leaf_handle) };
            if ok == 0 {
                unsafe { NtClose(leaf_handle) };
                return Err(WASI_EIO);
            }
        }

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
        let components = parse_relative_components(rel_path)?;

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1])?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        let res = open_relative_nt_component(
            parent_handle,
            leaf_name,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        match res {
            Ok(h) => {
                unsafe { NtClose(h) };
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn unlink_file_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        let components = parse_relative_components(rel_path)?;

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1])?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        let res = open_relative_nt_component(
            parent_handle,
            leaf_name,
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        let leaf_handle = res?;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_ENOTCAPABLE);
        }

        if info.n_number_of_links > 1 {
            unsafe { NtClose(leaf_handle) };
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

        unsafe { NtClose(leaf_handle) };

        if ok == 0 {
            Err(WASI_EIO)
        } else {
            Ok(())
        }
    }

    fn rmdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let root_handle = resolve_raw_handle(root_fd)?;
        let components = parse_relative_components(rel_path)?;

        let (parent_handle, leaf_name, should_close_parent) = if components.len() == 1 {
            (root_handle, components[0], false)
        } else {
            let parent = walk_parent_directory_handles(root_handle, &components[..components.len() - 1])?;
            (parent, components[components.len() - 1], parent != root_handle)
        };

        let res = open_relative_nt_component(
            parent_handle,
            leaf_name,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        );

        if should_close_parent {
            unsafe { NtClose(parent_handle) };
        }

        let leaf_handle = res?;

        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
        let ok = unsafe { GetFileInformationByHandle(leaf_handle, info.as_mut_ptr()) };
        if ok == 0 {
            unsafe { NtClose(leaf_handle) };
            return Err(WASI_EIO);
        }
        let info = unsafe { info.assume_init() };

        if info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            unsafe { NtClose(leaf_handle) };
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

        unsafe { NtClose(leaf_handle) };

        if ok == 0 {
            Err(WASI_ENOTEMPTY)
        } else {
            Ok(())
        }
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
}
