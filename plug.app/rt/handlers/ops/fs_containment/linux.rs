// linux openat2 atomic containment spike
// enforces resolve_beneath and pinned parent leaf mutations

#![allow(unused_imports, dead_code)]
use super::*;
use std::ffi::CString;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

// openat2 resolve flags from linux/openat2.h
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;
pub const RESOLVE_CACHED: u64 = 0x20;

// retry policy: 1 initial call plus 3 bounded retry (total 4 attempt)
pub const MAX_BOUNDED_RETRIES: u32 = 3;

// parse relative guest path into validated parent and leaf components
pub fn split_relative_path(path: &str) -> Result<(Option<String>, String), i32> {
    // reject rooted paths and backslashes
    if path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
        return Err(WASI_ENOTCAPABLE);
    }
    // reject leading or trailing slashes
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Err(WASI_EINVAL);
    }
    let parts: Vec<&str> = trimmed.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Err(WASI_EINVAL);
    }
    // check each component
    for p in &parts {
        if *p == "." || *p == ".." {
            return Err(WASI_ENOTCAPABLE);
        }
    }
    if parts.len() == 1 {
        Ok((None, parts[0].to_string()))
    } else {
        let parent = parts[..parts.len() - 1].join("/");
        let leaf = parts[parts.len() - 1].to_string();
        Ok((Some(parent), leaf))
    }
}

pub struct LinuxContainmentEngine;

impl LinuxContainmentEngine {
    pub fn new() -> Self {
        Self
    }

    // deterministic test seam for openat2 syscall execution
    pub fn openat2_syscall_with_runner<F>(
        dirfd: i32,
        c_path: &CString,
        how: &OpenHow,
        mut raw_call: F,
    ) -> Result<i32, i32>
    where
        F: FnMut(i32, &CString, &OpenHow) -> (libc::c_long, i32),
    {
        let mut retries = 0;
        loop {
            let (res, err) = raw_call(dirfd, c_path, how);
            if res >= 0 {
                return Ok(res as i32);
            }
            if err == libc::ENOSYS {
                // fail closed when openat2 unavailable in host kernel
                return Err(WASI_ENOTCAPABLE);
            }
            if err == libc::EAGAIN {
                if retries >= MAX_BOUNDED_RETRIES {
                    return Err(WASI_EAGAIN);
                }
                retries += 1;
                std::thread::yield_now();
                continue;
            }
            return Err(map_linux_openat2_err(err));
        }
    }

    #[cfg(target_os = "linux")]
    fn openat2_syscall(dirfd: i32, c_path: &CString, how: &OpenHow) -> Result<i32, i32> {
        Self::openat2_syscall_with_runner(dirfd, c_path, how, |dfd, path, h| {
            let res = unsafe {
                libc::syscall(
                    libc::SYS_openat2,
                    dfd,
                    path.as_ptr(),
                    h as *const OpenHow as *const libc::c_void,
                    std::mem::size_of::<OpenHow>(),
                )
            };
            let err = if res < 0 {
                std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL)
            } else {
                0
            };
            (res, err)
        })
    }

    #[cfg(target_os = "linux")]
    fn open_parent_pinned(&self, root_fd: i32, parent_rel: &str) -> Result<i32, i32> {
        let c_parent = CString::new(parent_rel).map_err(|_| WASI_EINVAL)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        Self::openat2_syscall(root_fd, &c_parent, &how)
    }
}

impl AtomicContainmentEngine for LinuxContainmentEngine {
    fn open_beneath(&self, root_fd: i32, rel_path: &str, flags: OpenFlags) -> Result<i32, i32> {
        // lexical validation: reject rooted paths and lexical ..
        let _ = split_relative_path(rel_path)?;

        #[cfg(target_os = "linux")]
        {
            let c_path = CString::new(rel_path).map_err(|_| WASI_EINVAL)?;
            let mut o_flags = libc::O_CLOEXEC;
            if flags.directory {
                o_flags |= libc::O_DIRECTORY;
            }
            if flags.write && flags.read {
                o_flags |= libc::O_RDWR;
            } else if flags.write {
                o_flags |= libc::O_WRONLY;
            } else {
                o_flags |= libc::O_RDONLY;
            }
            if flags.create {
                o_flags |= libc::O_CREAT;
            }
            // notice: never set O_TRUNC here; deferred truncate operates on verified handle

            let mut resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
            if !flags.follow_symlinks {
                resolve |= RESOLVE_NO_SYMLINKS;
            }

            let mode = if flags.create { 0o644 } else { 0 };
            let how = OpenHow {
                flags: o_flags as u64,
                mode,
                resolve,
            };

            let fd = Self::openat2_syscall(root_fd, &c_path, &how)?;

            // deferred truncate on verified descriptor
            if flags.truncate && flags.write {
                unsafe {
                    if libc::ftruncate(fd, 0) != 0 {
                        libc::close(fd);
                        return Err(WASI_EIO);
                    }
                }
            }

            Ok(fd)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // non-linux compilation stub: fail-closed for linux-specific engine
            let _ = (root_fd, flags);
            Err(WASI_ENOTCAPABLE)
        }
    }

    fn mkdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let (parent_opt, leaf) = split_relative_path(rel_path)?;

        #[cfg(target_os = "linux")]
        {
            let parent_dfd = if let Some(parent) = parent_opt {
                self.open_parent_pinned(root_fd, &parent)?
            } else {
                root_fd
            };

            let c_leaf = CString::new(leaf).map_err(|_| WASI_EINVAL)?;
            let res = unsafe { libc::mkdirat(parent_dfd, c_leaf.as_ptr(), 0o755) };

            if parent_dfd != root_fd {
                unsafe { libc::close(parent_dfd); }
            }

            if res == 0 {
                Ok(())
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
                Err(map_linux_leaf_err(err))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_fd, parent_opt, leaf);
            Err(WASI_ENOTCAPABLE)
        }
    }

    fn unlink_file_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let (parent_opt, leaf) = split_relative_path(rel_path)?;

        #[cfg(target_os = "linux")]
        {
            let parent_dfd = if let Some(parent) = parent_opt {
                self.open_parent_pinned(root_fd, &parent)?
            } else {
                root_fd
            };

            let c_leaf = CString::new(leaf).map_err(|_| WASI_EINVAL)?;
            let res = unsafe { libc::unlinkat(parent_dfd, c_leaf.as_ptr(), 0) };

            if parent_dfd != root_fd {
                unsafe { libc::close(parent_dfd); }
            }

            if res == 0 {
                Ok(())
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
                Err(map_linux_leaf_err(err))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_fd, parent_opt, leaf);
            Err(WASI_ENOTCAPABLE)
        }
    }

    fn rmdir_beneath(&self, root_fd: i32, rel_path: &str) -> Result<(), i32> {
        let (parent_opt, leaf) = split_relative_path(rel_path)?;

        #[cfg(target_os = "linux")]
        {
            let parent_dfd = if let Some(parent) = parent_opt {
                self.open_parent_pinned(root_fd, &parent)?
            } else {
                root_fd
            };

            let c_leaf = CString::new(leaf).map_err(|_| WASI_EINVAL)?;
            let res = unsafe { libc::unlinkat(parent_dfd, c_leaf.as_ptr(), libc::AT_REMOVEDIR) };

            if parent_dfd != root_fd {
                unsafe { libc::close(parent_dfd); }
            }

            if res == 0 {
                Ok(())
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL);
                Err(map_linux_leaf_err(err))
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_fd, parent_opt, leaf);
            Err(WASI_ENOTCAPABLE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_relative_path_lexical() {
        assert_eq!(split_relative_path("/etc/passwd"), Err(WASI_ENOTCAPABLE));
        assert_eq!(split_relative_path(r"\windows\system32"), Err(WASI_ENOTCAPABLE));
        assert_eq!(split_relative_path("C:data"), Err(WASI_ENOTCAPABLE));
        assert_eq!(split_relative_path("../escape"), Err(WASI_ENOTCAPABLE));
        assert_eq!(split_relative_path("sub/../escape"), Err(WASI_ENOTCAPABLE));
        assert_eq!(split_relative_path(""), Err(WASI_EINVAL));
        assert_eq!(split_relative_path("leaf.txt"), Ok((None, "leaf.txt".to_string())));
        assert_eq!(split_relative_path("a/b/c.txt"), Ok((Some("a/b".to_string()), "c.txt".to_string())));
    }

    #[test]
    fn test_eagain_retry_exhaustion() {
        let c_path = CString::new("test_target").unwrap();
        let how = OpenHow::default();
        let mut call_count = 0;

        let res = LinuxContainmentEngine::openat2_syscall_with_runner(3, &c_path, &how, |_, _, _| {
            call_count += 1;
            (-1, libc::EAGAIN)
        });

        // 1 initial attempt plus 3 bounded retries equals 4 total invocations
        assert_eq!(call_count, 4);
        assert_eq!(res, Err(WASI_EAGAIN));
    }

    #[test]
    fn test_openat2_unavailable_enosys_fail_closed() {
        let c_path = CString::new("test_target").unwrap();
        let how = OpenHow::default();
        let mut call_count = 0;

        let res = LinuxContainmentEngine::openat2_syscall_with_runner(3, &c_path, &how, |_, _, _| {
            call_count += 1;
            (-1, libc::ENOSYS)
        });

        // immediately fails closed on attempt 1 without fallback or retry
        assert_eq!(call_count, 1);
        assert_eq!(res, Err(WASI_ENOTCAPABLE));
    }
}
