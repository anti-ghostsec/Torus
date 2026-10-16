//! Confines a process on Linux and Android.
//!
//! A process confines itself, first thing, before it reads a single byte
//! from anyone, and everything it starts afterwards stays confined too:
//!
//! - Landlock limits the files it can open to the folder it is given and
//!   the programs it must run. Where the system lacks Landlock, files are
//!   not confined, and [`Isolation::files`] says so.
//! - A seccomp filter takes away the system calls a compromised process
//!   would use to reach further: debugging or reading other processes,
//!   loading kernel code, changing namespaces, and, for the video
//!   converter, opening any network connection at all.
//! - It can never gain privileges again (`PR_SET_NO_NEW_PRIVS`), and it is
//!   killed if the process that started it dies.
//!
//! What the process may reach is passed in its environment, by the editor
//! that starts it; see [`CONFINE_FILES`] and [`CONFINE_PROGRAMS`].

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// The folders a confined process may read and write, one per line.
pub const CONFINE_FILES: &str = "TORUS_CONFINE_FILES";
/// The programs and system folders it may read and run, one per line.
pub const CONFINE_PROGRAMS: &str = "TORUS_CONFINE_PROGRAMS";
/// Present when the process must have no network at all.
pub const CONFINE_OFFLINE: &str = "TORUS_CONFINE_OFFLINE";

/// How far confinement got.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Isolation {
    /// Files outside the given folder cannot be opened.
    pub files: bool,
    /// The dangerous system calls are refused.
    pub syscalls: bool,
}

// Landlock (include/uapi/linux/landlock.h). The system call numbers are the
// same on every architecture.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
/// What applies to a file, as opposed to a folder.
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | (1 << 14) | (1 << 15);

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Every file right the running kernel's Landlock knows, by its version.
fn handled_rights(abi: i64) -> u64 {
    let mut rights = (1u64 << 13) - 1;
    if abi >= 2 {
        rights |= 1 << 13; // refer
    }
    if abi >= 3 {
        rights |= 1 << 14; // truncate
    }
    if abi >= 5 {
        rights |= 1 << 15; // ioctl on devices
    }
    rights
}

/// Limits the files this process can open. `false` where the kernel has no
/// Landlock or refuses it.
fn landlock(read_write: &[PathBuf], read_run: &[PathBuf]) -> bool {
    unsafe {
        let abi = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, std::ptr::null::<RulesetAttr>(), 0usize, LANDLOCK_CREATE_RULESET_VERSION);
        if abi < 1 {
            return false;
        }
        let handled = handled_rights(abi);
        let attr = RulesetAttr { handled_access_fs: handled, handled_access_net: 0, scoped: 0 };
        let ruleset = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &attr as *const RulesetAttr, size_of::<RulesetAttr>(), 0u32);
        if ruleset < 0 {
            return false;
        }
        let ruleset = ruleset as RawFd;
        let allow = |path: &Path, rights: u64| {
            let Ok(name) = CString::new(path.as_os_str().as_bytes()) else { return };
            let fd = libc::open(name.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if fd < 0 {
                return;
            }
            let is_dir = std::fs::metadata(path).is_ok_and(|m| m.is_dir());
            let rights = if is_dir { rights & handled } else { rights & handled & FILE_RIGHTS };
            let rule = PathBeneathAttr { allowed_access: rights, parent_fd: fd };
            libc::syscall(SYS_LANDLOCK_ADD_RULE, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule as *const PathBeneathAttr, 0u32);
            libc::close(fd);
        };
        for path in read_write {
            allow(path, handled);
        }
        for path in read_run {
            allow(path, EXECUTE | READ_FILE | READ_DIR);
        }
        let done = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0u32) == 0;
        libc::close(ruleset);
        done
    }
}

// seccomp

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: Option<u32> = Some(0xC000_003E);
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: Option<u32> = Some(0xC000_00B7);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: Option<u32> = None;

/// System calls no confined process needs, and that would help one that has
/// been taken over to reach beyond its confinement.
fn refused_calls(offline: bool) -> Vec<libc::c_long> {
    let mut calls = vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_acct,
        libc::SYS_quotactl,
    ];
    if offline {
        calls.extend([libc::SYS_socket, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen, libc::SYS_accept4]);
    }
    calls
}

fn seccomp(offline: bool) -> bool {
    let Some(arch) = AUDIT_ARCH else { return false };
    let calls = refused_calls(offline);
    let count = calls.len();
    let mut program = vec![
        // Only this architecture's system call numbers mean what the list says.
        SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 4 },
        SockFilter { code: BPF_JEQ_K, jt: 1, jf: 0, k: arch },
        SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_KILL_PROCESS },
        SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
    ];
    // On x86_64, numbers with this bit set are the x32 interface: refused whole.
    let x32 = cfg!(target_arch = "x86_64");
    if x32 {
        program.push(SockFilter { code: BPF_JGE_K, jt: (count + 1) as u8, jf: 0, k: 0x4000_0000 });
    }
    for (at, call) in calls.iter().enumerate() {
        program.push(SockFilter { code: BPF_JEQ_K, jt: (count - at) as u8, jf: 0, k: *call as u32 });
    }
    program.push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });
    program.push(SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ERRNO | libc::EPERM as u32 });
    let prog = SockFprog { len: program.len() as u16, filter: program.as_ptr() };
    unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2 /* SECCOMP_MODE_FILTER */, &prog as *const SockFprog) == 0 }
}

fn lines(variable: &str) -> Vec<PathBuf> {
    std::env::var_os(variable)
        .map(|all| all.as_bytes().split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| PathBuf::from(OsStr::from_bytes(l))).collect())
        .unwrap_or_default()
}

/// Confines this process as its environment says, if it says anything.
/// `None` when the process was not started to be confined.
pub fn confine_from_surroundings() -> Option<Isolation> {
    let read_write = lines(CONFINE_FILES);
    let read_run = lines(CONFINE_PROGRAMS);
    if read_write.is_empty() && read_run.is_empty() {
        return None;
    }
    let offline = std::env::var_os(CONFINE_OFFLINE).is_some();
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    let files = landlock(&read_write, &read_run);
    let syscalls = seccomp(offline);
    Some(Isolation { files, syscalls })
}

/// The environment that makes a process confine itself on start.
pub fn surroundings(files: &[&Path], programs: &[&Path], offline: bool) -> Vec<(&'static str, std::ffi::OsString)> {
    let join = |paths: &[&Path]| {
        let mut all = Vec::new();
        for path in paths {
            all.extend_from_slice(path.as_os_str().as_bytes());
            all.push(b'\n');
        }
        std::ffi::OsString::from(OsStr::from_bytes(&all))
    };
    let mut told = vec![(CONFINE_FILES, join(files)), (CONFINE_PROGRAMS, join(programs))];
    if offline {
        told.push((CONFINE_OFFLINE, "1".into()));
    }
    told
}

/// Prepares a freshly forked child, between fork and exec: only the given
/// descriptors survive (moved to 3, 4, ...). With `die_with_parent`, it is
/// killed the moment its parent dies; a host is not, so that it can pack
/// its Tor bookkeeping away first (it stops by itself once its input closes).
///
/// # Safety
/// Only to be called in a `pre_exec` hook: it uses async-signal-safe
/// system calls only.
pub unsafe fn keep_only(ends: &[RawFd], die_with_parent: bool) -> std::io::Result<()> {
    unsafe {
        if die_with_parent {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
        }
        // Moved above every number they will be given, then into place.
        let mut moved = [0 as RawFd; 8];
        for (at, end) in ends.iter().enumerate() {
            let high = libc::fcntl(*end, libc::F_DUPFD, 64);
            if high < 0 {
                return Err(std::io::Error::last_os_error());
            }
            moved[at] = high;
        }
        for (at, high) in moved.iter().take(ends.len()).enumerate() {
            if libc::dup2(*high, 3 + at as RawFd) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // Everything else the editor had open is closed, whatever library
        // opened it and however it was flagged.
        let first = 3 + ends.len() as libc::c_uint;
        if libc::syscall(libc::SYS_close_range, first, libc::c_uint::MAX, 0u32) != 0 {
            for fd in first..4096 {
                libc::close(fd as RawFd);
            }
        }
        Ok(())
    }
}
