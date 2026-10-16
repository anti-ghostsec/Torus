//! Starts a host process inside a Windows AppContainer.
//!
//! An AppContainer process cannot read the user's files, cannot read other
//! processes' memory and cannot use the network except as its capabilities
//! allow. Each site gets a container of its own, so sites are confined from
//! one another as well as from the editor. The only capability granted is
//! outbound internet access, which Tor needs. A job object also forbids the
//! process from starting any other process and ends it if the editor dies.
//!
//! The program that decodes visitors' videos gets a container of its own
//! with no capability at all: it can reach neither the network nor any
//! file, and talks to its site's host over one pair of pipes.
//!
//! Containers are never registered with Windows. Registering one makes
//! Windows create a folder for it in the user's profile and an entry in the
//! registry; instead, a process is started straight into the container's
//! identity, which follows from its name, and that identity is given access
//! to one folder the app chooses, inside the app's own folder. Nothing is
//! written anywhere else.

use std::ffi::{c_void, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Mutex;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, ERROR_SUCCESS, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, HANDLE,
    HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, ACCESS_MODE,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, REVOKE_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
    TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    CreateWellKnownSid, FreeSid, WinCapabilityInternetClientSid, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, ResumeThread,
    TerminateProcess, UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES,
    STARTUPINFOEXW,
};

/// `SE_GROUP_ENABLED`: the capability is switched on.
const ENABLED: u32 = 4;
/// `SECURITY_MAX_SID_SIZE`.
const MAX_SID: usize = 68;

// Each launch names the handles the child receives (a handle list), so it can
// never pick up another handle the editor happens to hold. Launches are
// still made one at a time, since the extra pipe ends are marked
// inheritable for the instant of their launch.
static LAUNCH: Mutex<()> = Mutex::new(());

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0 .0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// SAFETY: a kernel handle may be used and closed from any thread.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

struct Sid(PSID);

impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.0);
        }
    }
}

/// The container's identity, creating the container on first use.
fn container_sid(name: &str) -> io::Result<Sid> {
    let name = wide(OsStr::new(name));
    // Derived, not registered: no profile folder and no registry entry.
    unsafe { Ok(Sid(DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr()))?)) }
}

/// Takes back a container's permission to run `programs`. Its folder is
/// the caller's to erase. A profile registered by an older version of this
/// app, if there is one, is removed as well.
pub fn remove_container(name: &str, programs: &[&Path]) {
    if let Ok(sid) = container_sid(name) {
        for program in programs {
            change_access(program, &sid, REVOKE_ACCESS, false);
        }
    }
    let name = wide(OsStr::new(name));
    unsafe {
        let _ = DeleteAppContainerProfile(PCWSTR(name.as_ptr()));
    }
}

/// Lets the container use one folder and everything that will be in it.
fn allow_folder(folder: &Path, sid: &Sid) -> io::Result<()> {
    if change_access(folder, sid, GRANT_ACCESS, true) {
        Ok(())
    } else {
        Err(io::Error::other("could not give the sandbox its folder"))
    }
}

/// Makes a folder readable and writable by the user running this program
/// alone: inherited permissions are cut off, so neither other accounts nor
/// sandboxes that every app package may use can look inside, wherever the
/// folder sits.
pub fn make_private(folder: &Path) -> io::Result<()> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Security::Authorization::SET_ACCESS;
    use windows::Win32::Security::{PROTECTED_DACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT};
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let token = Handle(token);
        let mut size = 0u32;
        let _ = GetTokenInformation(token.0, TokenUser, None, 0, &mut size);
        let mut buffer = vec![0u8; size as usize];
        GetTokenInformation(token.0, TokenUser, Some(buffer.as_mut_ptr().cast()), size, &mut size)?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL.0,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(user.User.Sid.0.cast()),
                ..Default::default()
            },
        };
        let mut acl: *mut ACL = null_mut();
        if SetEntriesInAclW(Some(&[entry]), None, &mut acl) != ERROR_SUCCESS {
            return Err(io::Error::other("could not describe the folder's permissions"));
        }
        let path = wide(folder.as_os_str());
        let set = SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        );
        LocalFree(Some(HLOCAL(acl.cast())));
        if set != ERROR_SUCCESS {
            return Err(io::Error::other("could not make the folder private"));
        }
        Ok(())
    }
}

/// Lets the container read and run the host program, which it could not
/// otherwise open. Best effort: an installed copy already allows this and
/// may not let us change it.
fn allow_running(program: &Path, sid: &Sid) {
    change_access(program, sid, GRANT_ACCESS, false);
}

/// Grants the container access to a file or folder, or takes away every
/// permission the container was given on it. On a folder (`inherit`), the
/// container may read and write it and everything put in it; on a file, it
/// may read and run it. Returns whether the change was made.
fn change_access(program: &Path, sid: &Sid, mode: ACCESS_MODE, inherit: bool) -> bool {
    use windows::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    let path = wide(program.as_os_str());
    let path = PCWSTR(path.as_ptr());
    unsafe {
        let mut current: *mut ACL = null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let read = GetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut current),
            None,
            &mut descriptor,
        );
        if read != ERROR_SUCCESS {
            return false;
        }
        let rights = match (mode == GRANT_ACCESS, inherit) {
            (false, _) => 0,
            (true, true) => GENERIC_ALL.0,
            (true, false) => (GENERIC_READ | GENERIC_EXECUTE).0,
        };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: rights,
            grfAccessMode: mode,
            grfInheritance: if inherit { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { NO_INHERITANCE },
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(sid.0 .0.cast()),
                ..Default::default()
            },
        };
        let mut updated: *mut ACL = null_mut();
        let mut changed = false;
        if SetEntriesInAclW(Some(&[entry]), Some(current), &mut updated) == ERROR_SUCCESS {
            changed = SetNamedSecurityInfoW(
                path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(updated),
                None,
            ) == ERROR_SUCCESS;
            LocalFree(Some(HLOCAL(updated.cast())));
        }
        LocalFree(Some(HLOCAL(descriptor.0)));
        changed
    }
}

/// What differs between the processes that are confined.
pub(crate) struct Terms<'a> {
    /// Whether the process may open outbound internet connections.
    pub network: bool,
    /// How many processes there may be, the one started included.
    pub processes: u32,
    /// The most memory each of them may commit, in bytes.
    pub memory: usize,
    /// Whether the process is ended the moment the editor is. A host is
    /// not: it stops by itself once its input closes, after packing its
    /// Tor bookkeeping away.
    pub die_with_editor: bool,
    /// Added to the few things the process is told about its surroundings.
    /// Names must sort after `TMP`.
    pub tell: Vec<(&'a str, OsString)>,
    /// Pipe ends the process is given besides its input and output.
    pub give: Vec<&'a PipeEnd>,
    /// Other programs the process must be able to run.
    pub run: Vec<&'a Path>,
}

/// One end of a pipe between two confined processes.
pub(crate) struct PipeEnd(Handle);

impl std::os::windows::io::IntoRawHandle for PipeEnd {
    fn into_raw_handle(self) -> std::os::windows::io::RawHandle {
        let raw = self.0 .0 .0;
        std::mem::forget(self);
        raw
    }
}

impl PipeEnd {
    /// How the process given this end finds it.
    pub fn number(&self) -> String {
        (self.0 .0 .0 as usize).to_string()
    }
}

/// Two pipes joining a host and its converter: what each reads and writes.
pub(crate) struct Link {
    pub host: (PipeEnd, PipeEnd),
    pub converter: (PipeEnd, PipeEnd),
}

pub(crate) fn link() -> io::Result<Link> {
    unsafe {
        let (mut host_reads, mut converter_writes) = (HANDLE::default(), HANDLE::default());
        CreatePipe(&mut host_reads, &mut converter_writes, None, 1 << 20)?;
        let (host_reads, converter_writes) = (PipeEnd(Handle(host_reads)), PipeEnd(Handle(converter_writes)));
        let (mut converter_reads, mut host_writes) = (HANDLE::default(), HANDLE::default());
        CreatePipe(&mut converter_reads, &mut host_writes, None, 1 << 20)?;
        let (converter_reads, host_writes) = (PipeEnd(Handle(converter_reads)), PipeEnd(Handle(host_writes)));
        Ok(Link { host: (host_reads, host_writes), converter: (converter_reads, converter_writes) })
    }
}

/// A confined host process. Dropping it ends the process.
pub(crate) struct Confined {
    process: Handle,
    _job: Handle,
}

impl Drop for Confined {
    fn drop(&mut self) {
        unsafe {
            let _ = TerminateProcess(self.process.0, 1);
        }
    }
}

/// One end for us, one for the child. Only the child's end can be inherited.
fn pipe(child_reads: bool) -> io::Result<(Handle, Handle)> {
    let inheritable = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: true.into(),
    };
    unsafe {
        let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
        CreatePipe(&mut read, &mut write, Some(&inheritable), 0)?;
        let (read, write) = (Handle(read), Handle(write));
        let (ours, theirs) = if child_reads { (write, read) } else { (read, write) };
        SetHandleInformation(ours.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))?;
        Ok((ours, theirs))
    }
}

/// Starts `program` confined, returning our ends of its input and output.
/// `folder` is the one place it may keep files; it is made if need be.
pub(crate) fn spawn(program: &Path, container: &str, folder: &Path, terms: Terms<'_>) -> io::Result<(File, File, Confined)> {
    let step = |what: &str, e: io::Error| io::Error::other(format!("{what}: {e}"));
    let sid = container_sid(container).map_err(|e| step("naming the container", e))?;
    let temp = folder.join("tmp");
    std::fs::create_dir_all(&temp).map_err(|e| step("preparing the container's folder", e))?;
    allow_folder(folder, &sid).map_err(|e| step("giving the container its folder", e))?;
    allow_running(program, &sid);
    for other in &terms.run {
        allow_running(other, &sid);
    }

    let _one_at_a_time = LAUNCH.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        // The single capability, where there is one: outbound internet connections.
        let mut internet = [0u8; MAX_SID];
        let mut length = MAX_SID as u32;
        let internet_sid = PSID(internet.as_mut_ptr().cast());
        CreateWellKnownSid(WinCapabilityInternetClientSid, None, Some(internet_sid), &mut length)?;
        let mut capabilities = [SID_AND_ATTRIBUTES { Sid: internet_sid, Attributes: ENABLED }];
        let security = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            Capabilities: if terms.network { capabilities.as_mut_ptr() } else { null_mut() },
            CapabilityCount: u32::from(terms.network),
            Reserved: 0,
        };

        let mut size = 0usize;
        let _ = InitializeProcThreadAttributeList(None, 2, None, &mut size);
        let mut storage = vec![0u8; size];
        let attributes = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        InitializeProcThreadAttributeList(Some(attributes), 2, None, &mut size)?;
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some((&security as *const SECURITY_CAPABILITIES).cast::<c_void>()),
            size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )?;

        let (our_stdin, child_stdin) = pipe(true)?;
        let (our_stdout, child_stdout) = pipe(false)?;
        // Exactly these handles are passed on, and no other the editor holds.
        let mut passed: Vec<HANDLE> = vec![child_stdin.0, child_stdout.0];
        passed.extend(terms.give.iter().map(|end| end.0 .0));
        UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(passed.as_ptr().cast::<c_void>()),
            passed.len() * size_of::<HANDLE>(),
            None,
            None,
        )?;

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_stdin.0;
        startup.StartupInfo.hStdOutput = child_stdout.0;
        startup.lpAttributeList = attributes;

        // The host learns nothing about the user's session: only where
        // Windows lives, and a scratch folder inside its own container.
        let mut environment = Vec::new();
        let mut set = |name: &str, value: &OsStr| {
            environment.extend(OsStr::new(name).encode_wide());
            environment.push(u16::from(b'='));
            environment.extend(value.encode_wide());
            environment.push(0);
        };
        // Windows refuses to start a container process without this one, and
        // the block has to stay in alphabetical order.
        set("LOCALAPPDATA", folder.as_os_str());
        if let Some(root) = std::env::var_os("SystemRoot") {
            set("SystemRoot", &root);
        }
        set("TEMP", temp.as_os_str());
        set("TMP", temp.as_os_str());
        let mut told = terms.tell;
        told.sort();
        for (name, value) in &told {
            set(name, value);
        }
        environment.push(0);

        // The extra pipe ends can be inherited only for the instant of this launch.
        for end in &terms.give {
            SetHandleInformation(end.0 .0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)?;
        }

        let program = wide(program.as_os_str());
        let directory = wide(folder.as_os_str());
        let mut info = PROCESS_INFORMATION::default();
        let created = CreateProcessW(
            PCWSTR(program.as_ptr()),
            None,
            None,
            None,
            true,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
            Some(environment.as_ptr().cast()),
            PCWSTR(directory.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        );
        DeleteProcThreadAttributeList(attributes);
        drop((child_stdin, child_stdout));
        for end in &terms.give {
            let _ = SetHandleInformation(end.0 .0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
        }
        created.map_err(|e| step("starting the program", e.into()))?;
        let (process, thread) = (Handle(info.hProcess), Handle(info.hThread));
        // From here on, dropping `confined` ends the process.
        let job = Handle(CreateJobObjectW(None, PCWSTR::null())?);
        let confined = Confined { process, _job: job };
        let stdin = File::from_raw_handle(our_stdin.0 .0);
        let stdout = File::from_raw_handle(our_stdout.0 .0);
        std::mem::forget((our_stdin, our_stdout));

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        if terms.die_with_editor {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        limits.BasicLimitInformation.ActiveProcessLimit = terms.processes;
        limits.ProcessMemoryLimit = terms.memory;
        SetInformationJobObject(
            confined._job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )?;
        AssignProcessToJobObject(confined._job.0, confined.process.0)?;
        // It was created paused so that it could not run a single
        // instruction outside the job.
        ResumeThread(thread.0);
        Ok((stdin, stdout, confined))
    }
}
