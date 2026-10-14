//! The editor never talks to the network. For each site that is online it
//! starts one host process and speaks to it over that process's standard
//! input and output, using the messages defined here.
//!
//! The split exists so that a flaw in the network-facing code exposes as
//! little as possible: a host process is handed finished pages and the one
//! key it needs. It never sees the vault, the passphrase, the editor's
//! memory, or any other site.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command as Launch};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use torus_core::{Record, Site};
use zeroize::Zeroizing;

#[cfg(windows)]
mod confine;

/// Larger than any site; a frame beyond this is a bug or an attack.
const MAX_FRAME: u32 = 256 * 1024 * 1024;
/// Connecting to Tor for the first time downloads the network directory.
const START_TIMEOUT: Duration = Duration::from_secs(300);
const GONE: &str = "the host process stopped unexpectedly";

/// Where a host process serves its site.
#[derive(Debug, Serialize, Deserialize)]
pub enum Target {
    /// A port on this computer only, for trying a site out.
    Loopback,
    /// A Tor onion service. `identity` is the site's secret key; the two
    /// folders hold Tor's own bookkeeping for this site.
    Onion { identity: Vec<u8>, state_dir: PathBuf, cache_dir: PathBuf },
}

/// Where a host keeps what visitors submit, and the key it is encrypted
/// with. Without one, records live in memory and are gone when the site stops.
#[derive(Debug, Serialize, Deserialize)]
pub struct Records {
    pub file: PathBuf,
    pub key: Vec<u8>,
}

/// Editor to host.
#[derive(Debug, Serialize, Deserialize)]
pub enum Command {
    /// Always the first message, and sent only once.
    Start { target: Target, site: Site, records: Option<Records> },
    /// Replace the pages being served. Submitted records are kept.
    Publish { site: Site },
    /// Try to open a file for reading and report the outcome. The contents
    /// are never read or returned.
    Probe { path: PathBuf },
    /// List what visitors have added to a collection.
    Records { collection: String },
    /// Remove a record for good, with its files and whatever belongs to it.
    Remove { collection: String, id: String },
    /// Let everyone see a record that was waiting for approval.
    Approve { collection: String, id: String },
    /// List the accounts that are moderators.
    Moderators,
    /// Make an account a moderator, or an ordinary account again.
    Moderator { id: String, on: bool },
    Stop,
}

/// Host to editor. Information only: nothing here asks the editor to act.
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// The site is being served at `address`.
    Ready { address: String },
    Status(Status),
    /// The answer to a `Probe`.
    Probed { readable: bool },
    /// The answer to `Records`.
    Listed { records: Vec<Record> },
    /// The answer to `Remove` and to `Approve`: whether there was such a record.
    Removed { removed: bool },
    /// The answer to `Moderators`, and to `Moderator` once it has been applied.
    Moderating { ids: Vec<String> },
    /// The site could not be started. The host exits after sending this.
    Failed { message: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Visitors can reach the site now.
    pub reachable: bool,
    /// The site has stopped and will not recover without being started again.
    pub broken: bool,
}

/// Writes one message: a 4-byte little-endian length, then JSON.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
    T: Serialize,
{
    // Zeroised because a `Start` frame carries a secret key.
    let body = Zeroizing::new(serde_json::to_vec(message)?);
    let length = u32::try_from(body.len()).ok().filter(|n| *n <= MAX_FRAME).ok_or(io::ErrorKind::InvalidData)?;
    writer.write_all(&length.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await
}

/// Reads one message, or `None` if the other side closed the pipe between messages.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin + ?Sized,
    T: DeserializeOwned,
{
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::BrokenPipe) => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_le_bytes(length);
    if length > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = Zeroizing::new(vec![0u8; length as usize]);
    reader.read_exact(&mut body).await?;
    Ok(Some(serde_json::from_slice(&body)?))
}

type Input = Box<dyn AsyncWrite + Send + Unpin>;
type Output = Box<dyn AsyncRead + Send + Unpin>;
/// Whatever keeps the process alive; dropping it ends the process.
type Keeper = Box<dyn std::any::Any + Send + Sync>;

fn plain(program: &Path) -> Result<(Input, Output, Keeper), String> {
    let mut launch = Launch::new(program);
    launch.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).kill_on_drop(true);
    // The host inherits nothing about the user's session.
    launch.env_clear();
    if let Some(root) = std::env::var_os("SystemRoot") {
        // Windows cannot open sockets without it.
        launch.env("SystemRoot", root);
    }
    #[cfg(windows)]
    launch.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child: Child = launch.spawn().map_err(|e| format!("could not start the host process: {e}"))?;
    let stdin = child.stdin.take().expect("piped above");
    let stdout = child.stdout.take().expect("piped above");
    Ok((Box::new(stdin), Box::new(stdout), Box::new(Mutex::new(child))))
}

/// The container a site's converter runs in, named after the site's own.
fn converter_container(container: &str) -> String {
    format!("{container}-media")
}

#[cfg(windows)]
fn confined(program: &Path, container: &str, converter: Option<&Path>) -> Result<(Input, Output, Keeper), String> {
    use confine::Terms;
    let failed = |e: io::Error| format!("could not start the sandbox: {e}");
    let mut terms = Terms { network: true, processes: 1, tell: Vec::new(), give: Vec::new(), run: Vec::new() };
    // The converter is the same program started in another role, in a
    // container that has no network, with the one program it may run.
    let link = converter.map(|_| confine::link()).transpose().map_err(failed)?;
    let mut keeper: Vec<Keeper> = Vec::new();
    if let (Some(link), Some(converter)) = (&link, converter) {
        let (reads, writes) = &link.converter;
        let its = Terms {
            network: false,
            processes: 2,
            tell: vec![
                (CONVERTER_PROGRAM, converter.as_os_str().to_owned()),
                (CONVERTER_ROLE, format!("{},{}", reads.number(), writes.number()).into()),
            ],
            give: vec![reads, writes],
            run: vec![converter],
        };
        let (_, _, process) = confine::spawn(program, &converter_container(container), its).map_err(failed)?;
        keeper.push(Box::new(process));
        let (reads, writes) = &link.host;
        terms.tell.push((CONVERTER_LINK, format!("{},{}", reads.number(), writes.number()).into()));
        terms.give = vec![reads, writes];
    }
    let (stdin, stdout, process) = confine::spawn(program, container, terms).map_err(failed)?;
    keeper.push(Box::new(process));
    // Our copies of the pipe ends close here, so each side notices when the other is gone.
    drop(link);
    Ok((Box::new(tokio::fs::File::from_std(stdin)), Box::new(tokio::fs::File::from_std(stdout)), Box::new(keeper)))
}

#[cfg(not(windows))]
fn confined(_program: &Path, _container: &str, _converter: Option<&Path>) -> Result<(Input, Output, Keeper), String> {
    Err("the sandbox is not available on this system yet".to_owned())
}

/// Starts a converter on its own, confined exactly as one beside a host
/// is, and returns the pipes to it: the one to read and the one to write.
/// For checking the confinement itself.
#[cfg(windows)]
#[doc(hidden)]
pub fn converter_alone(program: &Path, container: &str, converter: &Path) -> io::Result<(std::fs::File, std::fs::File, Keeper)> {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};
    let link = confine::link()?;
    let (reads, writes) = &link.converter;
    let terms = confine::Terms {
        network: false,
        processes: 2,
        tell: vec![
            (CONVERTER_PROGRAM, converter.as_os_str().to_owned()),
            (CONVERTER_ROLE, format!("{},{}", reads.number(), writes.number()).into()),
        ],
        give: vec![reads, writes],
        run: vec![converter],
    };
    let (_, _, process) = confine::spawn(program, &converter_container(container), terms)?;
    let confine::Link { host: (ours_reads, ours_writes), converter: theirs } = link;
    drop(theirs);
    // SAFETY: the handles are ours alone and are given away exactly once.
    let files = unsafe {
        (std::fs::File::from_raw_handle(ours_reads.into_raw_handle()), std::fs::File::from_raw_handle(ours_writes.into_raw_handle()))
    };
    Ok((files.0, files.1, Box::new(process)))
}

/// Tells a host which pipe ends lead to its converter: two numbers.
pub const CONVERTER_LINK: &str = "TORUS_MEDIA";
/// Tells the program it was started as a converter, and its pipe ends.
pub const CONVERTER_ROLE: &str = "TORUS_MEDIA_WORKER";
/// Tells a converter which program does the converting.
pub const CONVERTER_PROGRAM: &str = "TORUS_FFMPEG";

/// Opens the two pipe ends named by an environment variable: the one to
/// read from, then the one to write to.
pub fn pipe_ends(variable: &str) -> Option<(std::fs::File, std::fs::File)> {
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;
        let named = std::env::var(variable).ok()?;
        let (reads, writes) = named.split_once(',')?;
        let open = |number: &str| {
            let raw = number.parse::<usize>().ok().filter(|raw| *raw != 0)?;
            // Whatever this process starts must not be handed the pipe as well.
            unsafe {
                use windows::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
                SetHandleInformation(HANDLE(raw as *mut std::ffi::c_void), HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).ok()?;
            }
            // SAFETY: the editor made these for this process alone, and
            // nothing else here knows of them.
            Some(unsafe { std::fs::File::from_raw_handle(raw as *mut std::ffi::c_void) })
        };
        Some((open(reads)?, open(writes)?))
    }
    #[cfg(not(windows))]
    {
        let _ = variable;
        None
    }
}

/// A running host process, as the editor holds it. Dropping it ends the
/// process and takes the site offline.
pub struct Host {
    address: String,
    stdin: tokio::sync::Mutex<Input>,
    status: Arc<Mutex<Status>>,
    /// Where the answer to the question being asked is delivered.
    asked: Arc<Mutex<Option<oneshot::Sender<Event>>>>,
    reader: JoinHandle<()>,
    _keeper: Keeper,
}

impl Host {
    /// Starts `program` and waits until it is serving `site`.
    ///
    /// With `container` set, the process runs confined under that name; see
    /// [`container_folder`] for the only place it can then keep files.
    ///
    /// With `converter` set to a video converter's program, and only when
    /// confined, pictures and smaller copies are made from uploaded videos,
    /// by a second process that has neither network nor files.
    pub async fn start(
        program: &Path,
        container: Option<&str>,
        converter: Option<&Path>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Self, String> {
        let (stdin, stdout, keeper) = match container {
            Some(container) => confined(program, container, converter)?,
            None => plain(program)?,
        };
        Self::over(stdin, stdout, keeper, target, site, records).await
    }

    /// Starts a site on a host reached over the given pipes, whatever is at
    /// their other end: a program, or a task inside this one. Dropping
    /// `keeper` must stop that host.
    pub async fn over(
        mut stdin: Box<dyn AsyncWrite + Send + Unpin>,
        mut stdout: Box<dyn AsyncRead + Send + Unpin>,
        keeper: Box<dyn std::any::Any + Send + Sync>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Self, String> {
        write_frame(&mut stdin, &Command::Start { target, site, records }).await.map_err(|_| GONE.to_owned())?;
        let first = tokio::time::timeout(START_TIMEOUT, read_frame::<_, Event>(&mut stdout))
            .await
            .map_err(|_| "starting the site took too long".to_owned())?;
        let address = match first {
            Ok(Some(Event::Ready { address })) => address,
            Ok(Some(Event::Failed { message })) => return Err(message),
            _ => return Err(GONE.to_owned()),
        };

        let status = Arc::new(Mutex::new(Status::default()));
        let asked = Arc::new(Mutex::new(None::<oneshot::Sender<Event>>));
        let (shared, waiting) = (status.clone(), asked.clone());
        let reader = tokio::spawn(async move {
            while let Ok(Some(event)) = read_frame::<_, Event>(&mut stdout).await {
                match event {
                    Event::Status(now) => *shared.lock().unwrap_or_else(|e| e.into_inner()) = now,
                    Event::Ready { .. } | Event::Failed { .. } => {}
                    answer => {
                        if let Some(waiter) = waiting.lock().unwrap_or_else(|e| e.into_inner()).take() {
                            let _ = waiter.send(answer);
                        }
                    }
                }
            }
            // The pipe closed: the process is gone.
            *shared.lock().unwrap_or_else(|e| e.into_inner()) = Status { reachable: false, broken: true };
        });
        Ok(Self { address, stdin: tokio::sync::Mutex::new(stdin), status, asked, reader, _keeper: keeper })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn status(&self) -> Status {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replaces the pages the host serves.
    pub async fn publish(&self, site: Site) -> Result<(), String> {
        write_frame(&mut *self.stdin.lock().await, &Command::Publish { site }).await.map_err(|_| GONE.to_owned())
    }

    /// Asks the host to try opening a file and say whether it could. Used to
    /// check that the sandbox really holds, with a file it must not reach.
    pub async fn can_read(&self, path: &Path) -> Result<bool, String> {
        match self.ask(Command::Probe { path: path.to_owned() }).await? {
            Event::Probed { readable } => Ok(readable),
            _ => Err(GONE.to_owned()),
        }
    }

    /// What visitors have added to a collection, oldest first.
    pub async fn records(&self, collection: &str) -> Result<Vec<Record>, String> {
        match self.ask(Command::Records { collection: collection.to_owned() }).await? {
            Event::Listed { records } => Ok(records),
            _ => Err(GONE.to_owned()),
        }
    }

    /// Removes a record for good. Returns whether there was one.
    pub async fn remove(&self, collection: &str, id: &str) -> Result<bool, String> {
        match self.ask(Command::Remove { collection: collection.to_owned(), id: id.to_owned() }).await? {
            Event::Removed { removed } => Ok(removed),
            _ => Err(GONE.to_owned()),
        }
    }

    /// Lets everyone see a record that was waiting for approval. Returns
    /// whether there was one.
    pub async fn approve(&self, collection: &str, id: &str) -> Result<bool, String> {
        match self.ask(Command::Approve { collection: collection.to_owned(), id: id.to_owned() }).await? {
            Event::Removed { removed } => Ok(removed),
            _ => Err(GONE.to_owned()),
        }
    }

    /// The ids of the accounts that are moderators.
    pub async fn moderators(&self) -> Result<Vec<String>, String> {
        match self.ask(Command::Moderators).await? {
            Event::Moderating { ids } => Ok(ids),
            _ => Err(GONE.to_owned()),
        }
    }

    /// Makes an account a moderator or an ordinary account again, and
    /// returns who the moderators are afterwards.
    pub async fn set_moderator(&self, id: &str, on: bool) -> Result<Vec<String>, String> {
        match self.ask(Command::Moderator { id: id.to_owned(), on }).await? {
            Event::Moderating { ids } => Ok(ids),
            _ => Err(GONE.to_owned()),
        }
    }

    /// Sends a command that has an answer and waits for it.
    async fn ask(&self, command: Command) -> Result<Event, String> {
        // Holding the pipe for the whole exchange keeps questions from overlapping.
        let mut stdin = self.stdin.lock().await;
        let (answer, wait) = oneshot::channel();
        *self.asked.lock().unwrap_or_else(|e| e.into_inner()) = Some(answer);
        write_frame(&mut *stdin, &command).await.map_err(|_| GONE.to_owned())?;
        tokio::time::timeout(Duration::from_secs(20), wait)
            .await
            .map_err(|_| "the host process did not answer".to_owned())?
            .map_err(|_| GONE.to_owned())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Where the host program sits: beside the running program.
pub fn host_program() -> io::Result<PathBuf> {
    let mut path = std::env::current_exe()?;
    path.set_file_name(if cfg!(windows) { "torus-host.exe" } else { "torus-host" });
    Ok(path)
}

/// Keeps this program's memory from being written out when it crashes.
/// A crash report or core dump is a copy of memory, keys included, left on
/// disk or sent to the system's vendor. Call it first thing.
pub fn no_crash_dumps() {
    #[cfg(windows)]
    unsafe {
        use windows::core::PCWSTR;
        use windows::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
        };
        use windows::Win32::System::ErrorReporting::{
            WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
        };
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        let _ = WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        // Asks Windows Error Reporting to leave this program alone altogether.
        if let Some(name) = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_owned())) {
            use std::os::windows::ffi::OsStrExt;
            let name: Vec<u16> = name.encode_wide().chain(Some(0)).collect();
            let _ = WerAddExcludedApplication(PCWSTR(name.as_ptr()), false);
        }
    }
    #[cfg(unix)]
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
        // Also stops other programs of the same user from attaching to this
        // one and reading its memory.
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

/// Whether this system can confine host processes yet.
pub fn sandbox_available() -> bool {
    cfg!(windows)
}

/// The only folder a confined host may keep files in, created on first use.
#[cfg(windows)]
pub fn container_folder(container: &str) -> io::Result<PathBuf> {
    confine::container_folder(container)
}

/// Removes a container and everything a host kept in it.
#[cfg(windows)]
pub fn remove_container(container: &str) {
    confine::remove_container(&converter_container(container));
    confine::remove_container(container);
}

#[cfg(not(windows))]
pub fn container_folder(_container: &str) -> io::Result<PathBuf> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(not(windows))]
pub fn remove_container(_container: &str) {}
