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

pub mod node;

#[cfg(windows)]
mod confine;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod unix_confine;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix_confine::{confine_from_surroundings, Isolation};

/// Larger than any site; a frame beyond this is a bug or an attack.
const MAX_FRAME: u32 = 256 * 1024 * 1024;
/// Connecting to Tor for the first time downloads the network directory.
const START_TIMEOUT: Duration = Duration::from_secs(300);
const GONE: &str = "the host process stopped unexpectedly";
/// A Monero node over Tor can be slow, and some answers are large.
const FETCH_TIMEOUT: Duration = Duration::from_secs(180);

/// Where a host process serves its site.
#[derive(Debug, Serialize, Deserialize)]
pub enum Target {
    /// A port on this computer only, for trying a site out.
    Loopback,
    /// A Tor onion service. `identity` is the site's secret key; the two
    /// folders hold Tor's own bookkeeping for this site. That bookkeeping is
    /// readable only while the site is online: the host unpacks it from
    /// `kept`, encrypted with `kept_key`, and packs it back and erases the
    /// readable copy when it stops. The editor never reads the host's
    /// folder, so nothing the host puts there can mislead it.
    Onion {
        identity: Vec<u8>,
        state_dir: PathBuf,
        cache_dir: PathBuf,
        #[serde(default)]
        kept: Option<PathBuf>,
        #[serde(default)]
        kept_key: Vec<u8>,
    },
    /// No site: only a way through Tor to one Monero node, at `node` (a
    /// host and port), for the wallet the editor keeps. The host is given
    /// no key: it passes the wallet's questions to the node and the node's
    /// answers back, and only learns what the node itself learns. Tor's
    /// bookkeeping is kept as for an onion.
    Relay {
        node: String,
        state_dir: PathBuf,
        cache_dir: PathBuf,
        #[serde(default)]
        kept: Option<PathBuf>,
        #[serde(default)]
        kept_key: Vec<u8>,
    },
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
    /// For a relay: sends `body` to the node at `route` and returns what it
    /// answers, refusing an answer larger than `limit`.
    Fetch {
        route: String,
        #[serde(with = "hex::serde")]
        body: Vec<u8>,
        limit: usize,
    },
    /// The wallet's answer to the host's `Bank` question with this number.
    Banked { seq: u64, told: torus_core::money::Told },
    /// A question that has an answer, numbered so that a late answer to an
    /// earlier question is never taken for the answer to this one.
    Ask { seq: u64, question: Box<Command> },
    Stop,
}

/// Host to editor. Information only, with one exception: `Bank`, by which
/// a site's visitors use the wallet. The editor checks every such request
/// against its own books, so a host can ask for nothing its visitors could
/// not, and a site's withdrawals are limited by the day.
#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    /// Asks the wallet something on a visitor's behalf; answered with `Banked`.
    Bank { seq: u64, ask: torus_core::money::Ask },
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
    /// The answer to `Fetch`.
    Fetched { body: Result<HexBytes, String> },
    /// The answer to the `Ask` with the same number.
    Answer { seq: u64, answer: Box<Event> },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Visitors can reach the site now.
    pub reachable: bool,
    /// The site has stopped and will not recover without being started again.
    pub broken: bool,
}

/// Bytes carried as hex: a list of numbers in JSON would be four times larger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HexBytes(#[serde(with = "hex::serde")] pub Vec<u8>);

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
#[cfg(windows)]
fn converter_container(container: &str) -> String {
    format!("{container}-media")
}

/// The most memory a confined host may use. Enough for its largest job,
/// moving the index of a very long video, with room to spare.
#[cfg(windows)]
const HOST_MEMORY: usize = 4 << 30;
/// The most memory the converter may use, decoding 4K video included.
#[cfg(windows)]
const CONVERTER_MEMORY: usize = 6 << 30;

#[cfg(windows)]
fn confined(program: &Path, sandbox: &Sandbox<'_>, converter: Option<&Path>) -> Result<(Input, Output, Keeper), String> {
    use confine::Terms;
    let container = sandbox.name;
    let failed = |e: io::Error| format!("could not start the sandbox: {e}");
    let mut terms = Terms {
        network: true,
        processes: 1,
        memory: HOST_MEMORY,
        die_with_editor: false,
        tell: Vec::new(),
        give: Vec::new(),
        run: Vec::new(),
    };
    // The converter is the same program started in another role, in a
    // container that has no network, with the one program it may run.
    let link = converter.map(|_| confine::link()).transpose().map_err(failed)?;
    let mut keeper: Vec<Keeper> = Vec::new();
    if let (Some(link), Some(converter)) = (&link, converter) {
        let (reads, writes) = &link.converter;
        let its = Terms {
            network: false,
            processes: 2,
            memory: CONVERTER_MEMORY,
            die_with_editor: true,
            tell: vec![
                (CONVERTER_PROGRAM, converter.as_os_str().to_owned()),
                (CONVERTER_ROLE, format!("{},{}", reads.number(), writes.number()).into()),
            ],
            give: vec![reads, writes],
            run: vec![converter],
        };
        let room = sandbox.folder.join("converter");
        let (_, _, process) = confine::spawn(program, &converter_container(container), &room, its).map_err(failed)?;
        keeper.push(Box::new(process));
        let (reads, writes) = &link.host;
        terms.tell.push((CONVERTER_LINK, format!("{},{}", reads.number(), writes.number()).into()));
        terms.give = vec![reads, writes];
    }
    let (stdin, stdout, process) = confine::spawn(program, container, sandbox.folder, terms).map_err(failed)?;
    keeper.push(Box::new(process));
    // Our copies of the pipe ends close here, so each side notices when the other is gone.
    drop(link);
    Ok((Box::new(tokio::fs::File::from_std(stdin)), Box::new(tokio::fs::File::from_std(stdout)), Box::new(keeper)))
}

/// Where Linux and Android keep the files a dynamically linked program
/// needs when it starts, and the few the kernel reports facts through.
#[cfg(any(target_os = "linux", target_os = "android"))]
const SYSTEM_READS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/etc/ld.so.cache",
    "/system",
    "/apex",
    "/vendor",
    "/proc/meminfo",
    "/proc/cpuinfo",
    "/sys/devices/system/cpu",
    "/sys/fs/cgroup",
];
/// Where a confined process sends what it discards: the converter starts
/// its decoder with nowhere else to write messages.
#[cfg(any(target_os = "linux", target_os = "android"))]
const DISCARD: &str = "/dev/null";

/// A pipe whose ends close themselves when this process starts another.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd;
    let mut ends = [0; 2];
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (std::os::fd::OwnedFd::from_raw_fd(ends[0]), std::os::fd::OwnedFd::from_raw_fd(ends[1])) })
}

/// Starts `program` confining itself: see `unix_confine`. Only `ends` are
/// passed on, as descriptors 3, 4, ...
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_launch(
    program: &Path,
    told: Vec<(&'static str, std::ffi::OsString)>,
    ends: Vec<std::os::fd::OwnedFd>,
    piped: bool,
) -> io::Result<Child> {
    use std::os::fd::AsRawFd;
    let mut launch = Launch::new(program);
    let io = || if piped { Stdio::piped() } else { Stdio::null() };
    launch.stdin(io()).stdout(io()).stderr(Stdio::null()).kill_on_drop(true).env_clear();
    for (name, value) in told {
        launch.env(name, value);
    }
    let raw: Vec<i32> = ends.iter().map(|end| end.as_raw_fd()).collect();
    // Only the host is piped to the editor; the converter dies with whoever started it.
    let die_with_parent = !piped;
    // SAFETY: `keep_only` makes async-signal-safe system calls only.
    unsafe {
        launch.pre_exec(move || unix_confine::keep_only(&raw, die_with_parent));
    }
    let child = launch.spawn();
    // Our copies of the child's ends close here.
    drop(ends);
    child
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn confined(program: &Path, sandbox: &Sandbox<'_>, converter: Option<&Path>) -> Result<(Input, Output, Keeper), String> {
    let failed = |e: io::Error| format!("could not start the sandbox: {e}");
    let system: Vec<&Path> = SYSTEM_READS.iter().map(Path::new).collect();
    let mut keeper: Vec<Keeper> = Vec::new();
    let mut host_told = unix_confine::surroundings(&[sandbox.folder, Path::new(DISCARD)], &system, false);
    let mut host_ends = Vec::new();
    if let Some(converter) = converter {
        // The converter is the same program started in another role, with
        // no network and no files, and the one program it may run.
        let (host_reads, converter_writes) = unix_pipe().map_err(failed)?;
        let (converter_reads, host_writes) = unix_pipe().map_err(failed)?;
        let mut programs = system.clone();
        programs.push(converter);
        let mut told = unix_confine::surroundings(&[Path::new(DISCARD)], &programs, true);
        told.push((CONVERTER_PROGRAM, converter.as_os_str().to_owned()));
        told.push((CONVERTER_ROLE, "3,4".into()));
        let process = unix_launch(program, told, vec![converter_reads, converter_writes], false).map_err(failed)?;
        keeper.push(Box::new(Mutex::new(process)));
        host_told.push((CONVERTER_LINK, "3,4".into()));
        host_ends = vec![host_reads, host_writes];
    }
    let mut process = unix_launch(program, host_told, host_ends, true).map_err(failed)?;
    let stdin = process.stdin.take().expect("piped above");
    let stdout = process.stdout.take().expect("piped above");
    keeper.push(Box::new(Mutex::new(process)));
    Ok((Box::new(stdin), Box::new(stdout), Box::new(keeper)))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
fn confined(_program: &Path, _sandbox: &Sandbox<'_>, _converter: Option<&Path>) -> Result<(Input, Output, Keeper), String> {
    Err("the sandbox is not available on this system yet".to_owned())
}

/// Starts a converter on its own, confined exactly as one beside a host
/// is, and returns the pipes to it: the one to read and the one to write.
/// For checking the confinement itself.
#[cfg(windows)]
#[doc(hidden)]
pub fn converter_alone(
    program: &Path,
    container: &str,
    converter: &Path,
    folder: &Path,
) -> io::Result<(std::fs::File, std::fs::File, Keeper)> {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle};
    let link = confine::link()?;
    let (reads, writes) = &link.converter;
    let terms = confine::Terms {
        network: false,
        processes: 2,
        memory: CONVERTER_MEMORY,
        die_with_editor: true,
        tell: vec![
            (CONVERTER_PROGRAM, converter.as_os_str().to_owned()),
            (CONVERTER_ROLE, format!("{},{}", reads.number(), writes.number()).into()),
        ],
        give: vec![reads, writes],
        run: vec![converter],
    };
    let (_, _, process) = confine::spawn(program, &converter_container(container), folder, terms)?;
    let confine::Link { host: (ours_reads, ours_writes), converter: theirs } = link;
    drop(theirs);
    // SAFETY: the handles are ours alone and are given away exactly once.
    let files = unsafe {
        (std::fs::File::from_raw_handle(ours_reads.into_raw_handle()), std::fs::File::from_raw_handle(ours_writes.into_raw_handle()))
    };
    Ok((files.0, files.1, Box::new(process)))
}

/// Starts a converter on its own, confined exactly as one beside a host
/// is, and returns the pipes to it: the one to read and the one to write.
/// For checking the confinement itself.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[doc(hidden)]
pub fn converter_alone(
    program: &Path,
    _container: &str,
    converter: &Path,
    _folder: &Path,
) -> io::Result<(std::fs::File, std::fs::File, Keeper)> {
    let (ours_reads, converter_writes) = unix_pipe()?;
    let (converter_reads, ours_writes) = unix_pipe()?;
    let mut programs: Vec<&Path> = SYSTEM_READS.iter().map(Path::new).collect();
    programs.push(converter);
    let mut told = unix_confine::surroundings(&[Path::new(DISCARD)], &programs, true);
    told.push((CONVERTER_PROGRAM, converter.as_os_str().to_owned()));
    told.push((CONVERTER_ROLE, "3,4".into()));
    // Started outside any runtime by tests, so one is made for the launch.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let process = runtime.block_on(async { unix_launch(program, told, vec![converter_reads, converter_writes], false) })?;
    Ok((std::fs::File::from(ours_reads), std::fs::File::from(ours_writes), Box::new((Mutex::new(process), Mutex::new(runtime)))))
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
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let named = std::env::var(variable).ok()?;
        let (reads, writes) = named.split_once(',')?;
        let open = |number: &str| {
            let fd = number.parse::<i32>().ok().filter(|fd| *fd > 2)?;
            // Whatever this process starts must not be handed the pipe as well.
            unsafe {
                if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) != 0 {
                    return None;
                }
                Some(std::fs::File::from_raw_fd(fd))
            }
        };
        Some((open(reads)?, open(writes)?))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = variable;
        None
    }
}

/// Where a confined host runs: the name of its sandbox, and the one folder
/// it may keep files in.
pub struct Sandbox<'a> {
    pub name: &'a str,
    pub folder: &'a Path,
}

/// A running host process, as the editor holds it. Dropping it ends the
/// process and takes the site offline.
pub struct Host {
    address: String,
    stdin: Arc<tokio::sync::Mutex<Input>>,
    status: Arc<Mutex<Status>>,
    /// Where the answer to the question being asked is delivered, and its number.
    asked: Arc<Mutex<Option<(u64, oneshot::Sender<Event>)>>>,
    /// The number the next question gets.
    next_seq: std::sync::atomic::AtomicU64,
    /// Answers the host's questions to the wallet, once set.
    banker: Arc<Mutex<Option<Banker>>>,
    /// Held while a question is out.
    asking: tokio::sync::Mutex<()>,
    reader: JoinHandle<()>,
    _keeper: Keeper,
}

/// Answers a site's questions to the wallet.
pub type Banker = Arc<
    dyn Fn(torus_core::money::Ask) -> std::pin::Pin<Box<dyn std::future::Future<Output = torus_core::money::Told> + Send>>
        + Send
        + Sync,
>;

impl Host {
    /// Starts `program` and waits until it is serving `site`.
    ///
    /// With `sandbox` set, the process runs confined, able to keep files in
    /// the sandbox's folder only.
    ///
    /// With `converter` set to a video converter's program, and only when
    /// confined, pictures and smaller copies are made from uploaded videos,
    /// by a second process that has neither network nor files.
    pub async fn start(
        program: &Path,
        sandbox: Option<Sandbox<'_>>,
        converter: Option<&Path>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Self, String> {
        let (stdin, stdout, keeper) = match sandbox {
            Some(sandbox) => confined(program, &sandbox, converter)?,
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
        let asked = Arc::new(Mutex::new(None::<(u64, oneshot::Sender<Event>)>));
        let (shared, waiting) = (status.clone(), asked.clone());
        let banker: Arc<Mutex<Option<Banker>>> = Arc::default();
        let stdin = Arc::new(tokio::sync::Mutex::new(stdin));
        let (bank, answers) = (banker.clone(), stdin.clone());
        // Questions to the wallet are few at a time: a site's forms are
        // rate-limited, and pages ask once per view.
        let open_questions = Arc::new(tokio::sync::Semaphore::new(16));
        let reader = tokio::spawn(async move {
            while let Ok(Some(event)) = read_frame::<_, Event>(&mut stdout).await {
                match event {
                    Event::Status(now) => *shared.lock().unwrap_or_else(|e| e.into_inner()) = now,
                    // Only a numbered answer to the question still being
                    // waited for is delivered; anything else is late or stray.
                    Event::Answer { seq, answer } => {
                        let mut waiting = waiting.lock().unwrap_or_else(|e| e.into_inner());
                        if waiting.as_ref().is_some_and(|(wanted, _)| *wanted == seq) {
                            let (_, waiter) = waiting.take().expect("checked above");
                            let _ = waiter.send(*answer);
                        }
                    }
                    Event::Bank { seq, ask } => {
                        let banker = bank.lock().unwrap_or_else(|e| e.into_inner()).clone();
                        let Ok(permit) = open_questions.clone().try_acquire_owned() else { continue };
                        let answers = answers.clone();
                        tokio::spawn(async move {
                            let told = match banker {
                                Some(banker) => banker(ask).await,
                                None => torus_core::money::Told::Refused("This site has no wallet.".into()),
                            };
                            let _ = write_frame(&mut *answers.lock().await, &Command::Banked { seq, told }).await;
                            drop(permit);
                        });
                    }
                    _ => {}
                }
            }
            // The pipe closed: the process is gone.
            *shared.lock().unwrap_or_else(|e| e.into_inner()) = Status { reachable: false, broken: true };
        });
        Ok(Self { address, stdin, status, asked, next_seq: Default::default(), banker, asking: Default::default(), reader, _keeper: keeper })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// From now on, the site's questions to the wallet are put to `banker`.
    pub fn answer_bank_with(&self, banker: Banker) {
        *self.banker.lock().unwrap_or_else(|e| e.into_inner()) = Some(banker);
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

    /// For a relay: one request to the node, and its answer.
    pub async fn fetch(&self, route: &str, body: Vec<u8>, limit: usize) -> Result<Vec<u8>, String> {
        let command = Command::Fetch { route: route.to_owned(), body, limit };
        match self.ask_within(command, FETCH_TIMEOUT).await? {
            Event::Fetched { body } => body.map(|b| b.0),
            _ => Err(GONE.to_owned()),
        }
    }

    /// Sends a command that has an answer and waits for it.
    async fn ask(&self, command: Command) -> Result<Event, String> {
        self.ask_within(command, Duration::from_secs(20)).await
    }

    async fn ask_within(&self, command: Command, within: Duration) -> Result<Event, String> {
        // One question at a time; the pipe itself is held only to write, so
        // the wallet's answers to the host still get through meanwhile.
        let _turn = self.asking.lock().await;
        let seq = self.next_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (answer, wait) = oneshot::channel();
        *self.asked.lock().unwrap_or_else(|e| e.into_inner()) = Some((seq, answer));
        let question = Command::Ask { seq, question: Box::new(command) };
        write_frame(&mut *self.stdin.lock().await, &question).await.map_err(|_| GONE.to_owned())?;
        let answered = tokio::time::timeout(within, wait).await;
        // Whatever happened, this question is no longer waited for.
        let mut asked = self.asked.lock().unwrap_or_else(|e| e.into_inner());
        if asked.as_ref().is_some_and(|(wanted, _)| *wanted == seq) {
            *asked = None;
        }
        answered.map_err(|_| "the host process did not answer".to_owned())?.map_err(|_| GONE.to_owned())
    }
}

impl Host {
    /// Asks the host to stop and waits, for a while, until it has: a host
    /// stopping on its own packs its Tor bookkeeping away and erases the
    /// readable copy first. Then the process is ended either way.
    pub async fn stop(mut self) {
        let asked = write_frame(&mut *self.stdin.lock().await, &Command::Stop).await;
        if asked.is_ok() {
            // The reader ends when the host closes its output, by exiting.
            let _ = tokio::time::timeout(Duration::from_secs(30), &mut self.reader).await;
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Where the host program sits: beside the running program. On Android it
/// is packaged as a native library, the one place Android lets an app keep
/// programs it can start.
pub fn host_program() -> io::Result<PathBuf> {
    #[cfg(target_os = "android")]
    {
        Ok(native_library_dir()?.join("libtorus_host.so"))
    }
    #[cfg(not(target_os = "android"))]
    {
        let mut path = std::env::current_exe()?;
        path.set_file_name(if cfg!(windows) { "torus-host.exe" } else { "torus-host" });
        Ok(path)
    }
}

/// The folder Android unpacked this app's native libraries into: where the
/// library holding this code was loaded from.
#[cfg(target_os = "android")]
pub fn native_library_dir() -> io::Result<PathBuf> {
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    maps.lines()
        .filter_map(|line| line.split_whitespace().nth(5))
        .find(|path| path.ends_with("/libtorus_lib.so"))
        .and_then(|path| Path::new(path).parent().map(Path::to_path_buf))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "the app's native library folder"))
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

/// Whether this system can confine host processes. Whether a confinement
/// really holds is checked on every start, from outside.
pub fn sandbox_available() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "android"))
}

/// Takes back a container's permission to run `programs`. What its host
/// kept is in the folder the caller gave it, the caller's to erase.
#[cfg(windows)]
pub fn remove_container(container: &str, programs: &[&Path]) {
    confine::remove_container(&converter_container(container), programs);
    confine::remove_container(container, programs);
}

/// Makes a folder readable and writable by this user alone, whatever the
/// folder it sits in allows.
pub fn make_private(folder: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        confine::make_private(folder)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = folder;
        Ok(())
    }
}


#[cfg(not(windows))]
pub fn remove_container(_container: &str, _programs: &[&Path]) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn relay_and_wallet_messages_cross_the_pipe() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let fetch = Command::Ask { seq: 3, question: Box::new(Command::Fetch { route: "json_rpc".into(), body: vec![0, 1, 255], limit: 9 }) };
        write_frame(&mut a, &fetch).await.unwrap();
        match read_frame::<_, Command>(&mut b).await.unwrap() {
            Some(Command::Ask { seq: 3, question }) => match *question {
                Command::Fetch { route, body, limit } => assert_eq!((route.as_str(), body, limit), ("json_rpc", vec![0, 1, 255], 9)),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
        let answer = Event::Answer { seq: 3, answer: Box::new(Event::Fetched { body: Ok(HexBytes(vec![42; 1000])) }) };
        let bytes = serde_json::to_vec(&answer).unwrap();
        assert!(bytes.len() < 2100, "bytes go as hex, not as a list of numbers");
        write_frame(&mut b, &answer).await.unwrap();
        assert!(matches!(read_frame::<_, Event>(&mut a).await.unwrap(), Some(Event::Answer { seq: 3, .. })));

        let ask = Event::Bank { seq: 1, ask: torus_core::money::Ask::Purse { user: "u".into() } };
        write_frame(&mut a, &ask).await.unwrap();
        assert!(matches!(read_frame::<_, Event>(&mut b).await.unwrap(), Some(Event::Bank { seq: 1, .. })));
        let told = Command::Banked { seq: 1, told: torus_core::money::Told::Refused("no".into()) };
        write_frame(&mut b, &told).await.unwrap();
        assert!(matches!(read_frame::<_, Command>(&mut a).await.unwrap(), Some(Command::Banked { seq: 1, .. })));
    }
}
