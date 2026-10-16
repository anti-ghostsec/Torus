//! The host: serves one site, on Tor or on a local port, as told by the
//! editor over a pair of pipes. It opens no files of its own choosing and
//! stops as soon as the editor goes away.
//!
//! On desktop systems this runs as a program of its own, confined by the
//! operating system. Where programs cannot start others, as on Android, the
//! editor runs it inside itself over in-memory pipes; the conversation is
//! the same.

pub mod media;

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use torus_core::money::{Ask, Told};
use torus_host_api::node::Node;
use torus_host_api::{read_frame, write_frame, Command, Event, HexBytes, Records, Status, Target};
use torus_runtime::{serve, Live, Storage, Store};
use torus_tor::{Onion, Tor};
use zeroize::Zeroizing;

/// A background task that ends when this is dropped. A host running as its
/// own program would lose its tasks on exit anyway; one running inside the
/// editor must not leave a server behind when it is stopped.
struct Task(tokio::task::JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keeps whatever is serving the site alive.
enum Serving {
    Loopback(Task),
    Onion { onion: Onion, _tor: Tor, _keeping: Option<Task> },
    /// No site: a way through Tor to one Monero node.
    Relay { tor: std::sync::Arc<Tor>, node: Node, _keeping: Option<Task> },
}

/// Tor's bookkeeping for the site, readable only while the host runs.
#[derive(Clone)]
struct Kept {
    state: std::path::PathBuf,
    cache: std::path::PathBuf,
    file: std::path::PathBuf,
    key: Zeroizing<[u8; 32]>,
}

/// How often the bookkeeping is packed away while online, so that little is
/// lost if the device loses power.
const KEEP_EVERY: Duration = Duration::from_secs(5 * 60);

impl Kept {
    /// Erases whatever an earlier run left readable, and unpacks the copy.
    /// The directory cache is public, and fetched afresh instead.
    fn open(&self) -> std::io::Result<()> {
        torus_vault::folder::erase(&self.cache)?;
        std::fs::create_dir_all(&self.cache)?;
        torus_vault::folder::unpack(&self.file, &self.key, &self.state)
    }

    fn keep(&self) -> std::io::Result<()> {
        torus_vault::folder::pack(&self.state, &self.key, &self.file)
    }

    /// Packs the bookkeeping away and erases the readable copies.
    fn close(&self) {
        let _ = self.keep();
        let _ = torus_vault::folder::erase(&self.state);
        let _ = torus_vault::folder::erase(&self.cache);
    }
}

impl Serving {
    fn status(&self) -> Status {
        match self {
            Serving::Loopback(task) => Status { reachable: !task.0.is_finished(), broken: task.0.is_finished() },
            Serving::Onion { onion, .. } => Status { reachable: onion.reachable(), broken: onion.broken() },
            Serving::Relay { .. } => Status { reachable: true, broken: false },
        }
    }
}

async fn start(target: Target, live: Live, kept: &mut Option<Kept>) -> Result<(Serving, String), String> {
    match target {
        Target::Loopback => {
            let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
            let bound = listener.local_addr().map_err(|e| e.to_string())?;
            live.only_for_host(bound.to_string());
            let address = format!("http://{bound}");
            Ok((Serving::Loopback(Task(tokio::spawn(serve(listener, live)))), address))
        }
        Target::Onion { identity, state_dir, cache_dir, kept: file, kept_key } => {
            let identity = Zeroizing::new(identity);
            let identity = <[u8; 64]>::try_from(identity.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| "the onion key is damaged".to_owned())?;
            unpack(&state_dir, &cache_dir, file, kept_key, kept)?;
            let tor = Tor::connect(&state_dir, &cache_dir).await.map_err(|e| e.to_string())?;
            let onion = tor.launch("site", &identity, live).map_err(|e| e.to_string())?;
            let address = onion.address().to_owned();
            Ok((Serving::Onion { onion, _tor: tor, _keeping: keep_periodically(kept) }, address))
        }
        Target::Relay { node, state_dir, cache_dir, kept: file, kept_key } => {
            let node = Node::parse(&node).ok_or_else(|| "that is not a node's address".to_owned())?;
            unpack(&state_dir, &cache_dir, file, kept_key, kept)?;
            let tor = Tor::connect(&state_dir, &cache_dir).await.map_err(|e| e.to_string())?;
            let address = format!("{}:{}", node.host, node.port);
            Ok((Serving::Relay { tor: std::sync::Arc::new(tor), node, _keeping: keep_periodically(kept) }, address))
        }
    }
}

/// Unpacks Tor's bookkeeping, where the editor keeps it.
fn unpack(
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
    file: Option<std::path::PathBuf>,
    kept_key: Vec<u8>,
    kept: &mut Option<Kept>,
) -> Result<(), String> {
    let key = Zeroizing::new(kept_key);
    if let Some(file) = file {
        let key = <[u8; 32]>::try_from(key.as_slice()).map_err(|_| "the bookkeeping key is damaged".to_owned())?;
        let opened = Kept { state: state_dir.to_owned(), cache: cache_dir.to_owned(), file, key: Zeroizing::new(key) };
        opened.open().map_err(|e| format!("could not unpack Tor's bookkeeping: {e}"))?;
        *kept = Some(opened);
    }
    Ok(())
}

fn keep_periodically(kept: &Option<Kept>) -> Option<Task> {
    kept.clone().map(|kept| {
        Task(tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEEP_EVERY).await;
                let kept = kept.clone();
                let _ = tokio::task::spawn_blocking(move || kept.keep()).await;
            }
        }))
    })
}

/// Passes one request on to the relay's node.
async fn fetch(serving: &Serving, route: &str, body: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let Serving::Relay { tor, node, .. } = serving else { return Err("this host is not a relay".into()) };
    let stream = tor.open(&node.host, node.port).await.map_err(|e| e.to_string())?;
    torus_host_api::node::post(stream, node, route, body, limit).await
}

/// Refuses a site the checks reject, and opens its record store.
fn open(site: torus_core::Site, records: Option<Records>) -> Result<Live, String> {
    torus_core::check(&site).map_err(|_| "the site did not pass its checks".to_owned())?;
    let store = match records {
        None => Store::volatile(),
        Some(Records { file, key }) => {
            let key = Zeroizing::new(key);
            let key = <[u8; 32]>::try_from(key.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| "the record key is damaged".to_owned())?;
            Store::open(Storage { file, key }).map_err(|e| e.to_string())?
        }
    };
    Ok(Live::with_store(site, store))
}

/// Serves as told over `stdin`, reporting over `stdout`, until told to stop
/// or until `stdin` closes. Returns the exit code for a host program.
///
/// However it ends, Tor's bookkeeping is packed away and its readable copy
/// erased before this returns.
pub async fn run<R, W>(stdin: R, stdout: W) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let mut kept = None;
    let code = serve_site(stdin, stdout, &mut kept).await;
    if let Some(kept) = kept {
        let _ = tokio::task::spawn_blocking(move || kept.close()).await;
    }
    code
}

async fn serve_site<R, W>(mut stdin: R, mut stdout: W, kept: &mut Option<Kept>) -> i32
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{

    let Ok(Some(Command::Start { target, site, records })) = read_frame(&mut stdin).await else { return 2 };
    let live = match open(site, records) {
        Ok(live) => {
            // Where the editor started a converter beside this host, videos
            // get their pictures and smaller copies made by it.
            if let Some(converter) = media::Piped::from_surroundings() {
                live.convert_with(std::sync::Arc::new(converter));
            }
            live
        }
        Err(message) => {
            let _ = write_frame(&mut stdout, &Event::Failed { message }).await;
            return 1;
        }
    };
    // The site's visitors reach the wallet through the editor.
    let (bank, mut bank_questions) = mpsc::channel::<(Ask, oneshot::Sender<Told>)>(16);
    live.bank_with(std::sync::Arc::new(Piped(bank)));
    let mut waiting: std::collections::HashMap<u64, oneshot::Sender<Told>> = Default::default();
    let mut next_question = 0u64;
    let serving = match start(target, live.clone(), kept).await {
        Ok((serving, address)) => {
            if write_frame(&mut stdout, &Event::Ready { address }).await.is_err() {
                return 0;
            }
            serving
        }
        Err(message) => {
            let _ = write_frame(&mut stdout, &Event::Failed { message }).await;
            return 1;
        }
    };

    // Reading a frame cannot be interrupted halfway, so it gets its own task.
    let (commands, mut inbox) = mpsc::channel(4);
    tokio::spawn(async move {
        while let Ok(Some(command)) = read_frame::<_, Command>(&mut stdin).await {
            if commands.send(command).await.is_err() {
                break;
            }
        }
        // Dropping `commands` tells the loop below that the editor is gone.
    });

    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            command = inbox.recv() => {
                let event = match command {
                    // The editor checks sites before sending them; a site that
                    // fails the same check here is simply not put up.
                    Some(Command::Publish { site }) => {
                        if torus_core::check(&site).is_ok() {
                            live.publish(site);
                        }
                        continue;
                    }
                    Some(Command::Ask { seq, question }) => match *question {
                        Command::Fetch { route, body, limit } => {
                            let body = fetch(&serving, &route, &body, limit).await.map(HexBytes);
                            Event::Answer { seq, answer: Box::new(Event::Fetched { body }) }
                        }
                        question => match answer(&live, question) {
                            Some(answer) => Event::Answer { seq, answer: Box::new(answer) },
                            None => continue,
                        },
                    },
                    Some(Command::Banked { seq, told }) => {
                        if let Some(waiter) = waiting.remove(&seq) {
                            let _ = waiter.send(told);
                        }
                        continue;
                    }
                    // Told to stop, or the editor closed the pipe or died.
                    Some(Command::Stop) | None => return 0,
                    Some(question) => match answer(&live, question) {
                        Some(answer) => answer,
                        None => return 0,
                    },
                };
                // What the editor is told was done is on disk first, so a
                // site stopped right after loses nothing.
                live.settle().await;
                if write_frame(&mut stdout, &event).await.is_err() {
                    return 0;
                }
            }
            Some((ask, waiter)) = bank_questions.recv() => {
                // Questions whose visitor gave up waiting are forgotten.
                waiting.retain(|_, waiter| !waiter.is_closed());
                let seq = next_question;
                next_question += 1;
                waiting.insert(seq, waiter);
                if write_frame(&mut stdout, &Event::Bank { seq, ask }).await.is_err() {
                    return 0;
                }
            }
            _ = tick.tick() => {
                if write_frame(&mut stdout, &Event::Status(serving.status())).await.is_err() {
                    return 0;
                }
            }
        }
    }
}

/// The wallet, as a site's visitors reach it: questions go to the editor
/// over the pipe, and its answers come back the same way.
struct Piped(mpsc::Sender<(Ask, oneshot::Sender<Told>)>);

/// A withdrawal is made and signed by the editor, through the relay and
/// Tor: that can take a while.
const BANK_TIMEOUT: Duration = Duration::from_secs(240);

impl torus_runtime::Bank for Piped {
    fn ask(&self, ask: Ask) -> std::pin::Pin<Box<dyn std::future::Future<Output = Told> + Send>> {
        let questions = self.0.clone();
        Box::pin(async move {
            let (answer, wait) = oneshot::channel();
            if questions.send((ask, answer)).await.is_err() {
                return Told::Refused("The wallet cannot be reached right now.".into());
            }
            match tokio::time::timeout(BANK_TIMEOUT, wait).await {
                Ok(Ok(told)) => told,
                _ => Told::Refused("The wallet did not answer in time. If you withdrew, check your balance before trying again.".into()),
            }
        })
    }
}

/// The answer to a question from the editor. `None` for what is not a question.
fn answer(live: &Live, question: Command) -> Option<Event> {
    Some(match question {
        Command::Probe { path } => Event::Probed { readable: std::fs::File::open(path).is_ok() },
        Command::Records { collection } => Event::Listed { records: live.records(&collection) },
        Command::Remove { collection, id } => Event::Removed { removed: live.remove(&collection, &id) },
        Command::Approve { collection, id } => Event::Removed { removed: live.approve(&collection, &id) },
        Command::Moderators => Event::Moderating { ids: live.moderators() },
        Command::Moderator { id, on } => {
            live.set_moderator(&id, on);
            Event::Moderating { ids: live.moderators() }
        }
        Command::Start { .. }
        | Command::Publish { .. }
        | Command::Ask { .. }
        | Command::Fetch { .. }
        | Command::Banked { .. }
        | Command::Stop => return None,
    })
}

