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
use tokio::sync::mpsc;
use torus_host_api::{read_frame, write_frame, Command, Event, Records, Status, Target};
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
    Onion { onion: Onion, _tor: Tor },
}

impl Serving {
    fn status(&self) -> Status {
        match self {
            Serving::Loopback(task) => Status { reachable: !task.0.is_finished(), broken: task.0.is_finished() },
            Serving::Onion { onion, .. } => Status { reachable: onion.reachable(), broken: onion.broken() },
        }
    }
}

async fn start(target: Target, live: Live) -> Result<(Serving, String), String> {
    match target {
        Target::Loopback => {
            let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
            let address = format!("http://{}", listener.local_addr().map_err(|e| e.to_string())?);
            Ok((Serving::Loopback(Task(tokio::spawn(serve(listener, live)))), address))
        }
        Target::Onion { identity, state_dir, cache_dir } => {
            let identity = Zeroizing::new(identity);
            let identity = <[u8; 64]>::try_from(identity.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| "the onion key is damaged".to_owned())?;
            let tor = Tor::connect(&state_dir, &cache_dir).await.map_err(|e| e.to_string())?;
            let onion = tor.launch("site", &identity, live).map_err(|e| e.to_string())?;
            let address = onion.address().to_owned();
            Ok((Serving::Onion { onion, _tor: tor }, address))
        }
    }
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
pub async fn run<R, W>(mut stdin: R, mut stdout: W) -> i32
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
    let serving = match start(target, live.clone()).await {
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
                    Some(Command::Ask { seq, question }) => match answer(&live, *question) {
                        Some(answer) => Event::Answer { seq, answer: Box::new(answer) },
                        None => continue,
                    },
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
            _ = tick.tick() => {
                if write_frame(&mut stdout, &Event::Status(serving.status())).await.is_err() {
                    return 0;
                }
            }
        }
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
        Command::Start { .. } | Command::Publish { .. } | Command::Ask { .. } | Command::Stop => return None,
    })
}

