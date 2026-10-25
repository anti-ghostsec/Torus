//! Everything the editor can do, with no window attached, so it can be
//! tested directly. The window's commands in `lib.rs` only forward here.
//!
//! This process holds the vault and never touches the network: each site
//! that is online runs in a host process of its own, confined by the
//! operating system, and checked from here to be confined before the site
//! stays online.
//!
//! Nothing readable is left on disk while the app is closed: the vault and
//! visitors' data are encrypted, and Tor's own bookkeeping for a site is
//! kept encrypted too, unpacked only while that site is online.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use torus_core::{check, lint, render_canvas, Canvas, Finding, Site};
use torus_host_api::{Host, Records, Sandbox, Target};
use torus_onion_key::Identity;
use torus_vault::{folder, Vault};

use crate::money::{StoredMoney, Treasury};
use zeroize::Zeroizing;

/// What the vault file holds once decrypted.
#[derive(Serialize, Deserialize, Default)]
struct Payload {
    #[serde(default)]
    sites: Vec<Stored>,
    /// The number the next site gets. Numbers are never given out twice,
    /// so nothing a deleted site left behind can ever be taken for a new
    /// site's own.
    #[serde(default)]
    next_id: u32,
    /// Lock the vault after this many idle minutes; 0 never does.
    #[serde(default)]
    auto_lock_minutes: u32,
    /// Onion keys kept for later: found by a search, imported, or replaced
    /// on a site. None of them is any site's address now.
    #[serde(default)]
    saved: Vec<Vec<u8>>,
    /// The Monero wallet, once one has been made.
    #[serde(default)]
    money: Option<StoredMoney>,
    // Vaults written before multiple sites existed held exactly one.
    #[serde(default, skip_serializing)]
    site: Option<Site>,
    #[serde(default, skip_serializing)]
    identity: Option<Vec<u8>>,
}

/// The sealed part of a site file: the site, and only the secrets the owner
/// chose to carry with it.
#[derive(Serialize, Deserialize)]
struct Exported {
    site: Site,
    identity: Option<Vec<u8>>,
    records_key: Option<Vec<u8>>,
    seal_secret: Option<Vec<u8>>,
    /// Whether the site's encrypted folder follows the sealed part.
    content: bool,
}

/// The most beginnings one search looks for at once.
const MAX_PREFIXES: usize = 16;
/// Address file: `magic | sealed key`, the key padded so every file is alike.
const KEY_MAGIC: &[u8; 8] = b"TORUSKY1";
const KEY_FILE_PADDING: usize = 256;

/// Site file: `magic | sealed part's length | sealed part | archive, if any`.
const SITE_MAGIC: &[u8; 8] = b"TORUSST1";
/// The sealed part is a site's design and a few keys, padded: never huge.
const MAX_SITE_HEADER: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Stored {
    /// Never reused, so a site keeps its own Tor folder for life.
    id: u32,
    site: Site,
    /// The onion service's secret key. Present once the site has been published to Tor.
    identity: Option<Vec<u8>>,
    /// The key that what visitors submit is encrypted with on disk.
    #[serde(default)]
    records_key: Option<Vec<u8>>,
    /// The secret that opens what visitors send to sealed collections.
    #[serde(default)]
    seal_secret: Option<Vec<u8>>,
    /// The key Tor's bookkeeping for this site is kept encrypted with.
    #[serde(default)]
    tor_key: Option<Vec<u8>>,
}

struct Entry {
    id: u32,
    site: Site,
    identity: Option<Identity>,
    records_key: Option<Zeroizing<Vec<u8>>>,
    seal_secret: Option<Zeroizing<Vec<u8>>>,
    tor_key: Option<Zeroizing<Vec<u8>>>,
}

/// A site as the editor's window sees it: no secrets.
#[derive(Debug, Serialize)]
pub struct Listed {
    pub id: u32,
    pub site: Site,
    pub address: Option<String>,
}

struct Session {
    vault: Vault,
    sites: Vec<Entry>,
    next_id: u32,
    auto_lock_minutes: u32,
    saved: Vec<Identity>,
    money: Option<StoredMoney>,
}

impl Session {
    fn persist(&self) -> Result<(), Failure> {
        let sites = self
            .sites
            .iter()
            .map(|e| Stored {
                id: e.id,
                site: e.site.clone(),
                identity: e.identity.as_ref().map(|key| key.to_vec()),
                records_key: e.records_key.as_ref().map(|key| key.to_vec()),
                seal_secret: e.seal_secret.as_ref().map(|key| key.to_vec()),
                tor_key: e.tor_key.as_ref().map(|key| key.to_vec()),
            })
            .collect();
        let payload = Payload {
            sites,
            next_id: self.next_id,
            auto_lock_minutes: self.auto_lock_minutes,
            saved: self.saved.iter().map(|key| key.to_vec()).collect(),
            money: self.money.clone(),
            ..Payload::default()
        };
        let mut bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(Failure::new)?);
        // The vault's size says only roughly how much is in it.
        torus_vault::pad_json(&mut bytes);
        self.vault.save(&bytes).map_err(Failure::new)
    }

    /// Keeps a key for later, unless it is already kept or in use.
    fn keep(&mut self, key: Identity) {
        let known = self.saved.iter().chain(self.sites.iter().filter_map(|e| e.identity.as_ref())).any(|k| **k == *key);
        if !known {
            self.saved.push(key);
        }
    }

    fn entry(&mut self, id: u32) -> Result<&mut Entry, Failure> {
        self.sites.iter_mut().find(|e| e.id == id).ok_or_else(|| Failure::new("That site no longer exists."))
    }

    fn add(&mut self, site: Site) -> u32 {
        let id = self.sites.iter().map(|e| e.id + 1).max().unwrap_or(1).max(self.next_id).max(1);
        self.next_id = id + 1;
        self.sites.push(Entry { id, site, identity: None, records_key: None, seal_secret: None, tor_key: None });
        id
    }

    fn listed(&self) -> Vec<Listed> {
        self.sites
            .iter()
            .map(|e| Listed { id: e.id, site: e.site.clone(), address: e.identity.as_ref().map(torus_onion_key::address) })
            .collect()
    }
}

fn identity_from(bytes: Vec<u8>) -> Result<Identity, Failure> {
    let bytes = Zeroizing::new(bytes);
    <[u8; 64]>::try_from(bytes.as_slice()).map(Zeroizing::new).map_err(|_| Failure::new("A stored onion key is damaged."))
}

fn random_key() -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(&mut key).map_err(Failure::new)?;
    Ok(key)
}

/// Why something could not be done, in a form the window can show.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub message: String,
    pub findings: Vec<Finding>,
}

impl Failure {
    fn new(cause: impl std::fmt::Display) -> Self {
        Self { message: cause.to_string(), findings: Vec::new() }
    }
}

/// The single empty site a freshly set-up decoy shows, so that opening it
/// looks exactly like a new installation.
fn decoy_site() -> Site {
    torus_core::starters::by_name("board").unwrap_or_else(|| Site {
        title: "My site".into(),
        theme: Default::default(),
        pages: Vec::new(),
        collections: Vec::new(),
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
    })
}

/// Refuses a site with anything in it that blocks publishing.
fn checked(site: &Site) -> Result<(), Failure> {
    check(site).map_err(|findings| Failure { message: "The site has problems that block publishing.".into(), findings })
}

#[derive(Serialize)]
pub struct View {
    pub canvas: Option<Canvas>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct OnionStatus {
    pub id: u32,
    pub reachable: bool,
    pub broken: bool,
    /// Whether the system kept the host away from every file but its own.
    /// Always true where the site would not have been allowed online
    /// otherwise; on Android, whose oldest systems cannot confine files,
    /// false says the host is confined in every other way only.
    pub files_confined: bool,
}

/// A site that is online. Its host keeps Tor's bookkeeping readable only
/// while it runs: it unpacks it on start and packs it away and erases the
/// readable copy when it stops. The editor never reads the host's folder,
/// so nothing a compromised host puts there can lead the editor anywhere.
struct Hosted {
    host: Option<Host>,
    files_confined: bool,
}

impl Hosted {
    /// Stops the host the orderly way, so that it tidies up first.
    async fn retire(mut self) {
        if let Some(host) = self.host.take() {
            host.stop().await;
        }
    }
}

/// The shortest passphrase a vault may be made with.
const MIN_PASSPHRASE: usize = 10;

/// A search for an onion address that begins with chosen letters.
struct Mining {
    site: u32,
    /// Searched for in the decoy compartment: never shown in the other.
    decoy: bool,
    prefixes: Vec<torus_onion_key::Prefix>,
    stop: Arc<AtomicBool>,
    tried: Arc<AtomicU64>,
    found: Arc<Mutex<Option<Identity>>>,
    started: Instant,
    threads: usize,
}

impl Drop for Mining {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// How a search for an address is going, for the window.
#[derive(Debug, Serialize)]
pub struct MineStatus {
    pub site: u32,
    pub prefix: String,
    pub tried: u64,
    pub per_second: f64,
    /// How many keys it takes on average to find a match.
    pub expected: f64,
    pub threads: usize,
    /// The address found, once one has been.
    pub found: Option<String>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Hosted>>>;

/// Saves the wallet into the open vault.
fn keep_money(session: Arc<Mutex<Option<Session>>>) -> crate::money::Keep {
    Arc::new(move |stored| {
        let mut session = session.lock().unwrap_or_else(|e| e.into_inner());
        let session = session.as_mut().ok_or("The vault is locked.")?;
        session.money = Some(stored);
        session.persist().map_err(|e| e.message)
    })
}

/// Starts the relay: a sandboxed host that reaches the node through Tor
/// and is told nothing secret. Its folder is the open compartment's.
fn reach_node(tor_dir: &Path, host_program: &Path, prefix: &str, decoy: Arc<AtomicBool>) -> crate::money::Reach {
    let (tor_dir, program, container) = (tor_dir.to_owned(), host_program.to_owned(), format!("{prefix}-relay"));
    Arc::new(move |node, tor_key| {
        let decoy = decoy.load(Ordering::Relaxed);
        let sites = if decoy { tor_dir.with_file_name("alt-sites") } else { tor_dir.clone() };
        let (program, container) = (program.clone(), if decoy { format!("{container}-alt") } else { container.clone() });
        Box::pin(async move {
            if !torus_host_api::sandbox_available() {
                return Err("This system cannot confine the program that faces the network, so the wallet cannot reach a node here.".to_owned());
            }
            let dir = sites.join("relay");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let target = Target::Relay {
                node,
                state_dir: dir.join("state"),
                cache_dir: dir.join("cache"),
                kept: Some(dir.join("tor-state.bin")),
                kept_key: tor_key.to_vec(),
            };
            let sandbox = Sandbox { name: &container, folder: &dir };
            let host = Arc::new(Host::start(&program, Some(sandbox), None, target, decoy_site(), None).await?);
            Ok(torus_wallet::transport::Fetcher::new(move |route, body, limit| {
                let host = host.clone();
                async move { host.fetch(&route, body, limit).await }
            }))
        })
    })
}

pub struct Backend {
    /// Holds the vault file, and the encrypted copies of Tor's bookkeeping.
    data_dir: PathBuf,
    /// Holds each site's folder where the system has no sandbox folders of its own.
    tor_dir: PathBuf,
    host_program: PathBuf,
    /// Sandboxes are named after this plus the site's number.
    sandbox_prefix: String,
    session: Arc<Mutex<Option<Session>>>,
    /// Which compartment is open: false is the main one, true the decoy.
    /// It decides which vault file and which site folders are in use.
    decoy: Arc<AtomicBool>,
    /// The open compartment's Monero wallet.
    treasury: Arc<Treasury>,
    /// The local test server, and the site it serves.
    local: tokio::sync::Mutex<Option<(u32, Host)>>,
    /// One slot per site, each locked on its own: starting one site, which
    /// can take minutes, holds up nothing done with another.
    hosted: Mutex<HashMap<u32, Slot>>,
    /// The search for a chosen address, if one is under way or done.
    mining: Mutex<Option<Mining>>,
}

/// Ends a host that runs inside this program when the site is taken offline.
#[cfg(test)]
struct Inline(tokio::task::JoinHandle<i32>);

#[cfg(test)]
impl Drop for Inline {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts a host inside this program, speaking to it over in-memory pipes
/// exactly as it would be spoken to over a program's input and output.
#[cfg(test)]
async fn start_inline(target: Target, site: Site, records: Option<Records>) -> Result<Host, String> {
    let (to_host, host_input) = tokio::io::duplex(1 << 20);
    let (host_output, from_host) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(torus_host::run(host_input, host_output));
    Host::over(Box::new(to_host), Box::new(from_host), Box::new(Inline(task)), target, site, records).await
}

/// The program that converts videos, where this copy of the app has one:
/// beside the host program (on Android, among the app's native libraries),
/// or while developing in the project's tools.
fn converter_program(host_program: &Path) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "ffmpeg.exe"
    } else if cfg!(target_os = "android") {
        "libffmpeg.so"
    } else {
        "ffmpeg"
    };
    let beside = host_program.with_file_name(name);
    let developing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/ffmpeg").join(name);
    let developing_linux = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/ffmpeg/linux").join(name);
    [beside, developing, developing_linux]
        .into_iter()
        .find(|path| cfg!(debug_assertions) || path.parent() == host_program.parent())
        .filter(|path| path.is_file())
}

impl Backend {
    /// Starts a host for a site: a confined program of its own.
    async fn start_host(
        &self,
        sandbox: Option<Sandbox<'_>>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Host, String> {
        let converter = converter_program(&self.host_program);
        Host::start(&self.host_program, sandbox, converter.as_deref(), target, site, records).await
    }

    /// Answers a site's questions to the wallet: those of site `id` only.
    fn banker(&self, id: u32) -> torus_host_api::Banker {
        let treasury = self.treasury.clone();
        Arc::new(move |ask| {
            let treasury = treasury.clone();
            Box::pin(async move { treasury.ask(id, ask).await })
        })
    }

    pub fn new(data_dir: PathBuf, tor_dir: PathBuf, host_program: PathBuf) -> Self {
        // Only this user may look inside, wherever the folder was put.
        if std::fs::create_dir_all(&data_dir).is_ok() {
            let _ = torus_host_api::make_private(&data_dir);
        }
        let session: Arc<Mutex<Option<Session>>> = Arc::default();
        let decoy: Arc<AtomicBool> = Arc::default();
        let sandbox_prefix = "torus.site".to_owned();
        let treasury = Treasury::new(keep_money(session.clone()), reach_node(&tor_dir, &host_program, &sandbox_prefix, decoy.clone()));
        let backend = Self {
            data_dir,
            tor_dir,
            host_program,
            sandbox_prefix,
            session,
            decoy,
            treasury,
            local: Default::default(),
            hosted: Default::default(),
            mining: Mutex::new(None),
        };
        backend.erase_leftovers();
        backend
    }

    /// Erases readable Tor bookkeeping a previous run could not tidy away,
    /// because it was killed or the device lost power. What it had packed
    /// away last is still in its encrypted copy.
    fn erase_leftovers(&self) {
        let roots = [self.tor_dir.clone(), self.alt_sites_dir()];
        let folders: Vec<PathBuf> = roots
            .iter()
            .flat_map(|root| std::fs::read_dir(root).into_iter().flatten().flatten())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("site-"))
            .map(|entry| entry.path())
            .collect();
        for site in folders {
            let _ = folder::erase(&site.join("state"));
            let _ = folder::erase(&site.join("cache"));
        }
    }

    /// Whether the decoy compartment is the one open now.
    fn is_decoy(&self) -> bool {
        self.decoy.load(Ordering::Relaxed)
    }

    /// The main vault file, which a confined host must never be able to read.
    fn vault_path(&self) -> Result<PathBuf, Failure> {
        std::fs::create_dir_all(&self.data_dir).map_err(Failure::new)?;
        Ok(self.data_dir.join("project.vault"))
    }

    /// The decoy vault file. It always exists: on a fresh install it holds
    /// random bytes under a passphrase nobody knows, so the file never shows
    /// whether a decoy passphrase has been set.
    fn alt_vault_path(&self) -> PathBuf {
        self.data_dir.join("alt.vault")
    }

    /// The vault file for the compartment open now.
    fn active_vault_path(&self) -> Result<PathBuf, Failure> {
        Ok(if self.is_decoy() { self.alt_vault_path() } else { self.vault_path()? })
    }

    /// Where the open compartment keeps its sites. The decoy's are kept
    /// apart from the main ones, so the two never touch.
    fn sites_dir(&self) -> PathBuf {
        if self.is_decoy() { self.alt_sites_dir() } else { self.tor_dir.clone() }
    }

    fn alt_sites_dir(&self) -> PathBuf {
        self.tor_dir.with_file_name("alt-sites")
    }

    /// Where a site's Tor bookkeeping is kept encrypted between runs: in
    /// the site's own folder, where its host reads and writes it.
    fn kept_tor_path(&self, id: u32) -> Result<PathBuf, Failure> {
        let kept = self.site_dir(id)?.join("tor-state.bin");
        // Copies made by the first release, which packed them here itself.
        let earlier = self.data_dir.join("tor").join(format!("site-{id}.bin"));
        if earlier.is_file() && !kept.exists() {
            std::fs::create_dir_all(self.site_dir(id)?).map_err(Failure::new)?;
            std::fs::rename(&earlier, &kept).map_err(Failure::new)?;
        }
        Ok(kept)
    }

    fn with_session<T>(&self, f: impl FnOnce(&mut Session) -> Result<T, Failure>) -> Result<T, Failure> {
        f(self.session.lock().unwrap_or_else(|e| e.into_inner()).as_mut().ok_or_else(|| Failure::new("The vault is locked."))?)
    }

    fn slot(&self, id: u32) -> Slot {
        self.hosted.lock().unwrap_or_else(|e| e.into_inner()).entry(id).or_default().clone()
    }

    /// The slot of a site that is online, if it is.
    fn existing_slot(&self, id: u32) -> Option<Slot> {
        self.hosted.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
    }

    pub fn vault_exists(&self) -> Result<bool, Failure> {
        Ok(self.vault_path()?.exists())
    }

    /// Writes a backup of the whole installation to `file`: the vault and
    /// every site's data, all as they sit on disk, already encrypted. Every
    /// site is taken offline first, so nothing is written while it is copied.
    pub async fn export_backup(&self, file: PathBuf) -> Result<(), Failure> {
        self.shutdown().await;
        let data_dir = self.data_dir.clone();
        // Streamed on a blocking thread: a backup can be many gigabytes.
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let out = std::fs::File::create(&file)?;
            torus_vault::backup::export(&data_dir, &mut std::io::BufWriter::new(out))?;
            Ok(())
        })
        .await
        .map_err(Failure::new)?
        .map_err(Failure::new)
    }

    /// Writes one site to `file`, sealed under a passphrase of its own, so it
    /// can be moved to another installation or kept apart. The design always
    /// goes; what visitors added, and the onion address, only if asked. With
    /// its content the site is taken offline first, so nothing changes while
    /// it is copied.
    pub async fn export_site(
        &self,
        id: u32,
        file: PathBuf,
        passphrase: String,
        content: bool,
        address: bool,
    ) -> Result<(), Failure> {
        let passphrase = Zeroizing::new(passphrase);
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(Failure::new(format!("Use a passphrase of at least {MIN_PASSPHRASE} characters.")));
        }
        if content {
            self.stop(id).await;
        }
        let exported = self.with_session(|session| {
            let entry = session.entry(id)?;
            Ok(Exported {
                site: entry.site.clone(),
                identity: if address { entry.identity.as_ref().map(|key| key.to_vec()) } else { None },
                records_key: if content { entry.records_key.as_ref().map(|key| key.to_vec()) } else { None },
                seal_secret: if content { entry.seal_secret.as_ref().map(|key| key.to_vec()) } else { None },
                content: content && entry.records_key.is_some(),
            })
        })?;
        let dir = self.site_dir(id)?;
        tokio::task::spawn_blocking(move || -> Result<(), Failure> {
            let mut header = Zeroizing::new(serde_json::to_vec(&exported).map_err(Failure::new)?);
            torus_vault::pad_json(&mut header);
            let sealed = torus_vault::seal(&passphrase, &header).map_err(Failure::new)?;
            let written = (|| -> std::io::Result<()> {
                let mut out = std::io::BufWriter::new(std::fs::File::create(&file)?);
                out.write_all(SITE_MAGIC)?;
                out.write_all(&(sealed.len() as u32).to_le_bytes())?;
                out.write_all(&sealed)?;
                if exported.content {
                    // Already encrypted with the site's own key, which is in the
                    // sealed part. Tor's bookkeeping stays: it is rebuilt.
                    torus_vault::backup::export_only(&dir, &mut out, &|rel| rel != "tor-state.bin")?;
                }
                out.flush()
            })();
            if written.is_err() {
                let _ = std::fs::remove_file(&file);
            }
            written.map_err(Failure::new)
        })
        .await
        .map_err(Failure::new)?
    }

    /// Adds a site exported with [`Backend::export_site`] as a new site here.
    pub async fn import_site(&self, file: PathBuf, passphrase: String) -> Result<Listed, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        self.with_session(|_| Ok(()))?;
        let mut input = std::io::BufReader::new(std::fs::File::open(&file).map_err(Failure::new)?);
        let (exported, input) = tokio::task::spawn_blocking(move || -> Result<_, Failure> {
            let not_one = || Failure::new("This is not a Torus site file.");
            let mut magic = [0u8; 8];
            input.read_exact(&mut magic).map_err(|_| not_one())?;
            let mut len = [0u8; 4];
            input.read_exact(&mut len).map_err(|_| not_one())?;
            let len = u32::from_le_bytes(len) as usize;
            if &magic != SITE_MAGIC || len > MAX_SITE_HEADER {
                return Err(not_one());
            }
            let mut sealed = vec![0u8; len];
            input.read_exact(&mut sealed).map_err(|_| not_one())?;
            let opened = torus_vault::unseal(&sealed, &passphrase).map_err(|e| match e {
                torus_vault::Error::Locked => Failure::new("Wrong passphrase for this site file, or the file is damaged."),
                _ => not_one(),
            })?;
            let exported: Exported = serde_json::from_slice(&opened).map_err(|_| not_one())?;
            Ok((exported, input))
        })
        .await
        .map_err(Failure::new)??;
        let identity = exported.identity.map(identity_from).transpose()?;
        let id = self.with_session(|session| {
            // One address, one site: two copies online would fight over it.
            if let Some(identity) = &identity {
                if session.sites.iter().any(|e| e.identity.as_ref().is_some_and(|k| **k == **identity)) {
                    return Err(Failure::new("A site here already has this address. Delete it first, or import without the address."));
                }
            }
            Ok(session.add(exported.site.clone()))
        })?;
        let dir = self.site_dir(id)?;
        let unpacked = if exported.content {
            let dir = dir.clone();
            let mut input = input;
            tokio::task::spawn_blocking(move || {
                let _ = folder::erase(&dir);
                torus_vault::backup::unpack(&dir, &mut input)
            })
            .await
            .map_err(Failure::new)?
            .map_err(|e| Failure::new(format!("The site's content could not be read: {e}")))
        } else {
            Ok(())
        };
        let added = unpacked.and_then(|()| {
            self.with_session(|session| {
                let entry = session.entry(id)?;
                entry.identity = identity;
                entry.records_key = exported.records_key.map(Zeroizing::new);
                entry.seal_secret = exported.seal_secret.map(Zeroizing::new);
                session.persist()?;
                Ok(session.listed().into_iter().find(|l| l.id == id).expect("just added"))
            })
        });
        if added.is_err() {
            let _ = self.with_session(|session| {
                session.sites.retain(|e| e.id != id);
                Ok(())
            });
            let _ = folder::erase(&dir);
        }
        added
    }

    /// Restores a backup into this installation. Refused unless there is no
    /// vault here yet, so a restore never writes over existing sites.
    pub fn import_backup(&self, file: PathBuf) -> Result<(), Failure> {
        if self.vault_exists()? {
            return Err(Failure::new("Lock or remove the vault here before restoring a backup over it."));
        }
        std::fs::create_dir_all(&self.data_dir).map_err(Failure::new)?;
        let _ = torus_host_api::make_private(&self.data_dir);
        let input = std::fs::File::open(&file).map_err(Failure::new)?;
        torus_vault::backup::import(&self.data_dir, &mut std::io::BufReader::new(input)).map_err(Failure::new)
    }

    /// Creates the vault with a first site. Never replaces an existing vault.
    pub fn create_vault(&self, passphrase: String, site: Site) -> Result<Vec<Listed>, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        // Checked here too, not only in the window: everything rests on it.
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(Failure::new(format!("Use a passphrase of at least {MIN_PASSPHRASE} characters.")));
        }
        let path = self.vault_path()?;
        if path.exists() {
            return Err(Failure::new("A vault already exists."));
        }
        let vault = Vault::create(&path, &passphrase, b"{}").map_err(Failure::new)?;
        // A decoy vault is made at the same moment, sealed under a random
        // passphrase nobody holds. It exists whether or not the owner ever
        // sets a decoy passphrase, so its presence reveals nothing.
        self.make_blank_alt()?;
        self.decoy.store(false, Ordering::Relaxed);
        let mut session = Session { vault, sites: Vec::new(), next_id: 1, auto_lock_minutes: 0, saved: Vec::new(), money: None };
        session.add(site);
        session.persist()?;
        let listed = session.listed();
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        // Every vault has its wallet from the start; it stays off the
        // network until a site uses it.
        self.treasury.unload();
        self.treasury.ensure().map_err(Failure::new)?;
        Ok(listed)
    }

    /// Writes the decoy vault as an unopenable blank: a random passphrase,
    /// empty contents. Used when an installation is created, and to clear a
    /// decoy passphrase the owner no longer wants.
    fn make_blank_alt(&self) -> Result<(), Failure> {
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(random.as_mut()).map_err(Failure::new)?;
        let pass = torus_seal::to_hex(random.as_ref());
        Vault::create(&self.alt_vault_path(), &pass, b"{}").map_err(Failure::new)?;
        let _ = folder::erase(&self.alt_sites_dir());
        Ok(())
    }

    pub fn unlock(&self, passphrase: String) -> Result<Vec<Listed>, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        // Both compartments are always tried, in the same order and at the
        // same cost, so the time taken never shows which one (if either)
        // the passphrase opened, nor whether a decoy passphrase exists.
        let main = Vault::open(&self.vault_path()?, &passphrase);
        let alt = Vault::open(&self.alt_vault_path(), &passphrase);
        let (decoy, opened) = match (main, alt) {
            (Ok(main), _) => (false, Ok(main)),
            (Err(_), Ok(alt)) => (true, Ok(alt)),
            (Err(e), Err(_)) => (false, Err(e)),
        };
        let (mut vault, bytes) = opened.map_err(Failure::new)?;
        self.decoy.store(decoy, Ordering::Relaxed);
        let active = self.active_vault_path()?;
        // A vault made with weaker settings than today's is made again with them.
        if vault.weaker_than_default() {
            vault = Vault::create(&active, &passphrase, &bytes).map_err(Failure::new)?;
        }
        let mut payload: Payload = serde_json::from_slice(&bytes).map_err(Failure::new)?;
        if let Some(site) = payload.site.take() {
            payload.sites.push(Stored {
                id: 1,
                site,
                identity: payload.identity.take(),
                records_key: None,
                seal_secret: None,
                tor_key: None,
            });
        }
        let mut sites = Vec::new();
        for stored in payload.sites {
            let identity = stored.identity.map(identity_from).transpose()?;
            sites.push(Entry {
                id: stored.id,
                site: stored.site,
                identity,
                records_key: stored.records_key.map(Zeroizing::new),
                seal_secret: stored.seal_secret.map(Zeroizing::new),
                tor_key: stored.tor_key.map(Zeroizing::new),
            });
        }
        let next_id = sites.iter().map(|e| e.id + 1).max().unwrap_or(1).max(payload.next_id);
        let saved = payload.saved.into_iter().map(identity_from).collect::<Result<Vec<_>, _>>()?;
        let money = payload.money.take();
        if let Err(e) = self.treasury.load(money.as_ref()) {
            return Err(Failure::new(e));
        }
        let session = Session { vault, sites, next_id, auto_lock_minutes: payload.auto_lock_minutes, saved, money };
        let listed = session.listed();
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.treasury.ensure().map_err(Failure::new)?;
        Ok(listed)
    }

    /// Forgets the vault's key and everything decrypted with it.
    pub fn lock(&self) {
        self.treasury.unload();
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.decoy.store(false, Ordering::Relaxed);
    }

    /// Whether the compartment open now is the decoy one.
    pub fn in_decoy(&self) -> bool {
        self.is_decoy()
    }

    /// Sets the decoy passphrase: a second passphrase that opens a separate,
    /// empty installation instead of the real one. Only from the main
    /// compartment, and never the same as the main passphrase. An empty
    /// passphrase clears it, making the decoy an unopenable blank again.
    ///
    /// Setting it takes every site offline first, because it rewrites the
    /// decoy compartment's files.
    pub async fn set_decoy(&self, passphrase: String) -> Result<(), Failure> {
        if self.is_decoy() {
            return Err(Failure::new("The decoy passphrase can only be changed from your real passphrase."));
        }
        let passphrase = Zeroizing::new(passphrase);
        if passphrase.is_empty() {
            self.shutdown_hosts().await;
            return self.make_blank_alt();
        }
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(Failure::new(format!("Use a passphrase of at least {MIN_PASSPHRASE} characters.")));
        }
        // It must not open the real compartment, or the decoy would be no cover.
        if Vault::open(&self.vault_path()?, &passphrase).is_ok() {
            return Err(Failure::new("That is your real passphrase. The decoy must be different."));
        }
        self.shutdown_hosts().await;
        let alt = Vault::create(&self.alt_vault_path(), &passphrase, b"{}").map_err(Failure::new)?;
        // A blank install behind it: one empty starter site, so the decoy
        // looks like any new installation.
        let mut session = Session { vault: alt, sites: Vec::new(), next_id: 1, auto_lock_minutes: 0, saved: Vec::new(), money: None };
        session.add(crate::backend::decoy_site());
        let _ = folder::erase(&self.alt_sites_dir());
        session.persist()
    }

    pub fn save(&self, id: u32, site: Site) -> Result<(), Failure> {
        self.with_session(|session| {
            session.entry(id)?.site = site;
            session.persist()
        })
    }

    pub fn add_site(&self, site: Site) -> Result<u32, Failure> {
        self.with_session(|session| {
            let id = session.add(site);
            session.persist()?;
            Ok(id)
        })
    }

    /// Takes a site offline and erases it, including its onion key and Tor
    /// folder: the address is gone for good.
    pub async fn delete_site(&self, id: u32) -> Result<(), Failure> {
        self.with_session(|session| session.entry(id).map(|_| ()))?;
        self.stop(id).await;
        // Whatever the site and its users held becomes the owner's own.
        self.treasury.close_site(id).await.map_err(Failure::new)?;
        self.with_session(|session| {
            session.sites.retain(|e| e.id != id);
            session.persist()
        })?;
        let _ = std::fs::remove_file(self.kept_tor_path(id)?);
        if let Some(container) = self.container(id) {
            let converter = converter_program(&self.host_program);
            let mut programs = vec![self.host_program.as_path()];
            programs.extend(converter.as_deref());
            torus_host_api::remove_container(&container, &programs);
        }
        let _ = folder::erase(&self.site_dir(id)?);
        Ok(())
    }

    /// A ready-made site to start from.
    pub fn starter(&self, kind: &str) -> Result<Site, Failure> {
        torus_core::starters::by_name(kind).ok_or_else(|| Failure::new("There is no such starter."))
    }

    pub fn canvas(&self, site: &Site, slug: &str) -> View {
        View { canvas: render_canvas(site, slug), findings: lint(site) }
    }

    /// Gives the site a sealing secret if it lacks one, stores it, and
    /// returns the site with the matching public key filled in: the only
    /// part of the pair a host ever sees.
    fn with_seal_key(&self, id: u32, mut site: Site) -> Result<Site, Failure> {
        let public = self.with_session(|session| {
            let entry = session.entry(id)?;
            if entry.seal_secret.is_none() {
                entry.seal_secret = Some(torus_seal::new_secret().ok_or_else(|| Failure::new("No secure randomness."))?);
                session.persist()?;
            }
            let secret = session.entry(id)?.seal_secret.clone().expect("set above");
            torus_seal::public_key(&secret).ok_or_else(|| Failure::new("The stored sealing key is damaged."))
        })?;
        site.seal_key = Some(torus_seal::to_hex(&public));
        Ok(site)
    }

    /// Compiles the site and serves it on a port of this computer only.
    pub async fn publish_local(&self, id: u32, site: Site) -> Result<String, Failure> {
        let site = self.with_seal_key(id, site)?;
        checked(&site)?;
        let mut slot = self.local.lock().await;
        if let Some((_, host)) = slot.as_ref().filter(|(serving, host)| *serving == id && !host.status().broken) {
            host.publish(site).await.map_err(Failure::new)?;
            return Ok(host.address().to_owned());
        }
        // Another site's test server makes way.
        *slot = None;
        // Not confined: Windows blocks local connections into a sandbox, and
        // this server is never reachable from outside this computer. It
        // keeps nothing on disk.
        let host = self.start_host(None, Target::Loopback, site, None).await.map_err(Failure::new)?;
        host.answer_bank_with(self.banker(id));
        let address = host.address().to_owned();
        *slot = Some((id, host));
        Ok(address)
    }

    /// Gives the site an onion key, a record key and a key for its Tor
    /// bookkeeping if it lacks them, stores them, and returns them.
    #[allow(clippy::type_complexity)]
    fn secrets_for(&self, id: u32, site: Site) -> Result<(Identity, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), Failure> {
        self.with_session(|session| {
            let entry = session.entry(id)?;
            entry.site = site;
            if entry.identity.is_none() {
                entry.identity = Some(torus_onion_key::new_identity().map_err(Failure::new)?);
            }
            if entry.records_key.is_none() {
                entry.records_key = Some(random_key()?);
            }
            if entry.tor_key.is_none() {
                entry.tor_key = Some(random_key()?);
            }
            let secrets = (
                entry.identity.clone().expect("set above"),
                entry.records_key.clone().expect("set above"),
                entry.tor_key.clone().expect("set above"),
            );
            // Stored before they are ever used, so neither the address nor
            // what visitors submit can be lost.
            session.persist()?;
            Ok(secrets)
        })
    }

    /// The name of the sandbox a site's host process runs in. Each site
    /// gets its own, so sites are confined from one another as well as from
    /// the editor.
    fn container(&self, id: u32) -> Option<String> {
        torus_host_api::sandbox_available().then(|| format!("{}-{id}", self.sandbox_prefix))
    }

    /// The one folder a site's host may keep files in: Tor's bookkeeping
    /// and visitors' encrypted data. Inside this app's own folder, like
    /// everything else it keeps.
    fn site_dir(&self, id: u32) -> Result<PathBuf, Failure> {
        Ok(self.sites_dir().join(format!("site-{id}")))
    }

    /// Compiles a site and puts it on Tor in a host process of its own. A
    /// site's first publish creates its address; while it is online, later
    /// ones swap in the new pages.
    pub async fn publish_onion(&self, id: u32, site: Site) -> Result<String, Failure> {
        let site = self.with_seal_key(id, site)?;
        checked(&site)?;
        let slot = self.slot(id);
        let mut hosted = slot.lock().await;
        if let Some(host) = hosted.as_ref().and_then(|h| h.host.as_ref()).filter(|host| !host.status().broken) {
            host.publish(site.clone()).await.map_err(Failure::new)?;
            self.save(id, site)?;
            let identity = self.with_session(|session| Ok(session.entry(id)?.identity.clone()))?;
            return identity.map(|key| torus_onion_key::address(&key)).ok_or_else(|| Failure::new("The site has no address."));
        }
        if let Some(old) = hosted.take() {
            old.retire().await;
        }

        let Some(container) = self.container(id) else {
            return Err(Failure::new("This system cannot confine the program that faces the network, so sites are not put on Tor here."));
        };
        let (identity, records_key, tor_key) = self.secrets_for(id, site.clone())?;
        let dir = self.site_dir(id)?;
        std::fs::create_dir_all(&dir).map_err(Failure::new)?;
        let kept = self.kept_tor_path(id)?;
        let records = Records { file: dir.join("records.bin"), key: records_key.to_vec() };
        let target = Target::Onion {
            identity: identity.to_vec(),
            state_dir: dir.join("state"),
            cache_dir: dir.join("cache"),
            kept: Some(kept),
            kept_key: tor_key.to_vec(),
        };
        let host = self
            .start_host(Some(Sandbox { name: &container, folder: &dir }), target, site, Some(records))
            .await
            .map_err(Failure::new)?;
        // Its visitors reach the wallet, for this site's books only.
        host.answer_bank_with(self.banker(id));
        let mut online = Hosted { host: Some(host), files_confined: true };
        // Trust nothing: ask the running host to open the vault. If it can,
        // its files are not confined.
        let host = online.host.as_ref().expect("set above");
        let readable = host.can_read(&self.vault_path()?).await.map_err(Failure::new)?;
        if readable {
            // Android systems older than Landlock cannot confine files; the
            // host there is still confined in every other way, and what it
            // could read is encrypted. Anywhere else, the site goes offline.
            if !cfg!(target_os = "android") {
                online.retire().await;
                return Err(Failure::new(
                    "The sandbox check failed: the host process could read the vault. The site was not published.",
                ));
            }
            online.files_confined = false;
        }
        // The address shown is the one the key stands for, never what the
        // host says: a host that claims another is not trusted with the site.
        let address = torus_onion_key::address(&identity);
        if host.address() != address {
            online.retire().await;
            return Err(Failure::new("The host process reported a different address than the site's key. The site was not published."));
        }
        *hosted = Some(online);
        Ok(address)
    }

    /// The host serving a site, locked for the length of one question.
    async fn with_host<T>(
        &self,
        id: u32,
        missing: &str,
        ask: impl AsyncFnOnce(&Host) -> Result<T, String>,
    ) -> Result<T, Failure> {
        let slot = self.existing_slot(id).ok_or_else(|| Failure::new(missing))?;
        let hosted = slot.lock().await;
        let host = hosted.as_ref().and_then(|h| h.host.as_ref()).ok_or_else(|| Failure::new(missing))?;
        ask(host).await.map_err(Failure::new)
    }

    /// What visitors have added to a collection of a site that is online.
    pub async fn records(&self, id: u32, collection: String) -> Result<Vec<torus_core::Record>, Failure> {
        let mut records = self
            .with_host(id, "Publish the site to Tor to see what visitors have added.", async |host| host.records(&collection).await)
            .await?;
        // What was sealed is opened here, in the editor, with the secret
        // that never left the vault.
        let secret = self.with_session(|session| Ok(session.entry(id)?.seal_secret.clone()))?;
        for record in &mut records {
            let Some(sealed) = record.fields.get(torus_core::SEALED_FIELD) else { continue };
            let opened = secret
                .as_deref()
                .zip(torus_seal::from_hex(sealed))
                .and_then(|(secret, sealed)| torus_seal::open(secret, &sealed))
                .and_then(|plain| serde_json::from_slice(&plain).ok());
            record.fields = opened.unwrap_or_else(|| [("unreadable".to_owned(), "This could not be opened.".to_owned())].into());
        }
        Ok(records)
    }

    /// Removes a record for good, with its files and whatever belongs to it.
    pub async fn remove_record(&self, id: u32, collection: String, record: String) -> Result<bool, Failure> {
        let removed = self.with_host(id, "Publish the site to Tor first.", async |host| host.remove(&collection, &record).await).await?;
        // An account removed by the owner: what it held is the owner's.
        if removed && collection == torus_core::USERS {
            self.treasury.close_account(id, &record).map_err(Failure::new)?;
        }
        Ok(removed)
    }

    /// Lets everyone see a record that was waiting for approval.
    pub async fn approve_record(&self, id: u32, collection: String, record: String) -> Result<bool, Failure> {
        self.with_host(id, "Publish the site to Tor first.", async |host| host.approve(&collection, &record).await).await
    }

    /// The ids of the accounts that are moderators of a site that is online.
    pub async fn moderators(&self, id: u32) -> Result<Vec<String>, Failure> {
        self.with_host(id, "Publish the site to Tor first.", async |host| host.moderators().await).await
    }

    /// Makes an account a moderator, who may remove what others have added,
    /// or an ordinary account again.
    pub async fn set_moderator(&self, id: u32, account: String, on: bool) -> Result<Vec<String>, Failure> {
        self.with_host(id, "Publish the site to Tor first.", async |host| host.set_moderator(&account, on).await).await
    }

    /// The sites currently on Tor. A site still being started is left out.
    pub fn onion_status(&self) -> Vec<OnionStatus> {
        let slots: Vec<(u32, Slot)> =
            self.hosted.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(id, slot)| (*id, slot.clone())).collect();
        let mut all: Vec<OnionStatus> = slots
            .into_iter()
            .filter_map(|(id, slot)| {
                let hosted = slot.try_lock().ok()?;
                let online = hosted.as_ref()?;
                let status = online.host.as_ref()?.status();
                Some(OnionStatus { id, reachable: status.reachable, broken: status.broken, files_confined: online.files_confined })
            })
            .collect();
        all.sort_by_key(|status| status.id);
        all
    }

    /// Takes one site off Tor, and stops its local test server.
    pub async fn stop(&self, id: u32) {
        {
            let mut local = self.local.lock().await;
            if local.as_ref().is_some_and(|(serving, _)| *serving == id) {
                *local = None;
            }
        }
        let slot = self.hosted.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        if let Some(slot) = slot {
            let hosted = slot.lock().await.take();
            if let Some(hosted) = hosted {
                hosted.retire().await;
            }
        }
    }

    /// Starts searching for an address that begins with any of the words in
    /// `wanted` (separated by spaces or commas), for site `id`, on every
    /// processor but one. Replaces any search under way. The search goes on
    /// while the vault is locked; what it finds stays in memory only, until
    /// it is used or saved.
    pub fn mine_start(&self, id: u32, wanted: &str) -> Result<MineStatus, Failure> {
        let mut prefixes: Vec<torus_onion_key::Prefix> = Vec::new();
        for word in wanted.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
            let prefix = torus_onion_key::Prefix::new(word).map_err(|e| Failure::new(format!("\"{word}\": {e}")))?;
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
        if prefixes.is_empty() {
            return Err(Failure::new(torus_onion_key::BadPrefix::Empty));
        }
        if prefixes.len() > MAX_PREFIXES {
            return Err(Failure::new(format!("Search for at most {MAX_PREFIXES} beginnings at once.")));
        }
        self.with_session(|session| session.entry(id).map(|_| ()))?;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1)).max(1);
        let mining = Mining {
            site: id,
            decoy: self.is_decoy(),
            prefixes,
            stop: Arc::default(),
            tried: Arc::default(),
            found: Arc::default(),
            started: Instant::now(),
            threads,
        };
        for _ in 0..threads {
            let (prefixes, stop, tried, found) =
                (mining.prefixes.clone(), mining.stop.clone(), mining.tried.clone(), mining.found.clone());
            std::thread::spawn(move || {
                if let Some(identity) = torus_onion_key::mine_any(&prefixes, &stop, &tried) {
                    let mut slot = found.lock().unwrap_or_else(|e| e.into_inner());
                    if slot.is_none() {
                        *slot = Some(identity);
                    }
                    stop.store(true, Ordering::Relaxed);
                }
            });
        }
        *self.mining.lock().unwrap_or_else(|e| e.into_inner()) = Some(mining);
        self.mine_status().ok_or_else(|| Failure::new("The search could not start."))
    }

    /// How the search is going, if there is one in the compartment open now.
    /// Nothing at all while the vault is locked.
    pub fn mine_status(&self) -> Option<MineStatus> {
        self.with_session(|_| Ok(())).ok()?;
        let mining = self.mining.lock().unwrap_or_else(|e| e.into_inner());
        let mining = mining.as_ref().filter(|m| m.decoy == self.is_decoy())?;
        let tried = mining.tried.load(Ordering::Relaxed);
        let seconds = mining.started.elapsed().as_secs_f64().max(0.001);
        let found = mining.found.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(torus_onion_key::address);
        Some(MineStatus {
            site: mining.site,
            prefix: mining.prefixes.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "),
            tried,
            per_second: tried as f64 / seconds,
            expected: torus_onion_key::expected_tries_any(&mining.prefixes),
            threads: mining.threads,
            found,
        })
    }

    /// Stops the search, and forgets any address it found but was not used.
    pub fn mine_stop(&self) {
        let mut mining = self.mining.lock().unwrap_or_else(|e| e.into_inner());
        if mining.as_ref().is_some_and(|m| m.decoy == self.is_decoy()) {
            *mining = None;
        }
    }

    /// The address the search found for site `id`, taken out of the search.
    fn take_found(&self, id: Option<u32>) -> Result<Identity, Failure> {
        let mut mining = self.mining.lock().unwrap_or_else(|e| e.into_inner());
        let ours = mining.as_ref().filter(|m| m.decoy == self.is_decoy() && id.is_none_or(|id| m.site == id));
        let ours = ours.ok_or_else(|| Failure::new("No address has been found for this site."))?;
        let found = ours.found.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let found = found.ok_or_else(|| Failure::new("No address has been found yet."))?;
        *mining = None;
        Ok(found)
    }

    /// Whether site `id` is online now.
    async fn is_online(&self, id: u32) -> bool {
        match self.existing_slot(id) {
            Some(slot) => slot.lock().await.is_some(),
            None => false,
        }
    }

    /// Gives site `id` the key `identity`. The address it had before, if any,
    /// is kept among the saved addresses rather than lost.
    async fn give_address(&self, id: u32, identity: Identity, replace: bool) -> Result<String, Failure> {
        if self.is_online(id).await {
            return Err(Failure::new("Take the site offline first: it is online at its current address."));
        }
        let address = torus_onion_key::address(&identity);
        self.with_session(|session| {
            if session.sites.iter().any(|e| e.id != id && e.identity.as_ref().is_some_and(|k| **k == *identity)) {
                return Err(Failure::new("Another site here already has this address."));
            }
            let entry = session.entry(id)?;
            if entry.identity.is_some() && !replace {
                return Err(Failure::new("This site already has an address. Confirm that it should be replaced."));
            }
            let old = entry.identity.replace(identity.clone());
            session.saved.retain(|k| **k != *identity);
            if let Some(old) = old {
                session.keep(old);
            }
            session.persist()
        })?;
        // Tor's bookkeeping belonged to the old address.
        let _ = std::fs::remove_file(self.kept_tor_path(id)?);
        Ok(address)
    }

    /// Makes the address the search found site `id`'s own.
    pub async fn mine_use(&self, id: u32, replace: bool) -> Result<String, Failure> {
        if self.is_online(id).await {
            return Err(Failure::new("Take the site offline first: it is online at its current address."));
        }
        let has_one = self.with_session(|session| Ok(session.entry(id)?.identity.is_some()))?;
        if has_one && !replace {
            return Err(Failure::new("This site already has an address. Confirm that it should be replaced."));
        }
        let identity = self.take_found(Some(id))?;
        match self.give_address(id, identity.clone(), replace).await {
            Ok(address) => Ok(address),
            Err(error) => {
                // Not lost: kept for later instead.
                let _ = self.with_session(|session| {
                    session.keep(identity);
                    session.persist()
                });
                Err(error)
            }
        }
    }

    /// Keeps the address the search found among the saved addresses.
    pub fn mine_save(&self) -> Result<String, Failure> {
        self.with_session(|_| Ok(()))?;
        let identity = self.take_found(None)?;
        let address = torus_onion_key::address(&identity);
        self.with_session(|session| {
            session.keep(identity);
            session.persist()
        })?;
        Ok(address)
    }

    /// The saved addresses, none of which is a site's own.
    pub fn saved_addresses(&self) -> Result<Vec<String>, Failure> {
        self.with_session(|session| Ok(session.saved.iter().map(torus_onion_key::address).collect()))
    }

    fn saved_key(&self, address: &str) -> Result<Identity, Failure> {
        self.with_session(|session| {
            let all = session.saved.iter().chain(session.sites.iter().filter_map(|e| e.identity.as_ref()));
            all.into_iter()
                .find(|k| torus_onion_key::address(k) == address)
                .cloned()
                .ok_or_else(|| Failure::new("There is no such address here."))
        })
    }

    /// Makes a saved address site `id`'s own.
    pub async fn use_saved(&self, id: u32, address: String, replace: bool) -> Result<String, Failure> {
        let identity = self.with_session(|session| {
            session.saved.iter().find(|k| torus_onion_key::address(k) == address).cloned().ok_or_else(|| Failure::new("There is no such saved address."))
        })?;
        self.give_address(id, identity, replace).await
    }

    /// Forgets a saved address for good.
    pub fn forget_saved(&self, address: String) -> Result<(), Failure> {
        self.with_session(|session| {
            session.saved.retain(|k| torus_onion_key::address(k) != address);
            session.persist()
        })
    }

    /// Writes an address's key to `file`, sealed under a passphrase of its
    /// own: a saved address, or a site's. Whoever has the file and its
    /// passphrase can run a site at that address.
    pub async fn export_key(&self, address: String, file: PathBuf, passphrase: String) -> Result<(), Failure> {
        let passphrase = Zeroizing::new(passphrase);
        if passphrase.chars().count() < MIN_PASSPHRASE {
            return Err(Failure::new(format!("Use a passphrase of at least {MIN_PASSPHRASE} characters.")));
        }
        let identity = self.saved_key(&address)?;
        tokio::task::spawn_blocking(move || -> Result<(), Failure> {
            let mut inner = Zeroizing::new(identity.to_vec());
            inner.resize(KEY_FILE_PADDING, 0);
            let sealed = torus_vault::seal(&passphrase, &inner).map_err(Failure::new)?;
            std::fs::write(&file, [&KEY_MAGIC[..], &sealed].concat()).map_err(Failure::new)
        })
        .await
        .map_err(Failure::new)?
    }

    /// Adds the key in a file written by [`Backend::export_key`] to the
    /// saved addresses, and says which address it is.
    pub async fn import_key(&self, file: PathBuf, passphrase: String) -> Result<String, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        self.with_session(|_| Ok(()))?;
        let bytes = std::fs::read(&file).map_err(Failure::new)?;
        let identity = tokio::task::spawn_blocking(move || -> Result<Identity, Failure> {
            let not_one = || Failure::new("This is not a Torus address file.");
            let sealed = bytes.strip_prefix(&KEY_MAGIC[..]).ok_or_else(not_one)?;
            let inner = torus_vault::unseal(sealed, &passphrase).map_err(|e| match e {
                torus_vault::Error::Locked => Failure::new("Wrong passphrase for this address file, or the file is damaged."),
                _ => not_one(),
            })?;
            if inner.len() != KEY_FILE_PADDING || inner[64..].iter().any(|&b| b != 0) {
                return Err(not_one());
            }
            identity_from(inner[..64].to_vec())
        })
        .await
        .map_err(Failure::new)??;
        let address = torus_onion_key::address(&identity);
        self.with_session(|session| {
            session.keep(identity);
            session.persist()
        })?;
        Ok(address)
    }

    /// How many idle minutes before the vault locks itself; 0 never.
    pub async fn wallet(&self) -> Result<Option<crate::money::Summary>, Failure> {
        self.with_session(|_| Ok(()))?;
        Ok(self.treasury.summary().await)
    }

    pub async fn wallet_node(&self, node: String) -> Result<(), Failure> {
        self.treasury.set_node(node).await.map_err(Failure::new)
    }

    /// The wallet's secret keys, for restoring it elsewhere. Only with the
    /// passphrase typed again: whoever sees them has the coins.
    pub async fn wallet_keys(&self, passphrase: String) -> Result<crate::money::Restore, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        let path = self.active_vault_path()?;
        tokio::task::spawn_blocking(move || Vault::open(&path, &passphrase).map(|_| ()))
            .await
            .map_err(Failure::new)?
            .map_err(|_| Failure::new("That passphrase is not this vault's."))?;
        self.treasury.restore_keys().await.map_err(Failure::new)
    }

    fn amount(text: Option<String>) -> Result<Option<u64>, Failure> {
        match text.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            None => Ok(None),
            Some(text) => match torus_core::money::parse_xmr(text) {
                Some(amount) if amount > 0 => Ok(Some(amount)),
                _ => Err(Failure::new("That is not an amount of XMR, such as 0.05.")),
            },
        }
    }

    /// Sends from the owner's own account. Returns what was sent and the fee.
    pub async fn wallet_send(&self, address: String, amount: Option<String>) -> Result<(u64, u64), Failure> {
        let amount = Self::amount(amount)?;
        self.treasury.send_own(address, amount).await.map_err(Failure::new)
    }

    pub async fn wallet_limit(&self, id: u32, amount: String) -> Result<(), Failure> {
        let limit = match amount.trim() {
            "0" => 0,
            text => Self::amount(Some(text.to_owned()))?.ok_or_else(|| Failure::new("Give an amount of XMR, or 0 to allow no withdrawals."))?,
        };
        self.treasury.set_daily_limit(id, limit).await.map_err(Failure::new)
    }

    /// What a site and its users hold: deleting the site gives it to the owner.
    pub fn wallet_held_by(&self, id: u32) -> u64 {
        self.treasury.held_by(id)
    }

    pub fn auto_lock_minutes(&self) -> u32 {
        self.session.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map_or(0, |s| s.auto_lock_minutes)
    }

    /// Sets the idle time before the vault locks itself.
    pub fn set_auto_lock_minutes(&self, minutes: u32) -> Result<(), Failure> {
        self.with_session(|session| {
            session.auto_lock_minutes = minutes;
            session.persist()
        })
    }

    /// Takes every site offline, packs their bookkeeping away, and forgets
    /// the vault key: the panic action, before the window closes. Same work
    /// as [`shutdown`], named for what the window calls it.
    pub async fn panic(&self) {
        self.shutdown().await;
    }

    /// Takes every site offline and packs their Tor bookkeeping away. Called
    /// when the app closes.
    pub async fn shutdown(&self) {
        self.shutdown_hosts().await;
        self.lock();
    }

    /// Takes every site offline and stops the local server and any search,
    /// but keeps the vault unlocked.
    async fn shutdown_hosts(&self) {
        self.mine_stop();
        *self.local.lock().await = None;
        let ids: Vec<u32> = self.hosted.lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
        for id in ids {
            self.stop(id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use torus_core::{Align, Block, Page, Theme};

    fn site(title: &str, text: &str) -> Site {
        Site {
            title: title.into(),
            theme: Theme::default(),
        collections: vec![],
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
            pages: vec![Page {
                slug: "index".into(),
                title: "Home".into(),
                template: None,
            blocks: vec![Block::Text { text: text.into(), align: Align::Left }],
            }],
        }
    }

    fn backend_named(name: &str) -> (Backend, PathBuf) {
        backend(name)
    }

    fn backend(name: &str) -> (Backend, PathBuf) {
        let dir = std::env::temp_dir().join(format!("torus-backend-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The host program is built next to the test program's folder.
        let mut host = std::env::current_exe().unwrap();
        host.pop();
        host.pop();
        host.push(if cfg!(windows) { "torus-host.exe" } else { "torus-host" });
        (Backend::new(dir.join("data"), dir.join("tor"), host), dir)
    }

    async fn fetch(address: &str) -> std::io::Result<String> {
        let mut stream = tokio::net::TcpStream::connect(address.trim_start_matches("http://")).await?;
        let name = address.trim_start_matches("http://");
    stream.write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut out = String::new();
        stream.read_to_string(&mut out).await?;
        Ok(out)
    }

    #[test]
    fn sites_and_their_keys_survive_locking_and_unlocking() {
        let (first, dir) = backend("vault");
        assert!(!first.vault_exists().unwrap());
        assert!(first.save(1, site("x", "x")).is_err(), "saving must fail while locked");

        let listed = first.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();
        assert_eq!((listed.len(), listed[0].id, listed[0].address.is_none()), (1, 1, true));
        assert!(first.create_vault("another passphrase".into(), site("x", "x")).is_err(), "must not replace a vault");

        let second_id = first.add_site(site("Beta", "two")).unwrap();
        first.save(1, site("Alpha renamed", "one")).unwrap();
        let (key, records_key, _) = first.secrets_for(second_id, site("Beta", "two")).unwrap();
        let address = torus_onion_key::address(&key);

        // Nothing readable reaches the disk.
        let on_disk = std::fs::read(dir.join("data").join("project.vault")).unwrap();
        for secret in [b"Alpha".as_slice(), b"Beta".as_slice(), &key[..16]] {
            assert!(!on_disk.windows(secret.len()).any(|w| w == secret));
        }

        let (again, _) = backend("vault-reopen");
        let again = Backend::new(dir.join("data"), dir.join("tor"), again.host_program);
        assert!(again.unlock("wrong passphrase".into()).is_err());
        // Locked again, nothing can be read or changed until the passphrase is given.
        again.unlock("correct horse battery".into()).unwrap();
        again.lock();
        assert!(again.save(1, site("x", "x")).is_err() && again.add_site(site("x", "x")).is_err());
        let listed = again.unlock("correct horse battery".into()).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].site.title, "Alpha renamed");
        assert_eq!(listed[1].address.as_deref(), Some(address.as_str()));
        // The same key comes back, not a new one.
        let (same_key, same_records_key, _) = again.secrets_for(second_id, site("Beta", "two")).unwrap();
        assert_eq!((*same_key, &*same_records_key), (*key, &*records_key));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A deleted site's number is never given to a new site, so nothing it
    /// left behind can be mistaken for the new site's own.
    #[tokio::test]
    async fn site_numbers_are_never_reused() {
        let (backend, dir) = backend("numbers");
        backend.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();
        let second = backend.add_site(site("Beta", "two")).unwrap();
        backend.delete_site(second).await.unwrap();
        let third = backend.add_site(site("Gamma", "three")).unwrap();
        assert!(third > second, "number {second} was given out again");
        backend.lock();
        backend.unlock("correct horse battery".into()).unwrap();
        assert!(backend.add_site(site("Delta", "four")).unwrap() > third, "the count was lost on unlocking");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A site moves to another installation in a file of its own: with its
    /// content and address when asked, without them otherwise, and never
    /// twice with the same address.
    #[tokio::test]
    async fn a_site_is_exported_and_imported_with_what_was_chosen() {
        let (from, from_dir) = backend("export-from");
        from.create_vault("the first passphrase".into(), site("Shop", "goods")).unwrap();
        let id = from.add_site(site("Moving", "with me")).unwrap();
        let (identity, _, _) = from.secrets_for(id, site("Moving", "with me")).unwrap();
        let address = torus_onion_key::address(&identity);
        std::fs::create_dir_all(from.site_dir(id).unwrap().join("records.bin.files")).unwrap();
        std::fs::write(from.site_dir(id).unwrap().join("records.bin"), b"SEALED RECORDS").unwrap();
        std::fs::write(from.site_dir(id).unwrap().join("records.bin.files/abc"), b"SEALED FILE").unwrap();
        std::fs::write(from.site_dir(id).unwrap().join("tor-state.bin"), b"TOR").unwrap();

        let whole = from_dir.join("whole.torussite");
        let design = from_dir.join("design.torussite");
        assert!(from.export_site(id, whole.clone(), "short".into(), true, true).await.is_err(), "a weak passphrase is refused");
        from.export_site(id, whole.clone(), "the export passphrase".into(), true, true).await.unwrap();
        from.export_site(id, design.clone(), "the export passphrase".into(), false, false).await.unwrap();
        let bytes = std::fs::read(&whole).unwrap();
        assert!(!bytes.windows(6).any(|w| w == b"Moving"), "the design is sealed");

        let (to, to_dir) = backend("export-to");
        to.create_vault("another passphrase here".into(), site("Home", "mine")).unwrap();
        assert!(to.import_site(whole.clone(), "not the passphrase".into()).await.is_err());
        let moved = to.import_site(whole.clone(), "the export passphrase".into()).await.unwrap();
        assert_eq!(moved.site.title, "Moving");
        assert_eq!(moved.address.as_deref(), Some(address.as_str()), "the address came along");
        let dir = to.site_dir(moved.id).unwrap();
        assert_eq!(std::fs::read(dir.join("records.bin")).unwrap(), b"SEALED RECORDS");
        assert_eq!(std::fs::read(dir.join("records.bin.files/abc")).unwrap(), b"SEALED FILE");
        assert!(!dir.join("tor-state.bin").exists(), "Tor's bookkeeping is rebuilt, not carried");
        let (_, records_key, _) = to.secrets_for(moved.id, moved.site.clone()).unwrap();
        let (_, original_key, _) = from.secrets_for(id, site("Moving", "with me")).unwrap();
        assert_eq!(&*records_key, &*original_key, "the content can still be read");

        // The same address cannot be brought in twice.
        assert!(to.import_site(whole, "the export passphrase".into()).await.is_err());
        // The design alone: a new site with no address and nothing added.
        let copy = to.import_site(design, "the export passphrase".into()).await.unwrap();
        assert_eq!((copy.site.title.as_str(), copy.address), ("Moving", None));
        assert!(!to.site_dir(copy.id).unwrap().join("records.bin").exists());
        assert_eq!(to.unlock("another passphrase here".into()).unwrap().len(), 3, "both imports were kept");
        let _ = std::fs::remove_dir_all(from_dir);
        let _ = std::fs::remove_dir_all(to_dir);
    }

    /// A decoy passphrase opens a separate, empty installation; the real
    /// sites stay hidden behind the real passphrase; and the files never
    /// show whether a decoy passphrase has been set.
    #[tokio::test]
    async fn a_decoy_passphrase_opens_a_separate_installation() {
        let (backend, dir) = backend("decoy");
        backend.create_vault("the real passphrase here".into(), site("Secret", "hidden")).unwrap();
        backend.add_site(site("Also secret", "hidden too")).unwrap();
        // The decoy file exists from the start, before any decoy is set.
        assert!(dir.join("data/alt.vault").exists(), "no decoy vault was made");

        // A wrong passphrase opens nothing.
        assert!(backend.unlock("not either passphrase".into()).is_err());

        backend.set_decoy("the decoy passphrase ok".into()).await.unwrap();
        assert!(backend.set_decoy("the real passphrase here".into()).await.is_err(), "the decoy must differ from the real one");

        // The decoy passphrase opens a separate, nearly-empty installation.
        let decoy = backend.unlock("the decoy passphrase ok".into()).unwrap();
        assert!(backend.in_decoy());
        assert!(!decoy.iter().any(|s| s.site.title == "Secret"), "a real site showed in the decoy");
        backend.add_site(site("Decoy note", "nothing real")).unwrap();

        // The real passphrase still opens the real sites, untouched.
        let real = backend.unlock("the real passphrase here".into()).unwrap();
        assert!(!backend.in_decoy());
        assert!(real.iter().any(|s| s.site.title == "Secret") && real.iter().any(|s| s.site.title == "Also secret"));
        assert!(!real.iter().any(|s| s.site.title == "Decoy note"), "a decoy site leaked into the real compartment");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A chosen address is searched for, and becomes the site's only when
    /// asked, and an existing address is replaced only when that is confirmed.
    #[tokio::test]
    async fn a_mined_address_becomes_the_sites_own() {
        let (backend, dir) = backend("mine");
        backend.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();
        assert!(backend.mine_start(1, "ab1").is_err(), "1 cannot appear in an address");
        backend.mine_start(1, "ab").unwrap();
        let mut found = None;
        for _ in 0..200 {
            found = backend.mine_status().and_then(|status| status.found);
            if found.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let found = found.expect("a two-letter address is found in moments");
        assert!(found.starts_with("ab"));
        assert_eq!(backend.mine_use(1, false).await.unwrap(), found);
        let listed = backend.unlock("correct horse battery".into()).unwrap();
        assert_eq!(listed[0].address.as_deref(), Some(found.as_str()), "the vault keeps the chosen address");

        // A second search may not silently replace it.
        backend.mine_start(1, "cd").unwrap();
        for _ in 0..200 {
            if backend.mine_status().and_then(|status| status.found).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(backend.mine_use(1, false).await.is_err(), "the address was replaced without asking");
        assert!(backend.mine_use(1, true).await.unwrap().starts_with("cd"));
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn found_by_search(backend: &Backend) -> String {
        for _ in 0..400 {
            if let Some(found) = backend.mine_status().and_then(|status| status.found) {
                return found;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("nothing was found");
    }

    /// Found addresses are kept for later, survive locking, move between
    /// installations in sealed files, and are never shown to the other
    /// compartment. A replaced address is kept, not lost.
    #[tokio::test]
    async fn found_addresses_are_saved_exported_and_kept_apart() {
        let (backend, dir) = backend("saved");
        backend.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();
        backend.set_decoy("the decoy passphrase ok".into()).await.unwrap();

        // Any of several beginnings will do.
        backend.mine_start(1, "zz, ab q7").unwrap();
        assert_eq!(backend.mine_status().unwrap().prefix, "zz, ab, q7");
        let found = found_by_search(&backend).await;
        assert!(["zz", "ab", "q7"].iter().any(|p| found.starts_with(p)));
        assert_eq!(backend.mine_save().unwrap(), found);
        assert!(backend.mine_status().is_none(), "the search is done once saved");

        // A search running when the vault is locked is not shown to the decoy.
        backend.mine_start(1, "cd").unwrap();
        backend.lock();
        assert!(backend.mine_status().is_none(), "nothing shows while locked");
        backend.unlock("the decoy passphrase ok".into()).unwrap();
        assert!(backend.mine_status().is_none(), "the decoy saw the real compartment's search");
        assert!(backend.saved_addresses().unwrap().is_empty());
        backend.mine_stop();
        backend.unlock("correct horse battery".into()).unwrap();
        assert!(backend.mine_status().is_some(), "the decoy stopped the real search");
        backend.mine_stop();
        assert_eq!(backend.saved_addresses().unwrap(), vec![found.clone()], "saved addresses survive locking");

        // A saved address becomes a site's; replacing it keeps the old one.
        assert_eq!(backend.use_saved(1, found.clone(), false).await.unwrap(), found);
        assert!(backend.saved_addresses().unwrap().is_empty());
        let other = torus_onion_key::new_identity().unwrap();
        let other_address = torus_onion_key::address(&other);
        backend.with_session(|session| {
            session.keep(other.clone());
            Ok(())
        })
        .unwrap();
        assert!(backend.use_saved(1, other_address.clone(), false).await.is_err(), "replaced without asking");
        backend.use_saved(1, other_address.clone(), true).await.unwrap();
        assert_eq!(backend.saved_addresses().unwrap(), vec![found.clone()], "the replaced address was lost");

        // An address file opens only with its passphrase, anywhere.
        let file = dir.join("address.toruskey");
        assert!(backend.export_key(found.clone(), file.clone(), "short".into()).await.is_err());
        backend.export_key(found.clone(), file.clone(), "the file passphrase".into()).await.unwrap();
        let (elsewhere, elsewhere_dir) = backend_named("saved-elsewhere");
        elsewhere.create_vault("another passphrase here".into(), site("Beta", "two")).unwrap();
        assert!(elsewhere.import_key(file.clone(), "not the passphrase".into()).await.is_err());
        assert_eq!(elsewhere.import_key(file.clone(), "the file passphrase".into()).await.unwrap(), found);
        assert_eq!(elsewhere.saved_addresses().unwrap(), vec![found.clone()]);
        // Bringing it in twice keeps one copy.
        elsewhere.import_key(file, "the file passphrase".into()).await.unwrap();
        assert_eq!(elsewhere.saved_addresses().unwrap().len(), 1);

        backend.forget_saved(found).unwrap();
        assert!(backend.saved_addresses().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(elsewhere_dir);
    }

    /// Tor's bookkeeping left readable by a run that was killed is erased
    /// by the next start of the app, whether or not the site goes online.
    #[test]
    fn readable_leftovers_are_erased_on_start() {
        let (backend, dir) = backend("tor-folder");
        let state = dir.join("tor/site-1/state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("guards.json"), b"SECRET-GUARDS").unwrap();
        std::fs::write(dir.join("tor/site-1/records.bin"), b"encrypted, kept").unwrap();
        drop(backend);
        let again = Backend::new(dir.join("data"), dir.join("tor"), PathBuf::from("unused"));
        assert!(!state.exists(), "readable bookkeeping survived a restart");
        assert!(dir.join("tor/site-1/records.bin").exists(), "visitors' encrypted data was erased");
        drop(again);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn local_publishing_runs_in_a_host_process_and_stops_on_request() {
        let (backend, dir) = backend("local");
        backend.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();

        let address = backend.publish_local(1, site("Alpha", "first words")).await.unwrap();
        assert!(fetch(&address).await.unwrap().contains("first words"));

        // Publishing again keeps the address and swaps the pages.
        assert_eq!(backend.publish_local(1, site("Alpha", "second words")).await.unwrap(), address);
        let mut page = String::new();
        for _ in 0..50 {
            page = fetch(&address).await.unwrap();
            if page.contains("second words") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(page.contains("second words"));

        // A site with a publishing error is refused with the reasons.
        let mut broken = site("Alpha", "x");
        broken.pages[0].slug = "not-home".into();
        let failure = backend.publish_local(1, broken).await.unwrap_err();
        assert!(!failure.findings.is_empty());

        backend.stop(1).await;
        let mut gone = false;
        for _ in 0..50 {
            if fetch(&address).await.is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(gone, "the site was still served after being stopped");

        backend.delete_site(1).await.unwrap();
        assert!(backend.publish_onion(1, site("Alpha", "x")).await.is_err(), "a deleted site cannot be published");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Hosting inside this program, as on Android, behaves like hosting in
    /// a program of its own, and leaves nothing running when it is stopped.
    /// One request to a host on this computer, with what it answers.
    async fn exchange(address: &str, request: String) -> String {
        let name = address.trim_start_matches("http://");
        let mut stream = tokio::net::TcpStream::connect(name).await.unwrap();
        stream.write_all(request.replace("{host}", name).as_bytes()).await.unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        out
    }

    /// The relay reaches a real Monero node through Tor. Run inside this
    /// program: the sandbox is tested with sites. Set TORUS_TEST_NODE to
    /// choose the node.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "connects to the real Tor network and a public Monero node"]
    async fn the_relay_reaches_a_monero_node_through_tor() {
        let (_, dir) = backend("relay");
        let node = std::env::var("TORUS_TEST_NODE").unwrap_or_else(|_| "xmr-node.cakewallet.com:18081".into());
        let target = Target::Relay { node, state_dir: dir.join("state"), cache_dir: dir.join("cache"), kept: None, kept_key: Vec::new() };
        let host = Arc::new(start_inline(target, decoy_site(), None).await.unwrap());
        let fetcher = torus_wallet::transport::Fetcher::new(move |route, body, limit| {
            let host = host.clone();
            async move { host.fetch(&route, body, limit).await }
        });
        let daemon = torus_wallet::MoneroDaemon::new(fetcher).await.unwrap();
        let tip = torus_wallet::monero_wallet::interface::prelude::ProvidesBlockchainMeta::latest_block_number(&daemon).await.unwrap();
        println!("the chain is at block {tip}");
        assert!(tip > 3_000_000);
        // A new wallet reads a few blocks of the real chain.
        let mut wallet = torus_wallet::Wallet::new(torus_wallet::Keys::generate(), torus_wallet::State::unborn(torus_wallet::Chain::Mainnet));
        let found = wallet.sync(&daemon, 5).await.unwrap();
        assert!(found.is_empty());
        println!("read up to block {}", wallet.state.height());
    }

    #[tokio::test]
    async fn a_sites_visitors_reach_the_wallet_through_the_editor() {
        let mut shop = torus_core::starters::microblog();
        shop.title = "Shop".into();
        let host = start_inline(Target::Loopback, shop, None).await.unwrap();
        let asked: Arc<Mutex<Vec<torus_core::money::Ask>>> = Arc::default();
        let seen = asked.clone();
        host.answer_bank_with(Arc::new(move |ask| {
            seen.lock().unwrap().push(ask.clone());
            Box::pin(async move {
                match ask {
                    torus_core::money::Ask::Purse { .. } => torus_core::money::Told::Purse(torus_core::money::Purse {
                        address: "8pipedaddress".into(),
                        balance: 7 * torus_core::money::PER_XMR,
                        ..Default::default()
                    }),
                    torus_core::money::Ask::SiteAddress => torus_core::money::Told::SiteAddress(Some("8site".into())),
                    _ => torus_core::money::Told::Done,
                }
            })
        }));
        let address = host.address().to_owned();
        let body = "name=Ada&_password=correct+horse+battery";
        let joined = exchange(
            &address,
            format!(
                "POST /_account/signup HTTP/1.1\r\nHost: {{host}}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        let cookie = joined.lines().find_map(|l| l.strip_prefix("set-cookie: ")).and_then(|c| c.split(';').next()).unwrap().to_owned();
        let account = exchange(&address, format!("GET /account HTTP/1.1\r\nHost: {{host}}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n")).await;
        assert!(account.contains("<p class=\"balance\">7 XMR</p>"), "{account}");
        assert!(account.contains("8pipedaddress"));
        let users = host.records("users").await.unwrap();
        let asked = asked.lock().unwrap().clone();
        assert!(asked.contains(&torus_core::money::Ask::Purse { user: users[0].id.clone() }), "{asked:?}");
    }

    #[tokio::test]
    async fn real_publish_local_has_wallet_and_video_upload() {
        let (backend, dir) = backend("local-video");
        backend.create_vault("correct horse battery".into(), torus_core::starters::video_site()).unwrap();
        let address = backend.publish_local(1, torus_core::starters::video_site()).await.unwrap();
        let guest_account = exchange(&address, format!("GET /account HTTP/1.1\r\nHost: {{host}}\r\nConnection: close\r\n\r\n")).await;
        assert!(guest_account.contains("Sign in") && guest_account.contains("Create account"));
        let body = "name=Alice&_password=correct+horse+battery";
        let joined = exchange(
            &address,
            format!(
                "POST /_account/signup HTTP/1.1\r\nHost: {{host}}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        ).await;
        let cookie = joined.lines().find_map(|l| l.strip_prefix("set-cookie: ")).and_then(|c| c.split(';').next()).unwrap().to_owned();
        let member_account = exchange(&address, format!("GET /account HTTP/1.1\r\nHost: {{host}}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n")).await;
        assert!(member_account.contains("Your Monero"));
        let token = member_account.lines().find_map(|l| {
            if l.contains("name=\"_token\"") {
                let after = l.split("value=\"").nth(1)?;
                Some(after.split('"').next()?.to_owned())
            } else {
                None
            }
        }).unwrap();

        // Now test video upload to /_form/videos
        let boundary = "---------------------------1234567890123456789012345678";
        let mut body_bytes = Vec::new();
        let add_text = |b: &mut Vec<u8>, name: &str, val: &str| {
            b.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{val}\r\n").as_bytes());
        };
        add_text(&mut body_bytes, "_token", &token);
        add_text(&mut body_bytes, "_next", "/upload");
        add_text(&mut body_bytes, "title", "Test Video");
        add_text(&mut body_bytes, "description", "Test Description");
        
        body_bytes.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"video\"; filename=\"test.mp4\"\r\nContent-Type: video/mp4\r\n\r\n").as_bytes());
        let ftyp = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41\x00\x00\x00\x08mdat";
        body_bytes.extend_from_slice(ftyp);
        body_bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let name = address.trim_start_matches("http://");
        let mut stream = tokio::net::TcpStream::connect(name).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let head = format!("POST /_form/videos HTTP/1.1\r\nHost: {name}\r\nCookie: {cookie}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body_bytes.len());
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&body_bytes).await.unwrap();
        let mut res = String::new();
        use tokio::io::AsyncReadExt;
        stream.read_to_string(&mut res).await.unwrap();
        assert!(res.contains("303") || res.contains("200"), "Upload failed: {res}");
        backend.stop(1).await;
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_inline_host_serves_and_stops() {
        let host = start_inline(Target::Loopback, site("Inline", "served from inside"), None).await.unwrap();
        let address = host.address().to_owned();
        assert!(fetch(&address).await.unwrap().contains("served from inside"));
        host.publish(site("Inline", "published again")).await.unwrap();
        let mut page = String::new();
        for _ in 0..50 {
            page = fetch(&address).await.unwrap();
            if page.contains("published again") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(page.contains("published again"));
        assert!(host.records("nothing").await.unwrap().is_empty());

        drop(host);
        let mut gone = false;
        for _ in 0..50 {
            if fetch(&address).await.is_err() {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(gone, "the inline host kept serving after it was stopped");
    }

    /// The Publish button's whole path against the real Tor network: vault,
    /// key, sandboxed host process, sandbox self-check, Tor.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "connects to the real Tor network and takes a few minutes"]
    async fn publishing_to_tor_runs_sandboxed_and_reports_its_address() {
        let (mut backend, dir) = backend("onion");
        // A sandbox name of its own, so a real site is never touched.
        backend.sandbox_prefix = format!("torus.test-{}", std::process::id());
        let listed = backend.create_vault("correct horse battery".into(), site("Alpha", "one")).unwrap();
        let id = listed[0].id;

        let address = backend.publish_onion(id, site("Alpha", "published")).await.unwrap();
        println!("address: {address}");
        assert!(address.ends_with(".onion"));
        let (again, _) = super::tests::backend("onion-reopen");
        let again = Backend::new(dir.join("data"), dir.join("tor"), again.host_program);
        let relisted = again.unlock("correct horse battery".into()).unwrap();
        assert_eq!(relisted[0].address.as_deref(), Some(address.as_str()), "the vault holds a different address");

        // Publishing again while online keeps the address.
        assert_eq!(backend.publish_onion(id, site("Alpha", "published twice")).await.unwrap(), address);

        // Tor's own "reachable" report can stay off for a long time after a
        // site can in fact be visited (the host crate's live test visits
        // one), so only the host staying up is required here.
        for _ in 0..30 {
            let status = backend.onion_status();
            assert!(status.iter().any(|s| s.id == id) && status.iter().all(|s| !s.broken), "the host process stopped");
            if status.iter().any(|s| s.reachable) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        backend.stop(id).await;
        assert!(backend.onion_status().is_empty());
        backend.delete_site(id).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
