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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use torus_core::{check, lint, render_canvas, Canvas, Finding, Site};
use torus_host_api::{Host, Records, Sandbox, Target};
use torus_onion_key::Identity;
use torus_vault::{folder, Vault};
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
    // Vaults written before multiple sites existed held exactly one.
    #[serde(default, skip_serializing)]
    site: Option<Site>,
    #[serde(default, skip_serializing)]
    identity: Option<Vec<u8>>,
}

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
        let payload =
            Payload { sites, next_id: self.next_id, auto_lock_minutes: self.auto_lock_minutes, ..Payload::default() };
        let mut bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(Failure::new)?);
        // The vault's size says only roughly how much is in it.
        torus_vault::pad_json(&mut bytes);
        self.vault.save(&bytes).map_err(Failure::new)
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
    prefix: torus_onion_key::Prefix,
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

pub struct Backend {
    /// Holds the vault file, and the encrypted copies of Tor's bookkeeping.
    data_dir: PathBuf,
    /// Holds each site's folder where the system has no sandbox folders of its own.
    tor_dir: PathBuf,
    host_program: PathBuf,
    /// Sandboxes are named after this plus the site's number.
    sandbox_prefix: String,
    session: Mutex<Option<Session>>,
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
    [beside, developing].into_iter().find(|path| cfg!(debug_assertions) || path.parent() == host_program.parent()).filter(|path| path.is_file())
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
        let converter = sandbox.as_ref().and_then(|_| converter_program(&self.host_program));
        Host::start(&self.host_program, sandbox, converter.as_deref(), target, site, records).await
    }

    pub fn new(data_dir: PathBuf, tor_dir: PathBuf, host_program: PathBuf) -> Self {
        // Only this user may look inside, wherever the folder was put.
        if std::fs::create_dir_all(&data_dir).is_ok() {
            let _ = torus_host_api::make_private(&data_dir);
        }
        let backend = Self {
            data_dir,
            tor_dir,
            host_program,
            sandbox_prefix: "torus.site".into(),
            session: Mutex::new(None),
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
        let folders: Vec<PathBuf> = std::fs::read_dir(&self.tor_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("site-"))
            .map(|entry| entry.path())
            .collect();
        for site in folders {
            let _ = folder::erase(&site.join("state"));
            let _ = folder::erase(&site.join("cache"));
        }
    }

    fn vault_path(&self) -> Result<PathBuf, Failure> {
        std::fs::create_dir_all(&self.data_dir).map_err(Failure::new)?;
        Ok(self.data_dir.join("project.vault"))
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
        let mut session = Session { vault, sites: Vec::new(), next_id: 1, auto_lock_minutes: 0 };
        session.add(site);
        session.persist()?;
        let listed = session.listed();
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        Ok(listed)
    }

    pub fn unlock(&self, passphrase: String) -> Result<Vec<Listed>, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        let (mut vault, bytes) = Vault::open(&self.vault_path()?, &passphrase).map_err(Failure::new)?;
        // A vault made with weaker settings than today's is made again with them.
        if vault.weaker_than_default() {
            vault = Vault::create(&self.vault_path()?, &passphrase, &bytes).map_err(Failure::new)?;
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
        let session = Session { vault, sites, next_id, auto_lock_minutes: payload.auto_lock_minutes };
        let listed = session.listed();
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        Ok(listed)
    }

    /// Forgets the vault's key and everything decrypted with it.
    pub fn lock(&self) {
        *self.session.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
        Ok(self.tor_dir.join(format!("site-{id}")))
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
        self.with_host(id, "Publish the site to Tor first.", async |host| host.remove(&collection, &record).await).await
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

    /// Starts searching for an address that begins with `wanted`, for site
    /// `id`, on every processor but one. Replaces any search under way.
    pub fn mine_start(&self, id: u32, wanted: &str) -> Result<MineStatus, Failure> {
        let prefix = torus_onion_key::Prefix::new(wanted).map_err(Failure::new)?;
        self.with_session(|session| session.entry(id).map(|_| ()))?;
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get().saturating_sub(1)).max(1);
        let mining = Mining {
            site: id,
            prefix,
            stop: Arc::default(),
            tried: Arc::default(),
            found: Arc::default(),
            started: Instant::now(),
            threads,
        };
        for _ in 0..threads {
            let (prefix, stop, tried, found) =
                (mining.prefix.clone(), mining.stop.clone(), mining.tried.clone(), mining.found.clone());
            std::thread::spawn(move || {
                if let Some(identity) = torus_onion_key::mine(&prefix, &stop, &tried) {
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

    /// How the search is going, if there is one.
    pub fn mine_status(&self) -> Option<MineStatus> {
        let mining = self.mining.lock().unwrap_or_else(|e| e.into_inner());
        let mining = mining.as_ref()?;
        let tried = mining.tried.load(Ordering::Relaxed);
        let seconds = mining.started.elapsed().as_secs_f64().max(0.001);
        let found = mining.found.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(torus_onion_key::address);
        Some(MineStatus {
            site: mining.site,
            prefix: mining.prefix.as_str().to_owned(),
            tried,
            per_second: tried as f64 / seconds,
            expected: mining.prefix.expected_tries(),
            threads: mining.threads,
            found,
        })
    }

    /// Stops the search, and forgets any address it found but was not used.
    pub fn mine_stop(&self) {
        *self.mining.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Makes the address the search found the site's own. A site that has
    /// an address already loses it for good, so `replace` must say that is
    /// meant; a site that is online must be taken offline first.
    pub async fn mine_use(&self, id: u32, replace: bool) -> Result<String, Failure> {
        let online = match self.existing_slot(id) {
            Some(slot) => slot.lock().await.is_some(),
            None => false,
        };
        if online {
            return Err(Failure::new("Take the site offline first: it is online at its current address."));
        }
        let identity = {
            let mining = self.mining.lock().unwrap_or_else(|e| e.into_inner());
            let mining = mining.as_ref().filter(|m| m.site == id).ok_or_else(|| Failure::new("No address has been found for this site."))?;
            let found = mining.found.lock().unwrap_or_else(|e| e.into_inner());
            found.clone().ok_or_else(|| Failure::new("No address has been found yet."))?
        };
        let address = torus_onion_key::address(&identity);
        self.with_session(|session| {
            let entry = session.entry(id)?;
            if entry.identity.is_some() && !replace {
                return Err(Failure::new("This site already has an address. Confirm that it should be replaced."));
            }
            entry.identity = Some(identity);
            session.persist()
        })?;
        // Tor's bookkeeping belonged to the old address.
        let _ = std::fs::remove_file(self.kept_tor_path(id)?);
        self.mine_stop();
        Ok(address)
    }

    /// How many idle minutes before the vault locks itself; 0 never.
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
        self.mine_stop();
        *self.local.lock().await = None;
        let ids: Vec<u32> = self.hosted.lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
        for id in ids {
            self.stop(id).await;
        }
        self.lock();
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
