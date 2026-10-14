//! Everything the editor can do, with no window attached, so it can be
//! tested directly. The window's commands in `lib.rs` only forward here.
//!
//! This process holds the vault and never touches the network: each site
//! that is online runs in its own host process.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use torus_core::{check, lint, render_canvas, Canvas, Finding, Site};
use torus_host_api::{Host, Records, Target};
use torus_onion_key::Identity;
use torus_vault::Vault;
use zeroize::Zeroizing;

/// What the vault file holds once decrypted.
#[derive(Serialize, Deserialize, Default)]
struct Payload {
    #[serde(default)]
    sites: Vec<Stored>,
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
}

struct Entry {
    id: u32,
    site: Site,
    identity: Option<Identity>,
    records_key: Option<Zeroizing<Vec<u8>>>,
    seal_secret: Option<Zeroizing<Vec<u8>>>,
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
            })
            .collect();
        let bytes = Zeroizing::new(serde_json::to_vec(&Payload { sites, ..Payload::default() }).map_err(Failure::new)?);
        self.vault.save(&bytes).map_err(Failure::new)
    }

    fn entry(&mut self, id: u32) -> Result<&mut Entry, Failure> {
        self.sites.iter_mut().find(|e| e.id == id).ok_or_else(|| Failure::new("That site no longer exists."))
    }

    fn add(&mut self, site: Site) -> u32 {
        let id = self.sites.iter().map(|e| e.id + 1).max().unwrap_or(1);
        self.sites.push(Entry { id, site, identity: None, records_key: None, seal_secret: None });
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
}

pub struct Backend {
    /// Holds the vault file.
    data_dir: PathBuf,
    /// Holds Tor's bookkeeping, one folder per site.
    tor_dir: PathBuf,
    host_program: PathBuf,
    /// Sandboxes are named after this plus the site's number.
    sandbox_prefix: String,
    session: Mutex<Option<Session>>,
    // Both are held across the slow start of a host process, so that two
    // publishes cannot start the same site twice.
    local: tokio::sync::Mutex<Option<Host>>,
    hosted: tokio::sync::Mutex<HashMap<u32, Host>>,
}

/// Ends a host that runs inside this program when the site is taken offline.
#[cfg(any(target_os = "android", test))]
struct Inline(tokio::task::JoinHandle<i32>);

#[cfg(any(target_os = "android", test))]
impl Drop for Inline {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts a host inside this program, speaking to it over in-memory pipes
/// exactly as it would be spoken to over a program's input and output.
/// This is how sites are hosted where one program cannot start another.
#[cfg(any(target_os = "android", test))]
async fn start_inline(target: Target, site: Site, records: Option<Records>) -> Result<Host, String> {
    let (to_host, host_input) = tokio::io::duplex(1 << 20);
    let (host_output, from_host) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(torus_host::run(host_input, host_output));
    Host::over(Box::new(to_host), Box::new(from_host), Box::new(Inline(task)), target, site, records).await
}

/// The program that converts videos, where this copy of the app has one:
/// beside the host program, or while developing in the project's tools.
#[cfg(not(target_os = "android"))]
fn converter_program(host_program: &std::path::Path) -> Option<PathBuf> {
    let name = if cfg!(windows) { "ffmpeg.exe" } else { "ffmpeg" };
    let beside = host_program.with_file_name(name);
    let developing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/ffmpeg").join(name);
    [beside, developing].into_iter().find(|path| cfg!(debug_assertions) || path.parent() == host_program.parent()).filter(|path| path.is_file())
}

impl Backend {
    /// Starts a host for a site: a confined program of its own where the
    /// system allows that, and inside this program where it does not.
    #[cfg(not(target_os = "android"))]
    async fn start_host(
        &self,
        container: Option<&str>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Host, String> {
        let converter = converter_program(&self.host_program);
        Host::start(&self.host_program, container, converter.as_deref(), target, site, records).await
    }

    #[cfg(target_os = "android")]
    async fn start_host(
        &self,
        _container: Option<&str>,
        target: Target,
        site: Site,
        records: Option<Records>,
    ) -> Result<Host, String> {
        // Android confines every app to its own sandbox already, and offers
        // no way to run a second program inside it.
        let _ = &self.host_program;
        start_inline(target, site, records).await
    }

    pub fn new(data_dir: PathBuf, tor_dir: PathBuf, host_program: PathBuf) -> Self {
        Self {
            data_dir,
            tor_dir,
            host_program,
            sandbox_prefix: "torus.site".into(),
            session: Mutex::new(None),
            local: Default::default(),
            hosted: Default::default(),
        }
    }

    fn vault_path(&self) -> Result<PathBuf, Failure> {
        std::fs::create_dir_all(&self.data_dir).map_err(Failure::new)?;
        Ok(self.data_dir.join("project.vault"))
    }

    fn with_session<T>(&self, f: impl FnOnce(&mut Session) -> Result<T, Failure>) -> Result<T, Failure> {
        f(self.session.lock().unwrap().as_mut().ok_or_else(|| Failure::new("The vault is locked."))?)
    }

    pub fn vault_exists(&self) -> Result<bool, Failure> {
        Ok(self.vault_path()?.exists())
    }

    /// Creates the vault with a first site. Never replaces an existing vault.
    pub fn create_vault(&self, passphrase: String, site: Site) -> Result<Vec<Listed>, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        let path = self.vault_path()?;
        if path.exists() {
            return Err(Failure::new("A vault already exists."));
        }
        let vault = Vault::create(&path, &passphrase, b"{}").map_err(Failure::new)?;
        let mut session = Session { vault, sites: Vec::new() };
        session.add(site);
        session.persist()?;
        let listed = session.listed();
        *self.session.lock().unwrap() = Some(session);
        Ok(listed)
    }

    pub fn unlock(&self, passphrase: String) -> Result<Vec<Listed>, Failure> {
        let passphrase = Zeroizing::new(passphrase);
        let (vault, bytes) = Vault::open(&self.vault_path()?, &passphrase).map_err(Failure::new)?;
        let mut payload: Payload = serde_json::from_slice(&bytes).map_err(Failure::new)?;
        if let Some(site) = payload.site.take() {
            payload.sites.push(Stored { id: 1, site, identity: payload.identity.take(), records_key: None, seal_secret: None });
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
            });
        }
        let session = Session { vault, sites };
        let listed = session.listed();
        *self.session.lock().unwrap() = Some(session);
        Ok(listed)
    }

    /// Forgets the vault's key and everything decrypted with it.
    pub fn lock(&self) {
        *self.session.lock().unwrap() = None;
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
        self.hosted.lock().await.remove(&id);
        self.with_session(|session| {
            session.entry(id)?;
            session.sites.retain(|e| e.id != id);
            session.persist()
        })?;
        match self.container(id) {
            Some(container) => torus_host_api::remove_container(&container),
            None => {
                let _ = std::fs::remove_dir_all(self.tor_dir.join(format!("site-{id}")));
            }
        }
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
        if let Some(host) = slot.as_ref().filter(|host| !host.status().broken) {
            host.publish(site).await.map_err(Failure::new)?;
            return Ok(host.address().to_owned());
        }
        // Not confined: Windows blocks local connections into a sandbox, and
        // this server is never reachable from outside this computer.
        let host = self.start_host(None, Target::Loopback, site, None).await.map_err(Failure::new)?;
        let address = host.address().to_owned();
        *slot = Some(host);
        Ok(address)
    }

    /// Gives the site an onion key and a record key if it lacks them, stores
    /// them, and returns them.
    fn secrets_for(&self, id: u32, site: Site) -> Result<(Identity, Zeroizing<Vec<u8>>), Failure> {
        self.with_session(|session| {
            let entry = session.entry(id)?;
            entry.site = site;
            if entry.identity.is_none() {
                entry.identity = Some(torus_onion_key::new_identity().map_err(Failure::new)?);
            }
            if entry.records_key.is_none() {
                let mut key = Zeroizing::new(vec![0u8; 32]);
                getrandom::getrandom(&mut key).map_err(Failure::new)?;
                entry.records_key = Some(key);
            }
            let secrets = (entry.identity.clone().expect("set above"), entry.records_key.clone().expect("set above"));
            // Stored before they are ever used, so neither the address nor
            // what visitors submit can be lost.
            session.persist()?;
            Ok(secrets)
        })
    }

    /// The name of the sandbox a site's host process runs in, where the
    /// system has one. Each site gets its own, so sites are confined from
    /// one another as well as from the editor.
    fn container(&self, id: u32) -> Option<String> {
        torus_host_api::sandbox_available().then(|| format!("{}-{id}", self.sandbox_prefix))
    }

    /// Where Tor keeps its bookkeeping for a site: inside the site's sandbox
    /// folder where there is one, since that is all a confined host can reach.
    fn site_tor_dir(&self, id: u32) -> Result<PathBuf, Failure> {
        match self.container(id) {
            Some(container) => Ok(torus_host_api::container_folder(&container).map_err(Failure::new)?.join("tor")),
            None => Ok(self.tor_dir.join(format!("site-{id}"))),
        }
    }

    /// Compiles a site and puts it on Tor in a host process of its own. A
    /// site's first publish creates its address; while it is online, later
    /// ones swap in the new pages.
    pub async fn publish_onion(&self, id: u32, site: Site) -> Result<String, Failure> {
        let site = self.with_seal_key(id, site)?;
        checked(&site)?;
        let mut hosted = self.hosted.lock().await;
        if let Some(host) = hosted.get(&id).filter(|host| !host.status().broken) {
            host.publish(site.clone()).await.map_err(Failure::new)?;
            self.save(id, site)?;
            return Ok(host.address().to_owned());
        }
        hosted.remove(&id);

        let (identity, records_key) = self.secrets_for(id, site.clone())?;
        let dir = self.site_tor_dir(id)?;
        let (state_dir, cache_dir) = (dir.join("state"), dir.join("cache"));
        // Made here because a confined process cannot create them itself.
        std::fs::create_dir_all(&state_dir).map_err(Failure::new)?;
        std::fs::create_dir_all(&cache_dir).map_err(Failure::new)?;
        let container = self.container(id);
        let records = Records { file: dir.join("records.bin"), key: records_key.to_vec() };
        let target = Target::Onion { identity: identity.to_vec(), state_dir, cache_dir };
        let host =
            self.start_host(container.as_deref(), target, site, Some(records)).await.map_err(Failure::new)?;
        // Trust nothing: ask the running host to open the vault. If it can,
        // the sandbox is not holding and the site must not stay online.
        if container.is_some() && host.can_read(&self.vault_path()?).await.map_err(Failure::new)? {
            return Err(Failure::new("The sandbox check failed: the host process could read the vault. The site was not published."));
        }
        let address = host.address().to_owned();
        hosted.insert(id, host);
        Ok(address)
    }

    /// What visitors have added to a collection of a site that is online.
    pub async fn records(&self, id: u32, collection: String) -> Result<Vec<torus_core::Record>, Failure> {
        let hosted = self.hosted.lock().await;
        let host = hosted.get(&id).ok_or_else(|| Failure::new("Publish the site to Tor to see what visitors have added."))?;
        let mut records = host.records(&collection).await.map_err(Failure::new)?;
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
        let hosted = self.hosted.lock().await;
        let host = hosted.get(&id).ok_or_else(|| Failure::new("Publish the site to Tor first."))?;
        host.remove(&collection, &record).await.map_err(Failure::new)
    }

    /// Lets everyone see a record that was waiting for approval.
    pub async fn approve_record(&self, id: u32, collection: String, record: String) -> Result<bool, Failure> {
        let hosted = self.hosted.lock().await;
        let host = hosted.get(&id).ok_or_else(|| Failure::new("Publish the site to Tor first."))?;
        host.approve(&collection, &record).await.map_err(Failure::new)
    }

    /// The ids of the accounts that are moderators of a site that is online.
    pub async fn moderators(&self, id: u32) -> Result<Vec<String>, Failure> {
        let hosted = self.hosted.lock().await;
        let host = hosted.get(&id).ok_or_else(|| Failure::new("Publish the site to Tor first."))?;
        host.moderators().await.map_err(Failure::new)
    }

    /// Makes an account a moderator, who may remove what others have added,
    /// or an ordinary account again.
    pub async fn set_moderator(&self, id: u32, account: String, on: bool) -> Result<Vec<String>, Failure> {
        let hosted = self.hosted.lock().await;
        let host = hosted.get(&id).ok_or_else(|| Failure::new("Publish the site to Tor first."))?;
        host.set_moderator(&account, on).await.map_err(Failure::new)
    }

    /// The sites currently on Tor. Empty while a publish is still in progress.
    pub fn onion_status(&self) -> Vec<OnionStatus> {
        let Ok(hosted) = self.hosted.try_lock() else { return Vec::new() };
        hosted
            .iter()
            .map(|(id, host)| OnionStatus { id: *id, reachable: host.status().reachable, broken: host.status().broken })
            .collect()
    }

    /// Takes one site off Tor, and stops the local test server.
    pub async fn stop(&self, id: u32) {
        *self.local.lock().await = None;
        self.hosted.lock().await.remove(&id);
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
        stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await?;
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
        let (key, records_key) = first.secrets_for(second_id, site("Beta", "two")).unwrap();
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
        let (same_key, same_records_key) = again.secrets_for(second_id, site("Beta", "two")).unwrap();
        assert_eq!((*same_key, &*same_records_key), (*key, &*records_key));
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
