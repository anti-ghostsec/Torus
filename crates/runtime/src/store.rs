//! Everything visitors have added: records, accounts, sessions and files.
//!
//! It is kept in memory and, when the site has storage, written to disk
//! encrypted with a key that comes from the vault. Nothing is stored about
//! where a request came from, and no record carries a time.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use torus_core::{Data, Record, Site, Viewer, USERS, USER_NAME};
use zeroize::Zeroizing;

use crate::blobs::{self, Source, Staged, Target};

/// Beyond this, the oldest record of a collection makes room for the newest.
const MAX_RECORDS: usize = 5_000;
/// At most this many additions are accepted per minute across the site.
/// On Tor there is no visitor address to limit by, so the limit is shared.
const MAX_PER_MINUTE: u32 = 30;

const SESSION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_SESSIONS: usize = 20_000;
const NONCE_LEN: usize = 24;

/// Where and how a site's data is kept between runs.
pub struct Storage {
    /// The encrypted file holding records, accounts and sessions. Uploaded
    /// files go into a folder beside it.
    pub file: PathBuf,
    pub key: Zeroizing<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    TooFast,
    Storage,
    Full,
    NameTaken,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    user: String,
    /// Returned in every form served to this session.
    token: String,
    /// Seconds since 1970. Never shown to anyone.
    expires: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct FileInfo {
    pub content_type: String,
    pub size: u64,
}

/// What has been made from one uploaded video.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Made {
    /// A picture taken from it.
    #[serde(default)]
    still: Option<String>,
    /// Smaller copies: the pixels of the shorter side, and the file.
    #[serde(default)]
    sizes: Vec<(u32, String)>,
    /// Whether everything that was going to be made has been.
    #[serde(default)]
    done: bool,
}

/// What is written to disk.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// Per collection, oldest first.
    #[serde(default)]
    records: BTreeMap<String, Vec<Record>>,
    /// Account id to password hash.
    #[serde(default)]
    passwords: BTreeMap<String, String>,
    /// Hash of the session cookie to the session. The cookie itself is never stored.
    #[serde(default)]
    sessions: BTreeMap<String, Session>,
    #[serde(default)]
    files: BTreeMap<String, FileInfo>,
    /// The number the last record added was given.
    #[serde(default)]
    next_seq: u64,
    /// The accounts the site's owner has made moderators.
    #[serde(default)]
    moderators: BTreeSet<String>,
    /// Per uploaded video, what has been made from it.
    #[serde(default)]
    made: BTreeMap<String, Made>,
}

pub struct Store {
    state: State,
    storage: Option<Storage>,
    /// File contents, when there is no storage to put them in.
    memory: BTreeMap<String, Arc<Vec<u8>>>,
    window: Instant,
    in_window: u32,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut random = vec![0u8; bytes];
    getrandom::getrandom(&mut random).map_err(io::Error::other)?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

fn cookie_hash(cookie: &str) -> String {
    Sha256::digest(cookie.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

impl Store {
    /// Everything lives in memory only.
    pub fn volatile() -> Self {
        Self { state: State::default(), storage: None, memory: BTreeMap::new(), window: Instant::now(), in_window: 0 }
    }

    /// Loads what was stored before, or starts empty if nothing was.
    pub fn open(storage: Storage) -> io::Result<Self> {
        let state = match std::fs::read(&storage.file) {
            Ok(sealed) => {
                let damaged = || io::Error::new(io::ErrorKind::InvalidData, "the site's data is damaged or has a different key");
                if sealed.len() < NONCE_LEN {
                    return Err(damaged());
                }
                let (nonce, body) = sealed.split_at(NONCE_LEN);
                let plain = XChaCha20Poly1305::new(storage.key.as_ref().into())
                    .decrypt(XNonce::from_slice(nonce), body)
                    .map(Zeroizing::new)
                    .map_err(|_| damaged())?;
                serde_json::from_slice(&plain).map_err(|_| damaged())?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { state, storage: Some(storage), memory: BTreeMap::new(), window: Instant::now(), in_window: 0 })
    }

    /// Rewrites the data file. The old one stays intact until the new one is
    /// completely written.
    fn persist(&self) -> Result<(), Refused> {
        let Some(storage) = &self.storage else { return Ok(()) };
        let write = || -> io::Result<()> {
            let plain = Zeroizing::new(serde_json::to_vec(&self.state)?);
            let mut nonce = [0u8; NONCE_LEN];
            getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
            let mut sealed = nonce.to_vec();
            sealed.extend(
                XChaCha20Poly1305::new(storage.key.as_ref().into())
                    .encrypt(XNonce::from_slice(&nonce), plain.as_slice())
                    .map_err(|_| io::Error::other("could not encrypt the site's data"))?,
            );
            let mut temp = storage.file.clone().into_os_string();
            temp.push(".new");
            std::fs::write(&temp, sealed)?;
            std::fs::rename(&temp, &storage.file)
        };
        write().map_err(|_| Refused::Storage)
    }

    /// Counts one addition against the shared limit.
    pub(crate) fn allow(&mut self) -> Result<(), Refused> {
        if self.window.elapsed() >= Duration::from_secs(60) {
            self.window = Instant::now();
            self.in_window = 0;
        }
        if self.in_window >= MAX_PER_MINUTE {
            return Err(Refused::TooFast);
        }
        self.in_window += 1;
        Ok(())
    }

    // Records

    pub(crate) fn add(&mut self, site: &Site, collection: &str, mut record: Record) -> Result<String, Refused> {
        // Random, so that neither the order nor the number of records can be
        // read off an id, and record pages cannot be found by counting.
        record.id = blobs::random_id().map_err(|_| Refused::Storage)?;
        self.state.next_seq += 1;
        record.seq = self.state.next_seq;
        let id = record.id.clone();
        let list = self.state.records.entry(collection.to_owned()).or_default();
        list.push(record);
        // The oldest makes room, and takes its files and whatever belongs to
        // it along, so nothing is left behind that no page can reach.
        let oldest = (list.len() > MAX_RECORDS).then(|| list[0].id.clone());
        if let Some(oldest) = oldest {
            self.remove(site, collection, &oldest);
        }
        self.persist()?;
        Ok(id)
    }

    /// Removes a record and everything that hangs on it: its files, the
    /// records that belong to it, and for an account its password, sessions
    /// and everything it added. Returns whether there was such a record.
    pub(crate) fn remove(&mut self, site: &Site, collection: &str, id: &str) -> bool {
        let mut doomed = vec![(collection.to_owned(), id.to_owned())];
        let mut found = false;
        while let Some((collection, id)) = doomed.pop() {
            let Some(list) = self.state.records.get_mut(&collection) else { continue };
            let Some(at) = list.iter().position(|r| r.id == id) else { continue };
            let record = list.remove(at);
            found = true;
            if let Some(shape) = site.collection(&collection) {
                for field in shape.fields.iter().filter(|f| f.kind.is_file()) {
                    // Only what this server stored itself is ever deleted.
                    // A field's value is not proof of that: if a text field
                    // was later turned into a file field, its old values are
                    // whatever visitors typed, and must never name a file.
                    let Some(file) = record.fields.get(&field.name) else { continue };
                    self.drop_file(file);
                }
            }
            for other in &site.collections {
                let hangs_on = |r: &&Record| {
                    (other.parent.as_deref() == Some(collection.as_str()) && r.parent.as_deref() == Some(id.as_str()))
                        || (collection == USERS && r.owner.as_deref() == Some(id.as_str()))
                };
                let more = self.state.records.get(&other.name).into_iter().flatten().filter(hangs_on);
                doomed.extend(more.map(|r| (other.name.clone(), r.id.clone())));
            }
            if collection == USERS {
                self.state.moderators.remove(&id);
                self.state.passwords.remove(&id);
                self.state.sessions.retain(|_, s| s.user != id);
            }
        }
        if found {
            let _ = self.persist();
        }
        found
    }

    /// Deletes a file this server stored, and whatever was made from it.
    fn drop_file(&mut self, file: &str) {
        let made = self.state.made.remove(file).unwrap_or_default();
        let target = self.file_target();
        for file in made.still.iter().chain(made.sizes.iter().map(|(_, file)| file)).map(String::as_str).chain([file]) {
            if self.state.files.remove(file).is_some() {
                self.memory.remove(file);
                blobs::discard(&target, file);
            }
        }
    }

    // What is made from videos

    /// The uploaded videos nothing has been made from yet.
    pub(crate) fn unconverted(&self) -> Vec<String> {
        let copies: BTreeSet<&String> = self.state.made.values().flat_map(|m| m.sizes.iter().map(|(_, file)| file)).collect();
        let waiting = |(file, info): (&String, &FileInfo)| {
            let video = info.content_type.starts_with("video/") && !copies.contains(file);
            (video && !self.state.made.get(file).is_some_and(|m| m.done)).then(|| file.clone())
        };
        self.state.files.iter().filter_map(waiting).collect()
    }

    /// Keeps a file made from a video, unless the video has gone meanwhile
    /// or there is no room, in which case the file is deleted again.
    fn keep_made(&mut self, site: &Site, video: &str, staged: Staged, content_type: &str, place: impl FnOnce(&mut Made, String)) -> bool {
        if !self.state.files.contains_key(video) || !self.has_room_for(site, staged.size) {
            blobs::discard(&self.file_target(), &staged.id);
            return false;
        }
        let id = staged.id.clone();
        self.keep_file(staged, content_type);
        place(self.state.made.entry(video.to_owned()).or_default(), id);
        self.persist().is_ok()
    }

    pub(crate) fn keep_still(&mut self, site: &Site, video: &str, staged: Staged) -> bool {
        self.keep_made(site, video, staged, "image/jpeg", |made, file| made.still = Some(file))
    }

    pub(crate) fn keep_size(&mut self, site: &Site, video: &str, pixels: u32, staged: Staged) -> bool {
        self.keep_made(site, video, staged, "video/webm", |made, file| {
            made.sizes.push((pixels, file));
            made.sizes.sort();
        })
    }

    /// Puts a smaller encoding of a video in the upload's place and deletes
    /// the upload. Returns the file the video is now.
    pub(crate) fn replace_video(&mut self, site: &Site, video: &str, staged: Staged) -> Option<String> {
        if !self.state.files.contains_key(video) {
            blobs::discard(&self.file_target(), &staged.id);
            return None;
        }
        let new = staged.id.clone();
        self.keep_file(staged, "video/webm");
        // Only fields that hold files are rewritten: text that happens to
        // spell a file's name stays what its author typed.
        for shape in &site.collections {
            let Some(records) = self.state.records.get_mut(&shape.name) else { continue };
            for field in shape.fields.iter().filter(|f| f.kind.is_file()) {
                for record in records.iter_mut() {
                    if let Some(value) = record.fields.get_mut(&field.name).filter(|value| *value == video) {
                        *value = new.clone();
                    }
                }
            }
        }
        if let Some(made) = self.state.made.remove(video) {
            self.state.made.insert(new.clone(), made);
        }
        self.drop_file(video);
        let _ = self.persist();
        Some(new)
    }

    pub(crate) fn converted(&mut self, video: &str) {
        if self.state.files.contains_key(video) {
            self.state.made.entry(video.to_owned()).or_default().done = true;
            let _ = self.persist();
        }
    }

    // Accounts

    /// The account with this name, whatever its capitals, and its password hash.
    pub(crate) fn account(&self, name: &str) -> Option<(String, String)> {
        let users = self.state.records.get(USERS)?;
        let user = users.iter().find(|u| u.fields.get(USER_NAME).is_some_and(|n| n.eq_ignore_ascii_case(name)))?;
        Some((user.id.clone(), self.state.passwords.get(&user.id)?.clone()))
    }

    pub(crate) fn create_account(&mut self, site: &Site, record: Record, password_hash: String) -> Result<String, Refused> {
        let name = record.fields.get(USER_NAME).cloned().unwrap_or_default();
        if self.account(&name).is_some() {
            return Err(Refused::NameTaken);
        }
        if self.state.records.get(USERS).is_some_and(|users| users.len() >= MAX_RECORDS) {
            return Err(Refused::Full);
        }
        let id = self.add(site, USERS, record)?;
        self.state.passwords.insert(id.clone(), password_hash);
        self.persist()?;
        Ok(id)
    }

    /// Starts a session and returns the cookie value to hand to the browser.
    pub(crate) fn open_session(&mut self, user: &str) -> Result<String, Refused> {
        let time = now();
        self.state.sessions.retain(|_, s| s.expires > time);
        if self.state.sessions.len() >= MAX_SESSIONS {
            return Err(Refused::Full);
        }
        let cookie = random_hex(32).map_err(|_| Refused::Storage)?;
        let token = random_hex(16).map_err(|_| Refused::Storage)?;
        let session = Session { user: user.to_owned(), token, expires: time + SESSION_SECONDS };
        self.state.sessions.insert(cookie_hash(&cookie), session);
        self.persist()?;
        Ok(cookie)
    }

    pub(crate) fn viewer(&self, cookie: &str) -> Option<Viewer> {
        let session = self.state.sessions.get(&cookie_hash(cookie)).filter(|s| s.expires > now())?;
        let moderator = self.state.moderators.contains(&session.user);
        Some(Viewer { id: session.user.clone(), token: session.token.clone(), moderator })
    }

    /// Lets everyone see a record that was waiting for approval. Returns
    /// whether there was one.
    pub(crate) fn approve(&mut self, collection: &str, id: &str) -> bool {
        let waiting = self.state.records.get_mut(collection).and_then(|all| all.iter_mut().find(|r| r.id == id && r.held));
        let Some(record) = waiting else { return false };
        record.held = false;
        let _ = self.persist();
        true
    }

    // Moderators

    pub(crate) fn moderators(&self) -> Vec<String> {
        self.state.moderators.iter().cloned().collect()
    }

    /// Makes an account a moderator, or an ordinary account again. Returns
    /// whether there is such an account.
    pub(crate) fn set_moderator(&mut self, id: &str, on: bool) -> bool {
        if !self.state.records.get(USERS).is_some_and(|users| users.iter().any(|u| u.id == id)) {
            return false;
        }
        let changed = if on { self.state.moderators.insert(id.to_owned()) } else { self.state.moderators.remove(id) };
        if changed {
            let _ = self.persist();
        }
        true
    }

    pub(crate) fn close_session(&mut self, cookie: &str) {
        if self.state.sessions.remove(&cookie_hash(cookie)).is_some() {
            let _ = self.persist();
        }
    }

    // Files

    pub(crate) fn file_target(&self) -> Target {
        match &self.storage {
            None => Target::Memory,
            Some(storage) => {
                let mut dir = storage.file.clone().into_os_string();
                dir.push(".files");
                Target::Disk { dir: dir.into(), key: storage.key.clone() }
            }
        }
    }

    /// Whether `bytes` more of file data fit under the limit the owner set.
    pub(crate) fn has_room_for(&self, site: &Site, bytes: u64) -> bool {
        self.file_bytes().saturating_add(bytes) <= site.limits.storage_bytes()
    }

    /// How much file data the site holds.
    pub(crate) fn file_bytes(&self) -> u64 {
        self.state.files.values().map(|f| f.size).sum()
    }

    /// Makes an arrived file part of the site. Called once the record that
    /// uses it is about to be added.
    pub(crate) fn keep_file(&mut self, staged: Staged, content_type: &str) {
        if let Some(contents) = staged.memory {
            self.memory.insert(staged.id.clone(), Arc::new(contents));
        }
        self.state.files.insert(staged.id, FileInfo { content_type: content_type.to_owned(), size: staged.size });
    }

    pub(crate) fn file(&self, id: &str) -> Option<(FileInfo, Source)> {
        let info = self.state.files.get(id)?.clone();
        let source = match self.file_target() {
            Target::Memory => Source::Memory(self.memory.get(id)?.clone()),
            Target::Disk { dir, key } => Source::Disk { path: dir.join(id), key },
        };
        Some((info, source))
    }
}

/// The site's data as one visitor may see it: without what is still
/// waiting for approval, unless they are a moderator.
pub(crate) struct Seen<'a> {
    pub store: &'a Store,
    pub everything: bool,
}

impl Data for Seen<'_> {
    fn visit(&self, collection: &str, each: &mut dyn FnMut(&Record)) {
        self.store.visit(collection, &mut |record| {
            if self.everything || !record.held {
                each(record);
            }
        });
    }

    fn find(&self, collection: &str, id: &str) -> Option<Record> {
        self.store.find(collection, id).filter(|record| self.everything || !record.held)
    }

    fn still(&self, video: &str) -> Option<String> {
        self.store.still(video)
    }

    fn sizes(&self, video: &str) -> Vec<(u32, String)> {
        self.store.sizes(video)
    }
}

impl Data for Store {
    fn visit(&self, collection: &str, each: &mut dyn FnMut(&Record)) {
        self.state.records.get(collection).into_iter().flatten().for_each(each);
    }

    fn find(&self, collection: &str, id: &str) -> Option<Record> {
        self.state.records.get(collection)?.iter().find(|r| r.id == id).cloned()
    }

    fn still(&self, video: &str) -> Option<String> {
        self.state.made.get(video)?.still.clone()
    }

    fn sizes(&self, video: &str) -> Vec<(u32, String)> {
        self.state.made.get(video).map(|made| made.sizes.clone()).unwrap_or_default()
    }
}
