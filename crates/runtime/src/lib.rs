//! Serves a [`Site`]: its pages, rendered on request, and what its visitors
//! add to it: records, files and accounts.
//!
//! The server never makes an outbound connection, and the only files it
//! touches are its own encrypted data. Responses carry a small fixed set of
//! headers, so nothing about the host (clock, software, file times) reaches
//! a visitor.

// A refusal is a whole response, which is what a caller wants to send as is.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, BodyStream, Full, Limited, StreamBody};
pub use hyper::body::Bytes;
use hyper::body::{Frame, Incoming};
use hyper::header::{
    HeaderMap, HeaderValue, ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, COOKIE, LOCATION, RANGE, SET_COOKIE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use torus_core::{
    render_page, stylesheet, Collection, Data, Field, FieldKind, Page, Record, Site, Viewer, FILE_PATH, FORM_PATH,
    NEXT_FIELD, PARENT_FIELD, PASSWORD_FIELD, PASSWORD_MAX, PASSWORD_MIN, SIGN_IN_PATH, SIGN_OUT_PATH, SIGN_UP_PATH,
    STYLE_PATH, TOKEN_FIELD, USERS, USER_NAME,
};

use torus_core::{render_progress, PROGRESS_PATH, UPLOAD_PARAM, WAITED_PARAM};
use torus_core::{Visit, PAGE_PARAM, REMOVE_PATH, SEALED_FIELD, SEARCH_MAX, SEARCH_PARAM};

mod blobs;
mod faststart;
mod media;
mod scrub;
mod webm;
mod store;

use blobs::{Staged, Target};
use store::{Budget, Refused};
pub use media::{Converter, Job};
pub use store::{Storage, Store};

/// Pages may frame nothing but this site's own upload progress page, and
/// nothing may frame them.
const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; media-src 'self'; frame-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
/// The upload progress page loads only the stylesheet and may be framed
/// only by this site's own pages.
const PROGRESS_CSP: &str = "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'self'";
/// The most text a form submission may carry, all fields together.
const MAX_FORM_BYTES: usize = 64 * 1024;
const HTML: &str = "text/html; charset=utf-8";
/// Says nothing about the software that set it.
const SESSION_COOKIE: &str = "s";
/// Visitors arrive over Tor with no address to tell them apart by, so the
/// limits that keep one of them from exhausting the host are shared ones.
const MAX_CONNECTIONS: usize = 256;
/// Large uploads being received at once. Each holds disk space until it ends.
const MAX_UPLOADS: usize = 3;
/// Pictures being decoded at once. Decoding is the costliest thing a request can ask for.
const MAX_DECODES: usize = 2;
/// How long a visitor may go without sending the next piece of a form.
const BODY_IDLE: Duration = Duration::from_secs(120);

/// An upload on its way in: how much of it has been received.
struct Arriving {
    received: AtomicU64,
    total: u64,
}

/// Keeps an upload listed under its name for as long as it is arriving.
struct Tracked {
    live: Live,
    name: String,
    arriving: Arc<Arriving>,
}

impl Tracked {
    /// Lists the upload a request carries, if its address names one. The
    /// name was made up by this server for the page the form was on, and
    /// only that page's visitor knows it.
    fn begin(live: &Live, req: &Request<Incoming>) -> Option<Self> {
        let pairs = decode_form(req.uri().query()?.as_bytes())?;
        let name = pairs.into_iter().find(|(key, _)| key == UPLOAD_PARAM)?.1;
        let total: u64 = req.headers().get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()?;
        if !upload_name(&name) || total == 0 {
            return None;
        }
        let arriving = Arc::new(Arriving { received: AtomicU64::new(0), total });
        let mut all = live.arriving();
        // Never more names than there can be connections, and the first
        // upload to use a name keeps it.
        if all.len() >= MAX_CONNECTIONS || all.contains_key(&name) {
            return None;
        }
        all.insert(name.clone(), arriving.clone());
        drop(all);
        Some(Self { live: live.clone(), name, arriving })
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.live.arriving().remove(&self.name);
    }
}

/// Whether this could be a name this server gave an upload.
fn upload_name(name: &str) -> bool {
    name.len() == 24 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Inner {
    site: RwLock<Arc<Site>>,
    store: Mutex<Store>,
    arriving: Mutex<HashMap<String, Arc<Arriving>>>,
    /// Woken when a video may have arrived that nothing has been made from.
    work: tokio::sync::Notify,
    connections: Arc<Semaphore>,
    uploads: Semaphore,
    decodes: Semaphore,
    /// The one `Host` a request may name, when the site is served on this
    /// computer: a web page elsewhere cannot then reach it by pointing a
    /// name of its own at this computer (DNS rebinding).
    only_host: OnceLock<String>,
}

/// The live site. Publishing swaps all its pages at once, so a visitor never
/// sees half of an update; what visitors have added stays.
#[derive(Clone)]
pub struct Live(Arc<Inner>);

impl Live {
    /// A site whose data lives in memory only and is gone when it stops.
    pub fn new(site: Site) -> Self {
        Self::with_store(site, Store::volatile())
    }

    pub fn with_store(site: Site, store: Store) -> Self {
        Self(Arc::new(Inner {
            site: RwLock::new(Arc::new(site)),
            store: Mutex::new(store),
            arriving: Mutex::new(HashMap::new()),
            work: tokio::sync::Notify::new(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            uploads: Semaphore::new(MAX_UPLOADS),
            decodes: Semaphore::new(MAX_DECODES),
            only_host: OnceLock::new(),
        }))
    }

    /// Answers only requests made to `host` (such as `127.0.0.1:8080`).
    pub fn only_for_host(&self, host: String) {
        let _ = self.0.only_host.set(host);
    }

    pub fn publish(&self, site: Site) {
        *self.0.site.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(site);
    }

    /// What visitors have added to a collection, oldest first, for the
    /// site's owner to look through.
    pub fn records(&self, collection: &str) -> Vec<Record> {
        self.store().records(collection)
    }

    /// Removes a record for good, with its files and whatever belongs to it.
    pub fn remove(&self, collection: &str, id: &str) -> bool {
        let site = self.site();
        self.store().remove(&site, collection, id)
    }

    /// From now on, makes a picture and smaller copies from every uploaded
    /// video, one video at a time, using `converter`. Videos that arrived
    /// before are caught up on first.
    pub fn convert_with(&self, converter: Arc<dyn Converter>) {
        // From now on no video is served as it was uploaded: each is held
        // back until the converter has encoded it afresh.
        self.store().hold_videos = true;
        let live = self.clone();
        tokio::spawn(async move {
            loop {
                let waiting = live.store().unconverted();
                for video in waiting {
                    let (live, converter) = (live.clone(), converter.clone());
                    let _ = tokio::task::spawn_blocking(move || media::convert(&live, &*converter, &video)).await;
                }
                live.0.work.notified().await;
            }
        });
    }

    /// Lets everyone see a record that was waiting for approval.
    pub fn approve(&self, collection: &str, id: &str) -> bool {
        self.store().approve(collection, id)
    }

    /// The accounts that are moderators, by id.
    pub fn moderators(&self) -> Vec<String> {
        self.store().moderators()
    }

    /// Makes an account a moderator, who may remove what others have added,
    /// or an ordinary account again. Returns whether there is such an account.
    pub fn set_moderator(&self, id: &str, on: bool) -> bool {
        self.store().set_moderator(id, on)
    }

    /// Waits until every change made so far is safely on disk.
    pub async fn settle(&self) {
        let settled = self.store().settled();
        if let Some(settled) = settled {
            settled.await;
        }
    }

    /// Adds a record with one field, `name`, as if a visitor had: for tests
    /// that need many records without waiting out the per-minute limits.
    #[doc(hidden)]
    pub fn add_for_test(&self, collection: &str, name: &str) -> bool {
        let site = self.site();
        let record = Record { fields: [("name".to_owned(), name.to_owned())].into(), ..Record::default() };
        self.store().add(&site, collection, record).is_ok()
    }

    fn site(&self) -> Arc<Site> {
        self.0.site.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn arriving(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Arriving>>> {
        self.0.arriving.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Accepts connections until the task is dropped or aborted.
pub async fn serve(listener: TcpListener, live: Live) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        tokio::spawn(serve_connection(stream, live.clone()));
    }
}

/// Answers HTTP requests on one connection, whatever carries it: a loopback
/// socket or a stream arriving over Tor.
pub async fn serve_connection<S>(stream: S, live: Live)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Beyond the limit a connection is closed unanswered: answering would
    // take the very resources that are short.
    let Ok(_open) = live.0.connections.clone().try_acquire_owned() else { return };
    let service = service_fn(move |req| {
        let live = live.clone();
        async move { Ok::<_, Infallible>(respond(&live, req).await) }
    });
    let _ = http1::Builder::new()
        .auto_date_header(false)
        // No honest browser sends more than a few kilobytes of headers.
        .max_buf_size(16 * 1024)
        .timer(TokioTimer::new())
        // Drops clients that trickle their request headers (Slowloris).
        .header_read_timeout(Duration::from_secs(10))
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

type Body = UnsyncBoxBody<Bytes, Infallible>;
type Reply = Response<Body>;

async fn respond(live: &Live, req: Request<Incoming>) -> Reply {
    // Only plain paths: a full address in the request line is how proxies are
    // asked to fetch other hosts, and this is not a proxy.
    if req.uri().authority().is_some() {
        return not_found(false);
    }
    if let Some(only) = live.0.only_host.get() {
        let named = req.headers().get(hyper::header::HOST).and_then(|v| v.to_str().ok());
        if named != Some(only.as_str()) {
            return plain(StatusCode::MISDIRECTED_REQUEST, "This site is not served under that name.\n", false);
        }
    }
    let path = req.uri().path().to_owned();
    let site = live.site();
    let cookie = session_cookie(req.headers());
    let viewer = if site.accounts { cookie.as_deref().and_then(|c| live.store().viewer(c)) } else { None };
    let head = req.method() == Method::HEAD;
    // Browsers say where a request was started from. A form posted from
    // another site is refused whatever it carries: that is how a visitor
    // could be signed in to someone else's account without noticing, or
    // made to post on an anonymous board. Requests without the header,
    // from older browsers and other tools, are judged by the other checks.
    let foreign = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|from| from != "same-origin" && from != "none");
    if foreign && req.method() == Method::POST {
        return refuse_unread(req, plain(StatusCode::FORBIDDEN, "That form was sent from another site.\n", false)).await;
    }
    let posted = req.method() == Method::POST;
    let reply = route(live, &site, viewer, cookie, path, head, req).await;
    if posted {
        // What the visitor is told was saved must be on disk first. The wait
        // happens here, outside the store's lock and off the threads that
        // read and write the disk.
        live.settle().await;
        // Something may have been uploaded.
        live.0.work.notify_one();
    }
    reply
}

async fn route(
    live: &Live,
    site: &Arc<Site>,
    viewer: Option<Viewer>,
    cookie: Option<String>,
    path: String,
    head: bool,
    req: Request<Incoming>,
) -> Reply {
    match *req.method() {
        Method::GET | Method::HEAD => match (path.strip_prefix(FILE_PATH), path.strip_prefix(PROGRESS_PATH)) {
            (Some(id), _) => file(live, id, req.headers().get(RANGE), head),
            (_, Some(name)) => progress(live, name, req.uri().query(), head),
            _ => page(live, &site, &path, &visit(viewer, req.uri().query()), head),
        },
        Method::POST if site.accounts && path.starts_with(REMOVE_PATH) => {
            remove(live, &site, viewer, &path, req).await
        }
        Method::POST if site.accounts && path.starts_with(torus_core::APPROVE_PATH) => {
            approve(live, &site, viewer, &path, req).await
        }
        Method::POST if !site.accounts && path.starts_with("/_account/") => method_not_allowed(),
        Method::POST if path == SIGN_UP_PATH => sign_up(live, &site, viewer, req).await,
        Method::POST if path == SIGN_IN_PATH => sign_in(live, &site, viewer, req).await,
        Method::POST if path == SIGN_OUT_PATH => sign_out(live, &site, viewer, cookie, req).await,
        Method::POST => match path.strip_prefix(FORM_PATH).and_then(|name| site.collection(name)) {
            // Only collections that some page offers a form for can be added
            // to, and accounts only through signing up.
            Some(collection) if collection.name != USERS && site.has_form_for(&collection.name) => {
                submit(live, &site, collection, viewer, req).await
            }
            // The same answer whether or not such a collection exists.
            _ => method_not_allowed(),
        },
        _ => method_not_allowed(),
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let all = headers.get(COOKIE)?.to_str().ok()?;
    all.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == SESSION_COOKIE && value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| value.to_owned())
    })
}

/// What the query of a page address asks for: a search and a page number.
fn visit(viewer: Option<Viewer>, query: Option<&str>) -> Visit {
    let pairs = query.and_then(|q| decode_form(q.as_bytes())).unwrap_or_default();
    let get = |name: &str| pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str()).unwrap_or("");
    Visit {
        viewer,
        page: get(PAGE_PARAM).parse::<usize>().unwrap_or(0).min(100_000),
        search: clean(get(SEARCH_PARAM), FieldKind::Text).chars().take(SEARCH_MAX).collect(),
        size: get(torus_core::SIZE_PARAM).parse().ok(),
        upload: blobs::random_id().unwrap_or_default(),
    }
}

/// The small page framed under an upload form, saying how far the upload
/// with this name has got.
fn progress(live: &Live, name: &str, query: Option<&str>, head: bool) -> Reply {
    if !upload_name(name) {
        return not_found(head);
    }
    let arriving = live.arriving().get(name).map(|a| (a.received.load(Ordering::Relaxed), a.total));
    let waited = query
        .and_then(|q| decode_form(q.as_bytes()))
        .and_then(|pairs| pairs.into_iter().find(|(key, _)| key == WAITED_PARAM))
        .and_then(|(_, value)| value.parse::<u32>().ok())
        .unwrap_or(0);
    let mut res = build(StatusCode::OK, HTML, render_progress(name, arriving, waited).into(), head);
    res.headers_mut().insert("content-security-policy", HeaderValue::from_static(PROGRESS_CSP));
    res
}

fn page(live: &Live, site: &Site, path: &str, visit: &Visit, head: bool) -> Reply {
    if path == STYLE_PATH {
        return build(StatusCode::OK, "text/css; charset=utf-8", stylesheet(site).into(), head);
    }
    let store = live.store();
    // What waits for approval exists only for moderators: not in lists,
    // not in counts, and not at its own address.
    let store = store::Seen { store: &store, everything: visit.viewer.as_ref().is_some_and(|viewer| viewer.moderator) };
    if let Some(page) = site.pages.iter().find(|p| p.template.is_none() && p.path() == path) {
        return build(StatusCode::OK, HTML, render_page(site, page, None, &store, visit).into(), head);
    }
    // A template page: `/slug/<record id>`.
    let record_page = path.strip_prefix('/').and_then(|rest| rest.split_once('/')).and_then(|(slug, id)| {
        let page = site.pages.iter().find(|p| p.slug == slug)?;
        let record = store.find(page.template.as_deref()?, id)?;
        Some((page, record))
    });
    match record_page {
        Some((page, record)) => {
            build(StatusCode::OK, HTML, render_page(site, page, Some(&record), &store, visit).into(), head)
        }
        None => not_found(head),
    }
}

// Files

/// Reads `Range: bytes=...` against a file of `size` bytes. `Ok(None)` when
/// there is no usable range header; `Err` when the range cannot be served.
fn byte_range(header: Option<&HeaderValue>, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = header.and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("bytes=")) else {
        return Ok(None);
    };
    // Several ranges at once are not supported; serving the whole file is always allowed.
    if spec.contains(',') {
        return Ok(None);
    }
    let (first, last) = spec.split_once('-').ok_or(())?;
    let (start, end) = match (first.trim(), last.trim()) {
        ("", "") => return Err(()),
        ("", suffix) => {
            let count: u64 = suffix.parse().map_err(|_| ())?;
            (size.saturating_sub(count), size.saturating_sub(1))
        }
        (first, "") => (first.parse().map_err(|_| ())?, size.saturating_sub(1)),
        (first, last) => (first.parse().map_err(|_| ())?, last.parse::<u64>().map_err(|_| ())?.min(size.saturating_sub(1))),
    };
    if size == 0 || start > end || start >= size {
        return Err(());
    }
    Ok(Some((start, end)))
}

fn file(live: &Live, id: &str, range: Option<&HeaderValue>, head: bool) -> Reply {
    let Some((info, source)) = live.store().file(id) else { return not_found(head) };
    let (status, start, end) = match byte_range(range, info.size) {
        Ok(Some((start, end))) => (StatusCode::PARTIAL_CONTENT, start, end),
        Ok(None) => (StatusCode::OK, 0, info.size.saturating_sub(1)),
        Err(()) => {
            let mut res = plain(StatusCode::RANGE_NOT_SATISFIABLE, "That part of the file does not exist.\n", head);
            let whole = HeaderValue::from_str(&format!("bytes */{}", info.size)).expect("digits");
            res.headers_mut().insert(CONTENT_RANGE, whole);
            return res;
        }
    };
    let length = if info.size == 0 { 0 } else { end - start + 1 };
    let body: Body = if head {
        Full::new(Bytes::new()).boxed_unsync()
    } else {
        // Reading and decrypting happen on a thread meant for blocking work,
        // a few pieces ahead of the visitor, never on the threads that
        // answer requests.
        let (pieces, arriving) = tokio::sync::mpsc::channel::<Bytes>(4);
        tokio::task::spawn_blocking(move || {
            for piece in blobs::read(source, start, length) {
                if pieces.blocking_send(piece).is_err() {
                    break;
                }
            }
        });
        let stream = futures_util::stream::unfold(arriving, |mut arriving| async move {
            let piece = arriving.recv().await?;
            Some((Ok::<_, Infallible>(Frame::data(piece)), arriving))
        });
        StreamBody::new(stream).boxed_unsync()
    };
    let mut res = headers(Response::new(body), status, &info.content_type, length);
    res.headers_mut().insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // Shown in place and never under a name a visitor chose.
    res.headers_mut().insert(CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    if status == StatusCode::PARTIAL_CONTENT {
        let part = HeaderValue::from_str(&format!("bytes {start}-{end}/{}", info.size)).expect("digits");
        res.headers_mut().insert(CONTENT_RANGE, part);
    }
    res
}

// Submissions

/// Files that have arrived for a submission. Any that no record ends up
/// using are removed again when this is dropped.
struct Arrived {
    target: Target,
    files: Vec<(String, Staged, &'static str)>,
}

impl Arrived {
    fn take(&mut self, field: &str) -> Option<(Staged, &'static str)> {
        let at = self.files.iter().position(|(name, ..)| name == field)?;
        let (_, staged, content_type) = self.files.remove(at);
        Some((staged, content_type))
    }
}

impl Drop for Arrived {
    fn drop(&mut self) {
        for (_, staged, _) in &self.files {
            blobs::discard(&self.target, &staged.id);
        }
    }
}

struct Submission {
    texts: Vec<(String, String)>,
    arrived: Arrived,
}

impl Submission {
    fn text(&self, name: &str) -> &str {
        self.texts.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str()).unwrap_or("")
    }
}

fn bad(text: &'static str) -> Reply {
    plain(StatusCode::BAD_REQUEST, text, false)
}

/// Reads a submitted form, plain or with files. Files for `fields` are
/// checked and stored as they arrive; anything else is treated as text.
async fn read_submission(live: &Live, fields: &[Field], req: Request<Incoming>) -> Result<Submission, Reply> {
    let content_type =
        req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let target = live.store().file_target();
    let site = live.site();
    // What the browser says it is sending is the most any one file in it
    // can be, so room is asked for that much and not for the largest file
    // the site would ever take.
    let announced = req.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    let mut submission = Submission { texts: Vec::new(), arrived: Arrived { target: target.clone(), files: Vec::new() } };
    let too_large = || plain(StatusCode::PAYLOAD_TOO_LARGE, "That submission is too large.\n", false);

    if content_type.starts_with("application/x-www-form-urlencoded") {
        let body = tokio::time::timeout(BODY_IDLE, Limited::new(req.into_body(), MAX_FORM_BYTES).collect())
            .await
            .map_err(|_| bad("That submission took too long to arrive.\n"))?
            .map_err(|_| too_large())?;
        submission.texts = decode_form(&body.to_bytes()).ok_or_else(|| bad("That submission could not be read.\n"))?;
        return Ok(submission);
    }
    if !content_type.starts_with("multipart/form-data") {
        return Err(bad("That is not a form submission.\n"));
    }

    // The original header, since a boundary's capitals matter.
    let original = req.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let boundary = multer::parse_boundary(&original).map_err(|_| bad("That submission could not be read.\n"))?;
    let file_room: u64 = fields
        .iter()
        .filter(|f| f.kind.is_file())
        .map(|f| if f.kind == FieldKind::Video { site.limits.video_bytes() } else { f.kind.max_bytes() })
        .sum();
    let limit = multer::SizeLimit::new().whole_stream(file_room + 2 * MAX_FORM_BYTES as u64);
    // Counted as it arrives, so the frame under the form can say how far it has got.
    let tracked = Tracked::begin(live, &req);
    let counter = tracked.as_ref().map(|t| t.arriving.clone());
    let stream = BodyStream::new(req.into_body()).filter_map(move |frame| {
        let counter = counter.clone();
        async move {
            match frame {
                Ok(frame) => frame.into_data().ok().map(|data| {
                    if let Some(counter) = &counter {
                        counter.received.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    Ok(data)
                }),
                Err(e) => Some(Err(std::io::Error::other(e))),
            }
        }
    });
    let mut parts = multer::Multipart::with_constraints(stream, boundary, multer::Constraints::new().size_limit(limit));
    let mut text_bytes = 0usize;

    loop {
        let mut part = match parts.next_field().await {
            Ok(Some(part)) => part,
            Ok(None) => break,
            Err(multer::Error::StreamSizeExceeded { .. }) => return Err(too_large()),
            Err(_) => return Err(bad("That submission could not be read.\n")),
        };
        let name = part.name().unwrap_or("").to_owned();
        let Some(field) = fields.iter().find(|f| f.name == name && f.kind.is_file()) else {
            let mut value = Vec::new();
            while let Some(piece) = piece(&mut part).await? {
                text_bytes += piece.len();
                if text_bytes > MAX_FORM_BYTES {
                    return Err(too_large());
                }
                value.extend_from_slice(&piece);
            }
            let value = String::from_utf8(value).map_err(|_| bad("That submission could not be read.\n"))?;
            submission.texts.push((name, value));
            continue;
        };
        let max = match field.kind {
            FieldKind::Video => site.limits.video_bytes(),
            kind => kind.max_bytes(),
        };
        let needed = announced.map_or(max, |announced| announced.min(max));
        match field.kind {
            FieldKind::Image => {
                let mut picture = Vec::new();
                while let Some(piece) = piece(&mut part).await? {
                    if (picture.len() + piece.len()) as u64 > max {
                        return Err(too_large());
                    }
                    picture.extend_from_slice(&piece);
                }
                // A file input left empty still sends a part, with nothing in it.
                if picture.is_empty() {
                    continue;
                }
                if !live.store().has_room_for(&site, needed) {
                    return Err(plain(StatusCode::INSUFFICIENT_STORAGE, "This site has no room for more files.\n", false));
                }
                // Decoding is the costly step, so it runs off the request
                // threads, and only a few at a time.
                let _turn = live.0.decodes.acquire().await.map_err(|_| unavailable())?;
                let cleaned = tokio::task::spawn_blocking(move || blobs::clean_image(&picture)).await.ok().flatten();
                let (clean, content_type) = cleaned.ok_or_else(|| bad("That picture could not be read. Use PNG, JPEG, WebP or GIF.\n"))?;
                let staged = blobs::store(&target, &clean).map_err(|_| unavailable())?;
                submission.arrived.files.push((name, staged, content_type));
            }
            _ => {
                // Hold back the start until there is enough to tell what kind of file it is.
                let mut start = Vec::new();
                let mut ended = false;
                while start.len() < 12 && !ended {
                    match piece(&mut part).await? {
                        Some(piece) => start.extend_from_slice(&piece),
                        None => ended = true,
                    }
                }
                if start.is_empty() {
                    continue;
                }
                let content_type = blobs::video_type(&start).ok_or_else(|| bad("That is not an MP4 or WebM video.\n"))?;
                if !live.store().has_room_for(&site, needed) {
                    return Err(plain(StatusCode::INSUFFICIENT_STORAGE, "This site has no room for more files.\n", false));
                }
                let busy = || plain(StatusCode::TOO_MANY_REQUESTS, "Too many uploads are in progress. Try again shortly.\n", false);
                let _slot = live.0.uploads.try_acquire().map_err(|_| busy())?;
                let mut writer = blobs::Writer::new(target.clone()).map_err(|_| unavailable())?;
                // Blanks what the camera or editor recorded about itself, as the file streams past.
                let mut scrubber = scrub::Scrubber::new(content_type);
                let mut cleaned = Vec::new();
                let mut size = start.len() as u64;
                scrubber.push(&start, &mut cleaned);
                writer.write(&cleaned).map_err(|_| too_large())?;
                while !ended {
                    match piece(&mut part).await? {
                        Some(piece) => {
                            size += piece.len() as u64;
                            if size > max {
                                return Err(too_large());
                            }
                            cleaned.clear();
                            scrubber.push(&piece, &mut cleaned);
                            writer.write(&cleaned).map_err(|_| too_large())?;
                        }
                        None => ended = true,
                    }
                }
                cleaned.clear();
                scrubber.finish(&mut cleaned);
                writer.write(&cleaned).map_err(|_| too_large())?;
                // Without a converter to encode it afresh, a video is kept
                // only if all of it could be cleaned.
                if scrubber.incomplete() && !live.store().hold_videos {
                    return Err(bad("That video could not be cleaned of what the camera recorded about it, so it was not kept.\n"));
                }
                let staged = writer.finish().map_err(|_| unavailable())?;
                // An MP4 whose index came last gets it moved to the front,
                // so that playback can start before the whole file is fetched.
                let staged = if content_type == "video/mp4" {
                    let target = target.clone();
                    tokio::task::spawn_blocking(move || faststart::front_index(&target, staged))
                        .await
                        .map_err(|_| unavailable())?
                } else {
                    staged
                };
                submission.arrived.files.push((name, staged, content_type));
            }
        }
    }
    Ok(submission)
}

/// The next piece of one part of a multipart form.
async fn piece(part: &mut multer::Field<'_>) -> Result<Option<Bytes>, Reply> {
    tokio::time::timeout(BODY_IDLE, part.chunk())
        .await
        .map_err(|_| bad("That submission took too long to arrive.\n"))?
        .map_err(|_| bad("That submission could not be read.\n"))
}

/// Turns a submission into a record's fields, or says what is wrong with it.
/// Files the record uses are left in `submission` for the caller to keep.
fn record_fields(collection: &Collection, submission: &Submission) -> Result<BTreeMap<String, String>, Reply> {
    let mut fields = BTreeMap::new();
    let wrong = || bad("A required field was empty or a field was too long. Go back and try again.\n");
    for field in &collection.fields {
        if field.kind.is_file() {
            let arrived = submission.arrived.files.iter().find(|(name, ..)| *name == field.name);
            if field.required && arrived.is_none() {
                return Err(wrong());
            }
            fields.insert(field.name.clone(), arrived.map(|(_, staged, _)| staged.id.clone()).unwrap_or_default());
            continue;
        }
        let value = clean(submission.text(&field.name), field.kind);
        if (field.required && value.is_empty()) || value.chars().count() > field.kind.max_len() {
            return Err(wrong());
        }
        fields.insert(field.name.clone(), value);
    }
    // A collection with no fields, such as likes, is added to with the button alone.
    if !collection.fields.is_empty() && fields.values().all(String::is_empty) {
        return Err(bad("The form was empty. Go back and try again.\n"));
    }
    Ok(fields)
}

/// Makes the files a record uses part of the site.
fn keep_files(store: &mut Store, collection: &Collection, submission: &mut Submission) {
    for field in collection.fields.iter().filter(|f| f.kind.is_file()) {
        if let Some((staged, content_type)) = submission.arrived.take(&field.name) {
            store.keep_file(staged, content_type);
        }
    }
}

fn refusal(refused: Refused) -> Reply {
    match refused {
        Refused::TooFast => plain(StatusCode::TOO_MANY_REQUESTS, "Too many submissions right now. Try again in a minute.\n", false),
        Refused::NameTaken => bad("That name is taken. Go back and choose another.\n"),
        Refused::Full => plain(StatusCode::INSUFFICIENT_STORAGE, "This site cannot take any more of those.\n", false),
        Refused::Storage => unavailable(),
    }
}

/// Compares without stopping at the first difference, so timing says nothing.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn submit(live: &Live, site: &Site, collection: &Collection, viewer: Option<Viewer>, req: Request<Incoming>) -> Reply {
    // Decided before reading the body, so a guest cannot make the server
    // receive a large upload it will refuse.
    if collection.members_only && viewer.is_none() {
        return refuse_unread(req, plain(StatusCode::FORBIDDEN, "Sign in first.\n", false)).await;
    }
    let allowed = live.store().allow(Budget::Posts);
    if let Err(refused) = allowed {
        return refuse_unread(req, refusal(refused)).await;
    }
    let mut submission = match read_submission(live, &collection.fields, req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    // A signed-in visitor's forms carry a value only this site's pages know,
    // so another site cannot submit in their name.
    if let Some(viewer) = &viewer {
        if !same(submission.text(TOKEN_FIELD), &viewer.token) {
            return plain(StatusCode::FORBIDDEN, "That form has expired. Go back, reload the page and try again.\n", false);
        }
    }
    let fields = match record_fields(collection, &submission) {
        Ok(fields) => fields,
        Err(reply) => return reply,
    };
    // A blocked word in any text field: refuse it, or hold it for approval.
    // A moderator's own posts are never caught by the word filter.
    let is_moderator = viewer.as_ref().is_some_and(|v| v.moderator);
    let blocked = !is_moderator && fields.values().any(|value| site.moderation.blocks(value));
    if blocked && !site.moderation.blocked_held {
        return bad("That could not be posted. Go back and change it, then try again.\n");
    }
    let mut store = live.store();
    let parent = match &collection.parent {
        None => None,
        Some(parent) => {
            let id = submission.text(PARENT_FIELD);
            if store.find(parent, id).is_none() {
                return bad("What this was added to no longer exists.\n");
            }
            Some(id.to_owned())
        }
    };
    // What a moderator adds needs nobody's approval.
    let held = blocked || (collection.review && !is_moderator);
    let owner = if collection.members_only { viewer.map(|v| v.id) } else { None };
    // One per member: pressing again takes it back.
    if collection.once_each {
        let mine = store.records(&collection.name).into_iter().find(|r| r.owner == owner && r.parent == parent);
        if let Some(existing) = mine {
            store.remove(site, &collection.name, &existing.id);
            drop(store);
            return see_other(site, submission.text(NEXT_FIELD));
        }
    }
    // Sealed: from here on not even this server can read what was sent.
    let fields = if collection.sealed {
        let sealed = site
            .seal_key
            .as_deref()
            .and_then(torus_seal::from_hex)
            .zip(serde_json::to_vec(&fields).ok())
            .and_then(|(key, plain)| torus_seal::seal(&key, &plain));
        match sealed {
            Some(sealed) => BTreeMap::from([(SEALED_FIELD.to_owned(), torus_seal::to_hex(&sealed))]),
            None => return unavailable(),
        }
    } else {
        fields
    };
    keep_files(&mut store, collection, &mut submission);
    let record = Record { fields, parent, owner, held, ..Record::default() };
    if let Err(refused) = store.add(site, &collection.name, record) {
        return refusal(refused);
    }
    drop(store);
    if held {
        // Sent back to the page they would find nothing new on, a visitor
        // would think it was lost and send it again.
        return waiting_page(site, "Received. It will show once it has been approved.");
    }
    see_other(site, submission.text(NEXT_FIELD))
}

/// A plain page telling the visitor their submission is waiting, with a link
/// back to the site. Used for held posts and for accounts awaiting approval.
fn waiting_page(_site: &Site, message: &str) -> Reply {
    let message = escape_attribute(message);
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Received</title>\n\
         <link rel=\"stylesheet\" href=\"{STYLE_PATH}\">\n</head>\n<body>\n<main>\n\
         <p>{message}</p>\n<p><a href=\"/\">Back</a></p>\n</main>\n</body>\n</html>\n"
    );
    build(StatusCode::OK, HTML, page.into(), false)
}

/// `return_path` only lets through addresses made of plain characters, but
/// what goes into a page is escaped all the same.
fn escape_attribute(text: &str) -> String {
    text.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A moderator approves a record that was waiting.
async fn approve(live: &Live, site: &Site, viewer: Option<Viewer>, path: &str, req: Request<Incoming>) -> Reply {
    let target = path.strip_prefix(torus_core::APPROVE_PATH).and_then(|rest| rest.split_once('/'));
    let offered = site.any_block(&|b| matches!(b, torus_core::Block::Approve { .. }));
    let (Some((collection, id)), true) = (target, offered) else { return method_not_allowed() };
    let Some(viewer) = viewer else {
        return refuse_unread(req, plain(StatusCode::FORBIDDEN, "Sign in first.\n", false)).await;
    };
    let submission = match read_submission(live, &[], req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    if !same(submission.text(TOKEN_FIELD), &viewer.token) {
        return plain(StatusCode::FORBIDDEN, "That form has expired. Go back, reload the page and try again.\n", false);
    }
    // The same answer for someone who may not and for what is not waiting.
    if !viewer.moderator || collection == USERS || !live.store().approve(collection, id) {
        return plain(StatusCode::FORBIDDEN, "That is not yours to approve.\n", false);
    }
    see_other(site, submission.text(NEXT_FIELD))
}

/// A member removes a record they added, or their own account. A moderator
/// removes anything but someone else's account.
async fn remove(live: &Live, site: &Site, viewer: Option<Viewer>, path: &str, req: Request<Incoming>) -> Reply {
    let target = path.strip_prefix(REMOVE_PATH).and_then(|rest| rest.split_once('/'));
    let offered = site.any_block(&|b| matches!(b, torus_core::Block::Remove { .. }));
    let (Some((collection, id)), true) = (target, offered) else { return method_not_allowed() };
    let Some(viewer) = viewer else {
        return refuse_unread(req, plain(StatusCode::FORBIDDEN, "Sign in first.\n", false)).await;
    };
    let submission = match read_submission(live, &[], req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    if !same(submission.text(TOKEN_FIELD), &viewer.token) {
        return plain(StatusCode::FORBIDDEN, "That form has expired. Go back, reload the page and try again.\n", false);
    }
    let mut store = live.store();
    let own_account = collection == USERS && id == viewer.id;
    let mine = own_account
        || (viewer.moderator && collection != USERS)
        || store.find(collection, id).is_some_and(|r| r.owner.as_deref() == Some(viewer.id.as_str()));
    // The same answer for what is not theirs and for what does not exist.
    if !mine || !store.remove(site, collection, id) {
        return plain(StatusCode::FORBIDDEN, "That is not yours to remove.\n", false);
    }
    drop(store);
    if own_account {
        return session_reply(site, "/", "", 0);
    }
    see_other(site, submission.text(NEXT_FIELD))
}

/// Answers a request whose body will not be used. A small body is read to
/// its end first, because a browser that is cut off while still sending may
/// show a connection error instead of the answer.
async fn refuse_unread(req: Request<Incoming>, reply: Reply) -> Reply {
    let _ = Limited::new(req.into_body(), 4 * MAX_FORM_BYTES).collect().await;
    reply
}

// Accounts

fn hash_password(password: &str) -> Option<String> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).ok()?;
    let salt = SaltString::encode_b64(&salt).ok()?;
    Some(Argon2::default().hash_password(password.as_bytes(), &salt).ok()?.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

/// A hash to check against when there is no such account, so that a wrong
/// name takes as long to refuse as a wrong password.
fn decoy_hash() -> &'static str {
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| hash_password("no such account").unwrap_or_default())
}

fn session_reply(site: &Site, next: &str, cookie: &str, seconds: u64) -> Reply {
    let mut res = see_other(site, next);
    let value = format!("{SESSION_COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={seconds}");
    res.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&value).expect("hex and digits"));
    res
}

fn valid_name(name: &str) -> bool {
    (3..=30).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

async fn sign_up(live: &Live, site: &Site, viewer: Option<Viewer>, req: Request<Incoming>) -> Reply {
    let Some(users) = site.collection(USERS) else { return method_not_allowed() };
    if !site.any_block(&|b| matches!(b, torus_core::Block::SignUp { .. })) {
        return method_not_allowed();
    }
    if viewer.is_some() {
        return bad("You are already signed in.\n");
    }
    if let Err(refused) = live.store().allow(Budget::SignUps) {
        return refusal(refused);
    }
    let mut submission = match read_submission(live, &users.fields, req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    let fields = match record_fields(users, &submission) {
        Ok(fields) => fields,
        Err(reply) => return reply,
    };
    if !fields.get(USER_NAME).is_some_and(|name| valid_name(name)) {
        return bad("A name is 3 to 30 letters, digits, dashes or underscores. Go back and try again.\n");
    }
    let password = submission.text(PASSWORD_FIELD).to_owned();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&password.chars().count()) {
        return bad("A password is at least 10 characters. Go back and try again.\n");
    }
    // Deliberately slow, so it runs off the request threads.
    let Some(hash) = tokio::task::spawn_blocking(move || hash_password(&password)).await.ok().flatten() else {
        return unavailable();
    };
    let mut store = live.store();
    if store.account(&fields[USER_NAME]).is_some() {
        return refusal(Refused::NameTaken);
    }
    keep_files(&mut store, users, &mut submission);
    // Where the owner reviews new accounts, the account waits, held, and no
    // session is opened: it cannot be used until it is approved.
    let held = site.moderation.approve_accounts;
    let created = store.create_account(site, Record { fields, held, ..Record::default() }, hash);
    let opened = if held { created.map(|_| None) } else { created.and_then(|id| store.open_session(&id)).map(Some) };
    drop(store);
    match opened {
        Ok(Some(cookie)) => session_reply(site, submission.text(NEXT_FIELD), &cookie, 30 * 24 * 60 * 60),
        Ok(None) => waiting_page(site, "Your account was created. You can sign in once it has been approved."),
        Err(refused) => refusal(refused),
    }
}

async fn sign_in(live: &Live, site: &Site, viewer: Option<Viewer>, req: Request<Incoming>) -> Reply {
    if !site.any_block(&|b| matches!(b, torus_core::Block::SignIn { .. })) {
        return method_not_allowed();
    }
    if viewer.is_some() {
        return bad("You are already signed in.\n");
    }
    if let Err(refused) = live.store().allow(Budget::SignIns) {
        return refusal(refused);
    }
    let submission = match read_submission(live, &[], req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    let account = live.store().account(submission.text(USER_NAME).trim());
    let password = submission.text(PASSWORD_FIELD).to_owned();
    let (id, hash, held) = match account {
        Some((id, hash, held)) => (Some(id), hash, held),
        // The password is still checked against a decoy, so a wrong name
        // takes as long to refuse as a wrong password.
        None => (None, decoy_hash().to_owned(), false),
    };
    let correct = tokio::task::spawn_blocking(move || verify_password(&password, &hash)).await.unwrap_or(false);
    // An account waiting for approval cannot be signed in to yet. The answer
    // is the same as a wrong password, so a guess learns nothing either way.
    let Some(id) = id.filter(|_| correct && !held) else {
        return bad("Wrong name or password. Go back and try again.\n");
    };
    let opened = live.store().open_session(&id);
    match opened {
        Ok(cookie) => session_reply(site, submission.text(NEXT_FIELD), &cookie, 30 * 24 * 60 * 60),
        Err(refused) => refusal(refused),
    }
}

async fn sign_out(live: &Live, site: &Site, viewer: Option<Viewer>, cookie: Option<String>, req: Request<Incoming>) -> Reply {
    let (Some(viewer), Some(cookie)) = (viewer, cookie) else { return see_other(site, "/") };
    let submission = match read_submission(live, &[], req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    if !same(submission.text(TOKEN_FIELD), &viewer.token) {
        return plain(StatusCode::FORBIDDEN, "That form has expired. Go back, reload the page and try again.\n", false);
    }
    live.store().close_session(&cookie);
    session_reply(site, submission.text(NEXT_FIELD), "", 0)
}

// Helpers

/// Sends the visitor back to the page a form was on, and nowhere else.
fn see_other(site: &Site, wanted: &str) -> Reply {
    let mut res = plain(StatusCode::SEE_OTHER, "", false);
    let next = return_path(site, wanted);
    res.headers_mut().insert(LOCATION, HeaderValue::from_str(&next).unwrap_or(HeaderValue::from_static("/")));
    res
}

/// Accepts only an address on this site: a page's own path, or a template
/// page's path followed by a record id.
fn return_path(site: &Site, wanted: &str) -> String {
    let plain_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    let is_page = |p: &&Page| match &p.template {
        None => p.path() == wanted,
        Some(_) => wanted
            .strip_prefix(&format!("{}/", p.path()))
            .is_some_and(|id| !id.is_empty() && id.len() <= 64 && id.chars().all(plain_char)),
    };
    if site.pages.iter().any(|p| is_page(&p)) { wanted.to_owned() } else { "/".to_owned() }
}

/// Decodes `application/x-www-form-urlencoded`. `None` if it is not valid.
fn decode_form(body: &[u8]) -> Option<Vec<(String, String)>> {
    fn part(raw: &[u8]) -> Option<String> {
        let mut out = Vec::with_capacity(raw.len());
        let mut bytes = raw.iter().copied();
        while let Some(byte) = bytes.next() {
            match byte {
                b'+' => out.push(b' '),
                b'%' => {
                    let hex = [bytes.next()?, bytes.next()?];
                    out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
                }
                other => out.push(other),
            }
        }
        String::from_utf8(out).ok()
    }
    body.split(|b| *b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let mut halves = pair.splitn(2, |b| *b == b'=');
            Some((part(halves.next()?)?, part(halves.next().unwrap_or(b""))?))
        })
        .collect()
}

/// Drops characters that have no business in stored text and trims the rest.
fn clean(value: &str, kind: FieldKind) -> String {
    let kept: String = value
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' if kind == FieldKind::Text => Some(' '),
            '\n' | '\r' | '\t' => Some(c),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect();
    kept.trim().to_owned()
}

fn not_found(head: bool) -> Reply {
    plain(StatusCode::NOT_FOUND, "Not found\n", head)
}

fn unavailable() -> Reply {
    plain(StatusCode::SERVICE_UNAVAILABLE, "That could not be saved. Try again later.\n", false)
}

fn method_not_allowed() -> Reply {
    let mut res = plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n", false);
    res.headers_mut().insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
    res
}

fn plain(status: StatusCode, text: &'static str, head: bool) -> Reply {
    build(status, "text/plain; charset=utf-8", Bytes::from_static(text.as_bytes()), head)
}

fn build(status: StatusCode, content_type: &str, body: Bytes, head: bool) -> Reply {
    let length = body.len() as u64;
    let body = Full::new(if head { Bytes::new() } else { body }).boxed_unsync();
    headers(Response::new(body), status, content_type, length)
}

/// The headers every response carries, and no others unless a caller adds them.
fn headers(mut res: Reply, status: StatusCode, content_type: &str, length: u64) -> Reply {
    *res.status_mut() = status;
    let headers = res.headers_mut();
    let content_type =
        HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static("application/octet-stream"));
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("content-security-policy", HeaderValue::from_static(CSP));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    res
}
