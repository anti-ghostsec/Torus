//! A guestbook, used and abused over real HTTP: a form, a list of what was
//! submitted, and a page per entry.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use torus_core::{check, Align, Block, Collection, Field, FieldKind, Page, Site, Theme};
use torus_runtime::{serve, Live, Storage, Store};
use zeroize::Zeroizing;

fn guestbook() -> Site {
    let field = |name: &str, kind, required| Field { name: name.into(), label: name.to_uppercase(), kind, required };
    let site = Site {
        title: "Guestbook".into(),
        theme: Theme::default(),
        pages: vec![
            Page {
                slug: "index".into(),
                title: "Home".into(),
                template: None,
                blocks: vec![
                    Block::Form { collection: "notes".into(), submit_label: "Sign".into(), open: false, prefill: false },
                    Block::List {
                        collection: "notes".into(),
                        newest_first: true,
                        limit: 50,
                        layout: Default::default(),
                        scope: Default::default(),
                        active_first: false,
                        paged: false,
                        blocks: vec![
                            Block::Field { field: "name".into(), level: 3, align: Align::Left, preview: false },
                            Block::Link { label: "Read".into(), href: "/note/{id}".into(), align: Align::Left },
                        ],
                    },
                ],
            },
            Page {
                slug: "note".into(),
                title: "Note".into(),
                template: Some("notes".into()),
                blocks: vec![Block::Field { field: "message".into(), level: 0, align: Align::Left, preview: false }],
            },
        ],
        collections: vec![
            Collection {
                name: "notes".into(), parent: None, members_only: false,
                once_each: false, review: false,
                sealed: false,
                fields: vec![field("name", FieldKind::Text, true), field("message", FieldKind::LongText, false)],
            },
            // Listed nowhere and offered by no form: must not be writable.
            Collection { name: "private".into(), parent: None, members_only: false,
                once_each: false, review: false, sealed: false, fields: vec![field("secret", FieldKind::Text, true)] },
        ],
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
    };
    check(&site).unwrap();
    site
}

async fn start(live: Live) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, live));
    addr
}

async fn raw(addr: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn get(addr: SocketAddr, path: &str) -> String {
    raw(addr, format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).await
}

async fn post(addr: SocketAddr, path: &str, body: &str) -> String {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    raw(addr, request.as_bytes()).await
}

fn status(response: &str) -> &str {
    response.get(9..12).unwrap_or("")
}

fn location(response: &str) -> Option<&str> {
    response.lines().find_map(|line| line.strip_prefix("location: "))
}

#[tokio::test]
async fn a_visitor_signs_the_guestbook_and_the_entry_gets_its_own_page() {
    let addr = start(Live::new(guestbook())).await;
    assert!(get(addr, "/").await.contains("Nothing here yet."));

    let sent = post(addr, "/_form/notes", "_next=%2F&name=Ada+%3Cb%3E&message=first+line%0D%0Asecond").await;
    assert_eq!(status(&sent), "303");
    assert_eq!(location(&sent), Some("/"));
    assert!(!sent.to_ascii_lowercase().contains("\r\ndate:"));

    let home = get(addr, "/").await;
    assert!(home.contains("<h3>Ada &lt;b&gt;</h3>"), "the entry is listed, escaped:\n{home}");
    let id = home.split("href=\"/note/").nth(1).and_then(|rest| rest.split('"').next()).expect("a link to the entry");
    assert_eq!(id.len(), 24, "ids are long and random");

    let entry = get(addr, &format!("/note/{id}")).await;
    assert_eq!(status(&entry), "200");
    assert!(entry.contains("<p>first line<br>second</p>"));
    // A form on a record's page returns to that page.
    assert_eq!(status(&get(addr, "/note/000000000000000000000000").await), "404");
    assert_eq!(status(&get(addr, "/note").await), "404", "a template page has no address of its own");
    assert_eq!(status(&get(addr, "/note/").await), "404");
}

#[tokio::test]
async fn hostile_submissions_are_refused() {
    let addr = start(Live::new(guestbook())).await;

    // A required field missing, an empty form, and text that is too long.
    assert_eq!(status(&post(addr, "/_form/notes", "_next=/&message=hi").await), "400");
    assert_eq!(status(&post(addr, "/_form/notes", "").await), "400");
    assert_eq!(status(&post(addr, "/_form/notes", &format!("name={}", "a".repeat(201))).await), "400");
    // Broken encoding and the wrong content type.
    assert_eq!(status(&post(addr, "/_form/notes", "name=%zz").await), "400");
    assert_eq!(status(&post(addr, "/_form/notes", "name=%ff%fe").await), "400");
    let json = "POST /_form/notes HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    assert_eq!(status(&raw(addr, json.as_bytes()).await), "400");
    // More than the size limit.
    assert_eq!(status(&post(addr, "/_form/notes", &format!("name=a&message={}", "b".repeat(600_000))).await), "413");

    // Collections without a form, or that do not exist, cannot be written to
    // and are indistinguishable from each other.
    let private = post(addr, "/_form/private", "secret=x").await;
    let missing = post(addr, "/_form/nothing", "secret=x").await;
    assert_eq!((status(&private), status(&missing)), ("405", "405"));
    assert_eq!(private, missing);

    // Nothing above was stored.
    assert!(get(addr, "/").await.contains("Nothing here yet."));

    // The return address cannot send a visitor anywhere but this site's pages.
    for next in ["https://evil.example/", "//evil.example", "/nowhere", "/note/../..", "/note/ABC%0d%0aSet-Cookie:x"] {
        let encoded: String = next.bytes().map(|b| format!("%{b:02x}")).collect();
        let sent = post(addr, "/_form/notes", &format!("name=n&_next={encoded}")).await;
        assert_eq!(location(&sent), Some("/"), "accepted the return address {next:?}");
        assert!(!sent.contains("Set-Cookie"));
    }
    let sent = post(addr, "/_form/notes", "name=n&_next=%2Fnote%2Fabc123").await;
    assert_eq!(location(&sent), Some("/note/abc123"));

    // A form posted from another site is refused; one from this site, or
    // from a browser that does not say, is not.
    for (from, expected) in [("cross-site", "403"), ("same-site", "403"), ("same-origin", "303"), ("none", "303")] {
        let body = "name=visitor";
        let request = format!(
            "POST /_form/notes HTTP/1.1\r\nHost: x\r\nSec-Fetch-Site: {from}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(status(&raw(addr, request.as_bytes()).await), expected, "sent from {from}");
    }

    // Control characters are dropped, and one-line fields stay on one line.
    post(addr, "/_form/notes", "name=two%0Alines%00%1b%5Bm").await;
    assert!(get(addr, "/").await.contains("<h3>two lines[m</h3>"));
}

#[tokio::test]
async fn a_flood_of_submissions_is_slowed_down() {
    let addr = start(Live::new(guestbook())).await;
    let mut accepted = 0;
    let mut refused = 0;
    for n in 0..40 {
        match status(&post(addr, "/_form/notes", &format!("name=n{n}")).await) {
            "303" => accepted += 1,
            "429" => refused += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!((accepted, refused), (30, 10));
}

#[tokio::test]
async fn records_survive_a_restart_and_are_unreadable_on_disk() {
    let file = std::env::temp_dir().join(format!("torus-store-test-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&file);
    let storage = |key: u8| Storage { file: file.clone(), key: Zeroizing::new([key; 32]) };

    let addr = start(Live::with_store(guestbook(), Store::open(storage(7)).unwrap())).await;
    post(addr, "/_form/notes", "name=Remembered&message=a+very+recognisable+sentence").await;

    let on_disk = std::fs::read(&file).unwrap();
    for plain in [b"Remembered".as_slice(), b"recognisable", b"notes", b"message"] {
        assert!(!on_disk.windows(plain.len()).any(|w| w == plain), "the store holds readable text");
    }
    // Neither its size nor its times say much: padded to 64 KiB (plus the
    // nonce and tag), and dated like every other file the app writes.
    assert_eq!(on_disk.len(), 24 + 64 * 1024 + 16);
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    assert_eq!(modified, std::time::UNIX_EPOCH + Duration::from_secs(946_684_800), "the file's time tells when it was written");

    // The wrong key opens nothing; the right one brings the record back.
    assert!(Store::open(storage(8)).is_err());
    let again = start(Live::with_store(guestbook(), Store::open(storage(7)).unwrap())).await;
    assert!(get(again, "/").await.contains("<h3>Remembered</h3>"));
    let _ = std::fs::remove_file(&file);
}

/// A full collection refuses more instead of deleting what is already
/// there, so flooding a site cannot wipe it.
#[tokio::test]
async fn a_full_collection_keeps_what_it_has() {
    let live = Live::new(guestbook());
    let addr = start(live.clone()).await;
    assert_eq!(status(&post(addr, "/_form/notes", "name=first").await), "303");
    // Fill it to the limit directly; over HTTP the per-minute limit would take hours.
    for n in 1..5_000 {
        live.add_for_test("notes", &format!("filler {n}"));
    }
    assert_eq!(status(&post(addr, "/_form/notes", "name=one+too+many").await), "507");
    assert!(live.records("notes").iter().any(|r| r.fields["name"] == "first"), "the oldest was pushed out");
}
