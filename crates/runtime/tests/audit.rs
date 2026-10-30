//! Treats the server as a visitor's adversary would: hostile requests in,
//! and a search of everything that comes out for anything that could
//! identify the host or make a visitor's browser contact a third party.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use torus_core::{Align, Block, Page, Site, Theme};
use torus_runtime::{serve, Live};

fn site() -> Site {
    let text = |t: &str| Block::Text { text: t.into(), align: Align::Center };
    Site {
        title: "Audit <b>site</b>".into(),
        theme: Theme::default(),
        collections: vec![],
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        forward: None,
        pages: vec![
            Page {
                slug: "index".into(),
                title: "Home \"quoted\"".into(),
                template: None,
            blocks: vec![
                    Block::Heading { level: 1, text: "<img src=x onerror=alert(1)>".into(), align: Align::Left },
                    text("javascript:alert(1) </p><script>alert(1)</script>"),
                    Block::Link { label: "About".into(), href: "/about".into(), align: Align::Right },
                    Block::Link {
                        label: "Elsewhere".into(),
                        href: "http://exampleexampleexampleexampleexampleexampleexampleexa.onion/\"><script>".into(),
                        align: Align::Left,
                    },
                    Block::Divider,
                    Block::Columns { columns: vec![vec![text("left")], vec![text("right")]] },
                ],
            },
            Page { slug: "about".into(), title: "About".into(), template: None,
            blocks: vec![text("About us")] },
        ],
    }
}

async fn start() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, Live::new(site())));
    addr
}

/// Sends raw bytes and returns everything the server sends back before closing.
async fn raw(addr: std::net::SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn get(addr: std::net::SocketAddr, target: &str) -> String {
    raw(addr, format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes()).await
}

fn status(response: &str) -> &str {
    response.get(9..12).unwrap_or("")
}

/// Headers that would tell a visitor something about the host.
fn assert_no_host_details(response: &str) {
    let head = response.split("\r\n\r\n").next().unwrap().to_ascii_lowercase();
    for header in ["\r\ndate:", "\r\nserver:", "\r\netag:", "\r\nlast-modified:", "\r\nx-powered-by:", "\r\nvia:", "\r\nset-cookie:"] {
        assert!(!head.contains(header), "response exposes {header:?}:\n{head}");
    }
}

#[tokio::test]
async fn hostile_requests_get_nothing_useful() {
    let addr = start().await;

    for target in [
        "/../../etc/passwd",
        "/..%2f..%2fwindows%2fwin.ini",
        "/%2e%2e/%2e%2e/",
        "/about/../../secret",
        "//about",
        "/about/",
        "/ABOUT",
        "/index.html",
        "/style.css/..",
        "/%00",
        "/.git/config",
        "/C:/Windows/win.ini",
        "http://127.0.0.1/",
    ] {
        let response = get(addr, target).await;
        assert_eq!(status(&response), "404", "{target} was not refused:\n{response}");
        assert_no_host_details(&response);
    }

    // A query string must not change what is served or be reflected.
    let response = get(addr, "/about?q=%3Cscript%3Ealert(1)%3C/script%3E&next=//evil.example").await;
    assert_eq!(status(&response), "200");
    assert!(!response.contains("script") && !response.contains("evil"));

    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"] {
        let request = format!("{method} / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let response = raw(addr, request.as_bytes()).await;
        assert_eq!(status(&response), "405", "{method} was allowed");
        assert_no_host_details(&response);
    }

    // Requests the HTTP parser rejects before our code runs must not leak either.
    let huge = format!("GET / HTTP/1.1\r\nHost: x\r\nX-Pad: {}\r\n\r\n", "a".repeat(200_000));
    for request in [
        b"NOT HTTP AT ALL\r\n\r\n".to_vec(),
        huge.into_bytes(),
        vec![0u8; 4096],
    ] {
        let response = raw(addr, &request).await;
        assert!(!status(&response).starts_with('2'), "malformed request was served:\n{response}");
        assert_no_host_details(&response);
    }

    // Conditional and range requests must not reveal caching or file details.
    let request = b"GET / HTTP/1.1\r\nHost: x\r\nRange: bytes=0-10\r\nIf-None-Match: *\r\nIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n";
    let response = raw(addr, request).await;
    assert_eq!(status(&response), "200");
    assert!(!response.to_ascii_lowercase().contains("content-range"));
}

#[tokio::test]
async fn published_pages_cannot_run_code_or_call_out() {
    let addr = start().await;
    for path in ["/", "/about"] {
        let response = get(addr, path).await;
        assert_eq!(status(&response), "200");
        assert_no_host_details(&response);
        let body = response.split_once("\r\n\r\n").unwrap().1.to_ascii_lowercase();

        for forbidden in [
            "<script", "<iframe", "<object", "<embed", "<img", "<form", "<base", "<svg", "<style",
            " style=", "=\"javascript:", "=\"data:", "@import", " srcset", "http-equiv",
        ] {
            assert!(!body.contains(forbidden), "{path} contains {forbidden:?}:\n{body}");
        }
        // No event-handler attribute survives, whatever the author typed.
        for (at, _) in body.match_indices(" on") {
            let attribute: String = body[at + 1..].chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            let after = body[at + 1 + attribute.len()..].chars().next();
            let inside_tag = body[..at].rfind('<') > body[..at].rfind('>');
            assert!(!(inside_tag && after == Some('=')), "{path} has an event handler near: {}", &body[at..at + 30]);
        }
        // The only absolute addresses are links the author made to other onion sites.
        for (at, _) in body.match_indices("http") {
            let rest = &body[at..];
            if rest.starts_with("http://") || rest.starts_with("https://") {
                let host = rest.split("//").nth(1).unwrap().split(['/', '"', '&']).next().unwrap();
                assert!(host.ends_with(".onion"), "{path} references a clearnet host: {host}");
            }
        }
        // The only resource a page loads is its own stylesheet.
        assert_eq!(body.matches("<link").count(), 1);
        assert!(body.contains("<link rel=\"stylesheet\" href=\"/style.css\">"));
    }

    let response = get(addr, "/style.css").await;
    let css = response.split_once("\r\n\r\n").unwrap().1.to_ascii_lowercase();
    for forbidden in ["url(", "@import", "http", "expression(", "@font-face"] {
        assert!(!css.contains(forbidden), "stylesheet contains {forbidden:?}");
    }
}

#[tokio::test]
async fn idle_and_trickling_connections_are_dropped() {
    let addr = start().await;

    // Slowloris: start a request and never finish its headers.
    let mut slow = TcpStream::connect(addr).await.unwrap();
    slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
    // Keep-alive: finish one request, then hold the connection open in silence.
    let mut idle = TcpStream::connect(addr).await.unwrap();
    idle.write_all(b"GET /about HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();

    let started = Instant::now();
    for (name, stream) in [("trickling", &mut slow), ("idle", &mut idle)] {
        let mut sink = Vec::new();
        let closed = tokio::time::timeout(Duration::from_secs(25), stream.read_to_end(&mut sink)).await;
        assert!(closed.is_ok(), "a {name} connection was still open after {:?}", started.elapsed());
    }
}
