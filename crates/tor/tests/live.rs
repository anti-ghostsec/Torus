//! End-to-end check against the real Tor network. It publishes a throwaway
//! site built by the Torus compiler as an onion service from this machine,
//! then visits it through Tor the way a stranger would and inspects every
//! byte that comes back.
//!
//! Run it deliberately: `cargo test -p torus-tor --test live -- --ignored --nocapture`

use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_rtcompat::PreferredRuntime;
use torus_core::{Align, Block, Page, Site, Theme};
use torus_runtime::Live;
use torus_tor::{new_identity, Tor};

fn site() -> Site {
    let text = |t: &str| Block::Text { text: t.into(), align: Align::Left };
    Site {
        title: "Live test".into(),
        theme: Theme::default(),
        collections: vec![],
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        pages: vec![
            Page {
                slug: "index".into(),
                title: "Home".into(),
                template: None,
            blocks: vec![
                    Block::Heading { level: 1, text: "hello from the onion".into(), align: Align::Center },
                    text("<script>alert(1)</script>"),
                    Block::Link { label: "About".into(), href: "/about".into(), align: Align::Left },
                ],
            },
            Page { slug: "about".into(), title: "About".into(), template: None,
            blocks: vec![text("second page")] },
        ],
    }
}

/// One request on a fresh Tor stream, read until the server ends it.
async fn visit(visitor: &TorClient<PreferredRuntime>, address: &str, request: &str) -> Option<String> {
    let mut stream = match visitor.connect((address, 80)).await {
        Ok(stream) => stream,
        Err(e) => {
            println!("could not connect: {e}");
            return None;
        }
    };
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // Arti ends every stream with a generic reason, which its own client
        // reports as an error where a browser sees an ordinary close.
        match tokio::time::timeout(Duration::from_secs(60), stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => received.extend_from_slice(&chunk[..n]),
            Ok(_) => break,
            Err(_) => panic!("the server left the stream open"),
        }
    }
    Some(String::from_utf8(received).unwrap())
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n")
}

fn header_names(response: &str) -> Vec<String> {
    let head = response.split("\r\n\r\n").next().unwrap();
    let mut names: Vec<String> = head
        .lines()
        .skip(1)
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        .filter(|name| name != "connection")
        .collect();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "connects to the real Tor network and takes a few minutes"]
async fn a_published_site_survives_a_visit_over_tor() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();
    let dir = std::env::temp_dir().join(format!("torus-tor-test-{}", std::process::id()));

    let identity = new_identity().unwrap();
    let tor = Tor::connect(&dir.join("state"), &dir.join("cache")).await.unwrap();
    let onion = tor.launch("test", &identity, Live::new(site())).unwrap();
    let address = onion.address().to_owned();
    println!("address: {address}");

    // The status can lag behind real reachability, so wait a while and then
    // judge by an actual visit.
    for _ in 0..30 {
        if onion.reachable() {
            break;
        }
        assert!(!onion.broken(), "the service broke while starting");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    println!("state before visiting: {}", onion.state());

    let config = TorClientConfigBuilder::from_directories(dir.join("visitor-state"), dir.join("visitor-cache"))
        .build()
        .unwrap();
    let visitor = TorClient::create_bootstrapped(config).await.unwrap();

    let mut home = None;
    for attempt in 1..=6 {
        home = visit(&visitor, &address, &get("/")).await;
        if home.is_some() {
            break;
        }
        println!("attempt {attempt} failed; service state {}", onion.state());
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let home = home.expect("the site was never reachable over Tor");
    println!("{home}");

    let fixed = [
        "cache-control",
        "content-length",
        "content-security-policy",
        "content-type",
        "referrer-policy",
        "x-content-type-options",
    ];
    assert!(home.starts_with("HTTP/1.1 200"));
    assert_eq!(header_names(&home), fixed);
    assert!(home.contains("<h1 class=\"center\">hello from the onion</h1>"));
    assert!(home.ends_with("</html>\n"), "the page arrived cut short");
    assert!(!home.contains("<script"));

    let about = visit(&visitor, &address, &get("/about")).await.unwrap();
    assert!(about.starts_with("HTTP/1.1 200") && about.contains("second page"));

    let css = visit(&visitor, &address, &get("/style.css")).await.unwrap();
    assert!(css.starts_with("HTTP/1.1 200") && css.contains("text/css"));

    // Nothing this machine knows about itself may reach a visitor.
    let machine = std::env::var("COMPUTERNAME").unwrap_or_default().to_ascii_lowercase();
    let user = std::env::var("USERNAME").unwrap_or_default().to_ascii_lowercase();
    for (name, response) in [("home", &home), ("about", &about), ("css", &css)] {
        let lower = response.to_ascii_lowercase();
        for leak in ["127.0.0.1", "localhost", "192.168.", "10.0.", "c:\\", "/users/", "windows", "hyper", "arti", "torus"] {
            assert!(!lower.contains(leak), "{name} mentions {leak:?}");
        }
        for leak in [&machine, &user] {
            assert!(leak.len() < 3 || !lower.contains(leak.as_str()), "{name} mentions this machine or user");
        }
    }

    for (request, expected) in [
        (get("/../../windows/win.ini"), "404"),
        (get("/.git/config"), "404"),
        (get("http://127.0.0.1/"), "404"),
        ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(), "405"),
    ] {
        let response = visit(&visitor, &address, &request).await.unwrap();
        assert_eq!(response.get(9..12), Some(expected), "unexpected answer to {request:?}:\n{response}");
        assert!(!response.to_ascii_lowercase().contains("\r\ndate:"));
    }
    println!("all checks passed over Tor");

    drop(onion);
    let _ = std::fs::remove_dir_all(&dir);
}
