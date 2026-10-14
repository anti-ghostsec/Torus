use torus_core::{Align, Block, Page, Site, Theme};
use torus_runtime::{serve, Live};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn site(text: &str) -> Site {
    Site {
        title: "Test".into(),
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

async fn request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    out
}

fn header_names(response: &str) -> Vec<String> {
    let head = response.split("\r\n\r\n").next().unwrap();
    let mut names: Vec<String> = head
        .lines()
        .skip(1)
        .map(|l| l.split(':').next().unwrap().to_ascii_lowercase())
        // Echoed only because the test client asks for `Connection: close`.
        .filter(|name| name != "connection")
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn responses_carry_only_the_fixed_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let live = Live::new(site("first"));
    let server = tokio::spawn(serve(listener, live.clone()));

    let fixed = [
        "cache-control",
        "content-length",
        "content-security-policy",
        "content-type",
        "referrer-policy",
        "x-content-type-options",
    ];

    let ok = request(addr, "GET", "/").await;
    assert!(ok.starts_with("HTTP/1.1 200"));
    assert!(ok.contains("<p>first</p>"));
    assert_eq!(header_names(&ok), fixed);

    let missing = request(addr, "GET", "/../secret").await;
    assert!(missing.starts_with("HTTP/1.1 404"));
    assert_eq!(header_names(&missing), fixed);

    let post = request(addr, "POST", "/").await;
    assert!(post.starts_with("HTTP/1.1 405"));

    let head = request(addr, "HEAD", "/").await;
    assert!(head.starts_with("HTTP/1.1 200"));
    assert!(head.ends_with("\r\n\r\n"));

    live.publish(site("second"));
    assert!(request(addr, "GET", "/").await.contains("<p>second</p>"));

    server.abort();
}
