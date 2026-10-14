//! The whole publishing path against the real Tor network: a key made the
//! way the editor makes it, handed to the real host program running in its
//! sandbox, then the video-site starter used through Tor by a stranger:
//! create an account, upload a video, watch part of it.
//!
//! Run it deliberately: `cargo test -p torus-host --test live -- --ignored --nocapture`

use std::path::Path;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_rtcompat::PreferredRuntime;
use torus_core::starters::video_site;
use torus_host_api::{Host, Records, Target};

const HOST: &str = env!("CARGO_BIN_EXE_torus-host");

struct Answer {
    head: String,
    body: Vec<u8>,
}

impl Answer {
    fn status(&self) -> &str {
        self.head.get(9..12).unwrap_or("")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| line.strip_prefix(&format!("{name}: ")))
    }
}

/// One request on a fresh Tor stream. `None` if the site could not be reached.
async fn send(visitor: &TorClient<PreferredRuntime>, address: &str, request: &[u8]) -> Option<Answer> {
    let mut stream = visitor.connect((address, 80)).await.ok()?;
    stream.write_all(request).await.ok()?;
    stream.flush().await.ok()?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    // Arti's client reports the ordinary end of a stream as an error.
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(90), stream.read(&mut chunk)).await {
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some(Answer { head: String::from_utf8_lossy(&raw[..split]).into_owned(), body: raw[split + 4..].to_vec() })
}

fn request(method: &str, path: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out =
        format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{extra}Content-Length: {}\r\n\r\n", body.len())
            .into_bytes();
    out.extend_from_slice(body);
    out
}

fn after<'a>(page: &'a str, marker: &str, attribute: &str) -> &'a str {
    let rest = &page[page.find(marker).unwrap_or_else(|| panic!("{marker:?} not in page:\n{page}"))..];
    let start = rest.find(&format!("{attribute}=\"")).expect("the attribute") + attribute.len() + 2;
    &rest[start..start + rest[start..].find('"').unwrap()]
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "connects to the real Tor network and takes a few minutes"]
async fn a_sandboxed_video_site_works_over_tor() {
    let dir = std::env::temp_dir().join(format!("torus-host-live-{}", std::process::id()));
    let identity = torus_onion_key::new_identity().unwrap();
    let expected = torus_onion_key::address(&identity);

    // Confined wherever the sandbox exists, with all its files inside the container.
    let container = torus_host_api::sandbox_available().then(|| format!("torus.live-{}", std::process::id()));
    let folder = match &container {
        Some(name) => torus_host_api::container_folder(name).unwrap().join("tor"),
        None => dir.clone(),
    };
    // A confined process cannot create folders by walking down from the
    // drive, so they are made for it.
    std::fs::create_dir_all(folder.join("state")).unwrap();
    std::fs::create_dir_all(folder.join("cache")).unwrap();
    let target = Target::Onion { identity: identity.to_vec(), state_dir: folder.join("state"), cache_dir: folder.join("cache") };
    let records_file = folder.join("records.bin");
    let records = Records { file: records_file.clone(), key: vec![5; 32] };
    // With the converter present, pictures and smaller sizes are made too.
    let ffmpeg = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ffmpeg/ffmpeg.exe");
    let converter = ffmpeg.is_file().then_some(ffmpeg.as_path());
    let host =
        Host::start(Path::new(HOST), container.as_deref(), converter, target, video_site(), Some(records)).await.unwrap();
    println!("address: {}", host.address());
    assert_eq!(host.address(), expected, "Tor published at a different address than the editor shows");
    if container.is_some() {
        let outside = std::env::temp_dir().join("torus-live-outside.txt");
        std::fs::write(&outside, "x").unwrap();
        assert!(!host.can_read(&outside).await.unwrap(), "the confined host read a file outside its container");
        let _ = std::fs::remove_file(outside);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = TorClientConfigBuilder::from_directories(dir.join("visitor-state"), dir.join("visitor-cache"))
        .build()
        .unwrap();
    let visitor = TorClient::create_bootstrapped(config).await.unwrap();

    let mut home = None;
    for attempt in 1..=12 {
        println!("attempt {attempt}; host says {:?}", host.status());
        assert!(!host.status().broken, "the host process stopped");
        home = send(&visitor, &expected, &request("GET", "/", "", b"")).await;
        if home.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    let home = home.expect("the site was never reachable over Tor");
    assert_eq!(home.status(), "200");
    assert!(String::from_utf8_lossy(&home.body).contains("Latest videos"));
    assert!(!home.head.to_ascii_lowercase().contains("\r\ndate:"));

    // Create an account.
    let form = "Content-Type: application/x-www-form-urlencoded\r\n";
    let joined = send(
        &visitor,
        &expected,
        &request("POST", "/_account/signup", form, b"_next=%2Faccount&name=Stranger&_password=correct+horse+battery"),
    )
    .await
    .unwrap();
    assert_eq!(joined.status(), "303", "{}", String::from_utf8_lossy(&joined.body));
    let cookie = joined.header("set-cookie").and_then(|v| v.split(';').next()).expect("a session cookie").to_owned();
    let cookie = format!("Cookie: {cookie}\r\n");
    let account = send(&visitor, &expected, &request("GET", "/account", &cookie, b"")).await.unwrap();
    let account = String::from_utf8_lossy(&account.body).into_owned();
    let token = after(&account, "name=\"_token\"", "value").to_owned();

    // Upload a small video.
    let mut video = vec![0, 0, 0, 0x18];
    video.extend_from_slice(b"ftypmp42");
    video.extend((0..200_000u32).map(|n| (n.wrapping_mul(2_654_435_761) >> 24) as u8));
    let boundary = "----torusLiveBoundary";
    let mut body = Vec::new();
    for (name, value) in [("_token", token.as_str()), ("_next", "/upload"), ("title", "Sent over Tor")] {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"video\"; filename=\"v.mp4\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&video);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let multipart = format!("{cookie}Content-Type: multipart/form-data; boundary={boundary}\r\n");
    let uploaded = send(&visitor, &expected, &request("POST", "/_form/videos", &multipart, &body)).await.unwrap();
    assert_eq!(uploaded.status(), "303", "{}", String::from_utf8_lossy(&uploaded.body));

    // Find it on the home page and watch a part from the middle.
    let home = send(&visitor, &expected, &request("GET", "/", "", b"")).await.unwrap();
    let home = String::from_utf8_lossy(&home.body).into_owned();
    assert!(home.contains("Sent over Tor") && home.contains(">Stranger</a>"));
    let watch_path = after(&home, "class=\"button\" href=\"/watch/", "href").to_owned();
    let watch = send(&visitor, &expected, &request("GET", &watch_path, "", b"")).await.unwrap();
    let file_path = after(&String::from_utf8_lossy(&watch.body), "<video", "src").to_owned();
    let part = send(&visitor, &expected, &request("GET", &file_path, "Range: bytes=70000-70999\r\n", b"")).await.unwrap();
    assert_eq!(part.status(), "206");
    assert_eq!(part.header("content-range"), Some(format!("bytes 70000-70999/{}", video.len()).as_str()));
    assert!(part.body == video[70_000..71_000], "the wrong part of the video came back");

    // What the host stored is unreadable from outside it.
    let stored = std::fs::read(&records_file).expect("the host wrote its data file");
    assert!(!stored.windows(8).any(|w| w == b"Stranger"), "the data file is readable on disk");
    let mut files = std::path::PathBuf::from(&records_file).into_os_string();
    files.push(".files");
    let file = std::fs::read_dir(&files).unwrap().flatten().next().expect("the stored video");
    assert!(!std::fs::read(file.path()).unwrap().windows(8).any(|w| w == b"ftypmp42"), "the stored video is readable on disk");
    println!("an account was created and a video uploaded and watched, all over Tor, in the sandbox");

    if let (Some(ffmpeg), true) = (converter, container.is_some()) {
        // A real video this time, with its index at the end as cameras write it.
        std::fs::create_dir_all(&dir).unwrap();
        let made = dir.join("real.mp4");
        let source = ["-f", "lavfi", "-i", "testsrc2=size=1600x900:rate=30:duration=3", "-f", "lavfi", "-i", "sine=frequency=440:duration=3"];
        let encode = ["-c:v", "mpeg4", "-q:v", "2", "-c:a", "aac", "-metadata", "title=SECRETTITLE", "-y"];
        let ran = std::process::Command::new(ffmpeg).args(["-loglevel", "error"]).args(source).args(encode).arg(&made).status().unwrap();
        assert!(ran.success());
        let real = std::fs::read(&made).unwrap();
        println!("uploading a real video of {} bytes", real.len());
        let mut body = Vec::new();
        for (name, value) in [("_token", token.as_str()), ("_next", "/upload"), ("title", "A real one")] {
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"video\"; filename=\"v.mp4\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(&real);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let uploaded = send(&visitor, &expected, &request("POST", "/_form/videos", &multipart, &body)).await.unwrap();
        assert_eq!(uploaded.status(), "303", "{}", String::from_utf8_lossy(&uploaded.body));

        // Everything is made in the background, by the converter that has no network.
        let mut watch = String::new();
        for attempt in 1..=60 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            assert!(!host.status().broken, "the host process stopped");
            let Some(home) = send(&visitor, &expected, &request("GET", "/", "", b"")).await else { continue };
            let home = String::from_utf8_lossy(&home.body).into_owned();
            let card = &home[home.find("A real one").map_or(0, |at| home[..at].rfind("<article").unwrap_or(0))..];
            let path = after(card, "class=\"button\" href=\"/watch/", "href").to_owned();
            let Some(page) = send(&visitor, &expected, &request("GET", &path, "", b"")).await else { continue };
            watch = String::from_utf8_lossy(&page.body).into_owned();
            println!("attempt {attempt}: picture {}, sizes {}, smaller encoding {}", home.contains("<img class=\"preview\""), watch.contains("Watch in:"), watch.contains("720p"));
            // The last thing made is the smaller encoding, which changes the download.
            if watch.contains("360p") && watch.contains("720p") && home.contains("<img class=\"preview\"") {
                let download = after(&watch, "Full size", "href").to_owned();
                let kind = send(&visitor, &expected, &request("GET", &download, "Range: bytes=0-3\r\n", b"")).await;
                if kind.is_some_and(|k| k.header("content-type") == Some("video/webm")) {
                    break;
                }
            }
        }
        let home = send(&visitor, &expected, &request("GET", "/", "", b"")).await.unwrap();
        let home = String::from_utf8_lossy(&home.body).into_owned();
        let still = send(&visitor, &expected, &request("GET", after(&home, "<img class=\"preview\"", "src"), "", b"")).await.unwrap();
        assert_eq!(still.header("content-type"), Some("image/jpeg"));
        assert!(still.body.starts_with(&[0xFF, 0xD8]), "the card picture is not a JPEG");
        println!("the card picture is {} bytes", still.body.len());
        assert!(watch.contains("<strong>720p</strong>"), "{watch}");
        for chosen in [after(&watch, "<video controls", "src").to_owned(), after(&watch, "Full size", "href").to_owned()] {
            let whole = send(&visitor, &expected, &request("GET", &chosen, "", b"")).await.unwrap();
            assert_eq!(whole.header("content-type"), Some("video/webm"));
            assert!(whole.body.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]));
            assert!(whole.body.windows(4).any(|w| w == [0x1C, 0x53, 0xBB, 0x6B]), "no cues: it could not be skipped around in");
            assert!(!whole.body.windows(11).any(|w| w == b"SECRETTITLE"));
            println!("{chosen}: {} bytes, against {} uploaded", whole.body.len(), real.len());
            assert!(whole.body.len() < real.len());
        }
        println!("a real video got its picture, its sizes and a smaller encoding from the confined converter");
    }

    drop(host);
    if let Some(name) = &container {
        torus_host_api::remove_container(name);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
