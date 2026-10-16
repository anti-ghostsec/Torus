//! Drives the real host program the way the editor does.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use torus_core::{Align, Block, Page, Site, Theme};
use torus_host_api::{Host, Sandbox, Target};

const HOST: &str = env!("CARGO_BIN_EXE_torus-host");

fn site(text: &str) -> Site {
    Site {
        title: "Host test".into(),
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

async fn fetch(address: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(address.trim_start_matches("http://")).await?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await?;
    let mut out = String::new();
    stream.read_to_string(&mut out).await?;
    Ok(out)
}

#[tokio::test]
async fn host_serves_republishes_and_dies_with_its_owner() {
    let host = Host::start(Path::new(HOST), None, None, Target::Loopback, site("first"), None).await.unwrap();
    let address = host.address().to_owned();
    assert!(fetch(&address).await.unwrap().contains("<p>first</p>"));

    host.publish(site("second")).await.unwrap();
    // The new pages travel over a pipe, so allow a moment for them to land.
    let mut page = String::new();
    for _ in 0..50 {
        page = fetch(&address).await.unwrap();
        if page.contains("<p>second</p>") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(page.contains("<p>second</p>"));

    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(host.status().reachable && !host.status().broken);

    drop(host);
    let mut gone = false;
    for _ in 0..50 {
        if fetch(&address).await.is_err() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "the site was still being served after the editor let go of it");
}

#[tokio::test]
async fn a_damaged_key_is_reported_not_served() {
    let dir = std::env::temp_dir().join(format!("torus-host-test-{}", std::process::id()));
    let target = Target::Onion { identity: vec![1, 2, 3], state_dir: dir.join("state"), cache_dir: dir.join("cache"), kept: None, kept_key: Vec::new() };
    let error = Host::start(Path::new(HOST), None, None, target, site("x"), None).await.err().unwrap();
    assert!(error.contains("damaged"), "unexpected error: {error}");
}

/// The one folder a confined host may use in these tests.
fn sandbox_folder(container: &str) -> std::path::PathBuf {
    let folder = std::env::temp_dir().join(container);
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// Whether this kernel can confine files at all (Landlock). Containers and
/// old kernels may not; the editor refuses to publish there, and the file
/// checks below are skipped.
fn files_can_be_confined() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // landlock_create_ruleset(NULL, 0, VERSION) answers with the version.
        (unsafe { libc::syscall(444, std::ptr::null::<u8>(), 0usize, 1u32) }) >= 1
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        true
    }
}

/// The promise of the sandbox, checked from the inside: a confined host is
/// asked to open files and must fail on anything outside its own folder.
#[tokio::test]
async fn a_confined_host_cannot_open_the_users_files() {
    if !files_can_be_confined() {
        eprintln!("skipped: this kernel cannot confine files");
        return;
    }
    let container = format!("torus.test-{}", std::process::id());
    let folder = sandbox_folder(&container);
    let secret = std::env::temp_dir().join(format!("torus-secret-{}.txt", std::process::id()));
    std::fs::write(&secret, "stands in for the vault").unwrap();
    // A file that already exists outside any container: this test program.
    let program = std::env::current_exe().unwrap();

    // Without confinement the same program opens the file without trouble.
    let free = Host::start(Path::new(HOST), None, None, Target::Loopback, site("x"), None).await.unwrap();
    assert!(free.can_read(&secret).await.unwrap(), "the control case should be able to read the file");
    assert!(free.can_read(&program).await.unwrap(), "the control case should be able to read the program");
    drop(free);

    let sandbox = Sandbox { name: &container, folder: &folder };
    let host = Host::start(Path::new(HOST), Some(sandbox), None, Target::Loopback, site("x"), None).await.unwrap();
    assert!(!host.can_read(&secret).await.unwrap(), "a confined host read a file in the user's temp folder");
    assert!(!host.can_read(&program).await.unwrap(), "a confined host read a program beside its own");

    // Its own folder is the one place it may use.
    let own = folder.join("note.txt");
    std::fs::write(&own, "mine").unwrap();
    assert!(host.can_read(&own).await.unwrap(), "a confined host could not read its own folder");

    drop(host);
    torus_host_api::remove_container(&container, &[Path::new(HOST)]);
    let _ = std::fs::remove_dir_all(&folder);
    let _ = std::fs::remove_file(secret);
}

/// The process that decodes visitors' videos can reach nothing: not a
/// listener on this machine, not the internet, not a file.
#[test]
fn a_converter_can_reach_neither_the_network_nor_files() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let secret = std::env::temp_dir().join(format!("torus-converter-secret-{}.txt", std::process::id()));
    std::fs::write(&secret, "stands in for the vault").unwrap();

    // The same questions asked from here are answered yes, so a no means something.
    let free = torus_host::media::reach(port, &secret);
    assert!(free[0] && free[2], "the control case reaches the listener and the file: {free:?}");

    let container = format!("torus.test-conv-{}", std::process::id());
    // Any program will do as the one it may run; this test never converts.
    let (mut from, mut to, keeper) = torus_host_api::converter_alone(Path::new(HOST), &container, Path::new(HOST), &sandbox_folder(&container)).unwrap();
    let path = secret.to_string_lossy().into_owned();
    to.write_all(&[torus_host::media::PROBE]).unwrap();
    to.write_all(&u32::from(port).to_le_bytes()).unwrap();
    to.write_all(&(path.len() as u32).to_le_bytes()).unwrap();
    to.write_all(path.as_bytes()).unwrap();
    to.write_all(&0u32.to_le_bytes()).unwrap();
    to.flush().unwrap();
    let mut answer = [0u8; 4 + 3 + 4 + 1];
    from.read_exact(&mut answer).unwrap();
    assert_eq!(answer[..4], 3u32.to_le_bytes());
    let file_expected = u8::from(!files_can_be_confined());
    assert_eq!(answer[4..7], [0, 0, file_expected], "the converter reached the listener, the internet or the file, in that order");
    assert_eq!(answer[7..], [0, 0, 0, 0, 1]);

    drop(keeper);
    torus_host_api::remove_container(&format!("torus.test-conv-{}", std::process::id()), &[Path::new(HOST)]);
    let _ = std::fs::remove_file(secret);
}

/// Housekeeping: removes containers that failed test runs left behind.
#[cfg(windows)]
#[test]
#[ignore = "maintenance; run by hand"]
fn remove_leftover_test_containers() {
    let packages = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap()).join("Packages");
    for entry in std::fs::read_dir(packages).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("torus.test-") || name.starts_with("torus.live-") {
            println!("removing {name}");
            torus_host_api::remove_container(&name, &[]);
        }
    }
}

/// Forms work through the real host program, and what visitors submit
/// survives the host being stopped and started again.
#[tokio::test]
async fn submissions_are_kept_across_host_restarts() {
    use torus_core::{Collection, Field, FieldKind};
    use torus_host_api::Records;

    let mut guestbook = site("x");
    guestbook.collections.push(Collection {
        name: "notes".into(), parent: None, members_only: false,
                once_each: false, review: false,
                sealed: false,
        fields: vec![Field { name: "name".into(), label: "Name".into(), kind: FieldKind::Text, required: true }],
    });
    guestbook.pages[0].blocks = vec![
        Block::Form { collection: "notes".into(), submit_label: "Sign".into() },
        Block::List {
            collection: "notes".into(),
            newest_first: true,
            limit: 10,
                        layout: Default::default(),
                        scope: Default::default(),
                        active_first: false,
                        paged: false,
            blocks: vec![Block::Field { field: "name".into(), level: 2, align: Align::Left, preview: false }],
        },
    ];
    let file = std::env::temp_dir().join(format!("torus-host-records-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&file);
    let records = || Some(Records { file: file.clone(), key: vec![9; 32] });

    let host = Host::start(Path::new(HOST), None, None, Target::Loopback, guestbook.clone(), records()).await.unwrap();
    let address = host.address().trim_start_matches("http://").to_owned();
    let mut stream = TcpStream::connect(&address).await.unwrap();
    let body = "_next=%2F&name=Persistent+visitor";
    let request = format!(
        "POST /_form/notes HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 303"), "unexpected answer:\n{answer}");
    assert!(fetch(host.address()).await.unwrap().contains("<h2>Persistent visitor</h2>"));
    drop(host);

    // A host with the wrong key refuses to start rather than serve an empty site.
    let wrong = Some(Records { file: file.clone(), key: vec![1; 32] });
    assert!(Host::start(Path::new(HOST), None, None, Target::Loopback, guestbook.clone(), wrong).await.is_err());

    let again = Host::start(Path::new(HOST), None, None, Target::Loopback, guestbook, records()).await.unwrap();
    assert!(fetch(again.address()).await.unwrap().contains("<h2>Persistent visitor</h2>"));
    let on_disk = std::fs::read(&file).unwrap();
    assert!(!on_disk.windows(10).any(|w| w == b"Persistent"));
    drop(again);
    let _ = std::fs::remove_file(file);
}

/// The editor can ask a running host what visitors added, and have it removed.
#[tokio::test]
async fn the_owner_can_list_and_remove_what_was_added() {
    use torus_core::{Collection, Field, FieldKind};

    let mut guestbook = site("x");
    guestbook.collections.push(Collection {
        name: "notes".into(),
        parent: None,
        members_only: false,
                once_each: false, review: false,
                sealed: false,
        fields: vec![Field { name: "name".into(), label: "Name".into(), kind: FieldKind::Text, required: true }],
    });
    guestbook.pages[0].blocks = vec![Block::Form { collection: "notes".into(), submit_label: "Sign".into() }];
    let host = Host::start(Path::new(HOST), None, None, Target::Loopback, guestbook, None).await.unwrap();
    assert!(host.records("notes").await.unwrap().is_empty());

    let mut stream = TcpStream::connect(host.address().trim_start_matches("http://")).await.unwrap();
    let body = "name=Unwanted";
    let request = format!(
        "POST /_form/notes HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();

    let records = host.records("notes").await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].fields["name"], "Unwanted");
    assert!(host.remove("notes", &records[0].id).await.unwrap());
    assert!(!host.remove("notes", &records[0].id).await.unwrap());
    assert!(host.records("notes").await.unwrap().is_empty());
}

/// A real video, with what a phone writes about where and on what it was
/// recorded, goes through the real converter in its sandbox and comes back
/// as a clean VP9 WebM with none of it.
#[cfg(target_os = "linux")]
#[test]
fn a_real_video_is_encoded_afresh_in_the_sandbox() {
    use std::io::{Read, Write};
    let ffmpeg = Path::new("/usr/bin/ffmpeg");
    if !ffmpeg.is_file() {
        eprintln!("skipped: no ffmpeg on this system");
        return;
    }
    let made = std::env::temp_dir().join(format!("torus-phone-{}.mp4", std::process::id()));
    let status = std::process::Command::new(ffmpeg)
        .args(["-y", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=1920x1080:rate=30", "-f", "lavfi"])
        .args(["-i", "sine=frequency=440", "-t", "2", "-c:v", "mpeg4", "-c:a", "aac", "-movflags", "+faststart"])
        .args(["-metadata", "title=SECRET-TITLE", "-metadata", "location=+51.5007-000.1246/", "-metadata", "comment=SECRET-PHONE"])
        .arg(&made)
        .status()
        .unwrap();
    assert!(status.success());
    let video = std::fs::read(&made).unwrap();
    assert!(video.windows(6).any(|w| w == b"SECRET"));

    let container = format!("torus.test-real-{}", std::process::id());
    let (mut from, mut to, keeper) = torus_host_api::converter_alone(Path::new(HOST), &container, ffmpeg, &sandbox_folder(&container)).unwrap();
    // A request: re-encode whole (3), then the video in pieces, then the end.
    to.write_all(&[3, 0, 0, 0, 0]).unwrap();
    let sending = std::thread::spawn(move || {
        for piece in video.chunks(64 * 1024) {
            to.write_all(&(piece.len() as u32).to_le_bytes()).unwrap();
            to.write_all(piece).unwrap();
        }
        to.write_all(&0u32.to_le_bytes()).unwrap();
        to.flush().unwrap();
        to
    });
    let mut out = Vec::new();
    loop {
        let mut length = [0u8; 4];
        from.read_exact(&mut length).unwrap();
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 {
            break;
        }
        let mut piece = vec![0u8; length];
        from.read_exact(&mut piece).unwrap();
        out.extend_from_slice(&piece);
    }
    let mut worked = [0u8];
    from.read_exact(&mut worked).unwrap();
    let _to = sending.join().unwrap();
    assert_eq!(worked, [1], "the conversion failed");
    assert!(out.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]), "not a WebM");
    assert!(out.windows(5).any(|w| w == b"V_VP9"), "not VP9");
    assert!(out.windows(6).any(|w| w == b"A_OPUS"), "no Opus sound");
    // The upload's own encoder and version; the converter writes a bare "Lavf", the same for every video.
    for secret in [b"SECRET".as_slice(), b"51.5007", b"Lavf6", b"testsrc"] {
        assert!(!out.windows(secret.len()).any(|w| w == secret), "{:?} survived", String::from_utf8_lossy(secret));
    }
    drop(keeper);
    let _ = std::fs::remove_file(made);
}
