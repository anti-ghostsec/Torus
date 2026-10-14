//! Drives the real host program the way the editor does.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use torus_core::{Align, Block, Page, Site, Theme};
use torus_host_api::{Host, Target};

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
    let target = Target::Onion { identity: vec![1, 2, 3], state_dir: dir.join("state"), cache_dir: dir.join("cache") };
    let error = Host::start(Path::new(HOST), None, None, target, site("x"), None).await.err().unwrap();
    assert!(error.contains("damaged"), "unexpected error: {error}");
}

/// The promise of the sandbox, checked from the inside: a confined host is
/// asked to open files and must fail on anything outside its own folder.
#[cfg(windows)]
#[tokio::test]
async fn a_confined_host_cannot_open_the_users_files() {
    let container = format!("torus.test-{}", std::process::id());
    let secret = std::env::temp_dir().join(format!("torus-secret-{}.txt", std::process::id()));
    std::fs::write(&secret, "stands in for the vault").unwrap();
    // A file that already exists outside any container: this test program.
    let program = std::env::current_exe().unwrap();

    // Without confinement the same program opens the file without trouble.
    let free = Host::start(Path::new(HOST), None, None, Target::Loopback, site("x"), None).await.unwrap();
    assert!(free.can_read(&secret).await.unwrap(), "the control case should be able to read the file");
    assert!(free.can_read(&program).await.unwrap(), "the control case should be able to read the program");
    drop(free);

    let host = Host::start(Path::new(HOST), Some(&container), None, Target::Loopback, site("x"), None).await.unwrap();
    assert!(!host.can_read(&secret).await.unwrap(), "a confined host read a file in the user's temp folder");
    assert!(!host.can_read(&program).await.unwrap(), "a confined host read a program beside its own");

    // Its own folder is the one place it may use.
    let own = torus_host_api::container_folder(&container).unwrap().join("note.txt");
    std::fs::write(&own, "mine").unwrap();
    assert!(host.can_read(&own).await.unwrap(), "a confined host could not read its own folder");

    drop(host);
    torus_host_api::remove_container(&container);
    let _ = std::fs::remove_file(secret);
}

/// The process that decodes visitors' videos can reach nothing: not a
/// listener on this machine, not the internet, not a file.
#[cfg(windows)]
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
    let (mut from, mut to, keeper) = torus_host_api::converter_alone(Path::new(HOST), &container, Path::new(HOST)).unwrap();
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
    assert_eq!(answer[4..7], [0, 0, 0], "the converter reached the listener, the internet or the file, in that order");
    assert_eq!(answer[7..], [0, 0, 0, 0, 1]);

    drop(keeper);
    torus_host_api::remove_container(&format!("torus.test-conv-{}", std::process::id()));
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
            torus_host_api::remove_container(&name);
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
