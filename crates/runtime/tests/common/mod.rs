//! A bare-bones HTTP client and helpers shared by the tests that use a site as its visitors would.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use torus_core::Site;
use torus_runtime::{serve, Live};

/// Serves a site whose data lives in memory, and returns where.
pub async fn start(site: Site) -> (SocketAddr, Live) {
    let live = Live::new(site);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(listener, live.clone()));
    (addr, live)
}

/// Creates an account and returns its session cookie and form token.
pub async fn join(addr: SocketAddr, name: &str) -> (String, String) {
    let joined = post(addr, SIGN_UP, None, &[("name", name), ("_password", "correct horse battery")]).await;
    let cookie = joined.cookie().expect("a session");
    let token = after(&get(addr, "/account", Some(&cookie)).await.text(), "name=\"_token\"", "value").to_owned();
    (cookie, token)
}

pub struct Answer {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| line.strip_prefix(&format!("{name}: ")))
    }

    /// The session cookie this answer set, if any.
    pub fn cookie(&self) -> Option<String> {
        let value = self.header("set-cookie")?.split(';').next()?.strip_prefix("s=")?;
        Some(value.to_owned())
    }
}

pub async fn send(addr: SocketAddr, request: Vec<u8>) -> Answer {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&request).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut raw)).await;
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("a complete response");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    Answer { status, head, body: raw[split + 4..].to_vec() }
}

pub fn request(method: &str, path: &str, cookie: Option<&str>, extra: &str, body: &[u8]) -> Vec<u8> {
    let cookie = cookie.map(|c| format!("Cookie: s={c}\r\n")).unwrap_or_default();
    let mut out = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{cookie}{extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

pub async fn get(addr: SocketAddr, path: &str, cookie: Option<&str>) -> Answer {
    send(addr, request("GET", path, cookie, "", b"")).await
}

pub async fn get_range(addr: SocketAddr, path: &str, range: &str) -> Answer {
    send(addr, request("GET", path, None, &format!("Range: {range}\r\n"), b"")).await
}

pub fn encode(value: &str) -> String {
    value.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

pub async fn post(addr: SocketAddr, path: &str, cookie: Option<&str>, fields: &[(&str, &str)]) -> Answer {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("{k}={}", encode(v))).collect();
    let extra = "Content-Type: application/x-www-form-urlencoded\r\n";
    send(addr, request("POST", path, cookie, extra, body.join("&").as_bytes())).await
}

pub enum Part<'a> {
    Text(&'a str, &'a str),
    File(&'a str, &'a [u8]),
}

pub async fn upload(addr: SocketAddr, path: &str, cookie: Option<&str>, parts: &[Part<'_>]) -> Answer {
    let boundary = "----torusTestBoundary7MA4YWxk";
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match part {
            Part::Text(name, value) => {
                body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}").as_bytes());
            }
            Part::File(name, contents) => {
                let head = format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"C:\\Users\\someone\\secret name.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                );
                body.extend_from_slice(head.as_bytes());
                body.extend_from_slice(contents);
            }
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let extra = format!("Content-Type: multipart/form-data; boundary={boundary}\r\n");
    send(addr, request("POST", path, cookie, &extra, &body)).await
}

/// The value of the first `attribute="…"` after `marker` in a page.
pub fn after<'a>(page: &'a str, marker: &str, attribute: &str) -> &'a str {
    let rest = &page[page.find(marker).unwrap_or_else(|| panic!("{marker:?} not in page:\n{page}"))..];
    let start = rest.find(&format!("{attribute}=\"")).expect("the attribute") + attribute.len() + 2;
    &rest[start..start + rest[start..].find('"').unwrap()]
}

/// Bytes that start like an MP4 and then never repeat, so any mix-up of
/// positions shows.
pub fn fake_video(len: usize) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0x18];
    out.extend_from_slice(b"ftypmp42");
    let mut state = 0x1234_5678_u32;
    while out.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 24) as u8);
    }
    out
}

/// A small PNG carrying a text note, as a camera or editor might leave one.
pub fn picture_with_hidden_note() -> Vec<u8> {
    let mut png = std::io::Cursor::new(Vec::new());
    image::RgbImage::from_fn(40, 30, |x, y| image::Rgb([x as u8 * 6, y as u8 * 8, 90]))
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    let mut png = png.into_inner();
    let note = b"Comment\0taken at 51.5007N 0.1246W by SECRET-CAMERA";
    let mut chunk = (note.len() as u32).to_be_bytes().to_vec();
    let mut typed = b"tEXt".to_vec();
    typed.extend_from_slice(note);
    chunk.extend_from_slice(&typed);
    chunk.extend_from_slice(&crc32fast::hash(&typed).to_be_bytes());
    // Goes just before the closing IEND chunk, which is the last 12 bytes.
    let end = png.len() - 12;
    png.splice(end..end, chunk);
    png
}


pub const SIGN_UP: &str = "/_account/signup";
pub const SIGN_IN: &str = "/_account/signin";
pub const SIGN_OUT: &str = "/_account/signout";
