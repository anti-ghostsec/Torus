//! A Monero node's RPC, spoken over any stream: plain HTTP, one request
//! per connection. Kept apart from everything else so that the relay, which
//! runs it, needs nothing of the wallet.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HEADERS_LIMIT: usize = 64 << 10;

/// Where a node is: `host:port`, optionally after `user:password@`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub host: String,
    pub port: u16,
    pub login: Option<String>,
}

impl Node {
    pub fn parse(text: &str) -> Option<Node> {
        let text = text.trim().trim_start_matches("http://").trim_end_matches('/');
        let (login, place) = match text.rsplit_once('@') {
            Some((login, place)) => (Some(login.to_owned()), place),
            None => (None, text),
        };
        let (host, port) = place.rsplit_once(':')?;
        let port = port.parse().ok().filter(|p| *p != 0)?;
        let fine = !host.is_empty() && host.len() <= 255 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        fine.then(|| Node { host: host.to_ascii_lowercase(), port, login })
    }
}

/// Sends one request to the node over `stream` and returns its answer.
pub async fn post<S>(mut stream: S, node: &Node, route: &str, body: &[u8], limit: usize) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let route = format!("/{}", route.trim_start_matches('/'));
    if !route.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'_' || b == b'.') {
        return Err("not a node request".into());
    }
    let mut request = format!(
        "POST {route} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        node.host,
        node.port,
        body.len()
    );
    if let Some(login) = &node.login {
        request.push_str(&format!("Authorization: Basic {}\r\n", base64(login.as_bytes())));
    }
    request.push_str("\r\n");
    let failed = |e: std::io::Error| format!("the node could not be reached: {e}");
    stream.write_all(request.as_bytes()).await.map_err(failed)?;
    stream.write_all(body).await.map_err(failed)?;
    stream.flush().await.map_err(failed)?;
    let mut response = Vec::new();
    (&mut stream).take((limit + HEADERS_LIMIT) as u64 + 1).read_to_end(&mut response).await.map_err(failed)?;
    if response.len() > limit + HEADERS_LIMIT {
        return Err("the node's answer is too large".into());
    }
    parse(response, limit)
}

fn base64(input: &[u8]) -> String {
    const SET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(SET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn parse(response: Vec<u8>, limit: usize) -> Result<Vec<u8>, String> {
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| "the node's answer is not HTTP".to_string())?;
    let head = std::str::from_utf8(&response[..end]).map_err(|_| "the node's answer is not HTTP".to_string())?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status.split(' ').nth(1).unwrap_or("");
    if code != "200" {
        return Err(format!("the node answered {}", status.trim()));
    }
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked") {
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            length = value.parse::<usize>().ok();
        }
    }
    let mut body = response[end + 4..].to_vec();
    if chunked {
        body = unchunk(&body).ok_or_else(|| "the node's answer is damaged".to_string())?;
    } else if let Some(length) = length {
        if body.len() < length {
            return Err("the node's answer was cut off".into());
        }
        body.truncate(length);
    }
    if body.len() > limit {
        return Err("the node's answer is too large".into());
    }
    Ok(body)
}

fn unchunk(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = input.windows(2).position(|w| w == b"\r\n")?;
        let size = std::str::from_utf8(&input[..line]).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        input = &input[line + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(input.get(..size)?);
        input = input.get(size + 2..)?;
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_read() {
        let plain = b"HTTP/1.1 200 Ok\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        assert_eq!(parse(plain, 100).unwrap(), b"hello");
        let chunked = b"HTTP/1.1 200 Ok\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n".to_vec();
        assert_eq!(parse(chunked, 100).unwrap(), b"hello");
        assert!(parse(b"HTTP/1.1 401 Unauthorized\r\n\r\n".to_vec(), 100).is_err());
        assert!(parse(b"HTTP/1.1 200 Ok\r\nContent-Length: 9\r\n\r\nhello".to_vec(), 100).is_err());
        assert!(parse(b"HTTP/1.1 200 Ok\r\n\r\nhello".to_vec(), 3).is_err());
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"ab"), "YWI=");
        let node = Node::parse("user:pw@abcdef.onion:18089").unwrap();
        assert_eq!((node.host.as_str(), node.port, node.login.as_deref()), ("abcdef.onion", 18089, Some("user:pw")));
        assert_eq!(Node::parse("http://Node.example:18081/").unwrap().host, "node.example");
        assert!(Node::parse("node.example").is_none());
        assert!(Node::parse("bad host:1").is_none());
        assert!(Node::parse("x:0").is_none());
    }
}
