//! Fetches a page from an onion address given in `TORUS_ONION`, as a
//! stranger on the Tor network would. Used to check a site hosted elsewhere,
//! such as on a phone.
//!
//! `TORUS_ONION=<address>.onion TORUS_PATH=/ cargo test -p torus-tor --test visit -- --ignored --nocapture`

use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "connects to the real Tor network; needs TORUS_ONION"]
async fn a_site_hosted_elsewhere_can_be_visited() {
    let address = std::env::var("TORUS_ONION").expect("TORUS_ONION");
    let path = std::env::var("TORUS_PATH").unwrap_or_else(|_| "/".into());
    let dir = std::env::temp_dir().join(format!("torus-visit-{}", std::process::id()));
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache")).build().unwrap();
    let visitor = TorClient::create_bootstrapped(config).await.unwrap();

    let mut page = String::new();
    for attempt in 1..=12 {
        match visitor.connect((address.as_str(), 80)).await {
            Ok(mut stream) => {
                let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                stream.write_all(request.as_bytes()).await.unwrap();
                stream.flush().await.unwrap();
                let mut received = Vec::new();
                let mut chunk = [0u8; 4096];
                while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut chunk)).await {
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&chunk[..n]);
                }
                page = String::from_utf8_lossy(&received).into_owned();
                if !page.is_empty() {
                    break;
                }
            }
            Err(e) => println!("attempt {attempt}: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    println!("{}", page.chars().take(700).collect::<String>());
    assert!(page.starts_with("HTTP/1.1 200"), "the site could not be visited");
    let _ = std::fs::remove_dir_all(dir);
}
