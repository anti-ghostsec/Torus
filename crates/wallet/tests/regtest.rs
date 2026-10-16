//! Runs the wallet against a private Monero network on this computer.
//! Skipped unless MONEROD names a `monerod` program.

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use monero_daemon_rpc::MoneroDaemon;
use torus_host_api::node::{post, Node as Place};
use torus_wallet::transport::Fetcher;
use torus_wallet::{Keys, Slot, State, Wallet, Chain, PER_XMR};

struct Node {
    _process: tokio::process::Child,
    _folder: std::path::PathBuf,
    daemon: MoneroDaemon<Fetcher>,
}

async fn start() -> Option<Node> {
    let program = std::env::var_os("MONEROD")?;
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let p2p = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let folder = std::env::temp_dir().join(format!("torus-regtest-{port}"));
    let process = tokio::process::Command::new(program)
        .args(["--regtest", "--offline", "--fixed-difficulty", "1", "--non-interactive", "--no-igd", "--disable-rpc-ban", "--log-level", "0"])
        .arg(format!("--data-dir={}", folder.display()))
        .arg(format!("--rpc-bind-port={port}"))
        .arg(format!("--p2p-bind-port={p2p}"))
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let place = Place::parse(&address.to_string()).unwrap();
        let fetcher = Fetcher::new(move |route, body, limit| {
            let place = place.clone();
            async move {
                let stream = tokio::net::TcpStream::connect(address).await.map_err(|e| e.to_string())?;
                post(stream, &place, &route, &body, limit).await
            }
        });
        if let Ok(daemon) = MoneroDaemon::new(fetcher).await {
            return Some(Node { _process: process, _folder: folder, daemon });
        }
    }
    panic!("monerod did not start");
}

async fn mine(node: &Node, wallet: &Wallet, blocks: usize) {
    let address = wallet.parse_address(&wallet.address(Slot::OWNER)).unwrap();
    node.daemon.generate_blocks(&address, blocks).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn deposits_are_seen_and_payments_sent() {
    let Some(node) = start().await else { return };
    let mut owner = Wallet::new(Keys::generate(), State::new(Chain::Mainnet, 0));
    // A new chain's fees are far above the real network's.
    owner.max_fee_per_weight = u64::MAX;
    let mut elsewhere = Wallet::new(Keys::generate(), State::new(Chain::Mainnet, 0));
    // Coinbase outputs wait 60 blocks.
    mine(&node, &owner, 300).await;
    owner.sync(&node.daemon, usize::MAX).await.unwrap();
    let (spendable, _) = owner.balance();
    assert!(spendable > 10 * PER_XMR, "mined coins are spendable: {spendable}");

    // A site's user is given an address, and pays it from somewhere else.
    let user = Slot { account: 2, address: 7 };
    let deposit = owner.claim(user);
    assert!(deposit.starts_with('8'));
    let prepared = owner.prepare(&node.daemon, vec![(owner.parse_address(&deposit).unwrap(), 3 * PER_XMR / 2)]).await.unwrap();
    assert!(prepared.fee > 0, "fee {}", prepared.fee);
    owner.publish(&node.daemon, prepared).await.unwrap();
    let (after, _) = owner.balance();
    assert!(after < spendable, "the coins being sent are no longer counted");
    mine(&node, &elsewhere, 1).await;
    let arrivals = owner.sync(&node.daemon, usize::MAX).await.unwrap();
    let to_user: Vec<_> = arrivals.iter().filter(|a| a.slot == user).collect();
    assert_eq!(to_user.len(), 1, "{arrivals:?}");
    assert_eq!(to_user[0].amount, 3 * PER_XMR / 2);
    // Seen again on a later read, it is not reported twice.
    assert!(owner.sync(&node.daemon, usize::MAX).await.unwrap().is_empty());

    // A withdrawal to an address outside the wallet.
    mine(&node, &elsewhere, 10).await;
    owner.sync(&node.daemon, usize::MAX).await.unwrap();
    let outside = owner.parse_address(&elsewhere.address(Slot::OWNER)).unwrap();
    let prepared = owner.prepare(&node.daemon, vec![(outside, PER_XMR / 4)]).await.unwrap();
    owner.publish(&node.daemon, prepared).await.unwrap();
    mine(&node, &owner, 1).await;
    owner.sync(&node.daemon, usize::MAX).await.unwrap();
    let got = elsewhere.sync(&node.daemon, usize::MAX).await.unwrap();
    assert!(got.iter().any(|a| a.amount == PER_XMR / 4), "{got:?}");

    // Saved and loaded, the wallet carries on where it was.
    let saved = serde_json::to_string(&owner.state).unwrap();
    let keys = Keys::from_bytes(&owner.keys().to_bytes()[..]).unwrap();
    let before = owner.balance();
    let mut again = Wallet::new(keys, serde_json::from_str::<State>(&saved).unwrap());
    again.max_fee_per_weight = u64::MAX;
    assert_eq!(again.balance(), before);
    assert!(again.sync(&node.daemon, usize::MAX).await.unwrap().is_empty());

    // The same keys read from the start find the same coins.
    let mut restored = Wallet::new(Keys::from_bytes(&owner.keys().to_bytes()[..]).unwrap(), State::new(Chain::Mainnet, 0));
    restored.sync(&node.daemon, usize::MAX).await.unwrap();
    assert_eq!(restored.balance(), before);
}
