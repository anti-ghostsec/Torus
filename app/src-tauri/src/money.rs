//! The wallet as the editor runs it: kept in the vault, read up to date in
//! the background through the relay, and asked by the sites on their
//! visitors' behalf.
//!
//! Two locks, so that nothing slow holds up a page: the books (who holds
//! what) answer at once, while the wallet itself may be busy for a minute
//! reading the chain or making a transaction over Tor.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use torus_core::money::{format_xmr, Ask, Payee, Piconero, Purse, Told};
use torus_wallet::ledger::{Ledger, Party, Refused};
use torus_wallet::transport::Fetcher;
use torus_wallet::{Chain, Keys, MoneroDaemon, Slot, State, Wallet};
use zeroize::Zeroizing;

/// How often the chain is read once the wallet has caught up: about one
/// block's time.
const SYNC_EVERY: Duration = Duration::from_secs(90);
/// After a failure, wait this long before trying the node again.
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// Blocks read in one go while catching up, between which others may use the wallet.
const STEP: usize = 200;

/// Monero nodes reached only as onion services, run by people in the
/// Monero community, as listed on monero.fail. The wallet picks one at
/// random and keeps to it, moving to another only when it stops answering:
/// each node it uses learns a little about which blocks it asks for, so
/// the fewer the better. Nothing about who uses them reaches them: they
/// are reached over Tor, and never learn where this computer is.
const NODES: &[&str] = &[
    "plowsoffjexmxalw73tkjmf422gq6575fc7vicuu4javzn2ynnte6tyd.onion:18089",
    "plowsofe6cleftfmk2raiw5h2x66atrik3nja4bfd3zrfa2hdlgworad.onion:18089",
    "plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:18089",
    "moneroexnovtlp4datcwbgjznnulgm7q34wcl6r4gcvccruhkceb2xyd.onion:18089",
    "moneronkvv2hu2anvcc5b4qd5y7strnc2ob6khqsrtikmhocyvjpdjyd.onion:18089",
    "monerof5eqykw3hfrjmb66v7r4ft4hlilfzjw5q4huwolttutjuc5dyd.onion:18089",
    "monero3x5yrb7tsalxx64tr2qhfw54xy3eudhswvpaskfvsdk2tzb3id.onion:18089",
    "libertytmtitynvmnto2k42liys5fenb3wabaozmmmksyrc7jvgmjiqd.onion:18089",
    "xmrnode5i43mrkmkhe2l5h2brbsnxjd5bzh6sgqi5zncywgqwxpwmvyd.onion:18089",
    "hashvaultsvg2rinvxz7kos77hdfm6zrd5yco3tx2yh2linsmusfwyad.onion:18081",
    "rucknium757bokwv3ss35ftgc3gzb7hgbvvglbg3hisp7tsj2fkd2nyd.onion:18081",
    "xmrxmrxmrjau5dcdxzqrqicpai57njom6h5sd4qjitekkemfk6weppyd.onion:18081",
    "privacysrafqxgrtgpjbib66yb7ro2eevjiysbo7rplsqgwl6pax5vyd.onion:18089",
    "monerozck7ebftzypitkdbkndlzib5qr4ca73fm6jjuoh7wikiynihyd.onion:18089",
    "xmrowl7agi2g2qvlivwiv7d3wu6sjjxejjmoeecb2bh6ya4txkidd3id.onion:18089",
    "sanlorenzo6i7f27e4wumys2q7wfikgowisxg6pnc2vet7k3wqvyfoqd.onion:18089",
    "xmrrpcmyrz3imrldcwiqt4vm5asq2vefgzybamxdigx37p3ctfcjnsad.onion:18089",
    "monsterxzzefbr6jq3n2tu4xvlumnunlhbrhqny6naxpn6le3upke2yd.onion:18089",
    "anonxmrr5oiy7opr36l3mdsvmciwuxyxcybp6v3d4owaouwc6gsdj2qd.onion:18089",
    "supportxmrcnzyyl4gtmtvql446f4pdqfcrykwaltwsg3trj3ekn3fad.onion:18089",
];

/// A node from the list, at random.
fn random_pick() -> usize {
    let mut byte = [0u8; 4];
    let _ = getrandom::getrandom(&mut byte);
    u32::from_le_bytes(byte) as usize % NODES.len()
}

/// Another node from the list than `now`, at random.
fn another_pick(now: usize) -> usize {
    (now + 1 + random_pick() % (NODES.len() - 1)) % NODES.len()
}

/// What the vault keeps of the wallet.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredMoney {
    /// The secret spend key, in hex.
    spend: String,
    state: State,
    ledger: Ledger,
    /// A node the owner chose: `host:port`, an onion address or a name.
    /// Without one, the wallet uses `NODES[pick]`.
    #[serde(default)]
    node: Option<String>,
    #[serde(default = "random_pick")]
    pick: usize,
    /// The key Tor's bookkeeping for the relay is kept encrypted with, in hex.
    tor_key: String,
}

impl Drop for StoredMoney {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.spend);
    }
}

/// The wallet as the window sees it.
#[derive(Debug, Serialize)]
pub struct Summary {
    pub address: String,
    /// The node in use, and whether the owner chose it.
    pub node: String,
    pub chosen: bool,
    /// The owner's own account, apart from every site.
    pub own: Piconero,
    /// What the wallet can spend now, and what is on its way.
    pub spendable: Piconero,
    pub arriving: Piconero,
    /// What the sites and their users hold, in all.
    pub owed: Piconero,
    /// How far the wallet has read, and how far the chain goes, when known.
    pub height: usize,
    pub tip: Option<usize>,
    /// The last trouble reaching the node, if the last try failed.
    pub trouble: Option<String>,
    pub sites: Vec<SiteMoney>,
}

#[derive(Debug, Serialize)]
pub struct SiteMoney {
    pub site: u32,
    pub address: String,
    pub earned: Piconero,
    pub users: usize,
    pub held_by_users: Piconero,
    pub daily_limit: Piconero,
}

/// The keys someone needs to restore the wallet in another Monero wallet.
#[derive(Debug, Serialize)]
pub struct Restore {
    pub address: String,
    pub spend_key: String,
    pub view_key: String,
    pub height: usize,
}

/// Saves the wallet into the vault.
pub type Keep = Arc<dyn Fn(StoredMoney) -> Result<(), String> + Send + Sync>;
/// Starts the relay to a node and returns a way to reach it.
pub type Reach = Arc<dyn Fn(String, Zeroizing<Vec<u8>>) -> Pin<Box<dyn Future<Output = Result<Fetcher, String>> + Send>> + Send + Sync>;

struct Loaded {
    wallet: tokio::sync::Mutex<Wallet>,
    /// For pages, which must never wait on the wallet: its addresses, and
    /// what it held when last looked at.
    addresses: torus_wallet::Addresses,
    seen: Mutex<Seen>,
    /// The wallet's state as last saved, and its key, so the books can be
    /// saved without waiting for the wallet.
    saved_state: Mutex<State>,
    spend_hex: Zeroizing<String>,
    ledger: Mutex<Ledger>,
    node: Mutex<Option<String>>,
    pick: Mutex<usize>,
    /// Whether the chain needs reading: once any site has used the wallet,
    /// or it holds anything. Until then nothing reaches the network.
    wanted: std::sync::atomic::AtomicBool,
    tor_key: Zeroizing<Vec<u8>>,
    /// The node, once reached.
    daemon: tokio::sync::Mutex<Option<MoneroDaemon<Fetcher>>>,
    tip: Mutex<Option<usize>>,
    trouble: Mutex<Option<String>>,
}

pub struct Treasury {
    loaded: Mutex<Option<Arc<Loaded>>>,
    syncing: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    keep: Keep,
    reach: Reach,
    /// The highest fee per unit of weight a node may ask; see `Wallet`.
    max_fee: Option<u64>,
}

/// The wallet as last seen, for whoever cannot wait for it.
#[derive(Default, Clone, Copy)]
struct Seen {
    height: usize,
    unborn: bool,
    spendable: Piconero,
    arriving: Piconero,
}

fn seen(wallet: &Wallet) -> Seen {
    let (spendable, arriving) = wallet.balance();
    Seen { height: wallet.state.height(), unborn: wallet.state.is_unborn(), spendable, arriving }
}

fn today() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() / 86_400).unwrap_or(0)
}

fn party(payee: Payee) -> Party {
    match payee {
        Payee::Site => Party::Site,
        Payee::Account(id) => Party::User(id),
    }
}

fn refused(why: Refused) -> Told {
    Told::Refused(format!("That could not be done: {why}."))
}

impl Treasury {
    pub fn new(keep: Keep, reach: Reach) -> Arc<Treasury> {
        Arc::new(Treasury { loaded: Mutex::new(None), syncing: Mutex::new(None), keep, reach, max_fee: None })
    }

    fn loaded(&self) -> Option<Arc<Loaded>> {
        self.loaded.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn require(&self) -> Result<Arc<Loaded>, String> {
        self.loaded().ok_or_else(|| "There is no wallet yet.".to_owned())
    }

    /// Takes up the wallet the vault holds, if any, as the vault is unlocked.
    pub fn load(self: &Arc<Self>, stored: Option<&StoredMoney>) -> Result<(), String> {
        self.unload();
        let Some(stored) = stored else { return Ok(()) };
        let spend = Zeroizing::new(hex::decode(&stored.spend).map_err(|_| "The wallet's key is damaged.")?);
        let keys = Keys::from_bytes(&spend).map_err(|e| e.to_string())?;
        let tor_key = Zeroizing::new(hex::decode(&stored.tor_key).map_err(|_| "The wallet's relay key is damaged.")?);
        let mut ledger = stored.ledger.clone();
        // Books kept before earnings were passed on by themselves.
        ledger.sweep_all();
        // A wallet nothing has used yet stays off the network.
        let wanted = !ledger.sites.is_empty() || ledger.owed() > 0 || !stored.state.is_unborn();
        let mut wallet = Wallet::new(keys, stored.state.clone());
        if let Some(max) = self.max_fee {
            wallet.max_fee_per_weight = max;
        }
        let loaded = Loaded {
            addresses: wallet.addresses(),
            seen: Mutex::new(seen(&wallet)),
            saved_state: Mutex::new(wallet.state.clone()),
            spend_hex: wallet.spend_key_hex(),
            wallet: tokio::sync::Mutex::new(wallet),
            ledger: Mutex::new(ledger),
            node: Mutex::new(stored.node.clone()),
            pick: Mutex::new(stored.pick % NODES.len()),
            wanted: std::sync::atomic::AtomicBool::new(wanted),
            tor_key,
            daemon: tokio::sync::Mutex::new(None),
            tip: Mutex::new(None),
            trouble: Mutex::new(None),
        };
        *self.loaded.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(loaded));
        self.start_syncing();
        Ok(())
    }

    /// Forgets the wallet, as the vault is locked. The relay stops with it.
    pub fn unload(&self) {
        if let Some(task) = self.syncing.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        *self.loaded.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Makes a new wallet, unless there is one. There is one per
    /// compartment of the vault, made as the vault is first opened.
    pub fn ensure(self: &Arc<Self>) -> Result<(), String> {
        if self.loaded().is_some() {
            return Ok(());
        }
        let mut tor_key = Zeroizing::new(vec![0u8; 32]);
        getrandom::getrandom(&mut tor_key).map_err(|e| e.to_string())?;
        let keys = Keys::generate();
        let stored = StoredMoney {
            spend: hex::encode(&keys.to_bytes()[..]),
            state: State::unborn(Chain::Mainnet),
            ledger: Ledger::default(),
            node: None,
            pick: random_pick(),
            tor_key: hex::encode(&tor_key[..]),
        };
        (self.keep)(stored.clone())?;
        self.load(Some(&stored))
    }

    /// Saves the books, with the wallet as it was last saved: for changes
    /// that touch only the books, which must not wait on the wallet.
    fn save_books(&self, loaded: &Loaded) -> Result<(), String> {
        // Held until saved: one save at a time, so an older state is never
        // saved over a newer one.
        let saving = loaded.saved_state.lock().unwrap_or_else(|e| e.into_inner());
        let stored = StoredMoney {
            spend: loaded.spend_hex.to_string(),
            state: saving.clone(),
            ledger: loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            node: loaded.node.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            pick: *loaded.pick.lock().unwrap_or_else(|e| e.into_inner()),
            tor_key: hex::encode(&loaded.tor_key[..]),
        };
        (self.keep)(stored)
    }

    /// Saves what the wallet is now.
    async fn save(&self, loaded: &Loaded) -> Result<(), String> {
        let wallet = loaded.wallet.lock().await;
        self.save_with(loaded, &wallet)
    }

    fn save_with(&self, loaded: &Loaded, wallet: &Wallet) -> Result<(), String> {
        *loaded.seen.lock().unwrap_or_else(|e| e.into_inner()) = seen(wallet);
        let mut saving = loaded.saved_state.lock().unwrap_or_else(|e| e.into_inner());
        *saving = wallet.state.clone();
        let stored = StoredMoney {
            spend: wallet.spend_key_hex().to_string(),
            state: wallet.state.clone(),
            ledger: loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            node: loaded.node.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            pick: *loaded.pick.lock().unwrap_or_else(|e| e.into_inner()),
            tor_key: hex::encode(&loaded.tor_key[..]),
        };
        (self.keep)(stored)
    }

    pub async fn set_node(self: &Arc<Self>, node: String) -> Result<(), String> {
        let loaded = self.require()?;
        let node = node.trim().to_owned();
        // Nothing: back to one chosen from the list.
        let node = if node.is_empty() {
            None
        } else if torus_host_api::node::Node::parse(&node).is_none() {
            return Err("That is not a node's address. Write it as host:port, such as an onion address and 18089.".into());
        } else {
            Some(node)
        };
        *loaded.node.lock().unwrap_or_else(|e| e.into_inner()) = node;
        *loaded.daemon.lock().await = None;
        *loaded.trouble.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.save(&loaded).await?;
        self.start_syncing();
        Ok(())
    }

    fn start_syncing(self: &Arc<Self>) {
        let mut syncing = self.syncing.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(task) = syncing.take() {
            task.abort();
        }
        let treasury = Arc::downgrade(self);
        // Tauri's runtime: the vault may be opened from a thread that has none.
        *syncing = Some(tauri::async_runtime::spawn(async move {
            loop {
                let Some(treasury) = treasury.upgrade() else { return };
                let wanted = treasury.loaded().is_some_and(|l| l.wanted.load(std::sync::atomic::Ordering::Relaxed));
                if !wanted {
                    drop(treasury);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let pause = match treasury.sync_step().await {
                    Ok(true) => Duration::ZERO,
                    Ok(false) => SYNC_EVERY,
                    Err(trouble) => {
                        if let Some(loaded) = treasury.loaded() {
                            *loaded.trouble.lock().unwrap_or_else(|e| e.into_inner()) = Some(trouble);
                            // A node from the list that fails is left for another.
                            if loaded.node.lock().unwrap_or_else(|e| e.into_inner()).is_none() {
                                let mut pick = loaded.pick.lock().unwrap_or_else(|e| e.into_inner());
                                *pick = another_pick(*pick);
                                drop(pick);
                                let _ = treasury.save_books(&loaded);
                            }
                        }
                        RETRY_AFTER
                    }
                };
                drop(treasury);
                tokio::time::sleep(pause).await;
            }
        }));
    }

    /// The node in use: the owner's choice, or one from the list.
    fn node_of(loaded: &Loaded) -> String {
        match loaded.node.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            Some(node) => node,
            None => NODES[*loaded.pick.lock().unwrap_or_else(|e| e.into_inner()) % NODES.len()].to_owned(),
        }
    }

    /// The node, reached through the relay, started on first use.
    async fn daemon(&self, loaded: &Loaded) -> Result<MoneroDaemon<Fetcher>, String> {
        let mut daemon = loaded.daemon.lock().await;
        if let Some(daemon) = daemon.as_ref() {
            return Ok(daemon.clone());
        }
        let node = Self::node_of(loaded);
        let fetcher = (self.reach)(node, loaded.tor_key.clone()).await?;
        let reached = MoneroDaemon::new(fetcher).await.map_err(|e| format!("The node did not answer as a Monero node does: {e:?}"))?;
        *daemon = Some(reached.clone());
        Ok(reached)
    }

    /// Reads the chain some way further. `Ok(true)` if there is more to read.
    pub(crate) async fn sync_step(&self) -> Result<bool, String> {
        let Some(loaded) = self.loaded() else { return Ok(false) };
        let daemon = match self.daemon(&loaded).await {
            Ok(daemon) => daemon,
            Err(e) => {
                *loaded.daemon.lock().await = None;
                return Err(e);
            }
        };
        let mut wallet = loaded.wallet.lock().await;
        // Watched from now on: every address the books have handed out.
        let handed_out: Vec<Slot> = {
            let ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
            ledger
                .sites
                .values()
                .map(|book| Slot { account: book.account, address: book.users.values().map(|p| p.address).max().unwrap_or(0) })
                .collect()
        };
        for slot in handed_out {
            wallet.claim(slot);
        }
        let before = wallet.state.height();
        let arrivals = match wallet.sync(&daemon, STEP).await {
            Ok(arrivals) => arrivals,
            Err(e) => {
                drop(wallet);
                // Start again with a fresh connection next time.
                *loaded.daemon.lock().await = None;
                return Err(e.to_string());
            }
        };
        let tip = torus_wallet::monero_wallet::interface::prelude::ProvidesBlockchainMeta::latest_block_number(&daemon)
            .await
            .map_err(|e| format!("{e:?}"))?;
        *loaded.tip.lock().unwrap_or_else(|e| e.into_inner()) = Some(tip);
        *loaded.trouble.lock().unwrap_or_else(|e| e.into_inner()) = None;
        {
            let mut ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
            ledger.arrived(arrivals);
            let height = wallet.state.height();
            ledger.confirm(height, |id| wallet.owns(id));
        }
        if wallet.state.height() != before {
            self.save_with(&loaded, &wallet)?;
        } else {
            *loaded.seen.lock().unwrap_or_else(|e| e.into_inner()) = seen(&wallet);
        }
        Ok(wallet.state.height() < tip)
    }

    pub async fn summary(&self) -> Option<Summary> {
        let loaded = self.loaded()?;
        let ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let now = *loaded.seen.lock().unwrap_or_else(|e| e.into_inner());
        let (spendable, arriving) = (now.spendable, now.arriving);
        let sites = ledger
            .sites
            .iter()
            .filter_map(|(site, book)| {
                Some(SiteMoney {
                    site: site.parse().ok()?,
                    address: loaded.addresses.address(Slot { account: book.account, address: 0 }),
                    earned: book.earned_total,
                    users: book.users.len(),
                    held_by_users: book.users.values().map(|p| p.balance).sum(),
                    daily_limit: book.daily_limit,
                })
            })
            .collect();
        let chosen = loaded.node.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        let node = Self::node_of(&loaded);
        let tip = *loaded.tip.lock().unwrap_or_else(|e| e.into_inner());
        let trouble = loaded.trouble.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Some(Summary {
            address: loaded.addresses.address(Slot::OWNER),
            node,
            chosen,
            own: ledger.own,
            spendable,
            arriving,
            owed: ledger.owed(),
            height: if now.unborn { 0 } else { now.height },
            tip,
            trouble,
            sites,
        })
    }

    /// What it takes to restore the wallet elsewhere.
    pub async fn restore_keys(&self) -> Result<Restore, String> {
        let loaded = self.require()?;
        let wallet = loaded.wallet.lock().await;
        Ok(Restore {
            address: wallet.address(Slot::OWNER),
            spend_key: wallet.spend_key_hex().to_string(),
            view_key: wallet.view_key_hex().to_string(),
            height: wallet.state.birth,
        })
    }

    pub async fn set_daily_limit(&self, site: u32, limit: Piconero) -> Result<(), String> {
        let loaded = self.require()?;
        loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).open(&site.to_string()).daily_limit = limit;
        self.save(&loaded).await
    }

    /// An account on a site was deleted: what it held becomes the owner's.
    pub fn close_account(&self, site: u32, user: &str) -> Result<Piconero, String> {
        let Some(loaded) = self.loaded() else { return Ok(0) };
        let held = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).close_account(&site.to_string(), user);
        if held > 0 {
            self.save_books(&loaded)?;
        }
        Ok(held)
    }

    /// A site is deleted: what it held becomes the owner's own.
    pub async fn close_site(&self, site: u32) -> Result<(), String> {
        let Some(loaded) = self.loaded() else { return Ok(()) };
        loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).close(&site.to_string());
        self.save(&loaded).await
    }

    /// What a site's users hold, so the owner can be warned before deleting it.
    pub fn held_by(&self, site: u32) -> Piconero {
        let Some(loaded) = self.loaded() else { return 0 };
        let ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
        ledger.sites.get(&site.to_string()).map_or(0, |b| b.earned + b.users.values().map(|p| p.balance).sum::<Piconero>())
    }

    /// Sends from the owner's own account. `None` sends all of it.
    pub async fn send_own(&self, address: String, amount: Option<Piconero>) -> Result<(Piconero, Piconero), String> {
        let loaded = self.require()?;
        let own = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).own;
        self.send_out(&loaded, &address, amount, own, |ledger, total| ledger.spend_own(total).map(|_| ()), |ledger, total| {
            ledger.own = ledger.own.saturating_add(total)
        })
        .await
    }

    /// Makes, signs and sends a payment out of the wallet, taking it and its
    /// fee from a balance in the books first and giving it back if sending
    /// fails. `held` is the balance it is paid from.
    async fn send_out(
        &self,
        loaded: &Loaded,
        address: &str,
        amount: Option<Piconero>,
        held: Piconero,
        take: impl FnOnce(&mut Ledger, Piconero) -> Result<(), Refused>,
        give_back: impl FnOnce(&mut Ledger, Piconero),
    ) -> Result<(Piconero, Piconero), String> {
        let daemon = self.daemon(loaded).await?;
        let mut wallet = loaded.wallet.lock().await;
        let to = wallet.parse_address(address).map_err(|e| e.to_string())?;
        // Everything: the fee is found first, then taken from what is sent.
        let wanted = match amount {
            Some(amount) => amount,
            None => {
                let guess = held.saturating_sub(torus_core::money::PER_XMR / 1000).max(1);
                let fee = wallet.fee_for(&daemon, to, guess).await.map_err(|e| self.explain(e))?;
                held.checked_sub(fee).filter(|a| *a > 0).ok_or_else(|| format!("{} would not even pay the network's fee.", format_xmr(held)))?
            }
        };
        let prepared = wallet.prepare(&daemon, vec![(to, wanted)]).await.map_err(|e| self.explain(e))?;
        let fee = prepared.fee;
        let total = wanted.saturating_add(fee);
        if amount.is_none() && total > held {
            return Err("The fee changed while the payment was being made. Try again.".into());
        }
        take(&mut loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()), total).map_err(|e| e.to_string())?;
        if let Err(e) = wallet.publish(&daemon, prepared).await {
            give_back(&mut loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()), total);
            return Err(format!("The payment could not be sent, and nothing was taken: {e}"));
        }
        self.save_with(loaded, &wallet)?;
        Ok((wanted, fee))
    }

    fn explain(&self, error: torus_wallet::Error) -> String {
        match error {
            torus_wallet::Error::NotEnough { .. } => {
                "The wallet's coins are still settling from an earlier payment. Try again in about 20 minutes.".into()
            }
            e => e.to_string(),
        }
    }

    /// Answers a site's question, on behalf of one of its visitors.
    pub async fn ask(&self, site: u32, ask: Ask) -> Told {
        let Some(loaded) = self.loaded() else { return Told::Refused("This site has no wallet.".into()) };
        // A site uses the wallet: from now on it keeps up with the chain.
        loaded.wanted.store(true, std::sync::atomic::Ordering::Relaxed);
        let key = site.to_string();
        let day = today();
        let answer = match ask {
            Ask::Closed { user } => {
                return match self.close_account(site, &user) {
                    Ok(_) => Told::Done,
                    Err(e) => Told::Refused(e),
                };
            }
            Ask::Purse { user } => {
                let me = Party::User(user.clone());
                let (slot, made) = {
                    let mut ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
                    let had = ledger.sites.get(&key).is_some_and(|b| b.users.contains_key(&user));
                    (ledger.slot(&key, &me), !had)
                };
                // The wallet watches it from its next read of the chain on;
                // the books, saved now, remember it was handed out.
                if made {
                    if let Err(e) = self.save_books(&loaded) {
                        return Told::Refused(format!("The wallet could not be saved: {e}"));
                    }
                }
                let address = loaded.addresses.address(slot);
                let ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
                let book = &ledger.sites[&key];
                Told::Purse(Purse {
                    address,
                    balance: book.balance(&me),
                    arriving: ledger.arriving(&key, &me),
                    unlocked: book.unlocked_by(&user, day),
                    left_today: book.left_today(day),
                })
            }
            Ask::SiteAddress => {
                let slot = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).slot(&key, &Party::Site);
                Told::SiteAddress(Some(loaded.addresses.address(slot)))
            }
            Ask::Pay { from, to, amount } => {
                let done = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).transfer(&key, &Party::User(from), &party(to), amount);
                match done {
                    Ok(()) => Told::Done,
                    Err(why) => refused(why),
                }
            }
            Ask::Unlock { user, to, key: what, price, days } => {
                let days = (days > 0).then_some(u64::from(days));
                let done = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner()).unlock(&key, &user, &party(to), &what, price, days, day);
                match done {
                    Ok(_) => Told::Done,
                    Err(why) => refused(why),
                }
            }
            Ask::Withdraw { user, address, amount } => {
                let me = Party::User(user);
                let (held, left) = {
                    let ledger = loaded.ledger.lock().unwrap_or_else(|e| e.into_inner());
                    let book = ledger.sites.get(&key);
                    (book.map_or(0, |b| b.balance(&me)), book.map_or(0, |b| b.left_today(day)))
                };
                if held == 0 {
                    return Told::Refused("There is nothing to withdraw.".into());
                }
                let from = held.min(left);
                let (site_key, me_take, me_back) = (key.clone(), me.clone(), me.clone());
                let back_key = key.clone();
                let sent = self
                    .send_out(
                        &loaded,
                        &address,
                        amount,
                        from,
                        move |ledger, total| ledger.withdraw(&site_key, &me_take, total, 0, day).map(|_| ()),
                        move |ledger, total| {
                            ledger.refund(&torus_wallet::ledger::Withdrawal { site: back_key, party: me_back, amount: total, fee: 0, day })
                        },
                    )
                    .await;
                match sent {
                    Ok((amount, fee)) => Told::Withdrawn { amount, fee },
                    Err(why) => Told::Refused(why),
                }
            }
        };
        if matches!(answer, Told::Done) {
            if let Err(e) = self.save_books(&loaded) {
                return Told::Refused(format!("That was done but could not be saved: {e}"));
            }
        }
        answer
    }
}

#[cfg(test)]
mod tests {
    //! Against a private Monero network on this computer. Skipped unless
    //! MONEROD names a `monerod` program.

    use super::*;
    use std::net::TcpListener;
    use torus_core::money::PER_XMR;
    use torus_host_api::node::{post, Node};

    struct Network {
        _process: tokio::process::Child,
        port: u16,
    }

    async fn network() -> Option<Network> {
        let program = std::env::var_os("MONEROD")?;
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let p2p = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let folder = std::env::temp_dir().join(format!("torus-treasury-{port}"));
        let process = tokio::process::Command::new(program)
            .args(["--regtest", "--offline", "--fixed-difficulty", "1", "--non-interactive", "--no-igd", "--disable-rpc-ban", "--log-level", "0"])
            .arg(format!("--data-dir={}", folder.display()))
            .arg(format!("--rpc-bind-port={port}"))
            .arg(format!("--p2p-bind-port={p2p}"))
            .stdout(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        for _ in 0..120 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                return Some(Network { _process: process, port });
            }
        }
        panic!("monerod did not start");
    }

    fn direct(port: u16) -> Fetcher {
        let node = Node::parse(&format!("127.0.0.1:{port}")).unwrap();
        Fetcher::new(move |route, body, limit| {
            let node = node.clone();
            async move {
                let stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
                post(stream, &node, &route, &body, limit).await
            }
        })
    }

    async fn mine(port: u16, address: &str, blocks: usize) {
        let daemon = MoneroDaemon::new(direct(port)).await.unwrap();
        let address = torus_wallet::monero_wallet::address::MoneroAddress::from_str_with_unchecked_network(address).unwrap();
        daemon.generate_blocks(&address, blocks).await.unwrap();
    }

    async fn catch_up(treasury: &Treasury) {
        while treasury.sync_step().await.unwrap() {}
    }

    fn purse(told: Told) -> Purse {
        match told {
            Told::Purse(purse) => purse,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sites_users_deposit_tip_and_withdraw() {
        let Some(net) = network().await else { return };
        let port = net.port;
        let kept: Arc<Mutex<Option<StoredMoney>>> = Arc::default();
        let into = kept.clone();
        let keep: Keep = Arc::new(move |stored| {
            *into.lock().unwrap() = Some(stored);
            Ok(())
        });
        let reach: Reach = Arc::new(move |_, _| Box::pin(async move { Ok(direct(port)) }));
        let make = || {
            let mut treasury = Treasury::new(keep.clone(), reach.clone());
            Arc::get_mut(&mut treasury).unwrap().max_fee = Some(u64::MAX);
            treasury
        };
        let treasury = make();
        treasury.ensure().unwrap();
        assert!(kept.lock().unwrap().is_some(), "kept in the vault at once");
        treasury.set_node(format!("127.0.0.1:{port}")).await.unwrap();
        catch_up(&treasury).await;

        // Coins arrive in the owner's own account.
        let own = treasury.summary().await.unwrap().address;
        mine(port, &own, 300).await;
        catch_up(&treasury).await;
        let summary = treasury.summary().await.unwrap();
        assert!(summary.own > 100 * PER_XMR, "{summary:?}");
        assert_eq!(summary.owed, summary.own);

        // A user of site 1 gets an address and adds to it from the owner's account.
        let ada = purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await);
        assert_eq!(ada.balance, 0);
        let again = purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await);
        assert_eq!(again.address, ada.address, "always the same address");
        let bob = purse(treasury.ask(1, Ask::Purse { user: "bob".into() }).await);
        assert_ne!(bob.address, ada.address);
        let (sent, fee) = treasury.send_own(ada.address.clone(), Some(3 * PER_XMR)).await.unwrap();
        assert_eq!(sent, 3 * PER_XMR);
        assert!(fee > 0);
        mine(port, &own, 1).await;
        catch_up(&treasury).await;
        let arriving = purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await);
        assert_eq!((arriving.balance, arriving.arriving), (0, 3 * PER_XMR), "seen, not yet confirmed");
        mine(port, &own, 10).await;
        catch_up(&treasury).await;
        assert_eq!(purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await).balance, 3 * PER_XMR);

        // A tip, and a payment to unlock something, move nothing on the chain.
        assert_eq!(treasury.ask(1, Ask::Pay { from: "ada".into(), to: Payee::Account("bob".into()), amount: PER_XMR }).await, Told::Done);
        let unlock = Ask::Unlock { user: "ada".into(), to: Payee::Site, key: "pass:site".into(), price: PER_XMR / 2, days: 30 };
        assert_eq!(treasury.ask(1, unlock).await, Told::Done);
        let ada_now = purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await);
        assert_eq!(ada_now.balance, 3 * PER_XMR / 2);
        assert_eq!(ada_now.unlocked, vec!["pass:site".to_owned()]);
        assert!(matches!(
            treasury.ask(1, Ask::Pay { from: "bob".into(), to: Payee::Site, amount: 5 * PER_XMR }).await,
            Told::Refused(_)
        ));
        // Site 2's books are apart from site 1's.
        assert_eq!(purse(treasury.ask(2, Ask::Purse { user: "ada".into() }).await).balance, 0);

        // Bob withdraws everything he holds to an address outside the wallet.
        let outside = Wallet::new(Keys::generate(), State::new(Chain::Mainnet, 0)).address(Slot::OWNER);
        let told = treasury.ask(1, Ask::Withdraw { user: "bob".into(), address: outside.clone(), amount: None }).await;
        let Told::Withdrawn { amount, fee } = told else { panic!("{told:?}") };
        assert_eq!(amount + fee, PER_XMR);
        assert_eq!(purse(treasury.ask(1, Ask::Purse { user: "bob".into() }).await).balance, 0);
        // Nothing left: refused.
        assert!(matches!(treasury.ask(1, Ask::Withdraw { user: "bob".into(), address: outside.clone(), amount: None }).await, Told::Refused(_)));
        // A bad address takes nothing.
        let bad = treasury.ask(1, Ask::Withdraw { user: "ada".into(), address: "nonsense".into(), amount: Some(PER_XMR / 10) }).await;
        assert!(matches!(bad, Told::Refused(_)), "{bad:?}");
        assert_eq!(purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await).balance, 3 * PER_XMR / 2);
        mine(port, &own, 1).await;
        catch_up(&treasury).await;

        // What the site earned is already the owner's: the half paid for the pass.
        let summary = treasury.summary().await.unwrap();
        assert_eq!(summary.sites.iter().find(|s| s.site == 1).unwrap().earned, PER_XMR / 2);
        // Ada deletes her account: what she held becomes the owner's.
        let owners = summary.own;
        assert_eq!(treasury.ask(1, Ask::Closed { user: "ada".into() }).await, Told::Done);
        assert_eq!(treasury.summary().await.unwrap().own, owners + 3 * PER_XMR / 2);
        assert_eq!(purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await).balance, 0);
        let summary = treasury.summary().await.unwrap();
        assert!(summary.owed <= summary.spendable + summary.arriving, "never owes more than it holds: {summary:?}");

        // Locked and unlocked again, everything is as it was.
        let before = (summary.own, purse(treasury.ask(1, Ask::Purse { user: "ada".into() }).await));
        treasury.unload();
        assert!(treasury.summary().await.is_none());
        let stored = kept.lock().unwrap().clone();
        let reopened = make();
        reopened.load(stored.as_ref()).unwrap();
        let after = (reopened.summary().await.unwrap().own, purse(reopened.ask(1, Ask::Purse { user: "ada".into() }).await));
        assert_eq!(after, before);
        let keys = reopened.restore_keys().await.unwrap();
        assert_eq!(keys.address, own);
        assert_eq!(keys.spend_key.len(), 64);
    }
}
