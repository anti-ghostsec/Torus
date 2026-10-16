//! The Monero wallet kept in the vault.
//!
//! Each compartment of the vault has one wallet, made from one secret key.
//! Its accounts divide it: account 0 is the owner's own, and each site gets
//! an account of its own, in which each of the site's users gets an address
//! of their own. Every address is a Monero subaddress, so no one looking at
//! the chain can tell that two of them belong together.
//!
//! The wallet only knows what it owns and where on the chain it has read up
//! to. Who on a site owns how much is the business of the ledger kept beside
//! it (`ledger`); the coins themselves are pooled, as in any wallet.

use std::collections::BTreeMap;
use std::fmt;

use monero_wallet::address::{MoneroAddress, Network, SubaddressIndex};
use monero_wallet::ed25519::{Point, Scalar};
use monero_wallet::interface::prelude::*;
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SignableTransaction};
use monero_wallet::transaction::{Input, Timelock};
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair, WalletOutput};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub mod ledger;
pub mod transport;

pub use monero_daemon_rpc::MoneroDaemon;
pub use monero_wallet;
pub use monero_wallet::address::Network as Chain;

pub use torus_core::money::{format_xmr, parse_xmr, Piconero, PER_XMR};

/// Blocks after which a received output can be spent, by Monero's rules.
pub const SPENDABLE_AFTER: usize = 10;
/// Blocks after which a deposit is credited: a deeper reorganisation than
/// this would also break every exchange, and it is when the coins can be
/// spent anyway.
pub const CONFIRMATIONS: usize = SPENDABLE_AFTER;
/// The ring size Monero requires.
const RING: u8 = 16;
/// Blocks fetched from the node in one request.
const BATCH: usize = 50;
/// Hashes of recent blocks kept to notice the chain being reorganised.
const REMEMBERED: usize = 100;
/// Addresses watched beyond the last one handed out in each account, so that
/// a wallet restored from its seed finds what was sent to them.
const LOOKAHEAD: u32 = 50;
/// Accounts watched beyond the last one used, for the same reason.
const ACCOUNTS_AHEAD: u32 = 20;
/// The most inputs one transaction spends: more makes it unusually large.
const MAX_INPUTS: usize = 16;
/// Refuse a node's fee rate above this, per unit of weight. Mainnet's is
/// about 20 000 at normal priority; this is a hundred times that.
const MAX_FEE_PER_WEIGHT: u64 = 2_000_000;

#[derive(Debug)]
pub enum Error {
    Node(String),
    /// The wallet cannot pay this amount from what it can spend now.
    NotEnough { spendable: Piconero },
    BadAddress,
    WrongChain,
    Corrupt,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Node(e) => write!(f, "the Monero node could not be used: {e}"),
            Error::NotEnough { spendable } => write!(f, "not enough can be spent yet: {} available", format_xmr(*spendable)),
            Error::BadAddress => f.write_str("that is not a Monero address"),
            Error::WrongChain => f.write_str("that address is for a different Monero network"),
            Error::Corrupt => f.write_str("the wallet's saved state is damaged"),
            Error::Other(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for Error {}

fn node<E: fmt::Debug>(e: E) -> Error {
    Error::Node(format!("{e:?}"))
}

/// Where an address lives in the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Slot {
    pub account: u32,
    pub address: u32,
}

impl Slot {
    pub const OWNER: Slot = Slot { account: 0, address: 0 };

    fn index(self) -> Option<SubaddressIndex> {
        SubaddressIndex::new(self.account, self.address)
    }
}

/// The wallet's secret. Everything else follows from it.
pub struct Keys {
    spend: Zeroizing<Scalar>,
    view: Zeroizing<Scalar>,
}

impl Keys {
    pub fn generate() -> Keys {
        let mut seed = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(&mut seed[..]);
        // Reduced from 64 bytes so every key is equally likely.
        Keys::from_spend(Scalar::hash(&seed[..]))
    }

    /// Monero's own rule, so that the 25 words restore the same wallet in
    /// any Monero wallet: the view key is the hash of the spend key.
    fn from_spend(spend: Scalar) -> Keys {
        let bytes = Zeroizing::new(<[u8; 32]>::from(spend));
        let view = Scalar::hash(&bytes[..]);
        Keys { spend: Zeroizing::new(spend), view: Zeroizing::new(view) }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Keys, Error> {
        let spend = Scalar::read(&mut &bytes[..]).map_err(|_| Error::Corrupt)?;
        Ok(Keys::from_spend(spend))
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(<[u8; 32]>::from(*self.spend))
    }

    fn spend_point(&self) -> Point {
        Point::from(&curve(&self.spend) * curve25519::constants::ED25519_BASEPOINT_TABLE)
    }

    fn pair(&self) -> ViewPair {
        ViewPair::new(self.spend_point(), self.view.clone()).expect("a key derived as Monero does is valid")
    }

    /// The image of an output's key: it appears on the chain when the
    /// output is spent, and only the owner can work it out.
    fn key_image(&self, output: &WalletOutput) -> [u8; 32] {
        let key = Zeroizing::new(curve(&self.spend) + output.key_offset().into());
        let image = *key * Point::biased_hash(output.key().compress().to_bytes()).into();
        Point::from(image).compress().to_bytes()
    }
}

use curve25519_dalek as curve25519;

fn curve(scalar: &Scalar) -> curve25519::Scalar {
    (*scalar).into()
}

/// An output the wallet owns.
#[derive(Clone, Serialize, Deserialize)]
struct Owned {
    /// `WalletOutput`, serialised.
    #[serde(with = "hex::serde")]
    output: Vec<u8>,
    #[serde(with = "hex::serde")]
    image: Vec<u8>,
    slot: Slot,
    amount: Piconero,
    /// The block it was received in.
    block: usize,
    /// Locked by its sender beyond the usual ten blocks, until this block.
    #[serde(default)]
    locked_until: usize,
    /// The block its spending was seen in.
    #[serde(default)]
    spent: Option<usize>,
    /// Spent by a transaction this wallet sent that is not in a block yet:
    /// the transaction's hash, and the chain height when it was sent.
    #[serde(default)]
    sending: Option<(String, usize)>,
}

impl Owned {
    fn id(&self) -> String {
        hex::encode(&self.image)
    }

    fn decode(&self) -> Result<WalletOutput, Error> {
        WalletOutput::read(&mut &self.output[..]).map_err(|_| Error::Corrupt)
    }
}

/// A payment that arrived, for the ledger to credit once it is confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrival {
    /// Unique to the output, and the same however often it is seen.
    pub id: String,
    pub slot: Slot,
    pub amount: Piconero,
    pub block: usize,
}

/// What the wallet remembers between runs. It holds no secret: the keys are
/// kept apart from it, in the vault.
#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    chain: String,
    /// The block the wallet was made at; nothing before it can be ours.
    pub birth: usize,
    /// The next block to read.
    next: usize,
    /// Hashes of the last blocks read, by number.
    recent: BTreeMap<usize, String>,
    outputs: Vec<Owned>,
    /// For each account, the most addresses handed out in it.
    accounts: BTreeMap<u32, u32>,
    /// Made before the chain's height was known: it starts reading from
    /// wherever the chain is when it first reaches a node.
    #[serde(default)]
    unborn: bool,
}

fn chain_name(chain: Network) -> &'static str {
    match chain {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Stagenet => "stagenet",
    }
}

impl State {
    pub fn new(chain: Network, birth: usize) -> State {
        State {
            chain: chain_name(chain).into(),
            birth,
            next: birth,
            recent: BTreeMap::new(),
            outputs: Vec::new(),
            accounts: BTreeMap::new(),
            unborn: false,
        }
    }

    /// A brand-new wallet: nothing on the chain so far can be its own.
    pub fn unborn(chain: Network) -> State {
        State { unborn: true, ..State::new(chain, 0) }
    }

    pub fn chain(&self) -> Network {
        match self.chain.as_str() {
            "testnet" => Network::Testnet,
            "stagenet" => Network::Stagenet,
            _ => Network::Mainnet,
        }
    }

    /// How far the wallet has read: the number of the last block read.
    pub fn height(&self) -> usize {
        self.next.saturating_sub(1)
    }

    /// Whether it has read anything yet.
    pub fn is_unborn(&self) -> bool {
        self.unborn
    }
}

/// A transaction made and signed, ready to be published.
pub struct Prepared {
    transaction: monero_wallet::transaction::Transaction,
    spends: Vec<String>,
    pub fee: Piconero,
    pub hash: String,
}

pub struct Wallet {
    keys: Keys,
    pub state: State,
    /// A node asking more than this per unit of weight is refused, so a
    /// hostile node cannot make a payment cost a fortune.
    pub max_fee_per_weight: u64,
}

impl Wallet {
    pub fn new(keys: Keys, state: State) -> Wallet {
        Wallet { keys, state, max_fee_per_weight: MAX_FEE_PER_WEIGHT }
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The secret view key, in hex: with the address, enough to see every
    /// payment the wallet receives, but not to spend.
    pub fn view_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(<[u8; 32]>::from(*self.keys.view)))
    }

    /// The secret spend key, in hex: whoever has it has the coins. Any
    /// Monero wallet can be restored from it, with the address and the
    /// height the wallet was made at.
    pub fn spend_key_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(&self.keys.to_bytes()[..]))
    }

    pub fn address(&self, slot: Slot) -> String {
        let pair = self.keys.pair();
        match slot.index() {
            None => pair.legacy_address(self.state.chain()).to_string(),
            Some(index) => pair.subaddress(self.state.chain(), index).to_string(),
        }
    }

    /// Hands out the address `slot`, and watches for payments to it.
    pub fn claim(&mut self, slot: Slot) -> String {
        let most = self.state.accounts.entry(slot.account).or_insert(0);
        *most = (*most).max(slot.address);
        self.address(slot)
    }

    /// Checks that `text` is an address on this wallet's network.
    pub fn parse_address(&self, text: &str) -> Result<MoneroAddress, Error> {
        let text = text.trim();
        let any = MoneroAddress::from_str_with_unchecked_network(text).map_err(|_| Error::BadAddress)?;
        if any.network() != self.state.chain() {
            return Err(Error::WrongChain);
        }
        Ok(any)
    }

    fn scanner(&self) -> Scanner {
        let mut scanner = Scanner::new(self.keys.pair());
        let mut accounts = self.state.accounts.clone();
        let last = accounts.keys().next_back().copied().unwrap_or(0);
        for account in 0..=last.saturating_add(ACCOUNTS_AHEAD) {
            accounts.entry(account).or_insert(0);
        }
        for (account, most) in accounts {
            for address in 0..=most.saturating_add(LOOKAHEAD) {
                if let Some(index) = SubaddressIndex::new(account, address) {
                    scanner.register_subaddress(index);
                }
            }
        }
        scanner
    }

    /// Reads the chain up to its tip, or up to `limit` blocks of it.
    /// Returns the payments that arrived.
    pub async fn sync<D>(&mut self, daemon: &D, limit: usize) -> Result<Vec<Arrival>, Error>
    where
        D: ProvidesBlockchainMeta + ProvidesScannableBlocks + ProvidesBlockchain,
    {
        let tip = daemon.latest_block_number().await.map_err(node)?;
        if self.state.unborn {
            // A few blocks back, in case the chain is reorganised meanwhile.
            self.state.birth = tip.saturating_sub(SPENDABLE_AFTER);
            self.state.next = self.state.birth;
            self.state.unborn = false;
        }
        self.rewind_if_reorganised(daemon).await?;
        let mut scanner = self.scanner();
        let mut arrivals = Vec::new();
        let end = tip.min(self.state.next.saturating_add(limit).saturating_sub(1));
        while self.state.next <= end {
            let last = end.min(self.state.next + BATCH - 1);
            let blocks = daemon.contiguous_scannable_blocks(self.state.next..=last).await.map_err(node)?;
            for block in blocks {
                let number = block.block.number();
                if number != self.state.next {
                    return Err(Error::Node("the node sent blocks out of order".into()));
                }
                if let Some(previous) = self.state.recent.get(&(number.wrapping_sub(1))) {
                    if *previous != hex::encode(block.block.header.previous) {
                        // Reorganised while being read: start again from before it.
                        self.rewind(number.saturating_sub(REMEMBERED / 2));
                        return Ok(arrivals);
                    }
                }
                let hash = hex::encode(block.block.hash());
                let images: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .flat_map(|tx| tx.prefix().inputs.iter())
                    .filter_map(|input| match input {
                        Input::ToKey { key_image, .. } => Some(key_image.to_bytes()),
                        Input::Gen(_) => None,
                    })
                    .collect();
                for owned in &mut self.state.outputs {
                    if owned.spent.is_none() && images.iter().any(|image| image[..] == owned.image[..]) {
                        owned.spent = Some(number);
                        owned.sending = None;
                    }
                }
                let found = scanner.scan(block).map_err(node)?.ignore_additional_timelock();
                for output in found {
                    let slot = output
                        .subaddress()
                        .map(|index| Slot { account: index.account(), address: index.address() })
                        .unwrap_or(Slot::OWNER);
                    let image = self.keys.key_image(&output);
                    if self.state.outputs.iter().any(|o| o.image[..] == image[..]) {
                        // The same key twice: a burning bug. Only the first can be spent.
                        continue;
                    }
                    let locked_until = match output.additional_timelock() {
                        Timelock::Block(block) => block,
                        // Locked by time: rare, and not worth working out when it ends.
                        Timelock::Time(_) => usize::MAX,
                        Timelock::None => 0,
                    };
                    let owned = Owned {
                        output: output.serialize(),
                        image: image.to_vec(),
                        slot,
                        amount: output.commitment().amount,
                        block: number,
                        locked_until,
                        spent: None,
                        sending: None,
                    };
                    arrivals.push(Arrival { id: owned.id(), slot, amount: owned.amount, block: number });
                    // Watch further ahead of an address that was paid.
                    let known = self.state.accounts.get(&slot.account).copied();
                    if known.is_none_or(|most| slot.address > most) {
                        self.state.accounts.insert(slot.account, known.unwrap_or(0).max(slot.address));
                        scanner = self.scanner();
                    }
                    self.state.outputs.push(owned);
                }
                self.state.recent.insert(number, hash);
                while self.state.recent.len() > REMEMBERED {
                    self.state.recent.pop_first();
                }
                self.state.next = number + 1;
            }
        }
        self.release_stuck(tip);
        Ok(arrivals)
    }

    async fn rewind_if_reorganised<D: ProvidesBlockchain>(&mut self, daemon: &D) -> Result<(), Error> {
        let Some((&number, hash)) = self.state.recent.last_key_value() else { return Ok(()) };
        let now = daemon.block_hash(number).await.map_err(node)?;
        if hex::encode(now) == *hash {
            return Ok(());
        }
        // Walk back to the last block that is still on the chain.
        let known: Vec<(usize, String)> = self.state.recent.iter().rev().map(|(n, h)| (*n, h.clone())).collect();
        for (number, hash) in known {
            if hex::encode(daemon.block_hash(number).await.map_err(node)?) == hash {
                self.rewind(number + 1);
                return Ok(());
            }
        }
        self.rewind(self.state.recent.keys().next().copied().unwrap_or(self.state.birth));
        Ok(())
    }

    /// Forgets everything read from block `from` on.
    fn rewind(&mut self, from: usize) {
        let from = from.max(self.state.birth);
        self.state.outputs.retain(|o| o.block < from);
        for owned in &mut self.state.outputs {
            if owned.spent.is_some_and(|block| block >= from) {
                owned.spent = None;
            }
        }
        self.state.recent.retain(|number, _| *number < from);
        self.state.next = from;
    }

    /// A transaction that has not reached a block in a day most likely never
    /// will: its coins are counted as the wallet's again.
    fn release_stuck(&mut self, tip: usize) {
        for owned in &mut self.state.outputs {
            if owned.sending.as_ref().is_some_and(|(_, sent)| tip > sent + 720) {
                owned.sending = None;
            }
        }
    }

    /// Whether the wallet still has the output a payment arrived in.
    pub fn owns(&self, id: &str) -> bool {
        self.state.outputs.iter().any(|o| o.id() == id)
    }

    fn spendable_outputs(&self, tip: usize) -> Vec<&Owned> {
        self.state
            .outputs
            .iter()
            .filter(|o| o.spent.is_none() && o.sending.is_none())
            .filter(|o| o.block + SPENDABLE_AFTER <= tip + 1 && o.locked_until <= tip + 1)
            .collect()
    }

    /// What the whole wallet holds: (can be spent now, still arriving).
    pub fn balance(&self) -> (Piconero, Piconero) {
        let tip = self.state.height();
        let spendable: Piconero = self.spendable_outputs(tip).iter().map(|o| o.amount).sum();
        let all: Piconero = self.state.outputs.iter().filter(|o| o.spent.is_none() && o.sending.is_none()).map(|o| o.amount).sum();
        (spendable, all - spendable)
    }

    /// Makes and signs a transaction paying `payments`, with the change
    /// returned to the owner's own account. Nothing is sent yet.
    pub async fn prepare<D>(&self, daemon: &D, payments: Vec<(MoneroAddress, Piconero)>) -> Result<Prepared, Error>
    where
        D: ProvidesBlockchainMeta + ProvidesDecoys + ProvidesFeeRates,
    {
        let tip = daemon.latest_block_number().await.map_err(node)?;
        let fee_rate = daemon.fee_rate(FeePriority::Normal, self.max_fee_per_weight).await.map_err(node)?;
        let wanted: Piconero = payments.iter().map(|(_, amount)| *amount).sum();
        let mut candidates = self.spendable_outputs(tip.min(self.state.height()));
        let spendable: Piconero = candidates.iter().map(|o| o.amount).sum();
        // The smallest set of the largest outputs that covers the payment and a fee.
        candidates.sort_by(|a, b| b.amount.cmp(&a.amount));
        let mut chosen = Vec::new();
        let mut total: Piconero = 0;
        for owned in candidates {
            if chosen.len() == MAX_INPUTS {
                break;
            }
            chosen.push(owned);
            total = total.saturating_add(owned.amount);
            // Enough room for a fee of up to about 0.001 XMR; the exact fee is
            // checked when the transaction is made.
            if total >= wanted.saturating_add(PER_XMR / 1000) {
                break;
            }
        }
        if total < wanted {
            return Err(Error::NotEnough { spendable });
        }
        let mut rng = OsRng;
        let mut inputs = Vec::with_capacity(chosen.len());
        for owned in &chosen {
            let output = owned.decode()?;
            inputs.push(OutputWithDecoys::new(&mut rng, daemon, RING, tip, output).await.map_err(node)?);
        }
        let mut outgoing = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut outgoing[..]);
        let change = Change::new(self.keys.pair(), None);
        let signable = SignableTransaction::new(RctType::ClsagBulletproofPlus, outgoing, inputs, payments, change, Vec::new(), fee_rate)
            .map_err(|e| match e {
                monero_wallet::send::SendError::NotEnoughFunds { .. } => Error::NotEnough { spendable },
                e => Error::Other(format!("the transaction could not be made: {e}")),
            })?;
        let fee = signable.necessary_fee();
        let transaction = signable.sign(&mut rng, &self.keys.spend).map_err(|e| Error::Other(format!("the transaction could not be signed: {e}")))?;
        let hash = hex::encode(transaction.hash());
        Ok(Prepared { transaction, spends: chosen.iter().map(|o| o.id()).collect(), fee, hash })
    }

    /// The fee a payment of `amount` would cost now, without sending it.
    pub async fn fee_for<D>(&self, daemon: &D, to: MoneroAddress, amount: Piconero) -> Result<Piconero, Error>
    where
        D: ProvidesBlockchainMeta + ProvidesDecoys + ProvidesFeeRates,
    {
        Ok(self.prepare(daemon, vec![(to, amount)]).await?.fee)
    }

    /// Sends a prepared transaction. Its coins stop counting as the
    /// wallet's at once, so they can never be spent twice.
    pub async fn publish<D: PublishTransaction>(&mut self, daemon: &D, prepared: Prepared) -> Result<String, Error> {
        daemon.publish_transaction(&prepared.transaction).await.map_err(node)?;
        let height = self.state.height();
        for owned in &mut self.state.outputs {
            if prepared.spends.contains(&owned.id()) {
                owned.sending = Some((prepared.hash.clone(), height));
            }
        }
        Ok(prepared.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_survive_being_saved() {
        let keys = Keys::generate();
        let again = Keys::from_bytes(&keys.to_bytes()[..]).unwrap();
        let a = Wallet::new(keys, State::new(Network::Mainnet, 0));
        let b = Wallet::new(again, State::new(Network::Mainnet, 0));
        assert_eq!(a.address(Slot { account: 3, address: 7 }), b.address(Slot { account: 3, address: 7 }));
        assert!(a.address(Slot::OWNER).starts_with('4'));
        assert!(a.address(Slot { account: 1, address: 0 }).starts_with('8'));
        assert_ne!(a.address(Slot { account: 1, address: 0 }), a.address(Slot { account: 1, address: 1 }));
    }
}
