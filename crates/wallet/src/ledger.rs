//! Who on each site owns how much of the wallet.
//!
//! Coins sent to a user's address are credited to that user once they are
//! confirmed. After that, tips and purchases between users of a site only
//! move numbers here: nothing reaches the chain, so nothing about them can
//! be seen there, and they cost no fee. Only a withdrawal sends coins out.
//!
//! Each site has a daily limit on withdrawals. The site's host process,
//! which faces the network, asks for them on its users' behalf; were it
//! ever taken over, the limit bounds what could be taken from the site's
//! users in a day. The owner's own account is never reachable from a site.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Arrival, Piconero, Slot, CONFIRMATIONS, PER_XMR};

/// What a site's users may withdraw in a day, together, unless the owner
/// sets otherwise.
pub const DEFAULT_DAILY_LIMIT: Piconero = 5 * PER_XMR;
/// Smaller withdrawals would be mostly fee.
pub const MIN_WITHDRAWAL: Piconero = PER_XMR / 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    NoSuchSite,
    NotEnough { balance: Piconero },
    /// Over the site's daily withdrawal limit: this much is left today.
    OverLimit { left: Piconero },
    TooSmall,
    ToSelf,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NoSuchSite => f.write_str("this site has no wallet"),
            Refused::NotEnough { balance } => write!(f, "not enough: the balance is {}", crate::format_xmr(*balance)),
            Refused::OverLimit { left } => {
                write!(f, "this site's withdrawals for today are used up: {} left until tomorrow", crate::format_xmr(*left))
            }
            Refused::TooSmall => write!(f, "the least that can be withdrawn is {}", crate::format_xmr(MIN_WITHDRAWAL)),
            Refused::ToSelf => f.write_str("that would send it to the same place"),
        }
    }
}

/// Someone on a site who can hold coins.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Party {
    /// The site's owner: what the site itself has earned.
    Site,
    /// A user's account, by the id of their record.
    User(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Purse {
    /// Their address, within the site's account.
    pub address: u32,
    pub balance: Piconero,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Book {
    /// The site's account in the wallet.
    pub account: u32,
    /// What the site has earned: donations to its own address, and what
    /// users paid it.
    pub earned: Piconero,
    pub users: BTreeMap<String, Purse>,
    next_address: u32,
    pub daily_limit: Piconero,
    /// The day number and what was withdrawn on it.
    #[serde(default)]
    withdrawn: (u64, Piconero),
    /// What each user has paid to see, and until which day (`None`: for good).
    #[serde(default)]
    pub unlocked: BTreeMap<String, BTreeMap<String, Option<u64>>>,
}

impl Book {
    fn new(account: u32) -> Book {
        Book {
            account,
            earned: 0,
            users: BTreeMap::new(),
            // Address 0 of the account is the site's own.
            next_address: 1,
            daily_limit: DEFAULT_DAILY_LIMIT,
            withdrawn: (0, 0),
            unlocked: BTreeMap::new(),
        }
    }

    pub fn balance(&self, party: &Party) -> Piconero {
        match party {
            Party::Site => self.earned,
            Party::User(id) => self.users.get(id).map_or(0, |p| p.balance),
        }
    }

    fn take(&mut self, party: &Party, amount: Piconero) -> Result<(), Refused> {
        let balance = self.balance(party);
        if balance < amount {
            return Err(Refused::NotEnough { balance });
        }
        match party {
            Party::Site => self.earned -= amount,
            Party::User(id) => self.users.get_mut(id).expect("has a balance").balance -= amount,
        }
        Ok(())
    }

    fn give(&mut self, party: &Party, amount: Piconero) {
        match party {
            Party::Site => self.earned = self.earned.saturating_add(amount),
            Party::User(id) => {
                let next = &mut self.next_address;
                let purse = self.users.entry(id.clone()).or_insert_with(|| {
                    let address = *next;
                    *next += 1;
                    Purse { address, balance: 0 }
                });
                purse.balance = purse.balance.saturating_add(amount);
            }
        }
    }

    /// What may still be withdrawn on day `today`.
    pub fn left_today(&self, today: u64) -> Piconero {
        if self.withdrawn.0 == today {
            self.daily_limit.saturating_sub(self.withdrawn.1)
        } else {
            self.daily_limit
        }
    }

    pub fn has_unlocked(&self, user: &str, key: &str, today: u64) -> bool {
        self.unlocked.get(user).and_then(|keys| keys.get(key)).is_some_and(|until| until.is_none_or(|day| today <= day))
    }

    /// Everything a user has open on day `today`.
    pub fn unlocked_by(&self, user: &str, today: u64) -> Vec<String> {
        self.unlocked
            .get(user)
            .map(|keys| keys.iter().filter(|(_, until)| until.is_none_or(|day| today <= day)).map(|(k, _)| k.clone()).collect())
            .unwrap_or_default()
    }
}

/// A withdrawal taken from a balance and not yet known to be sent. If
/// sending fails, it is given back with [`Ledger::refund`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub site: String,
    pub party: Party,
    pub amount: Piconero,
    pub fee: Piconero,
    pub day: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    /// The owner's own account (account 0), apart from every site.
    pub own: Piconero,
    pub sites: BTreeMap<String, Book>,
    next_account: u32,
    /// Payments seen, not yet confirmed.
    pending: Vec<Arrival>,
    /// Payments credited, never to be credited again.
    credited: BTreeSet<String>,
}

impl Ledger {
    /// The site's book, made on first use.
    pub fn open(&mut self, site: &str) -> &mut Book {
        if !self.sites.contains_key(site) {
            self.next_account = self.next_account.max(1);
            let account = self.next_account;
            self.next_account += 1;
            self.sites.insert(site.to_owned(), Book::new(account));
        }
        self.sites.get_mut(site).expect("just made")
    }

    /// Where `party` on `site` is paid. Each user gets their own address.
    pub fn slot(&mut self, site: &str, party: &Party) -> Slot {
        let book = self.open(site);
        let address = match party {
            Party::Site => 0,
            Party::User(id) => {
                book.give(party, 0);
                book.users[id].address
            }
        };
        Slot { account: book.account, address }
    }

    fn owner_of(&self, slot: Slot) -> Option<(&str, Party)> {
        let (site, book) = self.sites.iter().find(|(_, book)| book.account == slot.account)?;
        if slot.address == 0 {
            return Some((site, Party::Site));
        }
        let (id, _) = book.users.iter().find(|(_, purse)| purse.address == slot.address)?;
        Some((site, Party::User(id.clone())))
    }

    /// Notes payments the wallet has just found.
    pub fn arrived(&mut self, arrivals: Vec<Arrival>) {
        for arrival in arrivals {
            if !self.credited.contains(&arrival.id) && !self.pending.iter().any(|p| p.id == arrival.id) {
                self.pending.push(arrival);
            }
        }
    }

    /// Credits what has been confirmed by block `tip`. `still_owned` says
    /// whether the wallet still has an output, which it would not if the
    /// chain had been reorganised since it was seen.
    pub fn confirm(&mut self, tip: usize, still_owned: impl Fn(&str) -> bool) {
        let pending = std::mem::take(&mut self.pending);
        for arrival in pending {
            if !still_owned(&arrival.id) {
                continue;
            }
            if arrival.block + CONFIRMATIONS > tip + 1 {
                self.pending.push(arrival);
                continue;
            }
            self.credited.insert(arrival.id.clone());
            match self.owner_of(arrival.slot).map(|(site, party)| (site.to_owned(), party)) {
                Some((site, party)) => self.open(&site).give(&party, arrival.amount),
                // To the owner's own account, or an address no site holds any more.
                None => self.own = self.own.saturating_add(arrival.amount),
            }
        }
    }

    /// What is on its way to `party`, not yet confirmed.
    pub fn arriving(&self, site: &str, party: &Party) -> Piconero {
        self.pending
            .iter()
            .filter(|a| self.owner_of(a.slot).is_some_and(|(s, p)| s == site && p == *party))
            .map(|a| a.amount)
            .sum()
    }

    /// Moves coins between two parties on a site: a tip or a purchase.
    pub fn transfer(&mut self, site: &str, from: &Party, to: &Party, amount: Piconero) -> Result<(), Refused> {
        if from == to {
            return Err(Refused::ToSelf);
        }
        let book = self.sites.get_mut(site).ok_or(Refused::NoSuchSite)?;
        book.take(from, amount)?;
        book.give(to, amount);
        Ok(())
    }

    /// Pays `price` from `user` to `to` for `key`, unless it is already
    /// open to them. `days` makes it last that many days from `today`.
    #[allow(clippy::too_many_arguments)]
    pub fn unlock(&mut self, site: &str, user: &str, to: &Party, key: &str, price: Piconero, days: Option<u64>, today: u64) -> Result<bool, Refused> {
        let book = self.sites.get(site).ok_or(Refused::NoSuchSite)?;
        if book.has_unlocked(user, key, today) {
            return Ok(false);
        }
        let from = Party::User(user.to_owned());
        if *to != from {
            self.transfer(site, &from, to, price)?;
        }
        let book = self.sites.get_mut(site).expect("checked");
        book.unlocked.entry(user.to_owned()).or_default().insert(key.to_owned(), days.map(|d| today + d.saturating_sub(1)));
        Ok(true)
    }

    /// Takes a withdrawal of `amount`, and its `fee`, from a balance, within
    /// the site's limit for day `today`.
    pub fn withdraw(&mut self, site: &str, party: &Party, amount: Piconero, fee: Piconero, today: u64) -> Result<Withdrawal, Refused> {
        if amount < MIN_WITHDRAWAL {
            return Err(Refused::TooSmall);
        }
        let book = self.sites.get_mut(site).ok_or(Refused::NoSuchSite)?;
        let total = amount.saturating_add(fee);
        let balance = book.balance(party);
        if balance < total {
            return Err(Refused::NotEnough { balance });
        }
        // What the owner takes out of the site's earnings is not limited:
        // the owner asks in the editor, not through the site.
        if matches!(party, Party::User(_)) {
            let left = book.left_today(today);
            if total > left {
                return Err(Refused::OverLimit { left });
            }
        }
        book.take(party, total)?;
        if matches!(party, Party::User(_)) {
            let already = if book.withdrawn.0 == today { book.withdrawn.1 } else { 0 };
            book.withdrawn = (today, already + total);
        }
        Ok(Withdrawal { site: site.to_owned(), party: party.clone(), amount, fee, day: today })
    }

    /// Gives back a withdrawal that could not be sent.
    pub fn refund(&mut self, withdrawal: &Withdrawal) {
        let total = withdrawal.amount.saturating_add(withdrawal.fee);
        if let Some(book) = self.sites.get_mut(&withdrawal.site) {
            book.give(&withdrawal.party, total);
            if matches!(withdrawal.party, Party::User(_)) && book.withdrawn.0 == withdrawal.day {
                book.withdrawn.1 = book.withdrawn.1.saturating_sub(total);
            }
        }
    }

    /// Moves what a site has earned into the owner's own account.
    pub fn collect(&mut self, site: &str, amount: Piconero) -> Result<(), Refused> {
        let book = self.sites.get_mut(site).ok_or(Refused::NoSuchSite)?;
        book.take(&Party::Site, amount)?;
        self.own = self.own.saturating_add(amount);
        Ok(())
    }

    /// Takes from the owner's own account, to send out.
    pub fn spend_own(&mut self, total: Piconero) -> Result<(), Refused> {
        if self.own < total {
            return Err(Refused::NotEnough { balance: self.own });
        }
        self.own -= total;
        Ok(())
    }

    /// What everyone together is owed: never more than the wallet holds.
    pub fn owed(&self) -> Piconero {
        self.sites.values().map(|b| b.earned + b.users.values().map(|p| p.balance).sum::<Piconero>()).sum::<Piconero>() + self.own
    }

    /// A site is deleted: whatever it held goes to the owner's own account,
    /// and its addresses are watched no more under its name.
    pub fn close(&mut self, site: &str) {
        if let Some(book) = self.sites.remove(site) {
            let held = book.earned + book.users.values().map(|p| p.balance).sum::<Piconero>();
            self.own = self.own.saturating_add(held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arrival(id: &str, slot: Slot, amount: Piconero, block: usize) -> Arrival {
        Arrival { id: id.into(), slot, amount, block }
    }

    #[test]
    fn deposits_are_credited_once_confirmed() {
        let mut ledger = Ledger::default();
        let alice = Party::User("alice".into());
        let slot = ledger.slot("blog", &alice);
        assert_eq!(slot, Slot { account: 1, address: 1 });
        assert_eq!(ledger.slot("blog", &alice), slot, "the same address every time");
        assert_eq!(ledger.slot("blog", &Party::User("bob".into())).address, 2);
        assert_eq!(ledger.slot("shop", &Party::Site), Slot { account: 2, address: 0 });

        ledger.arrived(vec![arrival("a", slot, 5 * PER_XMR, 100)]);
        ledger.arrived(vec![arrival("a", slot, 5 * PER_XMR, 100)]);
        ledger.confirm(105, |_| true);
        assert_eq!(ledger.sites["blog"].balance(&alice), 0);
        assert_eq!(ledger.arriving("blog", &alice), 5 * PER_XMR);
        ledger.confirm(109, |_| true);
        assert_eq!(ledger.sites["blog"].balance(&alice), 5 * PER_XMR, "credited once, after ten blocks");
        assert_eq!(ledger.arriving("blog", &alice), 0);
        ledger.arrived(vec![arrival("a", slot, 5 * PER_XMR, 100)]);
        ledger.confirm(200, |_| true);
        assert_eq!(ledger.sites["blog"].balance(&alice), 5 * PER_XMR, "never twice");

        // Seen, then gone in a reorganisation: never credited.
        ledger.arrived(vec![arrival("b", slot, PER_XMR, 300)]);
        ledger.confirm(320, |id| id != "b");
        assert_eq!(ledger.sites["blog"].balance(&alice), 5 * PER_XMR);
        assert_eq!(ledger.arriving("blog", &alice), 0);

        // To the owner's own account, and to the site's own address.
        ledger.arrived(vec![arrival("c", Slot::OWNER, PER_XMR, 1), arrival("d", Slot { account: 2, address: 0 }, 2, 1)]);
        ledger.confirm(400, |_| true);
        assert_eq!(ledger.own, PER_XMR);
        assert_eq!(ledger.sites["shop"].earned, 2);
        assert_eq!(ledger.owed(), 6 * PER_XMR + 2);
    }

    #[test]
    fn tips_purchases_and_withdrawals() {
        let mut ledger = Ledger::default();
        let alice = Party::User("alice".into());
        let bob = Party::User("bob".into());
        let slot = ledger.slot("tube", &alice);
        ledger.arrived(vec![arrival("a", slot, 10 * PER_XMR, 1)]);
        ledger.confirm(100, |_| true);

        ledger.transfer("tube", &alice, &bob, PER_XMR).unwrap();
        assert_eq!(ledger.sites["tube"].balance(&bob), PER_XMR);
        assert_eq!(ledger.transfer("tube", &bob, &alice, 2 * PER_XMR), Err(Refused::NotEnough { balance: PER_XMR }));
        assert_eq!(ledger.transfer("tube", &bob, &bob, 1), Err(Refused::ToSelf));
        assert_eq!(ledger.transfer("nowhere", &bob, &alice, 1), Err(Refused::NoSuchSite));

        assert!(ledger.unlock("tube", "alice", &bob, "video/1", PER_XMR, None, 5).unwrap());
        assert!(!ledger.unlock("tube", "alice", &bob, "video/1", PER_XMR, None, 6).unwrap(), "paid once");
        assert_eq!(ledger.sites["tube"].balance(&bob), 2 * PER_XMR);
        assert!(ledger.unlock("tube", "alice", &Party::Site, "pass", PER_XMR, Some(30), 10).unwrap());
        assert!(ledger.sites["tube"].has_unlocked("alice", "pass", 39));
        assert!(!ledger.sites["tube"].has_unlocked("alice", "pass", 40), "a 30-day pass ends");
        assert_eq!(ledger.sites["tube"].unlocked_by("alice", 39).len(), 2);
        assert_eq!(ledger.sites["tube"].balance(&alice), 7 * PER_XMR);

        let w = ledger.withdraw("tube", &alice, 3 * PER_XMR, PER_XMR / 100, 7).unwrap();
        assert_eq!(ledger.sites["tube"].balance(&alice), 4 * PER_XMR - PER_XMR / 100);
        assert_eq!(ledger.withdraw("tube", &alice, 3 * PER_XMR, 0, 7), Err(Refused::OverLimit { left: 2 * PER_XMR - PER_XMR / 100 }));
        ledger.refund(&w);
        assert_eq!(ledger.sites["tube"].balance(&alice), 7 * PER_XMR, "a failed withdrawal is given back");
        assert_eq!(ledger.sites["tube"].left_today(7), DEFAULT_DAILY_LIMIT);
        assert_eq!(ledger.withdraw("tube", &alice, 1, 0, 7), Err(Refused::TooSmall));
        // Tomorrow the limit is new.
        ledger.withdraw("tube", &alice, 4 * PER_XMR, 0, 7).unwrap();
        assert!(ledger.withdraw("tube", &alice, 2 * PER_XMR, 0, 7).is_err());
        assert!(ledger.withdraw("tube", &alice, 2 * PER_XMR, 0, 8).is_ok());

        ledger.collect("tube", PER_XMR).unwrap();
        assert_eq!(ledger.own, PER_XMR);
        ledger.close("tube");
        assert_eq!(ledger.own, PER_XMR + ledger_left(), "a deleted site's coins are the owner's");
        fn ledger_left() -> Piconero {
            // alice 1, bob 2
            3 * PER_XMR
        }
    }
}
