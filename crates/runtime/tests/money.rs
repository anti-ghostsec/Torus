//! The Monero blocks, used over real HTTP, with the wallet's books kept by
//! a stand-in for the editor.

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use torus_core::money::{Ask, Payee, Purse, Told, PER_XMR};
use torus_core::starters::microblog;
use torus_core::Block;
use torus_runtime::Bank;
use torus_wallet::ledger::{Ledger, Party};
use torus_wallet::{Arrival, Slot};

const SITE: &str = "blog";
const FEE: u64 = PER_XMR / 10_000;

#[derive(Clone, Default)]
struct Books(Arc<Mutex<Ledger>>);

fn party(payee: Payee) -> Party {
    match payee {
        Payee::Site => Party::Site,
        Payee::Account(id) => Party::User(id),
    }
}

impl Bank for Books {
    fn ask(&self, ask: Ask) -> std::pin::Pin<Box<dyn std::future::Future<Output = Told> + Send>> {
        let mut ledger = self.0.lock().unwrap();
        let told = match ask {
            Ask::Purse { user } => {
                let me = Party::User(user.clone());
                let slot = ledger.slot(SITE, &me);
                let book = &ledger.sites[SITE];
                Told::Purse(Purse {
                    address: format!("8addr{}x{}", slot.account, slot.address),
                    balance: book.balance(&me),
                    arriving: ledger.arriving(SITE, &me),
                    unlocked: book.unlocked_by(&user, 0),
                    left_today: book.left_today(0),
                })
            }
            Ask::SiteAddress => Told::SiteAddress(Some("8thesite".into())),
            Ask::Pay { from, to, amount } => match ledger.transfer(SITE, &Party::User(from), &party(to), amount) {
                Ok(()) => Told::Done,
                Err(refused) => Told::Refused(refused.to_string()),
            },
            Ask::Unlock { user, to, key, price, days } => {
                match ledger.unlock(SITE, &user, &party(to), &key, price, (days > 0).then_some(u64::from(days)), 0) {
                    Ok(_) => Told::Done,
                    Err(refused) => Told::Refused(refused.to_string()),
                }
            }
            Ask::Withdraw { user, address, amount } => {
                if !address.starts_with('4') && !address.starts_with('8') {
                    return Box::pin(async { Told::Refused("that is not a Monero address".into()) });
                }
                let me = Party::User(user);
                let amount = amount.unwrap_or_else(|| ledger.sites[SITE].balance(&me).saturating_sub(FEE));
                match ledger.withdraw(SITE, &me, amount, FEE, 0) {
                    Ok(w) => Told::Withdrawn { amount: w.amount, fee: w.fee },
                    Err(refused) => Told::Refused(refused.to_string()),
                }
            }
        };
        Box::pin(async move { told })
    }
}

impl Books {
    fn deposit(&self, user: &str, amount: u64) {
        let mut ledger = self.0.lock().unwrap();
        let slot = ledger.slot(SITE, &Party::User(user.into()));
        let id = format!("{user}{amount}{}", ledger.owed());
        ledger.arrived(vec![Arrival { id, slot, amount, block: 1 }]);
        ledger.confirm(1000, |_| true);
    }

    fn balance(&self, party: Party) -> u64 {
        self.0.lock().unwrap().sites[SITE].balance(&party)
    }
}

fn site() -> torus_core::Site {
    let mut site = microblog();
    let page = |slug: &str, site: &mut torus_core::Site| site.pages.iter().position(|p| p.slug == slug).unwrap();
    let account = page("account", &mut site);
    site.pages[account].blocks.push(Block::Wallet { label: "Your Monero".into() });
    let home = page("index", &mut site);
    site.pages[home].blocks.push(Block::Donate { label: "Support this site".into() });
    let post = page("post", &mut site);
    site.pages[post].blocks.insert(3, Block::Tip { amount: "0.01".into(), label: "Tip".into() });
    let profile = page("profile", &mut site);
    site.pages[profile].blocks.push(Block::Paid {
        price: "0.5".into(),
        label: "Subscribers see more".into(),
        days: 30,
        blocks: vec![Block::Text { text: "For subscribers only.".into(), align: Default::default() }],
    });
    assert!(torus_core::check(&site).is_ok(), "{:?}", torus_core::lint(&site));
    site
}

fn field_of(page: &str, form_action: &str, name: &str) -> String {
    let form = &page[page.find(&format!("action=\"{form_action}\"")).expect(form_action)..];
    after(form, &format!("name=\"{name}\""), "value").to_owned()
}

#[tokio::test]
async fn visitors_hold_tip_subscribe_and_withdraw() {
    let (addr, live) = start(site()).await;
    let books = Books::default();
    live.bank_with(Arc::new(books.clone()));

    let (ada, ada_token) = join(addr, "Ada").await;
    let (bob, bob_token) = join(addr, "Bob").await;
    let ada_id = live.records("users").iter().find(|u| u.fields["name"] == "Ada").unwrap().id.clone();
    let bob_id = live.records("users").iter().find(|u| u.fields["name"] == "Bob").unwrap().id.clone();

    // Each sees their own address, and nobody else's.
    let ada_wallet = get(addr, "/account", Some(&ada)).await.text();
    assert!(ada_wallet.contains("<p class=\"balance\">0 XMR</p>"), "{ada_wallet}");
    assert!(ada_wallet.contains("<svg class=\"qr\""));
    assert!(ada_wallet.contains("href=\"monero:8addr1x1\""));
    let bob_wallet = get(addr, "/account", Some(&bob)).await.text();
    assert!(bob_wallet.contains("8addr1x2") && !bob_wallet.contains("8addr1x1"));
    assert!(get(addr, "/account", None).await.text().contains("Sign in to see your wallet."));
    // Anyone sees the site's own address.
    assert!(get(addr, "/", None).await.text().contains("<code>8thesite</code>"));

    books.deposit(&ada_id, 2 * PER_XMR);
    assert!(get(addr, "/account", Some(&ada)).await.text().contains("<p class=\"balance\">2 XMR</p>"));

    // Bob posts; Ada tips him from the post's page.
    let fields = [("_token", bob_token.as_str()), ("_next", "/"), ("text", "Hello")];
    assert_eq!(post(addr, "/_form/posts", Some(&bob), &fields).await.status, 303);
    let post_id = live.records("posts")[0].id.clone();
    let here = format!("/post/{post_id}");
    let page = get(addr, &here, Some(&ada)).await.text();
    assert!(page.contains("Tip (0.01 XMR)"), "{page}");
    assert!(!get(addr, &here, Some(&bob)).await.text().contains("Tip (0.01 XMR)"), "nobody tips themselves");
    let block = field_of(&page, "/_wallet/tip", "_block");
    let record = field_of(&page, "/_wallet/tip", "_record");
    assert_eq!(record, format!("posts/{post_id}"));
    let tip = |token: String, cookie: String, record: String| {
        let (block, here) = (block.clone(), here.clone());
        async move {
            let fields = [("_token", token.as_str()), ("_next", here.as_str()), ("_block", block.as_str()), ("_record", record.as_str())];
            post(addr, "/_wallet/tip", Some(&cookie), &fields).await
        }
    };
    assert_eq!(tip(ada_token.clone(), ada.clone(), record.clone()).await.status, 303);
    assert_eq!(books.balance(Party::User(bob_id.clone())), PER_XMR / 100);
    assert_eq!(books.balance(Party::User(ada_id.clone())), 2 * PER_XMR - PER_XMR / 100);
    // A forged form cannot pick another block or a record that is not there.
    let forged = tip(ada_token.clone(), ada.clone(), "posts/nothing".into()).await;
    assert!(forged.text().contains("no longer on the page"));
    let fields = [("_token", ada_token.as_str()), ("_next", here.as_str()), ("_block", "0"), ("_record", record.as_str())];
    assert_eq!(post(addr, "/_wallet/tip", Some(&ada), &fields).await.status, 405, "the block named is not a tip");
    // Without the form's token, nothing is paid.
    assert_eq!(tip("forged".into(), ada.clone(), record.clone()).await.status, 403);
    assert_eq!(books.balance(Party::User(bob_id.clone())), PER_XMR / 100);

    // Bob's profile has something for his subscribers: Ada subscribes.
    let profile = format!("/profile/{bob_id}");
    let locked = get(addr, &profile, Some(&ada)).await.text();
    assert!(!locked.contains("For subscribers only."));
    assert!(locked.contains("0.5 XMR for 30 days") && locked.contains("Pay 0.5 XMR"), "{locked}");
    assert!(get(addr, &profile, Some(&bob)).await.text().contains("For subscribers only."), "his own is open to him");
    let block = field_of(&locked, "/_wallet/unlock", "_block");
    let record = field_of(&locked, "/_wallet/unlock", "_record");
    let fields = [("_token", ada_token.as_str()), ("_next", profile.as_str()), ("_block", block.as_str()), ("_record", record.as_str())];
    assert_eq!(post(addr, "/_wallet/unlock", Some(&ada), &fields).await.status, 303);
    assert!(get(addr, &profile, Some(&ada)).await.text().contains("For subscribers only."));
    // Paying again costs nothing more.
    assert_eq!(post(addr, "/_wallet/unlock", Some(&ada), &fields).await.status, 303);
    assert_eq!(books.balance(Party::User(bob_id.clone())), PER_XMR / 100 + PER_XMR / 2);
    // On someone else's page, the same block is a subscription to them instead.
    let own = format!("/profile/{ada_id}");
    assert!(!get(addr, &own, Some(&bob)).await.text().contains("For subscribers only."));
    // A guest is asked to sign in.
    assert!(get(addr, &profile, None).await.text().contains("Sign in to unlock this."));

    // Giving to the site from what one holds.
    let home = get(addr, "/", Some(&ada)).await.text();
    let block = field_of(&home, "/_wallet/give", "_block");
    let fields = [("_token", ada_token.as_str()), ("_next", "/"), ("_block", block.as_str()), ("amount", "0.1")];
    assert_eq!(post(addr, "/_wallet/give", Some(&ada), &fields).await.status, 303);
    assert_eq!(books.balance(Party::Site), PER_XMR / 10);

    // Withdrawing: a bad amount, a bad address, too much, then everything.
    let wallet = get(addr, "/account", Some(&ada)).await.text();
    let block = field_of(&wallet, "/_wallet/withdraw", "_block");
    let withdraw = |address: &'static str, amount: &'static str| {
        let (token, cookie, block) = (ada_token.clone(), ada.clone(), block.clone());
        async move {
            let fields = [("_token", token.as_str()), ("_next", "/account"), ("_block", block.as_str()), ("address", address), ("amount", amount)];
            post(addr, "/_wallet/withdraw", Some(&cookie), &fields).await.text()
        }
    };
    assert!(withdraw("8elsewhere", "lots").await.contains("not an amount of XMR"));
    assert!(withdraw("nope", "0.1").await.contains("not a Monero address"));
    assert!(withdraw("8elsewhere", "100").await.contains("not enough"));
    let held = books.balance(Party::User(ada_id.clone()));
    let sent = withdraw("8elsewhere", "").await;
    assert!(sent.contains(&format!("Sent: {} is on its way", torus_core::money::format_xmr(held - FEE))), "{sent}");
    assert_eq!(books.balance(Party::User(ada_id.clone())), 0);

    // A guest cannot use any of it.
    let fields = [("_next", "/account"), ("address", "8elsewhere"), ("amount", "")];
    assert_eq!(post(addr, "/_wallet/withdraw", None, &fields).await.status, 403);
    let _ = (Slot::OWNER, bob);
}

#[tokio::test]
async fn without_a_wallet_the_blocks_say_so() {
    let (addr, _live) = start(site()).await;
    let (ada, token) = join(addr, "Ada").await;
    assert!(get(addr, "/account", Some(&ada)).await.text().contains("The wallet cannot be reached right now."));
    assert!(!get(addr, "/", None).await.text().contains("Support this site"), "no address to show");
    let fields = [("_token", token.as_str()), ("_next", "/account"), ("address", "8x"), ("amount", "")];
    assert_eq!(post(addr, "/_wallet/withdraw", Some(&ada), &fields).await.status, 503);
}
