//! The Monero blocks' forms. The coins are not here: the host asks the
//! editor's wallet, which keeps the books, and passes on what it answers.
//!
//! What a form says is trusted for nothing that costs money. The amount of
//! a tip and the price of a paid block are looked up in the site itself,
//! at the block the form names, and the payee is worked out from the
//! record that block was shown with.

use std::future::Future;
use std::pin::Pin;

use hyper::body::Incoming;
use hyper::{Request, StatusCode};
use torus_core::money::{self, format_xmr, parse_xmr, Ask, Payee, Purse, Told, BLOCK_FIELD, RECORD_FIELD};
use torus_core::{Block, Data, Page, Site, Viewer, NEXT_FIELD, STYLE_PATH, TOKEN_FIELD};

use crate::{escape_attribute, plain, read_submission, refuse_unread, refusal, same, see_other, Live, Reply, HTML};

/// Where the wallet is: the editor, at the other end of the host's pipe.
pub trait Bank: Send + Sync {
    fn ask(&self, ask: Ask) -> Pin<Box<dyn Future<Output = Told> + Send>>;
}

/// Whether a page needs to know what its visitor holds, or the site's address.
pub(crate) fn needs(page: &Page) -> (bool, bool) {
    fn any(blocks: &[Block], test: &dyn Fn(&Block) -> bool) -> bool {
        blocks.iter().any(|b| test(b) || b.children().iter().any(|inner| any(inner, test)))
    }
    let purse = any(&page.blocks, &|b| matches!(b, Block::Wallet { .. } | Block::Donate { .. } | Block::Paid { .. }));
    let address = any(&page.blocks, &|b| matches!(b, Block::Donate { .. }));
    (purse, address)
}

/// What the page's visitor holds, and the site's address, as the page needs.
pub(crate) async fn look_up(live: &Live, page: &Page, viewer: Option<&Viewer>) -> (Option<Purse>, Option<String>) {
    let Some(bank) = live.bank() else { return (None, None) };
    let (wants_purse, wants_address) = needs(page);
    let purse = match viewer {
        Some(viewer) if wants_purse => match bank.ask(Ask::Purse { user: viewer.id.clone() }).await {
            Told::Purse(purse) => Some(purse),
            _ => None,
        },
        _ => None,
    };
    let address = if wants_address {
        match bank.ask(Ask::SiteAddress).await {
            Told::SiteAddress(address) => address,
            _ => None,
        }
    } else {
        None
    };
    (purse, address)
}

/// Answers a Monero form: `/_wallet/tip`, `unlock`, `give` or `withdraw`.
pub(crate) async fn post(live: &Live, site: &Site, viewer: Option<Viewer>, action: &str, req: Request<Incoming>) -> Reply {
    let Some(bank) = live.bank() else {
        return refuse_unread(req, plain(StatusCode::SERVICE_UNAVAILABLE, "Payments cannot be made right now.\n", false)).await;
    };
    let Some(viewer) = viewer else {
        return refuse_unread(req, plain(StatusCode::FORBIDDEN, "Sign in first.\n", false)).await;
    };
    let allowed = live.store().allow(crate::store::Budget::Posts);
    if let Err(refused) = allowed {
        return refuse_unread(req, refusal(refused)).await;
    }
    let submission = match read_submission(live, &[], req).await {
        Ok(submission) => submission,
        Err(reply) => return reply,
    };
    if !same(submission.text(TOKEN_FIELD), &viewer.token) {
        return plain(StatusCode::FORBIDDEN, "That form has expired. Go back, reload the page and try again.\n", false);
    }
    let here = submission.text(NEXT_FIELD).to_owned();
    let back = crate::return_path(site, &here);
    let ask = match action {
        "withdraw" => {
            if !site.any_block(&|b| matches!(b, Block::Wallet { .. })) {
                return crate::method_not_allowed();
            }
            let address = submission.text("address").trim().to_owned();
            let amount = match submission.text("amount").trim() {
                "" => None,
                typed => match parse_xmr(typed) {
                    Some(amount) if amount > 0 => Some(amount),
                    _ => return told(&back, "That is not an amount of XMR, such as 0.05."),
                },
            };
            Ask::Withdraw { user: viewer.id.clone(), address, amount }
        }
        "tip" | "unlock" | "give" => {
            let Some(found) = place(live, site, &here, submission.text(BLOCK_FIELD), submission.text(RECORD_FIELD)) else {
                return told(&back, "That is no longer on the page. Go back and reload it.");
            };
            let Placed { block, collection, record, here } = found;
            let payee = money::payee(collection.as_deref(), record.as_ref());
            if payee == Payee::Account(viewer.id.clone()) {
                return told(&back, "That would pay yourself.");
            }
            match (action, block) {
                ("tip", Block::Tip { amount, .. }) => match parse_xmr(&amount) {
                    Some(amount) if amount > 0 => Ask::Pay { from: viewer.id.clone(), to: payee, amount },
                    _ => return crate::method_not_allowed(),
                },
                ("unlock", Block::Paid { price, days, .. }) => match parse_xmr(&price) {
                    Some(price) if price > 0 => {
                        let key = money::unlock_key(days, &payee, collection.as_deref(), record.as_ref(), &here);
                        Ask::Unlock { user: viewer.id.clone(), to: payee, key, price, days }
                    }
                    _ => return crate::method_not_allowed(),
                },
                ("give", Block::Donate { .. }) => match parse_xmr(submission.text("amount")) {
                    Some(amount) if amount > 0 => Ask::Pay { from: viewer.id.clone(), to: Payee::Site, amount },
                    _ => return told(&back, "That is not an amount of XMR, such as 0.05."),
                },
                _ => return crate::method_not_allowed(),
            }
        }
        _ => return crate::method_not_allowed(),
    };
    let withdrawing = matches!(ask, Ask::Withdraw { .. });
    match bank.ask(ask).await {
        Told::Done => see_other(site, &here),
        Told::Withdrawn { amount, fee } => told(
            &back,
            &format!(
                "Sent: {} is on its way, and {} went to the network as its fee. It shows in the other wallet within a few minutes, and can be spent there after about 20.",
                format_xmr(amount),
                format_xmr(fee)
            ),
        ),
        Told::Refused(why) => told(&back, &why),
        _ if withdrawing => told(&back, "The withdrawal could not be made. Nothing was taken."),
        _ => told(&back, "That could not be done. Nothing was taken."),
    }
}

struct Placed {
    block: Block,
    collection: Option<String>,
    record: Option<torus_core::Record>,
    /// The address of the page, as its blocks were rendered with.
    here: String,
}

/// Finds the block a form names on the page it was on, and the record it
/// was shown with, checking that the record really belongs there.
fn place(live: &Live, site: &Site, here: &str, address: &str, record: &str) -> Option<Placed> {
    let (page, id) = find_page(site, here)?;
    let (block, scope) = money::locate(page, address)?;
    let store = live.store();
    let record = match (scope, record.split_once('/')) {
        (None, _) => None,
        (Some(scope), Some((collection, id_given))) if collection == scope => {
            // On a template page, only the page's own record.
            if page.template.as_deref() == Some(scope) && id != Some(id_given) && !lists(page, address) {
                return None;
            }
            let found = store.find(scope, id_given)?;
            if found.held {
                return None;
            }
            Some(found)
        }
        _ => return None,
    };
    Some(Placed { block: block.clone(), collection: scope.map(str::to_owned), record, here: here.to_owned() })
}

/// Whether the block at `address` sits inside a list on `page`.
fn lists(page: &Page, address: &str) -> bool {
    let steps: Vec<&str> = address.split('.').collect();
    (1..steps.len()).step_by(2).any(|end| matches!(money::locate(page, &steps[..end].join(".")), Some((Block::List { .. }, _))))
}

/// The page at `here`, and the record id in it for a template page.
pub(crate) fn find_page<'a>(site: &'a Site, here: &'a str) -> Option<(&'a Page, Option<&'a str>)> {
    if let Some(page) = site.pages.iter().find(|p| p.template.is_none() && p.path() == here) {
        return Some((page, None));
    }
    let (slug, id) = here.strip_prefix('/')?.split_once('/')?;
    let page = site.pages.iter().find(|p| p.slug == slug && p.template.is_some())?;
    Some((page, Some(id)))
}

/// A plain page with what happened, and a link back.
fn told(back: &str, message: &str) -> Reply {
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Wallet</title>\n\
         <link rel=\"stylesheet\" href=\"{STYLE_PATH}\">\n</head>\n<body>\n<main>\n\
         <p>{}</p>\n<p><a href=\"{}\">Back</a></p>\n</main>\n</body>\n</html>\n",
        escape_attribute(message),
        escape_attribute(back)
    );
    crate::build(StatusCode::OK, HTML, page.into(), false)
}
