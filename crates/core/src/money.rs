//! Monero on a site: amounts, who is paid, what a payment opens, and the
//! picture of an address that a phone's wallet can read.
//!
//! The coins themselves are kept by the editor's wallet. A page is only
//! told, through [`Visit`](crate::Visit), what the visitor holds.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::model::{Block, Page, Record, USERS};

/// The smallest unit of Monero: 10^12 make one XMR.
pub type Piconero = u64;
pub const PER_XMR: Piconero = 1_000_000_000_000;

/// Where the forms of the Monero blocks are sent: `/_wallet/tip` and so on.
pub const WALLET_PATH: &str = "/_wallet/";
/// The field naming the block a wallet form belongs to.
pub const BLOCK_FIELD: &str = "_block";
/// The field naming the record that block was shown with, if any.
pub const RECORD_FIELD: &str = "_record";

/// `1.5` XMR as "1.5 XMR"; whole amounts without a point.
pub fn format_xmr(amount: Piconero) -> String {
    let whole = amount / PER_XMR;
    let part = amount % PER_XMR;
    if part == 0 {
        return format!("{whole} XMR");
    }
    let digits = format!("{part:012}");
    format!("{whole}.{} XMR", digits.trim_end_matches('0'))
}

/// Reads an amount typed as XMR, such as `0.05` or `2`, with or without "XMR".
pub fn parse_xmr(text: &str) -> Option<Piconero> {
    let text = text.trim();
    let text = text.strip_suffix("XMR").or_else(|| text.strip_suffix("xmr")).unwrap_or(text).trim();
    let (whole, part) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if (whole.is_empty() && part.is_empty()) || part.len() > 12 || !digits(whole) || !digits(part) {
        return None;
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let part: u64 = if part.is_empty() { 0 } else { format!("{part:0<12}").parse().ok()? };
    whole.checked_mul(PER_XMR)?.checked_add(part)
}

/// What the signed-in visitor holds on this site.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Purse {
    /// Their own address: what is sent to it becomes theirs.
    pub address: String,
    pub balance: Piconero,
    /// Sent to them and seen, not yet confirmed.
    pub arriving: Piconero,
    /// What they have paid to see, by key (see [`unlock_key`]).
    pub unlocked: Vec<String>,
    /// What the site's users may still withdraw today.
    pub left_today: Piconero,
}

/// Who a payment made on a page goes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Payee {
    /// The site's owner.
    Site,
    /// An account, by the id of its record.
    Account(String),
}

/// What a site's host asks of the wallet, on behalf of its visitors. The
/// editor checks each against its own books: a host can only ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ask {
    /// What an account holds, giving it an address if it has none yet.
    Purse { user: String },
    /// The site's own address, for donations.
    SiteAddress,
    /// Moves `amount` from an account to `to`: a tip or a gift.
    Pay { from: String, to: Payee, amount: Piconero },
    /// Pays `price` for what `key` opens, unless it is open already.
    Unlock { user: String, to: Payee, key: String, price: Piconero, days: u16 },
    /// Sends `amount` (everything, when `None`) out of the wallet to `address`.
    Withdraw { user: String, address: String, amount: Option<Piconero> },
}

/// The wallet's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Told {
    Purse(Purse),
    SiteAddress(Option<String>),
    Done,
    Withdrawn { amount: Piconero, fee: Piconero },
    /// Not done, and why, in words for the visitor.
    Refused(String),
}

/// Whoever stands behind the record being shown: the account that added it,
/// or the account itself on an account's page. Otherwise the site.
pub fn payee(collection: Option<&str>, record: Option<&Record>) -> Payee {
    match (collection, record) {
        (Some(USERS), Some(record)) => Payee::Account(record.id.clone()),
        (_, Some(Record { owner: Some(owner), .. })) => Payee::Account(owner.clone()),
        _ => Payee::Site,
    }
}

/// What paying at a paid block opens. With `days`, a pass to everything
/// the same payee has behind a pass: a membership of the site, or a
/// subscription to one account. Without, the one record or page.
pub fn unlock_key(days: u16, payee: &Payee, collection: Option<&str>, record: Option<&Record>, page: &str) -> String {
    match (days, payee, collection.zip(record)) {
        (1.., Payee::Site, _) => "pass:site".into(),
        (1.., Payee::Account(id), _) => format!("pass:{id}"),
        (0, _, Some((collection, record))) => format!("item:{collection}/{}", record.id),
        (0, _, None) => format!("page:{page}"),
    }
}

/// The block at `address` on `page` ("2.0.1": the third block, its first
/// list of blocks, the second block in that), with the collection whose
/// records it is shown with there, if any: the template's, or that of the
/// list it sits in.
pub fn locate<'a>(page: &'a Page, address: &str) -> Option<(&'a Block, Option<&'a str>)> {
    let mut steps = address.split('.').map(|s| s.parse::<usize>().ok());
    let mut scope = page.template.as_deref();
    let mut block = page.blocks.get(steps.next()??)?;
    loop {
        let Some(child) = steps.next() else { return Some((block, scope)) };
        if let Block::List { collection, .. } = block {
            scope = Some(collection.as_str());
        }
        let list = *block.children().get(child?)?;
        block = list.get(steps.next()??)?;
    }
}

/// A Monero payment link: wallets that know the scheme open with it filled in.
pub fn payment_uri(address: &str, amount: Option<Piconero>) -> String {
    match amount {
        Some(amount) => {
            let text = format_xmr(amount);
            format!("monero:{address}?tx_amount={}", text.trim_end_matches(" XMR"))
        }
        None => format!("monero:{address}"),
    }
}

/// A QR code as an SVG drawing of squares, to put straight into a page:
/// no script and no separate request.
pub fn qr_svg(text: &str) -> String {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M) else {
        return String::new();
    };
    let width = code.width();
    let colors = code.to_colors();
    // A quiet zone of four squares on each side, as readers expect.
    let size = width + 8;
    let mut path = String::new();
    for (i, color) in colors.iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let _ = write!(path, "M{} {}h1v1h-1z", i % width + 4, i / width + 4);
        }
    }
    format!(
        "<svg class=\"qr\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" width=\"200\" height=\"200\" \
         role=\"img\" aria-label=\"QR code of the address\" shape-rendering=\"crispEdges\">\
         <rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path fill=\"#000\" d=\"{path}\"/></svg>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Audience;

    #[test]
    fn amounts_read_and_print() {
        assert_eq!(parse_xmr("1.5"), Some(1_500_000_000_000));
        assert_eq!(parse_xmr("0.000000000001"), Some(1));
        assert_eq!(parse_xmr(".25 XMR"), Some(250_000_000_000));
        assert_eq!(parse_xmr("2xmr"), Some(2 * PER_XMR));
        assert_eq!(parse_xmr("1.0000000000001"), None);
        assert_eq!(parse_xmr("-1"), None);
        assert_eq!(parse_xmr("1e3"), None);
        assert_eq!(parse_xmr(""), None);
        assert_eq!(parse_xmr("."), None);
        assert_eq!(parse_xmr("99999999999"), None, "more than can be counted");
        assert_eq!(format_xmr(1_500_000_000_000), "1.5 XMR");
        assert_eq!(format_xmr(3 * PER_XMR), "3 XMR");
        assert_eq!(format_xmr(1), "0.000000000001 XMR");
        assert_eq!(payment_uri("8abc", Some(PER_XMR / 20)), "monero:8abc?tx_amount=0.05");
    }

    #[test]
    fn payments_go_to_whoever_stands_behind_the_record() {
        let post = Record { id: "p1".into(), owner: Some("alice".into()), ..Record::default() };
        let anonymous = Record { id: "p2".into(), ..Record::default() };
        let account = Record { id: "bob".into(), ..Record::default() };
        assert_eq!(payee(Some("posts"), Some(&post)), Payee::Account("alice".into()));
        assert_eq!(payee(Some("posts"), Some(&anonymous)), Payee::Site);
        assert_eq!(payee(Some(USERS), Some(&account)), Payee::Account("bob".into()));
        assert_eq!(payee(None, None), Payee::Site);
        let alice = Payee::Account("alice".into());
        assert_eq!(unlock_key(30, &alice, Some("posts"), Some(&post), "/post"), "pass:alice");
        assert_eq!(unlock_key(30, &Payee::Site, None, None, "/"), "pass:site");
        assert_eq!(unlock_key(0, &alice, Some("posts"), Some(&post), "/post/p1"), "item:posts/p1");
        assert_eq!(unlock_key(0, &Payee::Site, None, None, "/guide"), "page:/guide");
    }

    #[test]
    fn blocks_are_found_by_address() {
        let tip = Block::Tip { amount: "0.01".into(), label: "Tip".into() };
        let page = Page {
            slug: "index".into(),
            title: "Home".into(),
            template: None,
            blocks: vec![
                Block::Divider,
                Block::Columns { columns: vec![vec![], vec![Block::Gate { audience: Audience::Members, blocks: vec![tip.clone()] }]] },
                Block::List {
                    collection: "posts".into(),
                    newest_first: false,
                    limit: 5,
                    blocks: vec![Block::Divider, tip.clone()],
                    layout: Default::default(),
                    scope: Default::default(),
                    active_first: false,
                    paged: false,
                },
            ],
        };
        assert_eq!(locate(&page, "0"), Some((&Block::Divider, None)));
        assert_eq!(locate(&page, "1.1.0.0.0"), Some((&tip, None)));
        assert_eq!(locate(&page, "2.0.1"), Some((&tip, Some("posts"))));
        assert_eq!(locate(&page, "2.0.2"), None);
        assert_eq!(locate(&page, "2.1.0"), None);
        assert_eq!(locate(&page, "9"), None);
        assert_eq!(locate(&page, ""), None);
        assert_eq!(locate(&page, "1.x"), None);
        assert_eq!(locate(&page, "1.1"), None, "a list of blocks is not a block");
    }

    #[test]
    fn addresses_draw_as_qr_codes() {
        let svg = qr_svg("monero:8BwU3GBhNyEP8Yv2Fx8rXgdK2Ux5TCSbXXtZrYc4y2rJhjS");
        assert!(svg.starts_with("<svg") && svg.contains("<path"));
        assert!(!svg.contains("<script"));
    }
}
