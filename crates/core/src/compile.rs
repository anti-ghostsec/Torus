use std::collections::BTreeMap;
use std::fmt::Write;

use serde::Serialize;

use crate::lint::{classify_link, lint, Finding, LinkTarget, Severity};
use crate::model::{
    Align, Audience, Block, Collection, Field, FieldKind, Layout, Page, Record, Scope, Site, Theme, ID_TOKEN, USERS,
    USER_NAME,
};
use crate::money::{self, format_xmr, parse_xmr, Payee, Purse, BLOCK_FIELD, RECORD_FIELD, WALLET_PATH};
use std::cell::RefCell;

/// Where every page loads its one stylesheet from.
pub const STYLE_PATH: &str = "/style.css";
/// Forms post to this path followed by the collection's name.
pub const FORM_PATH: &str = "/_form/";
/// Stored files are served from this path followed by the file's id.
pub const FILE_PATH: &str = "/_file/";
pub const SIGN_UP_PATH: &str = "/_account/signup";
pub const SIGN_IN_PATH: &str = "/_account/signin";
pub const SIGN_OUT_PATH: &str = "/_account/signout";
/// A member removes their own record by posting to this path followed by
/// the collection's name and the record's id.
pub const REMOVE_PATH: &str = "/_remove/";
pub const APPROVE_PATH: &str = "/_approve/";
/// A collection's feed is served at this path followed by its name.
pub const FEED_PATH: &str = "/_feed/";
/// A puzzle's picture is served at this path followed by its id and `.png`.
pub const PUZZLE_PATH: &str = "/_puzzle/";
/// The fields a form's puzzle sends: which puzzle, and the letters typed.
pub const PUZZLE_FIELD: &str = "_puzzle";
pub const PUZZLE_ANSWER_FIELD: &str = "_answer";
/// The query parameters a search box and the page links use.
pub const SEARCH_PARAM: &str = "q";
pub const PAGE_PARAM: &str = "p";
pub const SEARCH_MAX: usize = 100;
/// A page that says how far an upload has got is served at this path
/// followed by the upload's name.
pub const PROGRESS_PATH: &str = "/_progress/";
/// The query parameter that carries an upload's name on its form's address.
pub const UPLOAD_PARAM: &str = "u";
/// The query parameter that picks which size of a video to watch.
pub const SIZE_PARAM: &str = "v";
/// The query parameter counting how often a progress page has reloaded
/// itself with nothing to show.
pub const WAITED_PARAM: &str = "n";
/// After this many reloads with nothing to show, a progress page stops
/// reloading itself, so a page left open does not ask the site forever.
const PROGRESS_WAITS: u32 = 200;
/// The hidden form field naming the page to return to after submitting.
pub const NEXT_FIELD: &str = "_next";
/// The hidden form field naming the record a new record belongs to.
pub const PARENT_FIELD: &str = "_parent";
/// The hidden form field proving a request came from a page this site
/// served to the signed-in visitor.
pub const TOKEN_FIELD: &str = "_token";
pub const PASSWORD_FIELD: &str = "_password";
pub const PASSWORD_MIN: usize = 10;
pub const PASSWORD_MAX: usize = 200;

/// Where a page gets the records it shows.
pub trait Data {
    /// Shows `each` every record of a collection, oldest first, without
    /// copying any of them. Pages are rendered from this: a page that lists
    /// twenty records out of thousands must not copy the thousands.
    fn visit(&self, collection: &str, each: &mut dyn FnMut(&Record));

    /// Every record of a collection, oldest first.
    fn records(&self, collection: &str) -> Vec<Record> {
        let mut all = Vec::new();
        self.visit(collection, &mut |record| all.push(record.clone()));
        all
    }

    fn find(&self, collection: &str, id: &str) -> Option<Record> {
        let mut found = None;
        self.visit(collection, &mut |record| {
            if found.is_none() && record.id == id {
                found = Some(record.clone());
            }
        });
        found
    }

    /// The picture made from a video file, if one has been made.
    fn still(&self, _video: &str) -> Option<String> {
        None
    }

    /// The smaller copies made of a video file, smallest first: how many
    /// pixels the shorter side has, and the copy's file.
    fn sizes(&self, _video: &str) -> Vec<(u32, String)> {
        Vec::new()
    }

    /// How many times the page at this address has been viewed.
    fn views(&self, _path: &str) -> u64 {
        0
    }

    /// Makes a new puzzle for a form and returns its id, where the site
    /// can make puzzles.
    fn puzzle(&self) -> Option<String> {
        None
    }

    /// Whether a video may be shown yet. Where the host encodes every
    /// upload afresh, a video is held back until that is done, so that
    /// nothing the camera wrote into the original is ever served.
    fn ready(&self, _video: &str) -> bool {
        true
    }
}

/// A site with nothing submitted yet.
pub struct NoData;

impl Data for NoData {
    fn visit(&self, _collection: &str, _each: &mut dyn FnMut(&Record)) {}
}

/// How much of a field a search looks at. Enough for any honest search, and
/// it bounds what one request can make the server read.
const SEARCHED_CHARS: usize = 2_000;

fn mentions(value: &str, wanted: &str) -> bool {
    let end = value.char_indices().nth(SEARCHED_CHARS).map_or(value.len(), |(at, _)| at);
    value[..end].to_lowercase().contains(wanted)
}

/// The signed-in visitor a page is being rendered for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    /// The id of their record in the accounts collection.
    pub id: String,
    /// Goes into every form they are served and must come back with it.
    pub token: String,
    /// Whether the site's owner has made them a moderator, who may remove
    /// what others have added.
    pub moderator: bool,
}

/// What is particular to one request for a page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Visit {
    /// The signed-in visitor, if there is one.
    pub viewer: Option<Viewer>,
    /// Which page of the paged lists to show, counting from 0.
    pub page: usize,
    /// What was typed into the search box, if anything.
    pub search: String,
    /// The size of video the visitor picked: the pixels of its shorter
    /// side, or 0 for the full size. `None` when they have not picked.
    pub size: Option<u32>,
    /// A fresh random name for whatever this visitor uploads from this
    /// page, so that a small frame beside the form can show how far the
    /// upload has got. Empty where progress is not shown.
    pub upload: String,
    /// What the signed-in visitor holds in Monero on this site, where the
    /// site has a wallet and its blocks are on the page.
    pub purse: Option<Purse>,
    /// The site's own Monero address, where it has a wallet.
    pub site_address: Option<String>,
}

/// One page as the editor shows it: the published markup and stylesheet,
/// with every block and drop area tagged so the editor can map it back to
/// the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Canvas {
    /// The published stylesheet, rooted at `.page` instead of `body`.
    pub css: String,
    /// What goes inside `<body>`. Each block is wrapped in `<div data-b="PATH">`
    /// and each list of blocks carries `data-list="PATH"`, where a path is the
    /// dot-separated indexes leading to it (`2.1.0`: block 2, column 1, block 0).
    /// The blocks inside a list or a gate are its child list number 0.
    pub html: String,
}

/// Refuses a site the linter found anything in that blocks publishing.
pub fn check(site: &Site) -> Result<(), Vec<Finding>> {
    let findings = lint(site);
    if findings.iter().any(|f| f.severity == Severity::Error) {
        return Err(findings);
    }
    Ok(())
}

/// The stylesheet served at [`STYLE_PATH`].
pub fn stylesheet(site: &Site) -> String {
    style(&site.theme, "body")
}

/// Renders the small page shown in the frame under an upload form. It has no
/// scripts: it asks the browser to load it again every few seconds.
/// `arriving` is how many bytes of how many have been received, when the
/// upload named `name` is under way.
pub fn render_progress(name: &str, arriving: Option<(u64, u64)>, waited: u32) -> String {
    let megabytes = |bytes: u64| format!("{:.1}", bytes as f64 / 1_048_576.0);
    let (refresh, body) = match arriving {
        Some((received, total)) if total > 0 => {
            let percent = received.min(total) * 100 / total;
            let words = if received >= total {
                "Received. Finishing up.".to_owned()
            } else {
                format!(
                    "Uploading: {percent}% ({} of {} MB). Keep this page open until it finishes.",
                    megabytes(received),
                    megabytes(total)
                )
            };
            (Some("2".to_owned()), format!("<p>{words}</p>\n<progress max=\"100\" value=\"{percent}\">{percent}%</progress>\n"))
        }
        _ if waited < PROGRESS_WAITS => (
            Some(format!("3;url={PROGRESS_PATH}{}?{WAITED_PARAM}={}", query_escape(name), waited + 1)),
            "<p>Once you send a file, how far it has got shows here. Large files take minutes over Tor: keep this page open until it finishes.</p>\n".to_owned(),
        ),
        _ => (None, "<p>Reload the page to see how far an upload has got.</p>\n".to_owned()),
    };
    let refresh = refresh.map(|r| format!("<meta http-equiv=\"refresh\" content=\"{}\">\n", escape(&r))).unwrap_or_default();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n{refresh}\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>Upload progress</title>\n<link rel=\"stylesheet\" href=\"{STYLE_PATH}\">\n</head>\n\
         <body class=\"progress\">\n{body}</body>\n</html>\n"
    )
}

/// Renders a complete page. `record` is the one a template page is showing.
/// The same inputs always produce the same bytes.
pub fn render_page(site: &Site, page: &Page, record: Option<&Record>, data: &dyn Data, visit: &Visit) -> String {
    let here = match record {
        Some(record) => format!("{}/{}", page.path(), record.id),
        None => page.path(),
    };
    let mut html = String::new();
    let _ = write!(
        html,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <meta name=\"referrer\" content=\"no-referrer\">\n\
         <title>{} - {}</title>\n<link rel=\"stylesheet\" href=\"{STYLE_PATH}\">\n{}</head>\n<body>\n",
        escape(&page.title),
        escape(&site.title),
        feed_links(site, &page.blocks),
    );
    let view = View {
        site,
        data,
        here: &here,
        viewer: visit.viewer.as_ref(),
        page: visit.page,
        search: visit.search.trim(),
        size: visit.size,
        upload: &visit.upload,
        tagged: false,
        purse: visit.purse.as_ref(),
        site_address: visit.site_address.as_deref(),
        trail: RefCell::default(),
    };
    view.body(&mut html, page, record);
    html.push_str("</body>\n</html>\n");
    html
}

/// Renders one page for the editor. It never refuses: unsafe links are
/// rendered inert, lists show one made-up record so their layout is visible
/// before anyone has submitted anything, and what only members or only
/// guests would see is all shown.
pub fn render_canvas(site: &Site, slug: &str) -> Option<Canvas> {
    let page = site.pages.iter().find(|p| p.slug == slug)?;
    let here = page.path();
    let made_up = page.template.as_deref().and_then(|name| site.collection(name)).map(sample);
    let mut html = String::new();
    let view = View {
        site,
        data: &NoData,
        here: &here,
        viewer: None,
        page: 0,
        search: "",
        size: None,
        upload: "",
        tagged: true,
        purse: None,
        site_address: None,
        trail: RefCell::default(),
    };
    view.body(&mut html, page, made_up.as_ref());
    Some(Canvas { css: style(&site.theme, ".page"), html })
}

/// A stand-in record that shows each field's label where its value would be.
fn sample(collection: &Collection) -> Record {
    Record {
        id: "sample".into(),
        fields: collection
            .fields
            .iter()
            .map(|f| (f.name.clone(), if f.kind.is_file() { String::new() } else { placeholder(&f.label) }))
            .collect(),
        parent: None,
        owner: collection.members_only.then(|| "sample".to_owned()),
        seq: 0,
        held: false,
    }
}

/// Makes text safe to put in a link's query.
fn query_escape(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() { char::from(b).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn placeholder(label: &str) -> String {
    format!("\u{ab}{label}\u{bb}")
}

/// The record being shown at some point of a page, with its collection.
#[derive(Clone, Copy)]
struct Shown<'a> {
    collection: &'a Collection,
    record: &'a Record,
}

struct View<'a> {
    site: &'a Site,
    data: &'a dyn Data,
    /// The address of the page being rendered, for forms to return to.
    here: &'a str,
    viewer: Option<&'a Viewer>,
    page: usize,
    search: &'a str,
    size: Option<u32>,
    upload: &'a str,
    /// Whether to tag blocks and lists for the editor.
    tagged: bool,
    purse: Option<&'a Purse>,
    site_address: Option<&'a str>,
    /// Where on the page the block being rendered is (see `money::locate`),
    /// so that its forms can say which block sent them.
    trail: RefCell<Vec<usize>>,
}

impl View<'_> {
    fn body(&self, html: &mut String, page: &Page, record: Option<&Record>) {
        let _ = writeln!(html, "<header>\n<p class=\"site\">{}</p>", escape(&self.site.title));
        // A template page has no address of its own to link to.
        let listed: Vec<&Page> = self.site.pages.iter().filter(|p| p.template.is_none()).collect();
        if listed.len() > 1 {
            html.push_str("<nav>\n");
            for other in listed {
                let current = if other.slug == page.slug { " aria-current=\"page\"" } else { "" };
                let _ = writeln!(html, "<a href=\"{}\"{current}>{}</a>", escape(&other.path()), escape(&other.title));
            }
            html.push_str("</nav>\n");
        }
        html.push_str("</header>\n");
        html.push_str(if self.tagged { "<main data-list=\"\">\n" } else { "<main>\n" });
        let collection = page.template.as_deref().and_then(|name| self.site.collection(name));
        let shown = collection.zip(record).map(|(collection, record)| Shown { collection, record });
        self.blocks(html, &page.blocks, shown, self.tagged.then_some(""));
        html.push_str("</main>\n");
    }

    /// `shown` is the record being shown here, if any. `list_path` is the
    /// path of the list being rendered when tagging for the editor.
    fn blocks(&self, html: &mut String, blocks: &[Block], shown: Option<Shown<'_>>, list_path: Option<&str>) {
        for (index, block) in blocks.iter().enumerate() {
            self.trail.borrow_mut().push(index);
            self.block(html, index, block, shown, list_path);
            self.trail.borrow_mut().pop();
        }
    }

    /// Renders the blocks of child list `child` of the block being rendered.
    fn inside(&self, child: usize, html: &mut String, blocks: &[Block], shown: Option<Shown<'_>>, list_path: Option<&str>) {
        self.trail.borrow_mut().push(child);
        self.blocks(html, blocks, shown, list_path);
        self.trail.borrow_mut().pop();
    }

    /// Where the block being rendered is on the page.
    fn address(&self) -> String {
        self.trail.borrow().iter().map(|n| n.to_string()).collect::<Vec<_>>().join(".")
    }

    fn block(&self, html: &mut String, index: usize, block: &Block, shown: Option<Shown<'_>>, list_path: Option<&str>) {
        {
            let path = list_path.map(|list| if list.is_empty() { index.to_string() } else { format!("{list}.{index}") });
            if let Some(path) = &path {
                let _ = writeln!(html, "<div data-b=\"{path}\">");
            }
            let child = path.as_ref().map(|path| format!("{path}.0"));
            match block {
                Block::Heading { level, text, align } => heading(html, *level, text, *align),
                Block::Text { text, align } => paragraphs(html, text, *align),
                Block::Link { label, href, align } => self.link(html, label, href, *align, shown),
                Block::Divider => html.push_str("<hr>\n"),
                Block::Feed { collection, label } => {
                    let _ = writeln!(html, "<p><a class=\"feed\" href=\"{FEED_PATH}{}\">{}</a></p>", escape(collection), escape(label));
                }
                Block::Views { align } => {
                    let count = if self.tagged { 1234 } else { self.data.views(self.here) };
                    let _ = writeln!(html, "<p{}>{}</p>", class_with(*align, "count"), views_text(count));
                }
                Block::Columns { columns } => {
                    html.push_str("<div class=\"columns\">\n");
                    for (column_index, column) in columns.iter().enumerate() {
                        let column_path = path.as_ref().map(|path| format!("{path}.{column_index}"));
                        match &column_path {
                            Some(column_path) => {
                                let _ = writeln!(html, "<div data-list=\"{column_path}\">");
                            }
                            None => html.push_str("<div>\n"),
                        }
                        self.inside(column_index, html, column, shown, column_path.as_deref());
                        html.push_str("</div>\n");
                    }
                    html.push_str("</div>\n");
                }
                Block::Form { collection, submit_label, open, prefill } => {
                    self.form(html, collection, submit_label, *open, *prefill, shown)
                }
                Block::Search { label } => {
                    let _ = writeln!(
                        html,
                        "<form class=\"search\" method=\"get\" action=\"{}\">\n\
                         <p><input type=\"search\" name=\"{SEARCH_PARAM}\" value=\"{}\" maxlength=\"{SEARCH_MAX}\"> \
                         <button class=\"button\" type=\"submit\">{}</button></p>\n</form>",
                        escape(self.here),
                        escape(self.search),
                        escape(label)
                    );
                }
                Block::Count { collection, label, align } => {
                    let _ = writeln!(
                        html,
                        "<p{}>{} {}</p>",
                        class_with(*align, "count"),
                        self.count(collection, shown),
                        escape(label)
                    );
                }
                Block::Remove { label } => self.remove(html, label, shown),
                Block::Approve { label } => self.approve(html, label, shown),
                Block::List { collection, newest_first, limit, blocks, layout, scope, active_first, paged } => {
                    let class = if *layout == Layout::Grid { "list grid" } else { "list" };
                    let _ = writeln!(html, "<div class=\"{class}\">");
                    let listed = self.site.collection(collection);
                    match (&child, listed) {
                        // In the editor: one made-up record, and its blocks can be edited.
                        (Some(child), _) => {
                            let made_up = listed.map(sample);
                            let item = listed.zip(made_up.as_ref()).map(|(collection, record)| Shown { collection, record });
                            let _ = writeln!(html, "<article data-list=\"{child}\">");
                            self.inside(0, html, blocks, item, Some(child));
                            html.push_str("</article>\n");
                        }
                        (None, Some(listed)) => {
                            // First only note which records belong in the list,
                            // by id and freshness; the few that end up on this
                            // page are fetched afterwards.
                            let current = shown.map(|s| s.record.id.as_str());
                            // Searching narrows the lists that show a whole collection.
                            let wanted = (*scope == Scope::All && !self.search.is_empty()).then(|| self.search.to_lowercase());
                            let mut order: Vec<(u64, String)> = Vec::new();
                            self.data.visit(collection, &mut |r| {
                                let belongs = match scope {
                                    Scope::All => true,
                                    Scope::Children => current.is_some() && r.parent.as_deref() == current,
                                    Scope::Owned => current.is_some() && r.owner.as_deref() == current,
                                };
                                let matches = wanted.as_deref().is_none_or(|wanted| {
                                    listed
                                        .fields
                                        .iter()
                                        .filter(|f| !f.kind.is_file())
                                        .any(|f| r.fields.get(&f.name).is_some_and(|value| mentions(value, wanted)))
                                });
                                if belongs && matches {
                                    order.push((r.seq, r.id.clone()));
                                }
                            });
                            if *active_first {
                                // A record is as fresh as the newest thing that hangs on it.
                                let mut fresh: BTreeMap<String, u64> = BTreeMap::new();
                                for other in self.site.collections.iter().filter(|c| c.parent.as_deref() == Some(collection.as_str())) {
                                    self.data.visit(&other.name, &mut |child| {
                                        if let Some(parent) = &child.parent {
                                            let newest = fresh.entry(parent.clone()).or_default();
                                            *newest = (*newest).max(child.seq);
                                        }
                                    });
                                }
                                for (freshness, id) in &mut order {
                                    *freshness = (*freshness).max(fresh.get(id).copied().unwrap_or(0));
                                }
                                order.sort_by_key(|(freshness, _)| *freshness);
                            }
                            if *newest_first || *active_first {
                                order.reverse();
                            }
                            let per_page = usize::from(*limit).max(1);
                            let first = if *paged { self.page.saturating_mul(per_page).min(order.len()) } else { 0 };
                            let more = order.len() > first + per_page;
                            let records: Vec<Record> = order
                                .iter()
                                .skip(first)
                                .take(per_page)
                                .filter_map(|(_, id)| self.data.find(collection, id))
                                .collect();
                            if order.is_empty() {
                                html.push_str("<p class=\"empty\">Nothing here yet.</p>\n");
                            }
                            for record in &records {
                                html.push_str("<article>\n");
                                self.inside(0, html, blocks, Some(Shown { collection: listed, record }), None);
                                html.push_str("</article>\n");
                            }
                            if *paged && (first > 0 || more) {
                                html.push_str("<p class=\"pager\">");
                                if first > 0 {
                                    let _ = write!(html, "<a href=\"{}\">Back</a> ", self.page_link(self.page - 1));
                                }
                                if more {
                                    let _ = write!(html, "<a href=\"{}\">More</a>", self.page_link(self.page + 1));
                                }
                                html.push_str("</p>\n");
                            }
                        }
                        (None, None) => {}
                    }
                    html.push_str("</div>\n");
                }
                Block::Field { field, level, align, preview } => {
                    self.field(html, field, *level, *align, *preview, shown);
                }
                Block::Author { align } => self.author(html, *align, shown),
                Block::SignUp { submit_label } => self.sign_up(html, submit_label),
                Block::SignIn { submit_label } => self.sign_in(html, submit_label),
                Block::SignOut { submit_label } => self.sign_out(html, submit_label),
                Block::Gate { audience, blocks } => match &child {
                    Some(child) => {
                        let _ = writeln!(html, "<div class=\"gate\" data-list=\"{child}\">");
                        self.inside(0, html, blocks, shown, Some(child));
                        html.push_str("</div>\n");
                    }
                    None => {
                        if (*audience == Audience::Members) == self.viewer.is_some() {
                            self.inside(0, html, blocks, shown, None);
                        }
                    }
                },
                Block::Wallet { label } => self.wallet(html, label),
                Block::Donate { label } => self.donate(html, label),
                Block::Tip { amount, label } => self.tip(html, amount, label, shown),
                Block::Paid { price, label, days, blocks } => self.paid(html, price, label, *days, blocks, shown, child.as_deref()),
            }
            if path.is_some() {
                html.push_str("</div>\n");
            }
        }
    }

    /// Opens a form for one of the Monero blocks: it says which block sent
    /// it, and with which record, so the host can look up the amount itself.
    fn open_wallet_form(&self, html: &mut String, action: &str, shown: Option<Shown<'_>>) {
        self.open_form(html, &format!("{WALLET_PATH}{action}"), false);
        let _ = writeln!(html, "<input type=\"hidden\" name=\"{BLOCK_FIELD}\" value=\"{}\">", escape(&self.address()));
        if let Some(shown) = shown {
            let _ = writeln!(
                html,
                "<input type=\"hidden\" name=\"{RECORD_FIELD}\" value=\"{}/{}\">",
                escape(&shown.collection.name),
                escape(&shown.record.id)
            );
        }
    }

    /// An address to pay, as text, as a picture for a phone, and as a link
    /// that opens a wallet app.
    fn address_shown(&self, html: &mut String, address: &str) {
        let uri = money::payment_uri(address, None);
        let _ = writeln!(html, "<div class=\"pay\">{}", money::qr_svg(&uri));
        let _ = writeln!(html, "<p class=\"address\"><code>{}</code></p>", escape(address));
        let _ = writeln!(html, "<p><a class=\"button\" href=\"{}\">Open in a wallet app</a></p>\n</div>", escape(&uri));
    }

    fn wallet(&self, html: &mut String, label: &str) {
        if self.tagged {
            let sample = Purse { address: "8 your own address".into(), balance: money::PER_XMR / 4, ..Purse::default() };
            return self.wallet_of(html, label, &sample);
        }
        // Without a site address there is no wallet at all: nothing to show.
        match (self.viewer, self.purse) {
            (None, _) if self.site_address.is_some() => html.push_str("<p class=\"empty\">Sign in to see your wallet.</p>\n"),
            (Some(_), Some(purse)) => self.wallet_of(html, label, purse),
            _ => {}
        }
    }

    fn wallet_of(&self, html: &mut String, label: &str, purse: &Purse) {
        let _ = writeln!(html, "<section class=\"wallet\">\n<h2>{}</h2>", escape(label));
        let _ = writeln!(html, "<p class=\"balance\">{}</p>", format_xmr(purse.balance));
        if purse.arriving > 0 {
            let _ = writeln!(
                html,
                "<p class=\"arriving\">{} on its way: it counts once the network has confirmed it, about 20 minutes after it was sent.</p>",
                format_xmr(purse.arriving)
            );
        }
        html.push_str("<h3>Add to it</h3>\n<p>Send Monero to your own address below, from any wallet. Nobody else is given this address.</p>\n");
        self.address_shown(html, &purse.address);
        html.push_str("<h3>Withdraw</h3>\n");
        self.open_wallet_form(html, "withdraw", None);
        let _ = writeln!(
            html,
            "<p><label>To this Monero address<input type=\"text\" name=\"address\" required maxlength=\"110\" autocomplete=\"off\" spellcheck=\"false\"></label></p>\n\
             <p><label>Amount in XMR, or nothing for all of it<input type=\"text\" name=\"amount\" inputmode=\"decimal\" maxlength=\"24\" autocomplete=\"off\"></label></p>\n\
             <p class=\"hint\">The network's fee is taken from what you hold. Up to {} can be withdrawn from this site today.</p>",
            format_xmr(purse.left_today)
        );
        self.close_form(html, "Withdraw");
        let _ = writeln!(html, "<p><a href=\"{}\">Refresh</a></p>\n</section>", escape(self.here));
    }

    fn donate(&self, html: &mut String, label: &str) {
        let address = match (self.tagged, self.site_address) {
            (true, _) => "8 the site's own address",
            (false, Some(address)) => address,
            (false, None) => return,
        };
        let _ = writeln!(html, "<section class=\"donate\">\n<h2>{}</h2>", escape(label));
        self.address_shown(html, address);
        if let Some(purse) = self.purse.filter(|p| p.balance > 0) {
            self.open_wallet_form(html, "give", None);
            let _ = writeln!(
                html,
                "<p><label>Or give from what you hold ({}), in XMR<input type=\"text\" name=\"amount\" required inputmode=\"decimal\" maxlength=\"24\" autocomplete=\"off\"></label></p>",
                format_xmr(purse.balance)
            );
            self.close_form(html, "Give");
        }
        html.push_str("</section>\n");
    }

    /// Whether the signed-in visitor is who a payment here would go to.
    fn is_payee(&self, payee: &Payee) -> bool {
        matches!((payee, self.viewer), (Payee::Account(id), Some(viewer)) if *id == viewer.id)
    }

    fn tip(&self, html: &mut String, amount: &str, label: &str, shown: Option<Shown<'_>>) {
        let Some(amount) = parse_xmr(amount) else { return };
        let payee = money::payee(shown.map(|s| s.collection.name.as_str()), shown.map(|s| s.record));
        if !self.tagged && (self.viewer.is_none() || self.purse.is_none() || self.is_payee(&payee)) {
            return;
        }
        self.open_wallet_form(html, "tip", shown);
        let _ = writeln!(html, "<p><button class=\"button tip\" type=\"submit\">{} ({})</button></p>\n</form>", escape(label), format_xmr(amount));
    }

    #[allow(clippy::too_many_arguments)]
    fn paid(&self, html: &mut String, price: &str, label: &str, days: u16, blocks: &[Block], shown: Option<Shown<'_>>, child: Option<&str>) {
        let Some(price) = parse_xmr(price) else { return };
        let terms = if days == 0 { format_xmr(price) } else { format!("{} for {days} days", format_xmr(price)) };
        if let Some(child) = child {
            let _ = writeln!(html, "<div class=\"paid\" data-list=\"{child}\">\n<p class=\"price\">{} · {}</p>", escape(label), escape(&terms));
            self.inside(0, html, blocks, shown, Some(child));
            html.push_str("</div>\n");
            return;
        }
        let collection = shown.map(|s| s.collection.name.as_str());
        let payee = money::payee(collection, shown.map(|s| s.record));
        let key = money::unlock_key(days, &payee, collection, shown.map(|s| s.record), self.here);
        let open = self.is_payee(&payee) || self.purse.is_some_and(|p| p.unlocked.contains(&key));
        if open {
            self.inside(0, html, blocks, shown, None);
            return;
        }
        let _ = writeln!(html, "<div class=\"paid locked\">\n<p>{}</p>\n<p class=\"price\">{}</p>", escape(label), escape(&terms));
        match (self.viewer, self.purse) {
            (None, _) => html.push_str("<p class=\"empty\">Sign in to unlock this.</p>\n"),
            (Some(_), None) => html.push_str("<p class=\"empty\">Payments cannot be made right now.</p>\n"),
            (Some(_), Some(purse)) => {
                self.open_wallet_form(html, "unlock", shown);
                let _ = writeln!(html, "<p class=\"hint\">Paid from what you hold: {}.</p>", format_xmr(purse.balance));
                self.close_form(html, &format!("Pay {}", format_xmr(price)));
            }
        }
        html.push_str("</div>\n");
    }

    /// A link to another page of the lists on this page, keeping the search.
    fn page_link(&self, page: usize) -> String {
        let mut link = format!("?{PAGE_PARAM}={page}");
        if !self.search.is_empty() {
            let _ = write!(link, "&amp;{SEARCH_PARAM}={}", query_escape(self.search));
        }
        link
    }

    /// How many records of `collection` hang on the record being shown, or
    /// how many there are at all where no record is being shown.
    fn count(&self, collection: &str, shown: Option<Shown<'_>>) -> usize {
        if self.tagged {
            return 0;
        }
        let id = shown.map(|s| s.record.id.as_str());
        let by_parent = shown.is_some_and(|s| {
            self.site.collection(collection).is_some_and(|c| c.parent.as_deref() == Some(s.collection.name.as_str()))
        });
        let mut count = 0;
        self.data.visit(collection, &mut |r| {
            let counts = match id {
                None => true,
                Some(_) if by_parent => r.parent.as_deref() == id,
                Some(_) => r.owner.as_deref() == id,
            };
            if counts {
                count += 1;
            }
        });
        count
    }

    /// A button with which a moderator lets everyone see the record being
    /// shown. Only a record that is waiting has one.
    fn approve(&self, html: &mut String, label: &str, shown: Option<Shown<'_>>) {
        let Some(shown) = shown else { return };
        let waiting = shown.record.held && self.viewer.is_some_and(|viewer| viewer.moderator);
        if !waiting && !self.tagged {
            return;
        }
        let _ = writeln!(
            html,
            "<p class=\"held\">Waiting for approval. Only moderators see this.</p>\n\
             <form method=\"post\" action=\"{APPROVE_PATH}{}/{}\">\n<input type=\"hidden\" name=\"{NEXT_FIELD}\" value=\"{}\">",
            escape(&shown.collection.name),
            escape(&shown.record.id),
            escape(self.here)
        );
        if let Some(viewer) = self.viewer {
            let _ = writeln!(html, "<input type=\"hidden\" name=\"{TOKEN_FIELD}\" value=\"{}\">", escape(&viewer.token));
        }
        self.close_form(html, label);
    }

    /// A button with which the member who added the record being shown can remove it.
    fn remove(&self, html: &mut String, label: &str, shown: Option<Shown<'_>>) {
        let Some(shown) = shown else { return };
        // Theirs to remove: what they added, their own account, and for a
        // moderator anything but someone else's account.
        let mine = self.viewer.is_some_and(|viewer| {
            shown.record.owner.as_deref() == Some(viewer.id.as_str())
                || (shown.collection.name == USERS && shown.record.id == viewer.id)
                || (viewer.moderator && shown.collection.name != USERS)
        });
        if !mine && !self.tagged {
            return;
        }
        // Their own account, deleted with Monero still in it.
        let own_account = shown.collection.name == USERS && self.viewer.is_some_and(|v| v.id == shown.record.id);
        if let Some(purse) = self.purse.filter(|p| own_account && p.balance > 0) {
            let _ = writeln!(
                html,
                "<p class=\"hint\">You hold {} on this site. Withdraw it first: once your account is deleted, it goes to the site.</p>",
                format_xmr(purse.balance)
            );
        }
        // On the record's own page there is nothing to come back to afterwards.
        let on_its_page = self.here.ends_with(&format!("/{}", shown.record.id));
        let _ = writeln!(
            html,
            "<form method=\"post\" action=\"{REMOVE_PATH}{}/{}\">\n<input type=\"hidden\" name=\"{NEXT_FIELD}\" value=\"{}\">",
            escape(&shown.collection.name),
            escape(&shown.record.id),
            if on_its_page { "/".to_owned() } else { escape(self.here) }
        );
        if let Some(viewer) = self.viewer {
            let _ = writeln!(html, "<input type=\"hidden\" name=\"{TOKEN_FIELD}\" value=\"{}\">", escape(&viewer.token));
        }
        self.close_form(html, label);
    }

    fn field(&self, html: &mut String, name: &str, level: u8, align: Align, preview: bool, shown: Option<Shown<'_>>) {
        let Some(shown) = shown else { return };
        let Some(field) = shown.collection.field(name) else { return };
        let value = shown.record.fields.get(name).map(String::as_str).unwrap_or("");
        match field.kind {
            FieldKind::Text | FieldKind::LongText => match level {
                0 => paragraphs(html, value, align),
                level if !value.trim().is_empty() => heading(html, level, value, align),
                _ => {}
            },
            FieldKind::Code if !value.is_empty() => {
                let _ = writeln!(html, "<pre class=\"code\"><code>{}</code></pre>", escape(&value.replace("\r\n", "\n")));
            }
            FieldKind::Formatted => formatted(html, value),
            FieldKind::Code => {}
            // The editor has no file to show, so it marks the spot.
            FieldKind::Image | FieldKind::Video if self.tagged => {
                let _ = writeln!(html, "<p class=\"media\">{}</p>", escape(&placeholder(&field.label)));
            }
            FieldKind::Image | FieldKind::Video if !is_id(value) => {}
            FieldKind::Video if !self.data.ready(value) => {
                let _ = writeln!(html, "<p class=\"media\">This video is being prepared. It shows here once it is ready.</p>");
            }
            FieldKind::Image => {
                let _ = writeln!(html, "<p{}><img src=\"{FILE_PATH}{value}\" alt=\"\"></p>", class(align));
            }
            // A still frame, for cards in a list: the browser fetches just
            // enough of the video to show the frame at that moment, and
            // without controls it neither plays nor makes a sound. The
            // moment is taken from the file's id, so it differs per video
            // but is the same on every visit.
            FieldKind::Video if preview => match self.data.still(value) {
                // A real picture, where the host could make one: it is a
                // few kilobytes, and shows even in browsers set never to
                // load media.
                Some(still) => {
                    let _ = writeln!(html, "<img class=\"preview\" src=\"{FILE_PATH}{}\" alt=\"\" loading=\"lazy\">", escape(&still));
                }
                None => {
                    let second = 1 + u32::from(value.as_bytes()[0] % 8);
                    let _ = writeln!(
                        html,
                        "<video class=\"preview\" preload=\"metadata\" muted playsinline src=\"{FILE_PATH}{value}#t={second}\"></video>"
                    );
                }
            },
            FieldKind::Video => {
                // Smaller copies load faster over Tor. Without a choice
                // the middle one plays; the download is always the full size.
                let sizes = self.data.sizes(value);
                let usual = if sizes.iter().any(|(pixels, _)| *pixels == 720) { 720 } else { 0 };
                let wanted = self.size.unwrap_or(usual);
                let playing = sizes.iter().find(|(pixels, _)| *pixels == wanted);
                let source: &str = match playing {
                    Some((_, file)) => file,
                    None => value,
                };
                // Without scripts the browser's own player does everything;
                // the link is for browsers set never to play media in place.
                let _ = write!(html, "<video controls preload=\"metadata\" src=\"{FILE_PATH}{}\"></video>\n<p class=\"sizes\">", escape(source));
                if !sizes.is_empty() {
                    html.push_str("Watch in: ");
                    let choices = sizes.iter().map(|(pixels, _)| (*pixels, format!("{pixels}p"))).chain([(0, "Full size".to_owned())]);
                    for (pixels, name) in choices {
                        if playing.map_or(0, |(pixels, _)| *pixels) == pixels {
                            let _ = write!(html, "<strong>{name}</strong> · ");
                        } else {
                            let _ = write!(html, "<a href=\"{}?{SIZE_PARAM}={pixels}\">{name}</a> · ", escape(self.here));
                        }
                    }
                }
                let _ = writeln!(html, "<a href=\"{FILE_PATH}{value}\">Download the video</a></p>");
            }
        }
    }

    fn author(&self, html: &mut String, align: Align, shown: Option<Shown<'_>>) {
        let Some(owner) = shown.and_then(|s| s.record.owner.as_deref()) else { return };
        let name = if self.tagged {
            placeholder("Name")
        } else {
            match self.data.find(USERS, owner).and_then(|user| user.fields.get(USER_NAME).cloned()) {
                Some(name) => name,
                None => return,
            }
        };
        let _ = match self.site.page_for(USERS) {
            Some(profile) => writeln!(
                html,
                "<p{}><a href=\"{}/{}\">{}</a></p>",
                class_with(align, "author"),
                escape(&profile.path()),
                escape(owner),
                escape(&name)
            ),
            None => writeln!(html, "<p{}>{}</p>", class_with(align, "author"), escape(&name)),
        };
    }

    fn link(&self, html: &mut String, label: &str, href: &str, align: Align, shown: Option<Shown<'_>>) {
        let target = classify_link(href);
        let mut address = href.trim().to_owned();
        let mut usable = target != LinkTarget::Forbidden;
        if target == LinkTarget::Internal && address.contains(ID_TOKEN) {
            match shown {
                Some(shown) => address = address.replace(ID_TOKEN, &shown.record.id),
                None => usable = false,
            }
        }
        if !usable {
            let _ = writeln!(html, "<p{}><span class=\"button\">{}</span></p>", class(align), escape(label));
            return;
        }
        let rel = if target == LinkTarget::Internal { "" } else { " rel=\"noreferrer noopener\"" };
        let _ = writeln!(
            html,
            "<p{}><a class=\"button\" href=\"{}\"{rel}>{}</a></p>",
            class(align),
            escape(&address),
            escape(label)
        );
    }

    /// The opening of a form, with the fields every form carries.
    fn open_form(&self, html: &mut String, action: &str, files: bool) {
        self.open_form_to(html, action, files, self.here);
    }

    /// A form that sends the visitor on to `next` once it is done. A `next`
    /// ending in `/{id}` is completed with the id of the record just added.
    fn open_form_to(&self, html: &mut String, action: &str, files: bool, next: &str) {
        let encoding = if files { " enctype=\"multipart/form-data\"" } else { "" };
        let _ = writeln!(html, "<form method=\"post\" action=\"{}\"{encoding}>", escape(action));
        let _ = writeln!(html, "<input type=\"hidden\" name=\"{NEXT_FIELD}\" value=\"{}\">", escape(next));
        if let Some(viewer) = self.viewer {
            let _ = writeln!(html, "<input type=\"hidden\" name=\"{TOKEN_FIELD}\" value=\"{}\">", escape(&viewer.token));
        }
    }

    fn inputs(&self, html: &mut String, fields: &[Field], filled: Option<&Record>) {
        for field in fields {
            let (name, max) = (escape(&field.name), field.kind.max_len());
            let value = filled.and_then(|r| r.fields.get(&field.name)).map(|v| escape(v)).unwrap_or_default();
            let required = if field.required { " required" } else { "" };
            let _ = write!(html, "<p><label>{}<br>", escape(&field.label));
            let _ = match field.kind {
                FieldKind::Text => {
                    let value = if value.is_empty() { String::new() } else { format!(" value=\"{value}\"") };
                    write!(html, "<input type=\"text\" name=\"{name}\" maxlength=\"{max}\"{value}{required}>")
                }
                FieldKind::LongText => {
                    write!(html, "<textarea name=\"{name}\" rows=\"5\" maxlength=\"{max}\"{required}>{value}</textarea>")
                }
                FieldKind::Formatted => write!(
                    html,
                    "<textarea name=\"{name}\" rows=\"14\" maxlength=\"{max}\"{required}>{value}</textarea><br>\
                     <small># Heading · - list item · &gt; quote · **bold** · *italic* · `code` · [words](/address)</small>"
                ),
                FieldKind::Code => write!(
                    html,
                    "<textarea class=\"code\" name=\"{name}\" rows=\"16\" maxlength=\"{max}\" spellcheck=\"false\" wrap=\"off\"{required}>{value}</textarea>"
                ),
                FieldKind::Image => {
                    write!(html, "<input type=\"file\" name=\"{name}\" accept=\"image/png,image/jpeg,image/webp,image/gif\"{required}>")
                }
                FieldKind::Video => write!(html, "<input type=\"file\" name=\"{name}\" accept=\"video/mp4,video/webm\"{required}>"),
            };
            html.push_str("</label></p>\n");
        }
    }

    fn close_form(&self, html: &mut String, submit_label: &str) {
        let _ = writeln!(html, "<p><button class=\"button\" type=\"submit\">{}</button></p>\n</form>", escape(submit_label));
    }

    fn form(&self, html: &mut String, collection: &str, submit_label: &str, open: bool, prefill: bool, shown: Option<Shown<'_>>) {
        let Some(collection) = self.site.collection(collection) else {
            html.push_str("<p class=\"empty\">This form has no collection to add to.</p>\n");
            return;
        };
        if collection.members_only && self.viewer.is_none() && !self.tagged {
            html.push_str("<p class=\"empty\">Sign in to add to this.</p>\n");
            return;
        }
        let files = collection.has_files();
        // Opening the new record needs a page that shows records of this collection.
        let next = match self.site.pages.iter().find(|p| p.template.as_deref() == Some(collection.name.as_str())) {
            Some(page) if open => format!("{}/{{id}}", page.path()),
            _ => self.here.to_owned(),
        };
        self.open_form_to(html, &self.upload_address(&format!("{FORM_PATH}{}", collection.name), files), files, &next);
        if let (Some(_), Some(shown)) = (&collection.parent, shown) {
            let _ = writeln!(html, "<input type=\"hidden\" name=\"{PARENT_FIELD}\" value=\"{}\">", escape(&shown.record.id));
        }
        // The newest record already added here, to start from. Never what
        // waits for approval, and never a sealed collection's.
        let filled = match (&collection.parent, shown) {
            (Some(_), Some(shown)) if prefill && !collection.sealed && !self.tagged => {
                let mut newest: Option<Record> = None;
                self.data.visit(&collection.name, &mut |r| {
                    if r.parent.as_deref() == Some(shown.record.id.as_str())
                        && !r.held
                        && newest.as_ref().is_none_or(|n| r.seq > n.seq)
                    {
                        newest = Some(r.clone());
                    }
                });
                newest
            }
            _ => None,
        };
        self.inputs(html, &collection.fields, filled.as_ref());
        if self.site.moderation.puzzle_collections.contains(&collection.name) {
            self.puzzle(html);
        }
        self.close_form(html, submit_label);
        self.progress(html, files);
    }

    /// The address a form posts to. One that carries files also names the
    /// upload, so the server can report on it while it is still arriving.
    fn upload_address(&self, action: &str, files: bool) -> String {
        if files && !self.upload.is_empty() {
            format!("{action}?{UPLOAD_PARAM}={}", query_escape(self.upload))
        } else {
            action.to_owned()
        }
    }

    /// Under a form that carries files: a small frame showing how far the
    /// upload has got. Pages have no scripts, so the frame is a tiny page of
    /// its own that reloads itself every couple of seconds. Over Tor a large
    /// file takes minutes, and a visitor shown nothing gives up or leaves.
    fn progress(&self, html: &mut String, files: bool) {
        if !files {
            return;
        }
        if self.tagged {
            html.push_str("<p class=\"empty\">How far an upload has got is shown here.</p>\n");
        } else if !self.upload.is_empty() {
            let _ = writeln!(
                html,
                "<iframe class=\"progress\" src=\"{PROGRESS_PATH}{}\" title=\"Upload progress\"></iframe>",
                query_escape(self.upload)
            );
        }
    }

    fn password(&self, html: &mut String, new: bool) {
        let (hint, min) = if new {
            (" autocomplete=\"new-password\"", format!(" minlength=\"{PASSWORD_MIN}\""))
        } else {
            (" autocomplete=\"current-password\"", String::new())
        };
        let _ = writeln!(
            html,
            "<p><label>Password<br><input type=\"password\" name=\"{PASSWORD_FIELD}\"{min} maxlength=\"{PASSWORD_MAX}\"{hint} required></label></p>"
        );
    }

    fn sign_up(&self, html: &mut String, submit_label: &str) {
        let Some(users) = self.site.collection(USERS) else { return };
        if self.viewer.is_some() {
            return;
        }
        let files = users.has_files();
        self.open_form(html, &self.upload_address(SIGN_UP_PATH, files), files);
        self.inputs(html, &users.fields, None);
        self.password(html, true);
        if self.site.moderation.puzzle_sign_up {
            self.puzzle(html);
        }
        self.close_form(html, submit_label);
        self.progress(html, files);
    }

    /// A picture of a few letters, drawn by the site, and a box to type them
    /// in. Each one can be answered once.
    fn puzzle(&self, html: &mut String) {
        if self.tagged {
            html.push_str("<p class=\"media\">A picture of letters to type in is shown here.</p>\n");
            return;
        }
        match self.data.puzzle() {
            Some(id) => {
                let _ = writeln!(
                    html,
                    "<p><img class=\"puzzle\" src=\"{PUZZLE_PATH}{id}.png\" width=\"240\" height=\"80\" alt=\"A picture of six letters and digits\"></p>\n\
                     <input type=\"hidden\" name=\"{PUZZLE_FIELD}\" value=\"{id}\">\n\
                     <p><label>Type the letters in the picture<br><input type=\"text\" name=\"{PUZZLE_ANSWER_FIELD}\" maxlength=\"12\" \
                     autocomplete=\"off\" autocapitalize=\"characters\" spellcheck=\"false\" required></label></p>"
                );
            }
            None => html.push_str("<p class=\"empty\">This form needs a picture puzzle that could not be made. Reload the page.</p>\n"),
        }
    }

    fn sign_in(&self, html: &mut String, submit_label: &str) {
        let Some(name) = self.site.collection(USERS).and_then(|users| users.field(USER_NAME)) else { return };
        if self.viewer.is_some() {
            return;
        }
        self.open_form(html, SIGN_IN_PATH, false);
        self.inputs(html, std::slice::from_ref(name), None);
        self.password(html, false);
        self.close_form(html, submit_label);
    }

    fn sign_out(&self, html: &mut String, submit_label: &str) {
        if self.viewer.is_none() && !self.tagged {
            return;
        }
        self.open_form(html, SIGN_OUT_PATH, false);
        self.close_form(html, submit_label);
    }
}

/// Ids are made by the server from hex digits; anything else is not one.
fn is_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn heading(html: &mut String, level: u8, text: &str, align: Align) {
    let level = level.clamp(1, 6);
    let _ = writeln!(html, "<h{level}{}>{}</h{level}>", class(align), escape(text));
}

fn paragraphs(html: &mut String, text: &str, align: Align) {
    // Visitors' browsers send CRLF line ends; treat them like the editor's.
    let text = text.replace("\r\n", "\n");
    for paragraph in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
        let _ = writeln!(html, "<p{}>{}</p>", class(align), escape(paragraph).replace('\n', "<br>"));
    }
}

/// Links in a page's head that let feed readers find the page's feeds.
fn feed_links(site: &Site, blocks: &[Block]) -> String {
    fn gather(blocks: &[Block], out: &mut Vec<String>) {
        for block in blocks {
            if let Block::Feed { collection, .. } = block {
                if !out.contains(collection) {
                    out.push(collection.clone());
                }
            }
            for inner in block.children() {
                gather(inner, out);
            }
        }
    }
    let mut feeds = Vec::new();
    gather(blocks, &mut feeds);
    feeds
        .iter()
        .map(|name| {
            format!(
                "<link rel=\"alternate\" type=\"application/rss+xml\" title=\"{} - {}\" href=\"{FEED_PATH}{}\">\n",
                escape(&site.title),
                escape(name),
                escape(name)
            )
        })
        .collect()
}

/// A view count, said roughly: exact numbers would let someone who watches
/// the count go up tell when one particular visit happened.
pub fn views_text(count: u64) -> String {
    if count < 10 {
        return "Fewer than 10 views".into();
    }
    // Rounded down to tens, and above that to two significant digits.
    let mut step = 10u64;
    while count / step >= 100 {
        step *= 10;
    }
    let shown = (count / step) * step;
    let mut digits = shown.to_string();
    let mut at = digits.len();
    while at > 3 {
        at -= 3;
        digits.insert(at, ',');
    }
    format!("{digits}+ views")
}

/// Text with simple formatting, as described at [`FieldKind::Formatted`].
/// Everything typed is escaped first: the markup can only ever produce the
/// handful of plain elements below, and links only to ordinary addresses.
fn formatted(html: &mut String, text: &str) {
    let text = text.replace("\r\n", "\n");
    html.push_str("<div class=\"formatted\">\n");
    let mut lines = text.lines().peekable();
    let mut paragraph: Vec<&str> = Vec::new();
    let flush = |html: &mut String, paragraph: &mut Vec<&str>| {
        if !paragraph.is_empty() {
            let joined: Vec<String> = paragraph.iter().map(|l| inline(l.trim())).collect();
            let _ = writeln!(html, "<p>{}</p>", joined.join("<br>"));
            paragraph.clear();
        }
    };
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            flush(html, &mut paragraph);
            let mut code = Vec::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    break;
                }
                code.push(inner);
            }
            let _ = writeln!(html, "<pre class=\"code\"><code>{}</code></pre>", escape(&code.join("\n")));
        } else if let Some((level, rest)) = heading_line(trimmed) {
            flush(html, &mut paragraph);
            // The page's own title is the only first-level heading.
            let _ = writeln!(html, "<h{0}>{1}</h{0}>", level + 1, inline(rest));
        } else if list_item(trimmed).is_some() {
            flush(html, &mut paragraph);
            html.push_str("<ul>\n");
            let mut item = list_item(trimmed);
            while let Some(text) = item {
                let _ = writeln!(html, "<li>{}</li>", inline(text));
                item = lines.peek().and_then(|next| list_item(next.trim_start()));
                if item.is_some() {
                    lines.next();
                }
            }
            html.push_str("</ul>\n");
        } else if let Some(rest) = quote_line(trimmed) {
            flush(html, &mut paragraph);
            let mut quoted = vec![inline(rest)];
            while let Some(rest) = lines.peek().and_then(|next| quote_line(next.trim_start())) {
                quoted.push(inline(rest));
                lines.next();
            }
            let _ = writeln!(html, "<blockquote><p>{}</p></blockquote>", quoted.join("<br>"));
        } else if trimmed.is_empty() {
            flush(html, &mut paragraph);
        } else {
            paragraph.push(line);
        }
    }
    flush(html, &mut paragraph);
    html.push_str("</div>\n");
}

fn heading_line(line: &str) -> Option<(usize, &str)> {
    let level = line.chars().take_while(|&c| c == '#').count();
    let rest = line[level..].strip_prefix(' ')?;
    (1..=3).contains(&level).then_some((level, rest.trim()))
}

fn list_item(line: &str) -> Option<&str> {
    line.strip_prefix("- ").or_else(|| line.strip_prefix("* "))
}

fn quote_line(line: &str) -> Option<&str> {
    line.strip_prefix("> ").or_else(|| (line == ">").then_some(""))
}

/// One line's **bold**, *italic*, `code` and [links](/somewhere), with
/// everything else escaped. Marks that are not closed stay as typed.
fn inline(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        let after = &rest[c.len_utf8()..];
        let taken = match c {
            '`' => after.find('`').map(|end| {
                let _ = write!(out, "<code>{}</code>", escape(&after[..end]));
                1 + end + 1
            }),
            '*' if after.starts_with('*') => after[1..].find("**").filter(|&end| end > 0).map(|end| {
                let _ = write!(out, "<strong>{}</strong>", inline(&after[1..1 + end]));
                2 + end + 2
            }),
            '*' => after.find('*').filter(|&end| end > 0 && !after.starts_with(' ')).map(|end| {
                let _ = write!(out, "<em>{}</em>", inline(&after[..end]));
                1 + end + 1
            }),
            '[' => after.find("](").and_then(|middle| {
                let label = &after[..middle];
                let target_and_rest = &after[middle + 2..];
                let end = target_and_rest.find(')')?;
                let target = target_and_rest[..end].trim();
                if label.is_empty() || label.contains('[') || !safe_target(target) {
                    return None;
                }
                let outside = !target.starts_with('/') && !target.starts_with('#');
                let rel = if outside { " rel=\"noreferrer noopener\"" } else { "" };
                let _ = write!(out, "<a href=\"{}\"{rel}>{}</a>", escape(target), inline(label));
                Some(1 + middle + 2 + end + 1)
            }),
            _ => None,
        };
        match taken {
            Some(len) => rest = &rest[len..],
            None => {
                out.push_str(&escape(&rest[..c.len_utf8()]));
                rest = after;
            }
        }
    }
    out
}

/// An address on this site, or an ordinary web address. Never a script or
/// data address, and never one that could break out of the attribute.
fn safe_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    let well_formed = !target.is_empty() && !target.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | '\\'));
    let place = (target.starts_with('/') && !target.starts_with("//"))
        || target.starts_with('#')
        || lower.starts_with("http://")
        || lower.starts_with("https://");
    well_formed && place
}

fn class(align: Align) -> &'static str {
    match align {
        Align::Left => "",
        Align::Center => " class=\"center\"",
        Align::Right => " class=\"right\"",
    }
}

fn class_with(align: Align, base: &str) -> String {
    match align {
        Align::Left => format!(" class=\"{base}\""),
        Align::Center => format!(" class=\"{base} center\""),
        Align::Right => format!(" class=\"{base} right\""),
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn accent(theme: &Theme) -> &str {
    let value = theme.accent.as_str();
    let is_hex = value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex { value } else { "#7d4698" }
}

/// `root` is the selector of the element that stands for the page: `body`
/// when published, a wrapper element inside the editor.
fn style(theme: &Theme, root: &str) -> String {
    let (bg, fg, muted) = if theme.dark {
        ("#121214", "#e8e6ea", "#2c2a30")
    } else {
        ("#fbfafc", "#1b1a1d", "#dddae2")
    };
    format!(
        "*{{box-sizing:border-box}}\n\
         {root}{{margin:0;background:{bg};color:{fg};font:16px/1.6 system-ui,sans-serif}}\n\
         header,main{{max-width:60rem;margin:0 auto;padding:1rem}}\n\
         header{{border-bottom:1px solid {muted}}}\n\
         .site{{margin:0;font-weight:700}}\n\
         a{{color:{fg}}}\n\
         nav a{{margin-right:1rem}}\n\
         nav a[aria-current]{{color:{accent}}}\n\
         h1,h2,h3,h4,h5,h6{{line-height:1.25}}\n\
         p{{overflow-wrap:anywhere}}\n\
         hr{{border:0;border-top:1px solid {muted};margin:2rem 0}}\n\
         .center{{text-align:center}}\n\
         .right{{text-align:right}}\n\
         .button{{display:inline-block;padding:.5rem 1rem;border:0;border-radius:.4rem;background:{accent};color:#fff;font:inherit;text-decoration:none}}\n\
         span.button{{background:{muted};color:{fg}}}\n\
         .columns{{display:flex;flex-wrap:wrap;gap:1.5rem}}\n\
         .columns>div{{flex:1 1 14rem;min-width:0}}\n\
         label{{display:block}}\n\
         input,textarea{{width:100%;padding:.5rem;border:1px solid {muted};border-radius:.4rem;background:{bg};color:{fg};font:inherit}}\n\
         article{{padding:.25rem 0 .5rem;border-bottom:1px solid {muted}}}\n\
         .grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(13rem,1fr));gap:1rem}}\n\
         .grid article{{border:0;min-width:0}}\n\
         img,video{{display:block;max-width:100%;border-radius:.4rem}}\n\
         video{{width:100%;background:#000}}\n\
         video.preview{{aspect-ratio:16/9;object-fit:cover;pointer-events:none}}\n\
         img.preview{{aspect-ratio:16/9;object-fit:cover;width:100%}}\n\
         .held{{margin:.5rem 0;padding:.3rem .6rem;border-left:.25rem solid {accent};font-size:.9rem}}\n\
         iframe.progress{{display:block;width:100%;height:5rem;border:0}}\n\
         body.progress{{background:none;font-size:.9rem}}\n\
         body.progress p{{margin:0 0 .4rem}}\n\
         progress{{width:100%;height:1rem}}\n\
         .author,.count{{margin:.25rem 0;font-size:.9rem}}\n\
         .search input{{width:auto;min-width:60%}}\n\
         .pager a{{margin-right:1rem}}\n\
         .media{{padding:2rem 1rem;border:1px dashed {muted};border-radius:.4rem;text-align:center}}\n\
         img.puzzle{{background:#fff;border:1px solid {muted}}}\n\
         pre.code{{overflow:auto;padding:.75rem;border:1px solid {muted};border-radius:.4rem;font:14px/1.5 ui-monospace,monospace;white-space:pre;tab-size:4}}\n\
         textarea.code{{font:14px/1.5 ui-monospace,monospace;white-space:pre;tab-size:4}}\n\
         .formatted code{{font-family:ui-monospace,monospace;font-size:.9em}}\n\
         .formatted p,.formatted li{{overflow-wrap:anywhere}}\n\
         blockquote{{margin:1rem 0;padding:.1rem 1rem;border-left:.25rem solid {muted}}}\n\
         .empty{{opacity:.7}}\n\
         .wallet,.donate,.paid{{margin:1rem 0;padding:.5rem 1rem 1rem;border:1px solid {muted};border-radius:.4rem}}\n\
         .balance{{margin:.25rem 0;font-size:1.6rem;font-weight:700}}\n\
         .arriving,.hint,.price{{font-size:.9rem}}\n\
         .address code{{display:block;padding:.5rem;border:1px solid {muted};border-radius:.4rem;font:13px/1.5 ui-monospace,monospace;overflow-wrap:anywhere;user-select:all}}\n\
         svg.qr{{display:block;max-width:100%;height:auto;border-radius:.4rem}}\n\
         .paid.locked{{text-align:center}}\n\
         .paid.locked svg{{margin:0 auto}}\n",
        accent = accent(theme),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_counts_are_said_roughly() {
        let said: Vec<String> = [0, 9, 10, 19, 32, 99, 100, 345, 1234, 98_765, 1_234_567].map(views_text).to_vec();
        assert_eq!(
            said,
            [
                "Fewer than 10 views", "Fewer than 10 views", "10+ views", "10+ views", "30+ views", "90+ views", "100+ views",
                "340+ views", "1,200+ views", "98,000+ views", "1,200,000+ views",
            ]
        );
    }
    use crate::starters::video_site;

    fn text(text: &str) -> Block {
        Block::Text { text: text.into(), align: Align::Left }
    }

    fn page(slug: &str, blocks: Vec<Block>) -> Page {
        Page { slug: slug.into(), title: slug.into(), blocks, template: None }
    }

    fn site(blocks: Vec<Block>) -> Site {
        Site {
            title: "Test <site>".into(),
            theme: Theme::default(),
            pages: vec![page("index", blocks)],
            collections: vec![],
            accounts: false,
            seal_key: None,
            limits: Default::default(),
        moderation: Default::default(),
        }
    }

    fn home(site: &Site) -> String {
        check(site).unwrap();
        render_page(site, &site.pages[0], None, &NoData, &Visit::default())
    }

    fn list(collection: &str, blocks: Vec<Block>) -> Block {
        Block::List {
            collection: collection.into(),
            newest_first: true,
            limit: 2,
            blocks,
            layout: Layout::Rows,
            scope: Scope::All,
            active_first: false,
            paged: false,
        }
    }

    /// A guestbook: a form and a list on the home page, and a page per entry.
    fn guestbook() -> Site {
        let field = |name: &str, kind| Field { name: name.into(), label: name.to_uppercase(), kind, required: true };
        let mut site = site(vec![
            Block::Form { collection: "notes".into(), submit_label: "Sign".into(), open: false, prefill: false },
            list(
                "notes",
                vec![
                    Block::Field { field: "name".into(), level: 3, align: Align::Left, preview: false },
                    Block::Link { label: "Read".into(), href: "/note/{id}".into(), align: Align::Left },
                ],
            ),
        ]);
        site.collections.push(Collection {
            name: "notes".into(),
            fields: vec![field("name", FieldKind::Text), field("message", FieldKind::LongText)],
            parent: None,
            members_only: false,
                once_each: false, review: false,
                sealed: false,
        });
        let mut entry = page("note", vec![Block::Field { field: "message".into(), level: 0, align: Align::Left, preview: false }]);
        entry.template = Some("notes".into());
        site.pages.push(entry);
        site
    }

    /// Records by collection, standing in for the server's store.
    struct Held(Vec<(&'static str, Record)>);

    impl Data for Held {
        fn visit(&self, collection: &str, each: &mut dyn FnMut(&Record)) {
            self.0.iter().filter(|(name, _)| *name == collection).for_each(|(_, r)| each(r));
        }
    }

    fn record(id: &str, fields: &[(&str, &str)]) -> Record {
        Record {
            id: id.into(),
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Record::default()
        }
    }

    fn note(id: &str, name: &str, message: &str) -> (&'static str, Record) {
        ("notes", record(id, &[("name", name), ("message", message)]))
    }

    #[test]
    fn output_has_no_scripts_and_escapes_content() {
        let page = home(&site(vec![
            Block::Heading { level: 9, text: "<script>alert(1)</script>".into(), align: Align::Center },
            text("one\ntwo\n\nthree \"quoted\""),
        ]));
        assert!(!page.contains("<script"));
        assert!(page.contains("<h6 class=\"center\">&lt;script&gt;alert(1)&lt;/script&gt;</h6>"));
        assert!(page.contains("<p>one<br>two</p>"));
        assert!(page.contains("<p>three &quot;quoted&quot;</p>"));
        assert!(page.contains("Test &lt;site&gt;"));
        assert!(!page.contains("data-"));
    }

    #[test]
    fn forbidden_link_blocks_publishing_and_is_inert_in_the_editor() {
        let site = site(vec![Block::Link { label: "x".into(), href: "javascript:alert(1)".into(), align: Align::Left }]);
        assert!(check(&site).unwrap_err().iter().any(|f| f.severity == Severity::Error));
        assert!(!render_canvas(&site, "index").unwrap().html.contains("javascript:"));
    }

    #[test]
    fn canvas_tags_blocks_and_lists_with_their_paths() {
        let site = site(vec![text("a"), Block::Columns { columns: vec![vec![], vec![text("b"), Block::Divider]] }]);
        let canvas = render_canvas(&site, "index").unwrap();
        for tag in [
            "<main data-list=\"\">",
            "<div data-b=\"0\">",
            "<div data-b=\"1\">",
            "<div data-list=\"1.0\">",
            "<div data-list=\"1.1\">",
            "<div data-b=\"1.1.0\">",
            "<div data-b=\"1.1.1\">",
        ] {
            assert!(canvas.html.contains(tag), "missing {tag}");
        }
        assert!(canvas.css.contains(".page{"));
        assert!(!canvas.css.contains("body{"));
        assert!(render_canvas(&site, "missing").is_none());
    }

    #[test]
    fn hostile_accent_never_reaches_the_stylesheet() {
        let mut site = site(vec![]);
        site.theme.accent = "red}body{background:url(http://example.com)".into();
        assert!(!stylesheet(&site).contains("example.com"));
    }

    #[test]
    fn rendering_is_deterministic_and_requires_a_home_page() {
        let mut site = site(vec![Block::Divider]);
        site.pages.push(page("about", vec![]));
        assert_eq!(home(&site), home(&site));
        assert!(render_page(&site, &site.pages[1], None, &NoData, &Visit::default()).contains("aria-current"));
        site.pages.remove(0);
        assert!(check(&site).is_err());
    }

    #[test]
    fn older_sites_still_load() {
        let json = r#"{"type":"columns","id":"editor-only","columns":[[{"type":"text","text":"x"}]]}"#;
        let block: Block = serde_json::from_str(json).unwrap();
        assert_eq!(block, Block::Columns { columns: vec![vec![text("x")]] });
        let old: Site = serde_json::from_str(
            r#"{"title":"t","pages":[{"slug":"index","title":"Home","blocks":[
                {"type":"list","collection":"notes","limit":5,"blocks":[]}]}],
                "collections":[{"name":"notes","fields":[{"name":"n","label":"N"}]}]}"#,
        )
        .unwrap();
        assert!(!old.accounts && old.pages[0].template.is_none() && old.collections[0].parent.is_none());
        check(&old).unwrap();
    }

    #[test]
    fn a_form_offers_the_collections_fields_and_returns_to_its_page() {
        let page = home(&guestbook());
        assert!(page.contains("<form method=\"post\" action=\"/_form/notes\">"));
        assert!(page.contains("<input type=\"hidden\" name=\"_next\" value=\"/\">"));
        assert!(page.contains("<input type=\"text\" name=\"name\" maxlength=\"200\" required>"));
        assert!(page.contains("<textarea name=\"message\" rows=\"5\" maxlength=\"10000\" required></textarea>"));
        assert!(page.contains("<button class=\"button\" type=\"submit\">Sign</button>"));
        assert!(page.contains("Nothing here yet."));
    }

    #[test]
    fn a_list_repeats_its_blocks_per_record_and_links_to_each_records_page() {
        let site = guestbook();
        check(&site).unwrap();
        let data = Held(vec![
            note("aa", "First", "one"),
            note("bb", "<b>Second</b>", "two"),
            note("cc", "Third", "line one\r\nline two\r\n\r\nnext"),
        ]);
        let home = render_page(&site, &site.pages[0], None, &data, &Visit::default());
        // Newest first, limited to two, and escaped.
        let third = home.find("<h3>Third</h3>").expect("newest record missing");
        let second = home.find("<h3>&lt;b&gt;Second&lt;/b&gt;</h3>").expect("second record missing");
        assert!(third < second);
        assert!(!home.contains("First"));
        assert!(home.contains("href=\"/note/cc\""));
        assert_eq!(home.matches("<article>").count(), 2);

        // The template page shows one record and is left out of the navigation.
        let entry = render_page(&site, &site.pages[1], Some(&data.0[2].1), &data, &Visit::default());
        assert!(entry.contains("<p>line one<br>line two</p>\n<p>next</p>"));
        assert!(!entry.contains("<nav>"));
    }

    #[test]
    fn the_editor_shows_a_list_with_one_made_up_record_it_can_edit() {
        let canvas = render_canvas(&guestbook(), "index").unwrap().html;
        assert!(canvas.contains("<article data-list=\"1.0\">"));
        assert!(canvas.contains("<div data-b=\"1.0.0\">\n<h3>\u{ab}NAME\u{bb}</h3>"));
        assert!(canvas.contains("href=\"/note/sample\""));
        let template = render_canvas(&guestbook(), "note").unwrap().html;
        assert!(template.contains("<p>\u{ab}MESSAGE\u{bb}</p>"));
    }

    #[test]
    fn misplaced_dynamic_blocks_are_caught() {
        let errors = |site: &Site| lint(site).iter().filter(|f| f.severity == Severity::Error).count();
        let mut site = guestbook();
        assert_eq!(errors(&site), 0);
        // The moderation warning is raised but does not block publishing.
        assert!(lint(&site).iter().any(|f| f.message.contains("without review")));

        site.pages[0].blocks.push(Block::Field { field: "name".into(), level: 0, align: Align::Left, preview: false });
        assert_eq!(errors(&site), 1, "a field outside any record");
        site.pages[0].blocks.pop();

        site.pages[0].blocks.push(Block::Link { label: "x".into(), href: "/note/{id}".into(), align: Align::Left });
        assert_eq!(errors(&site), 1, "a record link outside any record");
        site.pages[0].blocks.pop();

        site.pages[1].blocks.push(Block::Field { field: "nope".into(), level: 0, align: Align::Left, preview: false });
        assert_eq!(errors(&site), 1, "a field the collection lacks");
        site.pages[1].blocks.pop();

        site.pages[0].blocks.push(Block::SignIn { submit_label: "x".into() });
        assert_eq!(errors(&site), 1, "account blocks while accounts are off");
        site.pages[0].blocks.pop();

        site.collections.clear();
        assert!(errors(&site) >= 3, "form, list and template all lost their collection");
    }

    /// The video site starter is the yardstick for everything a
    /// YouTube-like site needs, so it is rendered here in each situation.
    #[test]
    fn the_video_site_starter_renders_for_guests_and_members() {
        let site = video_site();
        check(&site).unwrap_or_else(|findings| panic!("the starter does not pass its own checks: {findings:#?}"));
        let page = |slug: &str| site.pages.iter().find(|p| p.slug == slug).unwrap();

        let mut ada = record("a1", &[("name", "Ada"), ("about", "I film things.")]);
        ada.owner = None;
        let mut video = record("f00d", &[("title", "First <video>"), ("description", "About it"), ("video", "beef"), ("thumbnail", "cafe")]);
        video.owner = Some("a1".into());
        let mut other = record("0dd", &[("title", "By someone else"), ("video", "aaaa")]);
        other.owner = Some("b2".into());
        let mut comment = record("c1", &[("text", "Nice one")]);
        comment.parent = Some("f00d".into());
        comment.owner = Some("a1".into());
        let mut stray = record("c2", &[("text", "On another video")]);
        stray.parent = Some("0dd".into());
        stray.owner = Some("a1".into());
        let data = Held(vec![
            ("users", ada.clone()),
            ("videos", video.clone()),
            ("videos", other),
            ("comments", comment),
            ("comments", stray),
        ]);
        let member = Visit {
            viewer: Some(Viewer { id: "a1".into(), token: "tok".into(), moderator: false }),
            upload: "0a1b2c".into(),
            ..Visit::default()
        };

        // Home: a grid of cards, each with a picture, a title and its author.
        let home = render_page(&site, page("index"), None, &data, &Visit::default());
        assert!(home.contains("<div class=\"list grid\">"));
        assert!(home.contains("<video class=\"preview\" preload=\"metadata\" muted playsinline src=\"/_file/beef#t="));
        assert!(!home.contains("<video controls"), "a card shows a still frame, not a player");
        assert!(home.contains("First &lt;video&gt;"));
        assert!(home.contains("href=\"/watch/f00d\""));
        assert!(home.contains("<a href=\"/channel/a1\">Ada</a>"));

        // Watch: the player, and only this video's comments.
        let watch = render_page(&site, page("watch"), Some(&video), &data, &Visit::default());
        assert!(watch.contains("<video controls preload=\"metadata\" src=\"/_file/beef\"></video>"));
        assert!(watch.contains("<p class=\"sizes\"><a href=\"/_file/beef\">Download the video</a></p>"));
        assert!(watch.contains("Nice one") && !watch.contains("On another video"));
        // A guest is asked to sign in instead of being shown the comment form.
        assert!(!watch.contains("action=\"/_form/comments\"") && watch.contains("Sign in to add to this."));
        let watch = render_page(&site, page("watch"), Some(&video), &data, &member);
        assert!(watch.contains("<form method=\"post\" action=\"/_form/comments\">"));
        assert!(watch.contains("<input type=\"hidden\" name=\"_parent\" value=\"f00d\">"));
        assert!(watch.contains("<input type=\"hidden\" name=\"_token\" value=\"tok\">"));
        assert!(watch.contains("<input type=\"hidden\" name=\"_next\" value=\"/watch/f00d\">"));

        // Upload: a file form for members, account forms for guests.
        let upload = render_page(&site, page("upload"), None, &data, &member);
        assert!(upload.contains("action=\"/_form/videos?u=0a1b2c\" enctype=\"multipart/form-data\""));
        assert!(upload.contains("<iframe class=\"progress\" src=\"/_progress/0a1b2c\""));
        // A form without files has no use for a progress frame.
        assert!(!watch.contains("<iframe"));
        assert!(upload.contains("<input type=\"file\" name=\"video\" accept=\"video/mp4,video/webm\" required>"));
        assert!(!upload.contains("/_account/signin"));
        let account = render_page(&site, page("account"), None, &data, &Visit::default());
        assert!(account.contains("action=\"/_account/signup\"") && account.contains("action=\"/_account/signin\""));
        assert!(account.contains("name=\"_password\" minlength=\"10\""));
        assert!(!account.contains("/_account/signout"));
        let account = render_page(&site, page("account"), None, &data, &member);
        assert!(account.contains("action=\"/_account/signout\"") && !account.contains("/_account/signup"));

        // Channel: one member's page, listing only their videos.
        let channel = render_page(&site, page("channel"), Some(&ada), &data, &Visit::default());
        assert!(channel.contains("<h1>Ada</h1>") && channel.contains("I film things."));
        assert!(channel.contains("First &lt;video&gt;") && !channel.contains("By someone else"));

        // Nothing rendered carries a script, and the editor can draw every page.
        for rendered in [&home, &watch, &upload, &account, &channel] {
            assert!(!rendered.contains("<script"));
        }
        for p in &site.pages {
            assert!(render_canvas(&site, &p.slug).is_some());
        }
    }
}
