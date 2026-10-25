use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Slug of the page served at `/`.
pub const HOME_SLUG: &str = "index";
/// Stands for the current record's id in a link, as in `/profile/{id}`.
pub const ID_TOKEN: &str = "{id}";
/// The collection that holds accounts, on a site that has them.
pub const USERS: &str = "users";
/// The field of [`USERS`] that holds the account's public name.
pub const USER_NAME: &str = "name";
/// The one field a record of a sealed collection has: the encrypted submission, in hex.
pub const SEALED_FIELD: &str = "sealed";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Site {
    pub title: String,
    #[serde(default)]
    pub theme: Theme,
    pub pages: Vec<Page>,
    /// The kinds of records visitors can add to this site.
    #[serde(default)]
    pub collections: Vec<Collection>,
    /// Whether visitors can create accounts. Accounts are the records of the
    /// collection called [`USERS`].
    #[serde(default)]
    pub accounts: bool,
    /// The public key that sealed collections are encrypted to, in hex. The
    /// editor fills it in when publishing; its secret never leaves the vault.
    #[serde(default)]
    pub seal_key: Option<String>,
    /// How much room visitors' files may take on the device hosting the site.
    #[serde(default)]
    pub limits: Limits,
    /// How the site is moderated: blocked words, and whether new accounts
    /// wait for approval.
    #[serde(default)]
    pub moderation: Moderation,
}

/// The owner's standing rules for what visitors may add.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Moderation {
    /// Words that may not appear in what visitors submit. Matched without
    /// regard to case, as whole words and as parts of words.
    pub blocked_words: Vec<String>,
    /// What to do with a submission that contains a blocked word: refuse it
    /// outright, or hold it for the owner or a moderator to approve.
    #[serde(default)]
    pub blocked_held: bool,
    /// Whether a new account must be approved before it can sign in.
    pub approve_accounts: bool,
    /// Collections a visitor may add to only after typing the letters in a
    /// picture the site draws: a brake on scripts that flood a form.
    #[serde(default)]
    pub puzzle_collections: Vec<String>,
    /// Whether signing up needs the same.
    #[serde(default)]
    pub puzzle_sign_up: bool,
}

impl Moderation {
    /// The blocked words that actually constrain anything: non-empty, lowercased.
    pub fn words(&self) -> impl Iterator<Item = String> + '_ {
        self.blocked_words.iter().map(|w| w.trim().to_lowercase()).filter(|w| !w.is_empty())
    }

    /// Whether `text` contains any blocked word. Matching folds case and
    /// looks inside words, so "scam" catches "Scams".
    pub fn blocks(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        self.words().any(|word| lower.contains(&word))
    }
}

/// How much room visitors' files may take. The owner sets these to what
/// the device hosting the site can spare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// The largest video a visitor may upload, in megabytes.
    pub video_mb: u32,
    /// The most file data the site keeps, all files together, in megabytes.
    pub storage_mb: u32,
    /// Whether smaller copies of a video are made for visitors to choose
    /// from. They load faster and take a little more room.
    pub sizes: bool,
    /// No longer read: every uploaded video is now encoded afresh before it
    /// is shown. Kept so that sites saved by older versions still load.
    pub shrink: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self { video_mb: 1024, storage_mb: 5 * 1024, sizes: true, shrink: true }
    }
}

impl Limits {
    const MEGABYTE: u64 = 1024 * 1024;

    /// Never more than a video field accepts at all, whatever was typed.
    pub fn video_bytes(self) -> u64 {
        (u64::from(self.video_mb.max(1)) * Self::MEGABYTE).min(FieldKind::Video.max_bytes())
    }

    pub fn storage_bytes(self) -> u64 {
        u64::from(self.storage_mb.clamp(1, 1024 * 1024)) * Self::MEGABYTE
    }
}

impl Site {
    pub fn collection(&self, name: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.name == name)
    }

    /// Whether some page carries a form that adds to this collection. A
    /// collection nothing on the site offers a form for must not be writable.
    pub fn has_form_for(&self, name: &str) -> bool {
        self.any_block(&|block| matches!(block, Block::Form { collection, .. } if collection == name))
    }

    /// Whether any block on any page, however deeply nested, passes `test`.
    pub fn any_block(&self, test: &dyn Fn(&Block) -> bool) -> bool {
        fn any(blocks: &[Block], test: &dyn Fn(&Block) -> bool) -> bool {
            blocks.iter().any(|block| test(block) || block.children().iter().any(|inner| any(inner, test)))
        }
        self.pages.iter().any(|page| any(&page.blocks, test))
    }

    /// The template page that shows the records of a collection, if there is one.
    pub fn page_for(&self, collection: &str) -> Option<&Page> {
        self.pages.iter().find(|p| p.template.as_deref() == Some(collection))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Theme {
    /// `#rrggbb`. Anything else falls back to the default at compile time.
    pub accent: String,
    pub dark: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self { accent: "#7d4698".into(), dark: true }
    }
}

/// A named set of records with the same fields: videos, comments, accounts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Collection {
    /// Lowercase letters, digits and dashes. Appears in form addresses.
    pub name: String,
    pub fields: Vec<Field>,
    /// Set when every record belongs to a record of another collection, as
    /// a comment belongs to a video.
    #[serde(default)]
    pub parent: Option<String>,
    /// Whether only signed-in visitors may add records. Each record then
    /// remembers the account that added it.
    #[serde(default)]
    pub members_only: bool,
    /// Whether each member may have at most one record per parent, added by
    /// submitting once and taken back by submitting again: a like, a vote,
    /// a bookmark. Such a collection may have no fields at all.
    #[serde(default)]
    pub once_each: bool,
    /// Whether what visitors send is encrypted on arrival to a key only the
    /// site's owner holds, so that the site itself cannot read it back: a
    /// contact form, a tip line. Nothing sealed can be shown on the site.
    #[serde(default)]
    pub sealed: bool,
    /// Whether what visitors add stays out of sight until the owner or a
    /// moderator has approved it.
    #[serde(default)]
    pub review: bool,
}

impl Collection {
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn has_files(&self) -> bool {
        self.fields.iter().any(|f| f.kind.is_file())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    /// Lowercase letters, digits and dashes.
    pub name: String,
    /// What visitors see next to the input.
    pub label: String,
    #[serde(default)]
    pub kind: FieldKind,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// One line.
    #[default]
    Text,
    /// Several lines.
    LongText,
    /// An uploaded picture. Re-encoded on arrival, which removes whatever
    /// the camera or editing program recorded inside the file.
    Image,
    /// An uploaded video, stored as it arrives.
    Video,
    /// Text shown exactly as typed, in a fixed-width font: for code, logs
    /// and anything whose spacing matters.
    Code,
    /// Several lines with simple formatting: `#` headings, `-` lists, `>`
    /// quotes, **bold**, *italic*, `code` and [links](/somewhere). Nothing
    /// typed can add a script or a style, or load anything.
    Formatted,
}

impl FieldKind {
    pub fn is_file(self) -> bool {
        matches!(self, FieldKind::Image | FieldKind::Video)
    }

    /// The most characters of text a visitor may submit. Files are measured
    /// with [`FieldKind::max_bytes`] instead.
    pub fn max_len(self) -> usize {
        match self {
            FieldKind::Text => 200,
            FieldKind::LongText => 10_000,
            FieldKind::Code | FieldKind::Formatted => 50_000,
            // As many as fit a file's id.
            FieldKind::Image | FieldKind::Video => 64,
        }
    }

    /// The largest file a visitor may upload to a field of this kind. In
    /// bytes, as a `u64` because a video can be larger than 32 bits count.
    pub fn max_bytes(self) -> u64 {
        match self {
            FieldKind::Text | FieldKind::LongText | FieldKind::Code | FieldKind::Formatted => self.max_len() as u64 * 4,
            FieldKind::Image => 8 * 1024 * 1024,
            FieldKind::Video => 10 * 1024 * 1024 * 1024,
        }
    }
}

/// One thing a visitor added. Records carry no time and no trace of where
/// they were sent from: only an unguessable id and what was submitted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    /// For a file field, the value is the id of the stored file.
    pub fields: BTreeMap<String, String>,
    /// The record this one belongs to, in a collection that has a parent.
    #[serde(default)]
    pub parent: Option<String>,
    /// The account that added this record, in a members-only collection.
    #[serde(default)]
    pub owner: Option<String>,
    /// Counts up across the whole site with every record added, so records
    /// of different collections can be put in order without storing a time.
    #[serde(default)]
    pub seq: u64,
    /// Waiting to be approved: shown to moderators only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Page {
    /// Lowercase letters, digits and dashes. `index` is the home page.
    pub slug: String,
    pub title: String,
    pub blocks: Vec<Block>,
    /// Set on a template page: the collection whose records it shows, one
    /// record per address (`/slug/<record id>`).
    #[serde(default)]
    pub template: Option<String>,
}

impl Page {
    /// URL path this page is served at. A template page serves one address
    /// below this per record.
    pub fn path(&self) -> String {
        if self.slug == HOME_SLUG {
            "/".into()
        } else {
            format!("/{}", self.slug)
        }
    }
}

/// A block is declarative: it carries content, never code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    Heading {
        level: u8,
        text: String,
        #[serde(default)]
        align: Align,
    },
    /// Plain text. Blank lines separate paragraphs.
    Text {
        text: String,
        #[serde(default)]
        align: Align,
    },
    /// Inside a list or on a template page, `{id}` in `href` stands for the
    /// record being shown, so `/profile/{id}` links to that record's page.
    Link {
        label: String,
        href: String,
        #[serde(default)]
        align: Align,
    },
    Divider,
    Columns { columns: Vec<Vec<Block>> },
    /// Lets a visitor add a record to a collection.
    Form {
        collection: String,
        submit_label: String,
        /// Afterwards, go to the new record's own page instead of back.
        #[serde(default)]
        open: bool,
        /// On a record's page, start the form filled in with the newest
        /// record already added there: for editing by adding a new version.
        #[serde(default)]
        prefill: bool,
    },
    /// Repeats `blocks` once for each record of a collection.
    List {
        collection: String,
        #[serde(default)]
        newest_first: bool,
        /// How many records to show at most.
        limit: u16,
        blocks: Vec<Block>,
        #[serde(default)]
        layout: Layout,
        #[serde(default)]
        scope: Scope,
        /// Order by what was last added to: a thread with a fresh reply
        /// comes before a newer thread without one.
        #[serde(default)]
        active_first: bool,
        /// Offer links to further pages when there are more than `limit`.
        #[serde(default)]
        paged: bool,
    },
    /// A search box. What is typed narrows the lists on the same page that
    /// show all of a collection.
    Search { label: String },
    /// Shows how many records of a collection hang on the record being
    /// shown: replies to a thread, likes of a post, videos of a member.
    Count {
        collection: String,
        label: String,
        #[serde(default)]
        align: Align,
    },
    /// Lets a member remove the record being shown, if they added it.
    Remove { label: String },
    /// A link to a feed of a collection's newest records, for feed readers.
    Feed { collection: String, label: String },
    /// How often this page has been viewed, roughly. Nothing about who
    /// viewed it, or when, is kept: only how many times.
    Views { align: Align },
    /// Lets a moderator approve the record being shown, while it is
    /// waiting for that. Nobody else sees it.
    Approve { label: String },
    /// Shows one field of the record being shown: the list item's, or the
    /// template page's. Text is shown as body text (`level` 0) or a heading
    /// (1 to 6); a picture or video is shown as itself.
    Field {
        field: String,
        #[serde(default)]
        level: u8,
        #[serde(default)]
        align: Align,
        /// Show a video as a still frame instead of a player: for cards in
        /// a list, where the player belongs on the page the card links to.
        #[serde(default)]
        preview: bool,
    },
    /// Shows who added the record being shown, linking to their page.
    Author {
        #[serde(default)]
        align: Align,
    },
    /// Lets a visitor create an account.
    SignUp { submit_label: String },
    SignIn { submit_label: String },
    SignOut { submit_label: String },
    /// Shows `blocks` only to signed-in visitors, or only to the others.
    Gate { audience: Audience, blocks: Vec<Block> },
    /// The signed-in visitor's Monero on this site: what they hold, their
    /// own address to add to it, and a form to withdraw it.
    Wallet { label: String },
    /// The site's own Monero address, for anyone to give to. Signed-in
    /// visitors can also give from what they hold.
    Donate { label: String },
    /// A button that gives `amount` XMR, from what the visitor holds, to
    /// whoever added the record being shown, or to the site.
    Tip { amount: String, label: String },
    /// Shows `blocks` only to visitors who have paid `price` XMR, to whoever
    /// added the record being shown or to the site. With `days` set, what
    /// is paid for is a pass of that many days to everything the same
    /// payee has behind a pass; without, just the record or page.
    Paid {
        price: String,
        label: String,
        #[serde(default)]
        days: u16,
        blocks: Vec<Block>,
    },
}

impl Block {
    /// The lists of blocks this block holds, in the order the editor numbers them.
    pub fn children(&self) -> Vec<&Vec<Block>> {
        match self {
            Block::Columns { columns } => columns.iter().collect(),
            Block::List { blocks, .. } | Block::Gate { blocks, .. } | Block::Paid { blocks, .. } => vec![blocks],
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Align {
    #[default]
    Left,
    Center,
    Right,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// One record under another.
    #[default]
    Rows,
    /// Cards side by side, as many as fit.
    Grid,
}

/// Which records of its collection a list shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    All,
    /// Only those that belong to the record being shown, as the comments
    /// on one video.
    Children,
    /// Only those added by the account being shown, as one member's videos.
    Owned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    Members,
    Guests,
}

pub(crate) fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
