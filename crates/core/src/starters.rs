//! Ready-made sites to start from. Each is ordinary data: everything in it
//! can be changed in the editor afterwards.

use crate::model::{
    Align, Audience, Block, Collection, Field, FieldKind, Layout, Page, Scope, Site, Theme, HOME_SLUG, USERS, USER_NAME,
};

/// The starters by the name the editor asks for them with.
pub fn by_name(name: &str) -> Option<Site> {
    match name {
        "video" => Some(video_site()),
        "board" => Some(board()),
        "microblog" => Some(microblog()),
        "wiki" => Some(wiki()),
        "pastebin" => Some(pastebin()),
        _ => None,
    }
}

fn field(name: &str, label: &str, kind: FieldKind, required: bool) -> Field {
    Field { name: name.into(), label: label.into(), kind, required }
}

fn heading(level: u8, text: &str) -> Block {
    Block::Heading { level, text: text.into(), align: Align::Left }
}

fn text(text: &str) -> Block {
    Block::Text { text: text.into(), align: Align::Left }
}

fn shown(field: &str, level: u8) -> Block {
    Block::Field { field: field.into(), level, align: Align::Left, preview: false }
}

/// A still frame of a video field, for cards.
fn still(field: &str) -> Block {
    Block::Field { field: field.into(), level: 0, align: Align::Left, preview: true }
}

fn link(label: &str, href: &str) -> Block {
    Block::Link { label: label.into(), href: href.into(), align: Align::Left }
}

fn count(collection: &str, label: &str) -> Block {
    Block::Count { collection: collection.into(), label: label.into(), align: Align::Left }
}

/// A button that only moderators see on records that belong to nobody.
fn moderate() -> Block {
    Block::Remove { label: "Remove".into() }
}

fn form(collection: &str, label: &str) -> Block {
    Block::Form { collection: collection.into(), submit_label: label.into(), open: false, prefill: false }
}

/// A form that takes the visitor to what they added once it is saved.
fn form_then_open(collection: &str, label: &str) -> Block {
    Block::Form { collection: collection.into(), submit_label: label.into(), open: true, prefill: false }
}

fn feed(collection: &str, label: &str) -> Block {
    Block::Feed { collection: collection.into(), label: label.into() }
}

fn views() -> Block {
    Block::Views { align: Align::Left }
}

fn author() -> Block {
    Block::Author { align: Align::Left }
}

fn page(slug: &str, title: &str, template: Option<&str>, blocks: Vec<Block>) -> Page {
    Page { slug: slug.into(), title: title.into(), blocks, template: template.map(str::to_owned) }
}

fn collection(name: &str, parent: Option<&str>, members_only: bool, fields: Vec<Field>) -> Collection {
    Collection {
        name: name.into(),
        fields,
        parent: parent.map(str::to_owned),
        members_only,
        once_each: false, review: false,
        sealed: false,
    }
}

/// One like per member per record, given by pressing once and taken back by pressing again.
fn likes(name: &str, parent: &str) -> Collection {
    Collection { once_each: true, ..collection(name, Some(parent), true, Vec::new()) }
}

struct Listing<'a> {
    collection: &'a str,
    scope: Scope,
    layout: Layout,
    limit: u16,
    newest_first: bool,
    active_first: bool,
    paged: bool,
}

impl Listing<'_> {
    fn of(collection: &str) -> Listing<'_> {
        Listing {
            collection,
            scope: Scope::All,
            layout: Layout::Rows,
            limit: 20,
            newest_first: true,
            active_first: false,
            paged: true,
        }
    }

    fn with(self, blocks: Vec<Block>) -> Block {
        Block::List {
            collection: self.collection.into(),
            newest_first: self.newest_first,
            limit: self.limit,
            blocks,
            layout: self.layout,
            scope: self.scope,
            active_first: self.active_first,
            paged: self.paged,
        }
    }
}

/// Sign-in and sign-up for guests, sign-out for members.
fn account_page() -> Page {
    page(
        "account",
        "Account",
        None,
        vec![
            Block::Gate {
                audience: Audience::Guests,
                blocks: vec![
                    heading(1, "Sign in"),
                    Block::SignIn { submit_label: "Sign in".into() },
                    heading(2, "New here? Create an account"),
                    Block::SignUp { submit_label: "Create account".into() },
                ],
            },
            Block::Gate {
                audience: Audience::Members,
                // Shows only where the owner has made a Monero wallet.
                blocks: vec![
                    text("You are signed in."),
                    Block::SignOut { submit_label: "Sign out".into() },
                    Block::Wallet { label: "Your Monero".into() },
                ],
            },
        ],
    )
}

/// Gives the author a little Monero. Shows only where the site has a wallet.
fn tip() -> Block {
    Block::Tip { amount: "0.01".into(), label: "Tip".into() }
}

fn members(blocks: Vec<Block>) -> Block {
    Block::Gate { audience: Audience::Members, blocks }
}

fn guests(blocks: Vec<Block>) -> Block {
    Block::Gate { audience: Audience::Guests, blocks }
}

/// A video-sharing site: members upload videos, everyone can watch and
/// search them, members comment and like, and every member has a channel.
pub fn video_site() -> Site {
    let card = |with_author: bool| {
        // The picture on a card is a frame of the video itself, so nobody
        // can put a misleading picture on their upload.
        let mut blocks = vec![still("video"), shown("title", 3)];
        if with_author {
            blocks.push(author());
        }
        blocks.push(link("Watch", "/watch/{id}"));
        blocks
    };
    let videos = |scope, with_author| {
        Listing { scope, layout: Layout::Grid, limit: 24, ..Listing::of("videos") }.with(card(with_author))
    };

    Site {
        title: "My video site".into(),
        theme: Theme::default(),
        accounts: true,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![
            collection(
                USERS,
                None,
                false,
                vec![
                    field(USER_NAME, "Name", FieldKind::Text, true),
                    field("about", "About you", FieldKind::LongText, false),
                ],
            ),
            collection(
                "videos",
                None,
                true,
                vec![
                    field("title", "Title", FieldKind::Text, true),
                    field("description", "Description", FieldKind::LongText, false),
                    field("video", "Video file (MP4 or WebM)", FieldKind::Video, true),
                ],
            ),
            collection("comments", Some("videos"), true, vec![field("text", "Your comment", FieldKind::LongText, true)]),
            likes("likes", "videos"),
        ],
        pages: vec![
            page(
                HOME_SLUG,
                "Home",
                None,
                vec![
                    heading(1, "Latest videos"),
                    Block::Search { label: "Search".into() },
                    videos(Scope::All, true),
                    feed("videos", "Follow new videos in a feed reader"),
                ],
            ),
            page(
                "upload",
                "Upload",
                None,
                vec![
                    guests(vec![text("Sign in to upload a video."), link("Sign in", "/account")]),
                    members(vec![
                        heading(1, "Upload a video"),
                        text("Large files take a long time over Tor. Keep this page open until it finishes."),
                        form("videos", "Upload"),
                    ]),
                ],
            ),
            account_page(),
            page(
                "watch",
                "Watch",
                Some("videos"),
                vec![
                    shown("video", 0),
                    shown("title", 1),
                    author(),
                    tip(),
                    views(),
                    count("likes", "likes"),
                    form("likes", "Like"),
                    shown("description", 0),
                    Block::Remove { label: "Delete this video".into() },
                    Block::Divider,
                    heading(2, "Comments"),
                    form("comments", "Comment"),
                    Listing { scope: Scope::Children, limit: 50, ..Listing::of("comments") }
                        .with(vec![author(), shown("text", 0), Block::Remove { label: "Delete".into() }]),
                ],
            ),
            page(
                "channel",
                "Channel",
                Some(USERS),
                vec![
                    shown(USER_NAME, 1),
                    shown("about", 0),
                    count("videos", "videos"),
                    heading(2, "Videos"),
                    videos(Scope::Owned, false),
                ],
            ),
        ],
    }
}

/// An anonymous image board with two boards. Nobody has an account: anyone
/// can start a thread or reply, with or without a picture, and a thread
/// moves to the top when it gets a reply.
pub fn board() -> Site {
    let post_fields = |with_subject: bool| {
        let mut fields = Vec::new();
        if with_subject {
            fields.push(field("subject", "Subject", FieldKind::Text, true));
        }
        fields.push(field("text", "Comment", FieldKind::LongText, true));
        fields.push(field("picture", "Picture (optional)", FieldKind::Image, false));
        fields
    };
    // Posting needs no account and stays anonymous. Accounts exist only so
    // that the owner can make some of them moderators.
    let mut site = Site {
        title: "My board".into(),
        theme: Theme::default(),
        accounts: true,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: Vec::new(),
        pages: vec![page(
            HOME_SLUG,
            "Boards",
            None,
            vec![
                heading(1, "Boards"),
                text("Nobody here has a name. Pictures are re-encoded on arrival, which removes what cameras hide in them."),
            ],
        )],
    };
    site.collections.push(collection(USERS, None, false, vec![field(USER_NAME, "Name", FieldKind::Text, true)]));
    site.pages.push(page(
        "staff",
        "Staff",
        None,
        vec![
            guests(vec![
                heading(1, "Staff"),
                text("Posting needs no account. This page is for the people who look after the boards."),
                Block::SignIn { submit_label: "Sign in".into() },
                heading(2, "Ask to help"),
                text("Create an account, then ask the owner to make it a moderator."),
                Block::SignUp { submit_label: "Create account".into() },
            ]),
            members(vec![
                text("You are signed in. If the owner has made you a moderator, a Remove button shows next to every post."),
                Block::SignOut { submit_label: "Sign out".into() },
            ]),
        ],
    ));
    for (slug, title) in [("random", "Random"), ("tech", "Technology")] {
        let (threads, replies, thread_page) = (format!("threads-{slug}"), format!("replies-{slug}"), format!("thread-{slug}"));
        site.collections.push(collection(&threads, None, false, post_fields(true)));
        site.collections.push(collection(&replies, Some(&threads), false, post_fields(false)));
        site.pages.push(page(
            slug,
            title,
            None,
            vec![
                heading(1, title),
                Block::Search { label: "Search".into() },
                Listing { limit: 15, active_first: true, ..Listing::of(&threads) }.with(vec![
                    shown("subject", 3),
                    shown("picture", 0),
                    shown("text", 0),
                    count(&replies, "replies"),
                    link("Open thread", &format!("/{thread_page}/{{id}}")),
                    moderate(),
                ]),
                heading(2, "Start a thread"),
                form(&threads, "Post"),
                feed(&threads, &format!("Follow {title} in a feed reader")),
            ],
        ));
        site.pages.push(page(
            &thread_page,
            "Thread",
            Some(&threads),
            vec![
                link(&format!("Back to {title}"), &format!("/{slug}")),
                shown("subject", 1),
                shown("picture", 0),
                shown("text", 0),
                Block::Divider,
                moderate(),
                Listing { scope: Scope::Children, limit: 100, newest_first: false, ..Listing::of(&replies) }
                    .with(vec![shown("picture", 0), shown("text", 0), moderate()]),
                heading(2, "Reply"),
                form(&replies, "Reply"),
            ],
        ));
    }
    site
}

/// A microblog: members write short posts with an optional picture, reply
/// to and like each other's, and each has a profile page.
pub fn microblog() -> Site {
    let post = || {
        vec![
            author(),
            shown("text", 0),
            shown("picture", 0),
            count("replies", "replies"),
            count("likes", "likes"),
            link("Open", "/post/{id}"),
        ]
    };
    Site {
        title: "My microblog".into(),
        theme: Theme::default(),
        accounts: true,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![
            collection(
                USERS,
                None,
                false,
                vec![
                    field(USER_NAME, "Name", FieldKind::Text, true),
                    field("about", "About you", FieldKind::LongText, false),
                    field("picture", "Profile picture", FieldKind::Image, false),
                ],
            ),
            collection(
                "posts",
                None,
                true,
                vec![
                    field("text", "What is happening?", FieldKind::LongText, true),
                    field("picture", "Picture (optional)", FieldKind::Image, false),
                ],
            ),
            collection("replies", Some("posts"), true, vec![field("text", "Your reply", FieldKind::LongText, true)]),
            likes("likes", "posts"),
        ],
        pages: vec![
            page(
                HOME_SLUG,
                "Home",
                None,
                vec![
                    members(vec![form("posts", "Post")]),
                    guests(vec![text("Sign in to post, reply and like."), link("Sign in", "/account")]),
                    Block::Search { label: "Search".into() },
                    Listing::of("posts").with(post()),
                    feed("posts", "Follow in a feed reader"),
                ],
            ),
            account_page(),
            page(
                "post",
                "Post",
                Some("posts"),
                vec![
                    author(),
                    shown("text", 0),
                    shown("picture", 0),
                    count("likes", "likes"),
                    form("likes", "Like"),
                    tip(),
                    Block::Remove { label: "Delete this post".into() },
                    Block::Divider,
                    heading(2, "Replies"),
                    Listing { scope: Scope::Children, limit: 50, newest_first: false, ..Listing::of("replies") }
                        .with(vec![author(), shown("text", 0), Block::Remove { label: "Delete".into() }]),
                    form("replies", "Reply"),
                ],
            ),
            page(
                "profile",
                "Profile",
                Some(USERS),
                vec![
                    shown("picture", 0),
                    shown(USER_NAME, 1),
                    shown("about", 0),
                    count("posts", "posts"),
                    heading(2, "Posts"),
                    Listing { scope: Scope::Owned, ..Listing::of("posts") }.with(post()),
                ],
            ),
        ],
    }
}

/// A wiki: members start articles and anyone signed in can edit them. An
/// edit is saved as a new version, so every article keeps its whole history,
/// and undoing vandalism is a moderator removing the bad version.
pub fn wiki() -> Site {
    // The newest version of an article is the article.
    let current = || {
        Listing { scope: Scope::Children, limit: 1, paged: false, ..Listing::of("versions") }.with(vec![shown("text", 0)])
    };
    Site {
        title: "My wiki".into(),
        theme: Theme::default(),
        accounts: true,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![
            collection(
                USERS,
                None,
                false,
                vec![
                    field(USER_NAME, "Name", FieldKind::Text, true),
                    field("about", "About you", FieldKind::LongText, false),
                ],
            ),
            collection("articles", None, true, vec![field("title", "Title", FieldKind::Text, true)]),
            collection(
                "versions",
                Some("articles"),
                true,
                vec![
                    field("text", "Article", FieldKind::Formatted, true),
                    field("summary", "What you changed (optional)", FieldKind::Text, false),
                ],
            ),
        ],
        pages: vec![
            page(
                HOME_SLUG,
                "Wiki",
                None,
                vec![
                    heading(1, "Wiki"),
                    text("Anyone with an account can start an article or improve one. Every edit is kept, so nothing is ever lost."),
                    Block::Search { label: "Search".into() },
                    heading(2, "Recently changed"),
                    Listing { limit: 50, active_first: true, ..Listing::of("articles") }
                        .with(vec![link_text("title"), count("versions", "edits")]),
                    members(vec![
                        heading(2, "Start an article"),
                        form_then_open("articles", "Create"),
                    ]),
                    guests(vec![text("Sign in to write or edit."), link("Sign in", "/account")]),
                    feed("articles", "Follow new articles in a feed reader"),
                ],
            ),
            page(
                "article",
                "Article",
                Some("articles"),
                vec![
                    link("All articles", "/"),
                    shown("title", 1),
                    current(),
                    views(),
                    Block::Divider,
                    members(vec![
                        heading(2, "Edit"),
                        text("The form starts with the article as it is now. Change what you like and save: your version becomes the article, and the earlier one stays in the history."),
                        Block::Form { collection: "versions".into(), submit_label: "Save".into(), open: false, prefill: true },
                    ]),
                    guests(vec![text("Sign in to edit this article."), link("Sign in", "/account")]),
                    heading(2, "History"),
                    Listing { scope: Scope::Children, limit: 25, ..Listing::of("versions") }.with(vec![
                        author(),
                        shown("summary", 0),
                        link("See this version", "/version/{id}"),
                        moderate(),
                    ]),
                    Block::Remove { label: "Delete this article".into() },
                ],
            ),
            page(
                "version",
                "Earlier version",
                Some("versions"),
                vec![
                    text("This is one version from an article's history. The article itself shows its newest version."),
                    author(),
                    shown("summary", 0),
                    Block::Divider,
                    shown("text", 0),
                    moderate(),
                ],
            ),
            account_page(),
            page(
                "member",
                "Member",
                Some(USERS),
                vec![
                    shown(USER_NAME, 1),
                    shown("about", 0),
                    count("versions", "edits"),
                    heading(2, "Articles started"),
                    Listing { scope: Scope::Owned, ..Listing::of("articles") }.with(vec![link_text("title")]),
                ],
            ),
        ],
    }
}

/// A list entry's title, then a link to its page.
fn link_text(field: &str) -> Block {
    // Kept as two blocks so each can be restyled or removed on its own.
    Block::Columns { columns: vec![vec![shown(field, 3)], vec![link("Read", "/article/{id}")]] }
}

/// A pastebin: anyone pastes text or code without an account and is taken
/// to its page, whose address is the only way to find it. Nothing is
/// listed, so a paste is seen only by those its address is given to.
pub fn pastebin() -> Site {
    Site {
        title: "My pastebin".into(),
        theme: Theme::default(),
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![collection(
            "pastes",
            None,
            false,
            vec![
                field("title", "Title (optional)", FieldKind::Text, false),
                field("text", "Paste", FieldKind::Code, true),
            ],
        )],
        pages: vec![
            page(
                HOME_SLUG,
                "New paste",
                None,
                vec![
                    heading(1, "New paste"),
                    text("Paste text or code and save it. You are taken to its own page: share that address with whoever should see it. Pastes are never listed, and their addresses cannot be guessed."),
                    form_then_open("pastes", "Save paste"),
                ],
            ),
            page(
                "paste",
                "Paste",
                Some("pastes"),
                vec![shown("title", 1), shown("text", 0), link("New paste", "/")],
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{check, render_canvas, render_page, NoData, Visit};

    #[test]
    fn every_starter_passes_the_checks_and_renders_every_page() {
        for name in ["video", "board", "microblog", "wiki", "pastebin"] {
            let site = by_name(name).unwrap();
            check(&site).unwrap_or_else(|findings| panic!("{name} does not pass its checks: {findings:#?}"));
            for page in &site.pages {
                assert!(render_canvas(&site, &page.slug).is_some(), "{name}/{}", page.slug);
                if page.template.is_none() {
                    let html = render_page(&site, page, None, &NoData, &Visit::default());
                    assert!(!html.contains("<script"), "{name}/{}", page.slug);
                }
            }
            // Starters survive the trip to the editor and back.
            let json = serde_json::to_string(&site).unwrap();
            assert_eq!(serde_json::from_str::<Site>(&json).unwrap(), site);
        }
        assert!(by_name("nothing").is_none());
    }
}
