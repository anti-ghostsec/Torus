//! The board and microblog starters, used over real HTTP as their visitors would.

mod common;

use common::*;
use torus_core::starters::{board, microblog};

/// A small real picture.
fn picture() -> Vec<u8> {
    let mut png = std::io::Cursor::new(Vec::new());
    image::RgbImage::from_fn(16, 16, |x, y| image::Rgb([x as u8 * 15, y as u8 * 15, 120]))
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();
    png.into_inner()
}

/// Every `/thread-random/<id>` link on a page, in the order they appear.
fn thread_ids(page: &str) -> Vec<String> {
    page.split("href=\"/thread-random/").skip(1).map(|rest| rest.split('"').next().unwrap().to_owned()).collect()
}

#[tokio::test]
async fn an_anonymous_board_bumps_pages_and_searches_its_threads() {
    let (addr, live) = start(board()).await;
    assert!(get(addr, "/", None).await.text().contains(">Random</a>"));

    // Nobody signs in: anyone starts a thread, with or without a picture.
    let image = picture();
    let first = upload(
        addr,
        "/_form/threads-random",
        None,
        &[Part::Text("_next", "/random"), Part::Text("subject", "First thread"), Part::Text("text", "about apples"), Part::File("picture", &image)],
    )
    .await;
    assert_eq!((first.status, first.header("location")), (303, Some("/random")), "{}", first.text());
    assert!(first.header("set-cookie").is_none(), "an anonymous board must never set a cookie");
    for n in 2..=17 {
        let subject = format!("Thread number {n}");
        let sent = upload(
            addr,
            "/_form/threads-random",
            None,
            &[Part::Text("subject", &subject), Part::Text("text", "about pears"), Part::File("picture", b"")],
        )
        .await;
        assert_eq!(sent.status, 303, "{}", sent.text());
    }
    // Threads on one board do not show on the other.
    assert!(get(addr, "/tech", None).await.text().contains("Nothing here yet."));

    // Fifteen to a page, newest first, with a link to the rest.
    let front = get(addr, "/random", None).await.text();
    assert_eq!(front.matches("<article>").count(), 15);
    assert!(front.contains("Thread number 17") && !front.contains("First thread"));
    assert!(front.contains("<a href=\"?p=1\">More</a>") && !front.contains(">Back</a>"));
    let second = get(addr, "/random?p=1", None).await.text();
    assert_eq!(second.matches("<article>").count(), 2);
    assert!(second.contains("First thread") && second.contains("<img src=\"/_file/"));
    assert!(second.contains("<a href=\"?p=0\">Back</a>") && !second.contains(">More</a>"));
    assert!(get(addr, "/random?p=99999999999999999999", None).await.status == 200, "a silly page number is harmless");

    // A reply brings the oldest thread back to the top, and is counted.
    let first_id = thread_ids(&second).pop().expect("the first thread");
    let thread_page = format!("/thread-random/{first_id}");
    let reply = upload(
        addr,
        "/_form/replies-random",
        None,
        &[Part::Text("_next", &thread_page), Part::Text("_parent", &first_id), Part::Text("text", "a reply <b>here</b>")],
    )
    .await;
    assert_eq!((reply.status, reply.header("location")), (303, Some(thread_page.as_str())));
    let front = get(addr, "/random", None).await.text();
    assert_eq!(thread_ids(&front).first(), Some(&first_id), "the replied-to thread should lead");
    assert!(front.contains("<p class=\"count\">1 replies</p>"));
    let thread = get(addr, &thread_page, None).await.text();
    assert!(thread.contains("<h1>First thread</h1>") && thread.contains("a reply &lt;b&gt;here&lt;/b&gt;"));
    // A reply cannot be attached to a thread on the other board.
    let stray = upload(addr, "/_form/replies-tech", None, &[Part::Text("_parent", &first_id), Part::Text("text", "x")]).await;
    assert_eq!(stray.status, 400);

    // Searching narrows the list and survives paging links; odd input is harmless.
    let found = get(addr, "/random?q=APPLES", None).await.text();
    assert_eq!(found.matches("<article>").count(), 1);
    assert!(found.contains("First thread") && found.contains("value=\"APPLES\""));
    let many = get(addr, "/random?q=pears", None).await.text();
    assert!(many.contains("<a href=\"?p=1&amp;q=pears\">More</a>"));
    let hostile = get(addr, "/random?q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E", None).await.text();
    assert!(!hostile.contains("<script") && hostile.contains("Nothing here yet."));

    // Nothing was stored about who posted.
    for record in live.records("threads-random").iter().chain(live.records("replies-random").iter()) {
        assert!(record.owner.is_none());
    }
}

#[tokio::test]
async fn microblog_members_post_like_reply_and_remove_only_their_own() {
    let (addr, live) = start(microblog()).await;
    let (ada, ada_token) = join(addr, "Ada").await;
    let (bob, bob_token) = join(addr, "Bob").await;

    // Guests see the timeline but no post form.
    let guest = get(addr, "/", None).await.text();
    assert!(guest.contains("Sign in to post, reply and like.") && !guest.contains("action=\"/_form/posts\""));

    let posted = upload(
        addr,
        "/_form/posts",
        Some(&ada),
        &[Part::Text("_token", &ada_token), Part::Text("_next", "/"), Part::Text("text", "Hello from Ada")],
    )
    .await;
    assert_eq!(posted.status, 303, "{}", posted.text());
    let home = get(addr, "/", Some(&bob)).await.text();
    assert!(home.contains("Hello from Ada") && home.contains(">Ada</a>"));
    let post_path = after(&home, "class=\"button\" href=\"/post/", "href").to_owned();
    let post_id = post_path.trim_start_matches("/post/").to_owned();

    // Liking twice takes the like back; each member counts once.
    let like = |cookie: String, token: String| {
        let (post_id, post_path) = (post_id.clone(), post_path.clone());
        async move {
            let fields = [("_token", token.as_str()), ("_parent", post_id.as_str()), ("_next", post_path.as_str())];
            post(addr, "/_form/likes", Some(&cookie), &fields).await.status
        }
    };
    assert_eq!(like(bob.clone(), bob_token.clone()).await, 303);
    assert_eq!(like(ada.clone(), ada_token.clone()).await, 303);
    assert!(get(addr, &post_path, None).await.text().contains("<p class=\"count\">2 likes</p>"));
    assert_eq!(like(bob.clone(), bob_token.clone()).await, 303);
    assert!(get(addr, &post_path, None).await.text().contains("<p class=\"count\">1 likes</p>"));
    assert_eq!(live.records("likes").len(), 1);
    assert_eq!(post(addr, "/_form/likes", None, &[("_parent", post_id.as_str())]).await.status, 403, "guests cannot like");

    // Bob replies. Each sees a delete button only on what is theirs.
    let reply = [("_token", bob_token.as_str()), ("_parent", post_id.as_str()), ("text", "Hello back")];
    assert_eq!(post(addr, "/_form/replies", Some(&bob), &reply).await.status, 303);
    let reply_id = live.records("replies")[0].id.clone();
    let as_bob = get(addr, &post_path, Some(&bob)).await.text();
    assert!(as_bob.contains(&format!("action=\"/_remove/replies/{reply_id}\"")));
    assert!(!as_bob.contains(&format!("action=\"/_remove/posts/{post_id}\"")));
    assert!(!get(addr, &post_path, None).await.text().contains("/_remove/"), "guests see no delete buttons");

    // Bob cannot remove Ada's post, with or without a valid token of his own.
    let remove_post = format!("/_remove/posts/{post_id}");
    assert_eq!(post(addr, &remove_post, Some(&bob), &[("_token", bob_token.as_str())]).await.status, 403);
    assert_eq!(post(addr, &remove_post, None, &[]).await.status, 403);
    assert_eq!(post(addr, &remove_post, Some(&ada), &[("_token", "forged")]).await.status, 403);
    assert_eq!(live.records("posts").len(), 1);
    // The answer for something that does not exist is the same as for something not his.
    let missing = post(addr, "/_remove/posts/000000000000000000000000", Some(&bob), &[("_token", bob_token.as_str())]).await;
    let not_his = post(addr, &remove_post, Some(&bob), &[("_token", bob_token.as_str())]).await;
    assert_eq!((missing.status, missing.text()), (not_his.status, not_his.text()));

    // Bob removes his reply; Ada removes her post, and its like goes with it.
    let removed = post(addr, &format!("/_remove/replies/{reply_id}"), Some(&bob), &[("_token", bob_token.as_str()), ("_next", post_path.as_str())]).await;
    assert_eq!((removed.status, removed.header("location")), (303, Some(post_path.as_str())));
    assert!(live.records("replies").is_empty());
    let removed = post(addr, &remove_post, Some(&ada), &[("_token", ada_token.as_str()), ("_next", "/")]).await;
    assert_eq!(removed.status, 303);
    assert!(live.records("posts").is_empty() && live.records("likes").is_empty());
    assert_eq!(get(addr, &post_path, None).await.status, 404);

    // The profile counts and lists only that member's posts.
    for (cookie, token, words) in [(&ada, &ada_token, "Ada again"), (&bob, &bob_token, "Bob speaking")] {
        let sent = upload(addr, "/_form/posts", Some(cookie), &[Part::Text("_token", token), Part::Text("text", words)]).await;
        assert_eq!(sent.status, 303);
    }
    let ada_id = live.records("users").into_iter().find(|u| u.fields["name"] == "Ada").unwrap().id;
    let profile = get(addr, &format!("/profile/{ada_id}"), None).await.text();
    assert!(profile.contains("<h1>Ada</h1>") && profile.contains("<p class=\"count\">1 posts</p>"));
    assert!(profile.contains("Ada again") && !profile.contains("Bob speaking"));
}

/// A tip line: what a visitor sends is readable only with the secret that
/// stays in the vault, never by the site that received it.
#[tokio::test]
async fn a_sealed_collection_cannot_be_read_by_the_site_itself() {
    use torus_core::{check, Block, Collection, Field, FieldKind, Page, Site, Theme};

    let secret = torus_seal::new_secret().unwrap();
    let mut site = Site {
        title: "Tips".into(),
        theme: Theme::default(),
        accounts: false,
        seal_key: Some(torus_seal::to_hex(&torus_seal::public_key(&secret).unwrap())),
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![Collection {
            name: "tips".into(),
            fields: vec![Field { name: "message".into(), label: "Message".into(), kind: FieldKind::LongText, required: true }],
            parent: None,
            members_only: false,
            once_each: false, review: false,
            sealed: true,
        }],
        pages: vec![Page {
            slug: "index".into(),
            title: "Home".into(),
            template: None,
            blocks: vec![Block::Form { collection: "tips".into(), submit_label: "Send".into() }],
        }],
    };
    check(&site).unwrap();

    let (addr, live) = start(site.clone()).await;
    let sent = post(addr, "/_form/tips", None, &[("message", "the documents are in locker 12")]).await;
    assert_eq!(sent.status, 303, "{}", sent.text());

    // The site holds one field of ciphertext and nothing readable.
    let stored = live.records("tips");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].fields.keys().collect::<Vec<_>>(), ["sealed"]);
    assert!(!format!("{:?}", stored[0]).contains("locker"));

    // The owner's secret opens it; another secret does not.
    let sealed = torus_seal::from_hex(&stored[0].fields["sealed"]).unwrap();
    let opened = torus_seal::open(&secret, &sealed).expect("the owner can read it");
    assert!(String::from_utf8_lossy(&opened).contains("the documents are in locker 12"));
    assert!(torus_seal::open(&torus_seal::new_secret().unwrap(), &sealed).is_none());

    // A site that tries to show a sealed collection does not pass its checks,
    // and one without a key refuses submissions rather than store them readable.
    let mut showing = site.clone();
    showing.pages[0].blocks.push(Block::Count { collection: "tips".into(), label: "tips".into(), align: Default::default() });
    assert!(check(&showing).is_err());
    site.seal_key = None;
    let (keyless, live) = start(site).await;
    assert_eq!(post(keyless, "/_form/tips", None, &[("message", "x")]).await.status, 503);
    assert!(live.records("tips").is_empty());
}

/// If a site's owner turns a text field into a picture field, what visitors
/// typed into it earlier must never be treated as the name of a stored file.
#[tokio::test]
async fn old_text_in_a_field_that_became_a_file_field_cannot_name_a_file_to_delete() {
    use torus_core::{Block, Collection, Field, FieldKind, Page, Site, Theme};
    use torus_runtime::{Live, Storage, Store};

    let dir = std::env::temp_dir().join(format!("torus-retype-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("data.bin.files")).unwrap();
    // A file beside the store that a crafted value points at.
    let bystander = dir.join("bystander.txt");
    std::fs::write(&bystander, "must survive").unwrap();

    let site = |kind| Site {
        title: "Retyped".into(),
        theme: Theme::default(),
        accounts: false,
        seal_key: None,
        limits: Default::default(),
        moderation: Default::default(),
        collections: vec![Collection {
            name: "notes".into(),
            fields: vec![Field { name: "note".into(), label: "Note".into(), kind, required: true }],
            parent: None,
            members_only: false,
            once_each: false, review: false,
            sealed: false,
        }],
        pages: vec![Page {
            slug: "index".into(),
            title: "Home".into(),
            template: None,
            blocks: vec![Block::Form { collection: "notes".into(), submit_label: "Send".into() }],
        }],
    };
    let store = Store::open(Storage { file: dir.join("data.bin"), key: zeroize::Zeroizing::new([4; 32]) }).unwrap();
    let live = Live::with_store(site(FieldKind::Text), store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(torus_runtime::serve(listener, live.clone()));

    assert_eq!(post(addr, "/_form/notes", None, &[("note", "../bystander.txt")]).await.status, 303);
    let id = live.records("notes")[0].id.clone();

    // The owner changes the field's kind, then removes the record.
    live.publish(site(FieldKind::Image));
    assert!(live.remove("notes", &id));
    assert!(bystander.exists(), "removing the record deleted a file its text pointed at");
    let _ = std::fs::remove_dir_all(dir);
}

/// On the board nobody owns a post, so nobody can remove one: except the
/// accounts the owner has made moderators.
#[tokio::test]
async fn only_a_moderator_can_remove_posts_from_the_board() {
    let (addr, live) = start(board()).await;
    let sent = upload(addr, "/_form/threads-random", None, &[Part::Text("subject", "Unwanted"), Part::Text("text", "spam")]).await;
    assert_eq!(sent.status, 303, "{}", sent.text());
    let thread = live.records("threads-random")[0].id.clone();
    let path = format!("/_remove/threads-random/{thread}");

    let staff = post(addr, SIGN_UP, None, &[("name", "Mod"), ("_password", "correct horse battery")]).await;
    let cookie = staff.cookie().expect("a session");
    let token = after(&get(addr, "/staff", Some(&cookie)).await.text(), "name=\"_token\"", "value").to_owned();

    // An ordinary account sees no button and is refused.
    assert!(!get(addr, "/random", Some(&cookie)).await.text().contains("/_remove/"));
    assert_eq!(post(addr, &path, Some(&cookie), &[("_token", &token)]).await.status, 403);
    assert_eq!(post(addr, &path, None, &[]).await.status, 403);

    // Only an account that exists can be made a moderator.
    assert!(!live.set_moderator("0123456789abcdef01234567", true));
    let account = live.records("users")[0].id.clone();
    assert!(live.set_moderator(&account, true));
    assert_eq!(live.moderators(), vec![account.clone()]);

    // A moderator sees the button, still needs the form token, and cannot
    // remove accounts.
    assert!(get(addr, "/random", Some(&cookie)).await.text().contains(&path));
    assert!(!get(addr, "/random", None).await.text().contains("/_remove/"));
    assert_eq!(post(addr, &path, Some(&cookie), &[("_token", "wrong")]).await.status, 403);
    let other = post(addr, SIGN_UP, None, &[("name", "Other"), ("_password", "correct horse battery")]).await;
    assert!(other.cookie().is_some());
    let other_id = live.records("users").iter().find(|u| u.id != account).unwrap().id.clone();
    let on_account = post(addr, &format!("/_remove/users/{other_id}"), Some(&cookie), &[("_token", &token)]).await;
    assert_eq!(on_account.status, 403);
    assert_eq!(live.records("users").len(), 2);

    let removed = post(addr, &path, Some(&cookie), &[("_token", &token), ("_next", "/random")]).await;
    assert_eq!((removed.status, removed.header("location")), (303, Some("/random")), "{}", removed.text());
    assert!(live.records("threads-random").is_empty());

    // Taking the role away takes the right away.
    assert!(live.set_moderator(&account, false));
    let again = upload(addr, "/_form/threads-random", None, &[Part::Text("subject", "Second"), Part::Text("text", "x")]).await;
    assert_eq!(again.status, 303);
    let second = live.records("threads-random")[0].id.clone();
    let refused = post(addr, &format!("/_remove/threads-random/{second}"), Some(&cookie), &[("_token", &token)]).await;
    assert_eq!(refused.status, 403);
}

/// Finds the list of a collection anywhere on a page and adds a block to it.
fn add_to_list(blocks: &mut Vec<torus_core::Block>, collection: &str, added: &torus_core::Block) -> bool {
    use torus_core::Block;
    let mut done = false;
    for block in blocks.iter_mut() {
        done |= match block {
            Block::List { collection: listed, blocks, .. } if listed == collection => {
                blocks.push(added.clone());
                true
            }
            Block::List { blocks, .. } | Block::Gate { blocks, .. } => add_to_list(blocks, collection, added),
            Block::Columns { columns } => columns.iter_mut().any(|column| add_to_list(column, collection, added)),
            _ => false,
        };
    }
    done
}

/// With review turned on, a post exists for nobody but moderators until one
/// of them, or the owner, approves it.
#[tokio::test]
async fn held_posts_are_invisible_until_approved() {
    let mut site = microblog();
    site.collections.iter_mut().find(|c| c.name == "posts").unwrap().review = true;
    let approve = torus_core::Block::Approve { label: "Approve".into() };
    assert!(add_to_list(&mut site.pages[0].blocks, "posts", &approve));
    torus_core::check(&site).unwrap();
    let (addr, live) = start(site).await;
    let (ada, ada_token) = join(addr, "Ada").await;
    let (bob, bob_token) = join(addr, "Bob").await;
    let bob_id = live.records("users").iter().find(|u| u.fields["name"] == "Bob").unwrap().id.clone();
    assert!(live.set_moderator(&bob_id, true));
    let post_as = |cookie: String, token: String, text: &'static str| async move {
        upload(addr, "/_form/posts", Some(&cookie), &[Part::Text("_token", &token), Part::Text("_next", "/"), Part::Text("text", text)]).await
    };

    // The author is told it arrived, and is not sent back to a page it is missing from.
    let sent = post_as(ada.clone(), ada_token.clone(), "Held words").await;
    assert_eq!(sent.status, 200, "{}", sent.text());
    assert!(sent.text().contains("It will show once it has been approved.") && sent.text().contains("<a href=\"/\">Back</a>"));
    let id = live.records("posts")[0].id.clone();
    assert!(live.records("posts")[0].held);

    // Nobody but a moderator sees it: not in the list, not at its own address.
    for viewer in [None, Some(&ada)] {
        let home = get(addr, "/", viewer.map(String::as_str)).await.text();
        assert!(!home.contains("Held words") && !home.contains("/_approve/"));
        assert_eq!(get(addr, &format!("/post/{id}"), viewer.map(String::as_str)).await.status, 404);
    }
    let home = get(addr, "/", Some(&bob)).await.text();
    assert!(home.contains("Held words") && home.contains("Waiting for approval."));
    assert!(home.contains(&format!("action=\"/_approve/posts/{id}\"")));
    assert_eq!(get(addr, &format!("/post/{id}"), Some(&bob)).await.status, 200);

    // Only a moderator approves, and only with the form token.
    let path = format!("/_approve/posts/{id}");
    assert_eq!(post(addr, &path, None, &[]).await.status, 403);
    assert_eq!(post(addr, &path, Some(&ada), &[("_token", &ada_token)]).await.status, 403);
    assert_eq!(post(addr, &path, Some(&bob), &[("_token", "wrong")]).await.status, 403);
    assert!(live.records("posts")[0].held);
    let approved = post(addr, &path, Some(&bob), &[("_token", &bob_token), ("_next", "/")]).await;
    assert_eq!((approved.status, approved.header("location")), (303, Some("/")));
    let home = get(addr, "/", None).await.text();
    assert!(home.contains("Held words") && !home.contains("Waiting for approval."));
    assert_eq!(get(addr, &format!("/post/{id}"), None).await.status, 200);
    assert_eq!(post(addr, &path, Some(&bob), &[("_token", &bob_token)]).await.status, 403, "there is nothing left to approve");

    // What a moderator posts needs no approval; the owner can approve from the editor.
    assert_eq!(post_as(bob.clone(), bob_token.clone(), "From staff").await.status, 303);
    assert!(get(addr, "/", None).await.text().contains("From staff"));
    assert_eq!(post_as(ada.clone(), ada_token.clone(), "Second try").await.status, 200);
    let waiting = live.records("posts").into_iter().find(|r| r.held).unwrap();
    assert!(live.approve("posts", &waiting.id) && !live.approve("posts", &waiting.id));
    assert!(get(addr, "/", None).await.text().contains("Second try"));
}

/// Shared limits are kept apart: a flood of sign-in attempts, which anyone
/// can send, leaves members able to post.
#[tokio::test]
async fn a_flood_of_sign_ins_does_not_stop_members_posting() {
    let (addr, _live) = start(microblog()).await;
    let (ada, ada_token) = join(addr, "Ada").await;
    let mut refused = 0;
    for _ in 0..40 {
        let tried = post(addr, torus_core::SIGN_IN_PATH, None, &[("name", "Ada"), ("_password", "wrong guess here")]).await;
        if tried.status == 429 {
            refused += 1;
        }
    }
    assert_eq!(refused, 10, "sign-ins have a budget of their own");
    let posted = upload(
        addr,
        "/_form/posts",
        Some(&ada),
        &[Part::Text("_token", &ada_token), Part::Text("_next", "/"), Part::Text("text", "Still here")],
    )
    .await;
    assert_eq!(posted.status, 303, "{}", posted.text());
}


/// A blocked word is refused outright, or held for approval; and an account
/// that must be approved cannot sign in until it is.
#[tokio::test]
async fn moderation_blocks_words_and_holds_new_accounts() {
    let mut site = microblog();
    site.moderation.blocked_words = vec!["spam".into()];
    let (addr, live) = start(site.clone()).await;
    let (ada, token) = join(addr, "Ada").await;
    let text = |body: &'static str| [Part::Text("_token", &token), Part::Text("_next", "/"), Part::Text("text", body)];

    // A post with a blocked word (case-folded, inside a word) is refused.
    assert_eq!(upload(addr, "/_form/posts", Some(&ada), &text("a friendly hello")).await.status, 303);
    assert_eq!(upload(addr, "/_form/posts", Some(&ada), &text("SPAMMY offer")).await.status, 400, "a blocked word was posted");

    // Held instead of refused: kept, waiting, not shown to a guest.
    site.moderation.blocked_held = true;
    live.publish(site.clone());
    assert!(upload(addr, "/_form/posts", Some(&ada), &text("more spam here")).await.text().contains("once it has been approved"));
    assert!(!get(addr, "/", None).await.text().contains("more spam here"), "a held post showed to a guest");

    // With approval on, a new account is held and cannot sign in yet.
    site.moderation.approve_accounts = true;
    live.publish(site);
    let joined = post(addr, torus_core::SIGN_UP_PATH, None, &[("name", "newcomer"), ("_password", "correct horse battery")]).await;
    assert!(joined.text().contains("once it has been approved"), "{}", joined.text());
    assert!(joined.cookie().is_none(), "a held account was given a session");
    let tried = post(addr, torus_core::SIGN_IN_PATH, None, &[("name", "newcomer"), ("_password", "correct horse battery")]).await;
    assert_eq!(tried.status, 400);
    assert!(tried.cookie().is_none());

    // Once approved, the account can sign in.
    let account = live.records("users").into_iter().find(|u| u.fields["name"] == "newcomer").unwrap().id;
    assert!(live.approve("users", &account));
    let ok = post(addr, torus_core::SIGN_IN_PATH, None, &[("name", "newcomer"), ("_password", "correct horse battery")]).await;
    assert_eq!(ok.status, 303, "{}", ok.text());
    assert!(ok.cookie().is_some());
}
