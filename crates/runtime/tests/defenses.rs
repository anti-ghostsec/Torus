//! Picture puzzles, feeds and view counts, used over real HTTP.

mod common;

use common::*;
use torus_core::starters::{pastebin, wiki};
use torus_core::{Align, Block};

fn puzzle_id(page: &str) -> String {
    after(page, "name=\"_puzzle\"", "value").to_owned()
}

#[tokio::test]
async fn forms_with_a_puzzle_need_its_answer_once() {
    let mut site = wiki();
    site.moderation.puzzle_sign_up = true;
    site.moderation.puzzle_collections = vec!["articles".into()];
    let (addr, live) = start(site).await;

    let account = get(addr, "/account", None).await.text();
    let id = puzzle_id(&account);
    assert!(account.contains(&format!("src=\"/_puzzle/{id}.png\"")), "{account}");
    let picture = get(addr, &format!("/_puzzle/{id}.png"), None).await;
    assert_eq!((picture.status, picture.header("content-type")), (200, Some("image/png")));
    assert!(picture.body.starts_with(b"\x89PNG"));
    assert_eq!(get(addr, "/_puzzle/nothing.png", None).await.status, 404);

    let answer = live.puzzle_answer_for_tests(&id).unwrap();
    let sign_up = |puzzle: String, typed: String| async move {
        let fields = [("name", "Ada"), ("_password", "correct horse battery"), ("_puzzle", &puzzle), ("_answer", &typed)];
        post(addr, SIGN_UP, None, &fields).await
    };
    // No answer, then a wrong one: refused, and that puzzle is used up.
    assert_eq!(sign_up(String::new(), String::new()).await.status, 400);
    assert_eq!(sign_up(id.clone(), "WRONG1".into()).await.status, 400);
    assert_eq!(sign_up(id.clone(), answer.clone()).await.status, 400, "a puzzle was answered after a wrong guess");
    assert_eq!(get(addr, &format!("/_puzzle/{id}.png"), None).await.status, 404);
    assert!(live.records("users").is_empty());

    // A fresh puzzle, answered right, in lower case.
    let id = puzzle_id(&get(addr, "/account", None).await.text());
    let answer = live.puzzle_answer_for_tests(&id).unwrap();
    let joined = sign_up(id.clone(), answer.to_lowercase()).await;
    assert_eq!(joined.status, 303, "{}", joined.text());
    let cookie = joined.cookie().unwrap();
    // Once used, never again.
    assert_eq!(sign_up(id, answer).await.status, 400);

    // Adding to a protected collection needs one too.
    let home = get(addr, "/", Some(&cookie)).await.text();
    let token = after(&home, "name=\"_token\"", "value").to_owned();
    let id = puzzle_id(&home);
    let make = |puzzle: String, typed: String| {
        let token = token.clone();
        let cookie = cookie.clone();
        async move {
            let fields = [("_token", token.as_str()), ("_next", "/"), ("title", "Onions"), ("_puzzle", &puzzle), ("_answer", &typed)];
            post(addr, "/_form/articles", Some(&cookie), &fields).await.status
        }
    };
    assert_eq!(make(id.clone(), "NOPE".into()).await, 400);
    let id = puzzle_id(&get(addr, "/", Some(&cookie)).await.text());
    let answer = live.puzzle_answer_for_tests(&id).unwrap();
    assert_eq!(make(id, answer).await, 303);
    assert_eq!(live.records("articles").len(), 1);
}

#[tokio::test]
async fn a_feed_lists_the_newest_records_and_only_where_offered() {
    let mut site = wiki();
    site.pages[0].blocks.push(Block::Feed { collection: "articles".into(), label: "Follow new articles".into() });
    let (addr, live) = start(site).await;
    let (ada, token) = join(addr, "Ada").await;
    for title in ["First", "Second <b>&</b>"] {
        let fields = [("_token", token.as_str()), ("_next", "/"), ("title", title)];
        assert_eq!(post(addr, "/_form/articles", Some(&ada), &fields).await.status, 303);
    }

    let home = get(addr, "/", None).await.text();
    assert!(home.contains("<link rel=\"alternate\" type=\"application/rss+xml\""), "readers can find the feed");
    assert!(home.contains("href=\"/_feed/articles\">Follow new articles</a>"));

    let feed = get(addr, "/_feed/articles", None).await;
    assert_eq!(feed.header("content-type"), Some("application/rss+xml; charset=utf-8"));
    let xml = feed.text();
    let body = xml.split("\r\n\r\n").nth(1).unwrap_or(&xml);
    assert!(body.starts_with("<?xml"));
    // Newest first, escaped, linked to each record's page on the address used.
    let (second, first) = (body.find("Second &lt;b&gt;&amp;&lt;/b&gt;").unwrap(), body.find("<title>First</title>").unwrap());
    assert!(second < first, "{body}");
    let id = &live.records("articles")[0].id;
    assert!(body.contains(&format!("<link>http://x/article/{id}</link>")), "{body}");
    assert!(!body.to_lowercase().contains("<pubdate>"), "records carry no time, and feeds add none");

    // Collections without a feed block, and accounts, have no feed.
    assert_eq!(get(addr, "/_feed/versions", None).await.status, 404);
    assert_eq!(get(addr, "/_feed/users", None).await.status, 404);
    let (paste_addr, _) = start(pastebin()).await;
    assert_eq!(get(paste_addr, "/_feed/pastes", None).await.status, 404, "unlisted pastes stay unlisted");
}

#[tokio::test]
async fn views_are_counted_without_anything_about_the_viewer() {
    let mut site = pastebin();
    let paste_page = site.pages.iter_mut().find(|p| p.slug == "paste").unwrap();
    paste_page.blocks.push(Block::Views { align: Align::Left });
    let (addr, live) = start(site).await;
    let saved = post(addr, "/_form/pastes", None, &[("_next", "/paste/{id}"), ("text", "hello")]).await;
    let place = saved.header("location").unwrap().to_owned();

    assert!(get(addr, &place, None).await.text().contains("Fewer than 10 views"));
    for _ in 0..30 {
        get(addr, &place, None).await;
    }
    // 31 views, said roughly.
    assert!(get(addr, &place, None).await.text().contains("<p class=\"count\">30+ views</p>"));
    // Looking at a page's headers alone is not a view.
    let before = get(addr, &place, None).await.text();
    assert!(before.contains("30+ views"));

    // A page without a count counts nothing, and a removed record leaves
    // no count behind.
    get(addr, "/", None).await;
    let id = place.trim_start_matches("/paste/").to_owned();
    assert!(live.remove("pastes", &id));
    assert_eq!(get(addr, &place, None).await.status, 404);
}
