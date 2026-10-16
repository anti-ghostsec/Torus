//! The pastebin and wiki starters, used over real HTTP as their visitors would.

mod common;

use common::*;
use torus_core::starters::{pastebin, wiki};

#[tokio::test]
async fn a_paste_opens_on_its_own_page_exactly_as_typed_and_is_listed_nowhere() {
    let (addr, live) = start(pastebin()).await;
    let home = get(addr, "/", None).await.text();
    // The form names the paste's page, to be completed with its id.
    assert!(home.contains("name=\"_next\" value=\"/paste/{id}\""), "{home}");

    let code = "    fn main() {\n\tprintln!(\"<b>&</b>\");\n    }\n\n";
    let saved = post(addr, "/_form/pastes", None, &[("_next", "/paste/{id}"), ("title", "Hello"), ("text", code)]).await;
    assert_eq!(saved.status, 303, "{}", saved.text());
    let place = saved.header("location").expect("sent on to the paste").to_owned();
    let id = &live.records("pastes")[0].id;
    assert_eq!(place, format!("/paste/{id}"));

    let page = get(addr, &place, None).await.text();
    // Indents, tabs and markup characters survive; only trailing blank lines go.
    assert!(
        page.contains("<pre class=\"code\"><code>    fn main() {\n\tprintln!(&quot;&lt;b&gt;&amp;&lt;/b&gt;&quot;);\n    }</code></pre>"),
        "{page}"
    );
    assert!(!get(addr, "/", None).await.text().contains(id.as_str()), "a paste is never listed");

    // The completed address is checked like any other: nowhere off the site.
    let away = post(addr, "/_form/pastes", None, &[("_next", "//elsewhere.example/{id}"), ("text", "x")]).await;
    assert_eq!(away.header("location"), Some("/"));
}

#[tokio::test]
async fn a_wiki_article_is_edited_by_adding_versions_and_keeps_its_history() {
    let (addr, live) = start(wiki()).await;
    let (ada, ada_token) = join(addr, "Ada").await;
    let (bob, bob_token) = join(addr, "Bob").await;

    // Starting an article goes straight to it.
    let made = post(addr, "/_form/articles", Some(&ada), &[("_token", &ada_token), ("_next", "/article/{id}"), ("title", "Onions")]).await;
    assert_eq!(made.status, 303, "{}", made.text());
    let article = made.header("location").unwrap().to_owned();
    let id = article.trim_start_matches("/article/").to_owned();

    let first = "# Layers\nOnions have **layers** and *taste*.\n- one\n- two\n\n> a quote\n\n[home](/) [bad](javascript:alert(1)) <script>x</script>";
    let edit = |cookie: String, token: String, text: &'static str, summary: &'static str| {
        let (id, article) = (id.clone(), article.clone());
        async move {
            let fields = [("_token", token.as_str()), ("_parent", id.as_str()), ("_next", article.as_str()), ("text", text), ("summary", summary)];
            post(addr, "/_form/versions", Some(&cookie), &fields).await.status
        }
    };
    assert_eq!(edit(ada.clone(), ada_token.clone(), first, "First draft").await, 303);

    let page = get(addr, &article, Some(&bob)).await.text();
    assert!(page.contains("<h2>Layers</h2>"), "{page}");
    assert!(page.contains("<strong>layers</strong>") && page.contains("<em>taste</em>"));
    assert!(page.contains("<ul>\n<li>one</li>\n<li>two</li>\n</ul>"));
    assert!(page.contains("<blockquote><p>a quote</p></blockquote>"));
    assert!(page.contains("<a href=\"/\">home</a>"));
    // Neither a script address nor typed markup becomes anything but text.
    assert!(!page.contains("href=\"javascript") && page.contains("[bad](javascript:alert(1))"));
    assert!(!page.contains("<script>") && page.contains("&lt;script&gt;"));
    // The edit form starts from the article as it is.
    assert!(page.contains("&gt; a quote"), "the form is filled in with the current text");
    assert!(page.contains("value=\"First draft\""));

    // Bob's edit becomes the article; Ada's stays in the history.
    assert_eq!(edit(bob.clone(), bob_token.clone(), "Shorter now.", "Trimmed").await, 303);
    let page = get(addr, &article, None).await.text();
    let shown = page.split("<hr>").next().unwrap();
    assert!(shown.contains("Shorter now.") && !shown.contains("Layers"), "{page}");
    assert!(page.contains("Trimmed") && page.contains("First draft"));
    assert_eq!(live.records("versions").len(), 2);

    // Guests read but cannot edit.
    assert!(page.contains("Sign in to edit this article.") && !page.contains("action=\"/_form/versions\""));
}
