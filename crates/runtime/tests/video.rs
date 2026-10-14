//! The video-site starter, used over real HTTP the way its visitors would:
//! create an account, upload a video with a picture, watch it and skip
//! around in it, comment, visit a channel, sign out and back in.

mod common;

use common::*;
use tokio::net::TcpListener;
use torus_core::starters::video_site;
use torus_runtime::{serve, Live, Storage, Store};
use zeroize::Zeroizing;

/// The video site with one addition an owner might make in the editor: a
/// picture that uploaders choose, shown on the cards.
fn site_with_pictures() -> torus_core::Site {
    use torus_core::{Align, Block, Field, FieldKind};
    let mut site = video_site();
    let videos = site.collections.iter_mut().find(|c| c.name == "videos").unwrap();
    videos.fields.push(Field { name: "thumbnail".into(), label: "Picture".into(), kind: FieldKind::Image, required: false });
    for block in &mut site.pages[0].blocks {
        if let Block::List { blocks, .. } = block {
            blocks.insert(0, Block::Field { field: "thumbnail".into(), level: 0, align: Align::Left, preview: false });
        }
    }
    torus_core::check(&site).unwrap();
    site
}

#[tokio::test]
async fn a_member_uploads_a_video_and_others_watch_and_comment() {
    let dir = std::env::temp_dir().join(format!("torus-video-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let storage = || Storage { file: dir.join("data.bin"), key: Zeroizing::new([3; 32]) };
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Live::with_store(site_with_pictures(), Store::open(storage()).unwrap())));
        addr
    };

    // A guest sees an empty site and cannot upload or comment.
    assert!(get(addr, "/", None).await.text().contains("Nothing here yet."));
    let video = fake_video(300_000);
    let small = fake_video(2_000);
    let refused = upload(addr, "/_form/videos", None, &[Part::Text("title", "x"), Part::File("video", &small)]).await;
    assert_eq!(refused.status, 403);
    assert!(get(addr, "/upload", None).await.text().contains("Sign in to upload a video."));

    // Creating an account.
    let weak = post(addr, SIGN_UP, None, &[("name", "Ada"), ("_password", "short")]).await;
    assert_eq!(weak.status, 400);
    let odd = post(addr, SIGN_UP, None, &[("name", "A d a!"), ("_password", "correct horse battery")]).await;
    assert_eq!(odd.status, 400);
    let joined = post(
        addr,
        SIGN_UP,
        None,
        &[("_next", "/account"), ("name", "Ada"), ("about", "I film <things>."), ("_password", "correct horse battery")],
    )
    .await;
    assert_eq!((joined.status, joined.header("location")), (303, Some("/account")));
    let cookie = joined.cookie().expect("a session cookie");
    let set = joined.header("set-cookie").unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict") && set.contains("Path=/"));
    assert_eq!(cookie.len(), 64);
    let taken = post(addr, SIGN_UP, None, &[("name", "ADA"), ("_password", "another long password")]).await;
    assert_eq!(taken.status, 400, "names differing only in capitals are the same name");
    // Accounts cannot be made through the ordinary form address.
    assert_eq!(post(addr, "/_form/users", None, &[("name", "Mallory")]).await.status, 405);

    let account = get(addr, "/account", Some(&cookie)).await.text();
    assert!(account.contains("You are signed in.") && !account.contains("/_account/signup"));
    let token = after(&account, "name=\"_token\"", "value").to_owned();

    // Uploading: refused without the page's token, and for a file that is not a video.
    let thumbnail = picture_with_hidden_note();
    let no_token = upload(addr, "/_form/videos", Some(&cookie), &[Part::Text("title", "x"), Part::File("video", &video)]).await;
    assert_eq!(no_token.status, 403);
    let not_video = upload(
        addr,
        "/_form/videos",
        Some(&cookie),
        &[Part::Text("_token", &token), Part::Text("title", "x"), Part::File("video", b"MZ this is a program, not a video")],
    )
    .await;
    assert_eq!(not_video.status, 400);
    let uploaded = upload(
        addr,
        "/_form/videos",
        Some(&cookie),
        &[
            Part::Text("_token", &token),
            Part::Text("_next", "/upload"),
            Part::Text("title", "My first <video>"),
            Part::Text("description", "Shot on location."),
            Part::File("video", &video),
            Part::File("thumbnail", &thumbnail),
        ],
    )
    .await;
    assert_eq!((uploaded.status, uploaded.header("location")), (303, Some("/upload")), "{}", uploaded.text());

    // The home page shows the card; nothing refused above left a trace.
    let home = get(addr, "/", None).await.text();
    assert_eq!(home.matches("<article>").count(), 1);
    assert!(home.contains("My first &lt;video&gt;"));
    // The card shows a still frame taken from the video itself.
    assert!(home.contains("<video class=\"preview\" preload=\"metadata\" muted playsinline src=\"/_file/"));
    let watch_path = after(&home, "class=\"button\" href=\"/watch/", "href").to_owned();
    let channel_path = after(&home, "class=\"author\"", "href").to_owned();
    let picture_path = after(&home, "<img", "src").to_owned();

    // The picture was re-encoded: it is still a picture, and the note is gone.
    let picture = get(addr, &picture_path, None).await;
    assert_eq!((picture.status, picture.header("content-type")), (200, Some("image/jpeg")));
    assert!(image::load_from_memory(&picture.body).is_ok());
    assert!(!picture.body.windows(6).any(|w| w == b"SECRET") && !picture.body.windows(4).any(|w| w == b"tEXt"));

    // Watching: the whole file, and any part of it.
    let watch = get(addr, &watch_path, None).await.text();
    assert!(watch.contains("<h1>My first &lt;video&gt;</h1>") && watch.contains("Shot on location."));
    let file_path = after(&watch, "<video", "src").to_owned();
    let whole = get(addr, &file_path, None).await;
    assert_eq!((whole.status, whole.header("content-type")), (200, Some("video/mp4")));
    assert_eq!(whole.header("accept-ranges"), Some("bytes"));
    assert!(whole.body == video, "the video came back changed");
    assert!(!whole.head.to_ascii_lowercase().contains("secret name"), "the uploader's file name leaked");

    for (range, from, to) in [
        ("bytes=0-0", 0, 0),
        ("bytes=100-199", 100, 199),
        ("bytes=65530-65545", 65_530, 65_545),
        ("bytes=131000-", 131_000, video.len() - 1),
        ("bytes=-50", video.len() - 50, video.len() - 1),
        ("bytes=299990-999999999", 299_990, video.len() - 1),
    ] {
        let part = get_range(addr, &file_path, range).await;
        assert_eq!(part.status, 206, "{range}");
        assert_eq!(part.header("content-range"), Some(format!("bytes {from}-{to}/{}", video.len()).as_str()), "{range}");
        assert!(part.body == video[from..=to], "{range} returned the wrong bytes");
    }
    assert_eq!(get_range(addr, &file_path, "bytes=300000-").await.status, 416);
    assert_eq!(get_range(addr, &file_path, "bytes=5-2").await.status, 416);
    assert_eq!(get_range(addr, &file_path, "bytes=abc").await.status, 416);
    let head = send(addr, request("HEAD", &file_path, None, "", b"")).await;
    assert_eq!((head.status, head.header("content-length"), head.body.len()), (200, Some("300000"), 0));
    assert_eq!(get(addr, "/_file/000000000000000000000000", None).await.status, 404);
    assert_eq!(get(addr, "/_file/../data.bin", None).await.status, 404);

    // Commenting needs an account, the page's token, and a real video.
    let video_id = watch_path.trim_start_matches("/watch/");
    let comment = [("_parent", video_id), ("_next", watch_path.as_str()), ("text", "Lovely <i>work</i>")];
    assert_eq!(post(addr, "/_form/comments", None, &comment).await.status, 403);
    assert_eq!(post(addr, "/_form/comments", Some(&cookie), &comment).await.status, 403, "no token");
    let with_token = |extra: (&'static str, &'static str)| {
        let mut fields = vec![("_token", token.as_str()), ("_next", watch_path.as_str()), ("text", "Lovely <i>work</i>")];
        fields.push(extra);
        fields
    };
    let orphan = post(addr, "/_form/comments", Some(&cookie), &with_token(("_parent", "000000000000000000000000"))).await;
    assert_eq!(orphan.status, 400);
    let mut fields = vec![("_token", token.as_str()), ("_next", watch_path.as_str()), ("text", "Lovely <i>work</i>")];
    fields.push(("_parent", video_id));
    let said = post(addr, "/_form/comments", Some(&cookie), &fields).await;
    assert_eq!((said.status, said.header("location")), (303, Some(watch_path.as_str())));
    let watch = get(addr, &watch_path, Some(&cookie)).await.text();
    assert!(watch.contains("Lovely &lt;i&gt;work&lt;/i&gt;"));
    assert!(watch.contains(&format!("<a href=\"{channel_path}\">Ada</a>")));
    assert!(watch.contains("action=\"/_form/comments\""));

    // The channel page lists this member's videos.
    let channel = get(addr, &channel_path, None).await.text();
    assert!(channel.contains("<h1>Ada</h1>") && channel.contains("I film &lt;things&gt;."));
    assert!(channel.contains("My first &lt;video&gt;"));

    // Signing out ends the session; signing in again needs the password.
    assert_eq!(post(addr, SIGN_OUT, Some(&cookie), &[("_token", "wrong")]).await.status, 403);
    let out = post(addr, SIGN_OUT, Some(&cookie), &[("_token", &token), ("_next", "/account")]).await;
    assert_eq!(out.status, 303);
    assert!(out.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert!(get(addr, "/account", Some(&cookie)).await.text().contains("/_account/signin"), "the old cookie still works");
    let wrong = post(addr, SIGN_IN, None, &[("name", "Ada"), ("_password", "not the password")]).await;
    let nobody = post(addr, SIGN_IN, None, &[("name", "Nobody"), ("_password", "not the password")]).await;
    assert_eq!((wrong.status, nobody.status), (400, 400));
    assert_eq!(wrong.text(), nobody.text(), "a wrong name and a wrong password must look the same");
    let back = post(addr, SIGN_IN, None, &[("name", "ada"), ("_password", "correct horse battery"), ("_next", "/")]).await;
    assert_eq!(back.status, 303);
    let cookie = back.cookie().expect("a new session");

    // On disk: nothing readable, and nothing left over from refused uploads.
    let mut stored_files = 0;
    for entry in std::fs::read_dir(dir.join("data.bin.files")).unwrap().flatten() {
        let bytes = std::fs::read(entry.path()).unwrap();
        assert!(!bytes.windows(8).any(|w| w == b"ftypmp42") && !bytes.windows(4).any(|w| w == &video[5000..5004]));
        stored_files += 1;
    }
    assert_eq!(stored_files, 2, "one video and one picture, and no remains of refused uploads");
    let data = std::fs::read(dir.join("data.bin")).unwrap();
    for plain in [b"Ada".as_slice(), b"Lovely", b"argon2", b"first", cookie.as_bytes()] {
        assert!(!data.windows(plain.len()).any(|w| w == plain), "the data file holds readable text");
    }

    // After a restart everything is still there, including the session.
    let again = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Live::with_store(site_with_pictures(), Store::open(storage()).unwrap())));
        addr
    };
    assert!(get(again, &file_path, None).await.body == video);
    assert!(get(again, "/account", Some(&cookie)).await.text().contains("You are signed in."));
    let _ = std::fs::remove_dir_all(&dir);
}


/// The owner looks through what was added and removes some of it.
#[tokio::test]
async fn removing_a_video_or_an_account_takes_everything_with_it() {
    let live = Live::new(video_site());
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, live.clone()));
        addr
    };
    let join = |name: &'static str| async move {
        let joined = post(addr, SIGN_UP, None, &[("name", name), ("_password", "correct horse battery")]).await;
        let cookie = joined.cookie().expect("a session");
        let token = after(&get(addr, "/account", Some(&cookie)).await.text(), "name=\"_token\"", "value").to_owned();
        (cookie, token)
    };
    let (ada, ada_token) = join("Ada").await;
    let (bob, bob_token) = join("Bob").await;

    let video = fake_video(90_000);
    let sent = upload(
        addr,
        "/_form/videos",
        Some(&ada),
        &[Part::Text("_token", &ada_token), Part::Text("title", "Kept briefly"), Part::File("video", &video)],
    )
    .await;
    assert_eq!(sent.status, 303);
    let videos = live.records("videos");
    assert_eq!(videos.len(), 1);
    let (video_id, file_id) = (videos[0].id.clone(), videos[0].fields["video"].clone());
    let comment = [("_token", bob_token.as_str()), ("_parent", video_id.as_str()), ("text", "Bob was here")];
    assert_eq!(post(addr, "/_form/comments", Some(&bob), &comment).await.status, 303);
    assert_eq!(live.records("comments").len(), 1);

    // Removing Bob's account removes his comment and ends his session.
    let bob_id = live.records("users").into_iter().find(|u| u.fields["name"] == "Bob").unwrap().id;
    assert!(live.remove("users", &bob_id));
    assert!(live.records("comments").is_empty());
    assert!(get(addr, "/account", Some(&bob)).await.text().contains("/_account/signin"));
    assert_eq!(post(addr, SIGN_IN, None, &[("name", "Bob"), ("_password", "correct horse battery")]).await.status, 400);
    assert!(!live.remove("users", &bob_id), "there is nothing left to remove");

    // Removing the video removes its page and its file.
    assert_eq!(get(addr, &format!("/_file/{file_id}"), None).await.status, 200);
    assert!(live.remove("videos", &video_id));
    assert_eq!(get(addr, &format!("/watch/{video_id}"), None).await.status, 404);
    assert_eq!(get(addr, &format!("/_file/{file_id}"), None).await.status, 404);
    assert!(get(addr, "/", None).await.text().contains("Nothing here yet."));
    // Ada herself is untouched.
    assert!(get(addr, "/account", Some(&ada)).await.text().contains("You are signed in."));
}

/// What a camera writes about itself is gone from the video the site serves.
#[tokio::test]
async fn an_uploaded_video_is_served_without_its_camera_details() {
    let part = |kind: &[u8; 4], body: &[u8]| {
        let mut out = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    };
    let pictures: Vec<u8> = (0..150_000u32).map(|n| (n % 249) as u8).collect();
    let video = [
        part(b"ftyp", b"isom\0\0\x02\0isomiso2"),
        part(b"moov", &part(b"udta", b"recorded at SECRET-GPS-POSITION on a SECRET-PHONE")),
        part(b"mdat", &pictures),
    ]
    .concat();

    let (addr, live) = common::start(video_site()).await;
    let (cookie, token) = join(addr, "Ada").await;
    let sent = upload(
        addr,
        "/_form/videos",
        Some(&cookie),
        &[Part::Text("_token", &token), Part::Text("title", "Holiday"), Part::File("video", &video)],
    )
    .await;
    assert_eq!(sent.status, 303, "{}", sent.text());

    let file = live.records("videos")[0].fields["video"].clone();
    let served = get(addr, &format!("/_file/{file}"), None).await;
    assert_eq!(served.body.len(), video.len(), "the file changed length, so players would lose their place");
    assert!(!served.body.windows(6).any(|w| w == b"SECRET"), "camera details were served");
    assert!(served.body.ends_with(&pictures), "the pictures themselves changed");
}

/// The frame under an upload form says how far an upload has got while it
/// is still arriving, and to nobody who does not know the upload's name.
#[tokio::test]
async fn an_upload_reports_how_far_it_has_got() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (addr, live) = start(video_site()).await;
    let (cookie, token) = join(addr, "Ada").await;

    let page = get(addr, "/upload", Some(&cookie)).await;
    assert!(page.header("content-security-policy").unwrap().contains("frame-src 'self'"));
    let page = page.text();
    let frame = after(&page, "<iframe class=\"progress\"", "src").to_owned();
    let action = after(&page, "<form method=\"post\" action=\"/_form/videos", "action").to_owned();
    let name = frame.trim_start_matches("/_progress/").to_owned();
    assert_eq!(action, format!("/_form/videos?u={name}"));
    // Every page view gets a name of its own.
    assert!(!get(addr, "/upload", Some(&cookie)).await.text().contains(&name));

    let waiting = get(addr, &frame, None).await;
    assert_eq!(waiting.status, 200);
    let policy = waiting.header("content-security-policy").unwrap();
    assert!(policy.contains("frame-ancestors 'self'") && !policy.contains("frame-src"));
    assert!(waiting.text().contains(&format!("content=\"3;url={frame}?n=1\"")));
    assert!(get(addr, &format!("{frame}?n=200"), None).await.text().contains("Reload the page"));
    assert!(!get(addr, &format!("{frame}?n=200"), None).await.text().contains("http-equiv"));
    assert_eq!(get(addr, "/_progress/not-a-name", None).await.status, 404);
    assert_eq!(get(addr, "/_progress/%3Cscript%3E", None).await.status, 404);

    // Send half of an upload and stop there.
    let video = fake_video(400_000);
    let boundary = "----torusTestBoundaryHalf";
    let mut body = Vec::new();
    for (field, value) in [("_token", token.as_str()), ("_next", "/"), ("title", "Slow one")] {
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"video\"; filename=\"v.mp4\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&video);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let head = format!(
        "POST {action} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nCookie: s={cookie}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let half = body.len() / 2;
    stream.write_all(&body[..half]).await.unwrap();
    stream.flush().await.unwrap();

    let mut shown = String::new();
    for _ in 0..100 {
        shown = get(addr, &frame, None).await.text();
        if shown.contains("Uploading: 4") || shown.contains("Uploading: 50%") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(shown.contains("<progress max=\"100\" value=\""), "{shown}");
    assert!(shown.contains("of 0.4 MB") && shown.contains("content=\"2\""), "{shown}");
    // Someone guessing at names learns nothing.
    let guess = get(addr, "/_progress/0123456789abcdef01234567", None).await.text();
    assert!(!guess.contains("Uploading"));

    // The rest arrives, the video is kept, and the name is forgotten.
    stream.write_all(&body[half..]).await.unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer).await;
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 303"), "{}", String::from_utf8_lossy(&answer));
    assert_eq!(live.records("videos").len(), 1);
    assert!(!get(addr, &frame, None).await.text().contains("Uploading"));
}

/// Stands in for the real converter: a frame of 1920 by 1080, and WebMs laid
/// out the way a converter writes them to a pipe.
struct Stand;

fn element(id: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = id.to_vec();
    out.push(0x01);
    out.extend_from_slice(&(body.len() as u64).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn piped_webm(fill: u8) -> Vec<u8> {
    let entry = element(&[0xAE], &[element(&[0xD7], &[1]), element(&[0x83], &[1])].concat());
    let mut out = [
        element(&[0x1A, 0x45, 0xDF, 0xA3], &element(&[0x42, 0x82], b"webm")),
        vec![0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        element(&[0x15, 0x49, 0xA9, 0x66], &element(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40])),
        element(&[0x16, 0x54, 0xAE, 0x6B], &entry),
    ]
    .concat();
    for second in 0..3u16 {
        let block = element(&[0xA3], &[vec![0x81, 0, 0, 0x80], vec![fill; 2_000]].concat());
        out.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &[element(&[0xE7], &(second * 1000).to_be_bytes()), block].concat()));
    }
    out
}

impl torus_runtime::Converter for Stand {
    fn convert(
        &self,
        job: torus_runtime::Job,
        input: &mut (dyn Iterator<Item = hyper::body::Bytes> + Send),
        output: &mut (dyn FnMut(&[u8]) -> bool + Send),
    ) -> bool {
        // A converter reads all it is given.
        if input.map(|piece| piece.len()).sum::<usize>() == 0 {
            return false;
        }
        let made = match job {
            torus_runtime::Job::Still => {
                let mut png = std::io::Cursor::new(Vec::new());
                image::RgbImage::from_pixel(1920, 1080, image::Rgb([200, 30, 30])).write_to(&mut png, image::ImageFormat::Png).unwrap();
                png.into_inner()
            }
            torus_runtime::Job::Smaller(pixels) => piped_webm((pixels / 10) as u8),
            torus_runtime::Job::Whole => piped_webm(0xEE),
        };
        made.chunks(700).all(|piece| output(piece))
    }
}

#[tokio::test]
async fn a_picture_and_smaller_sizes_are_made_from_an_uploaded_video() {
    let (addr, live) = start(video_site()).await;
    live.convert_with(std::sync::Arc::new(Stand));
    let (cookie, token) = join(addr, "Ada").await;
    let video = fake_video(300_000);
    let sent = upload(
        addr,
        "/_form/videos",
        Some(&cookie),
        &[Part::Text("_token", &token), Part::Text("_next", "/"), Part::Text("title", "Sizes"), Part::File("video", &video)],
    )
    .await;
    assert_eq!(sent.status, 303, "{}", sent.text());
    let uploaded = live.records("videos")[0].fields["video"].clone();

    // Everything is made in the background; the upload itself did not wait for it.
    let mut now = uploaded.clone();
    for _ in 0..200 {
        now = live.records("videos")[0].fields["video"].clone();
        if now != uploaded {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_ne!(now, uploaded, "the smaller encoding takes the upload's place");
    assert_eq!(get(addr, &format!("/_file/{uploaded}"), None).await.status, 404, "and the upload is gone");

    // Cards show a picture, not a video.
    let home = get(addr, "/", None).await.text();
    let still = after(&home, "<img class=\"preview\"", "src").to_owned();
    assert!(!home.contains("<video"));
    let picture = get(addr, &still, None).await;
    assert_eq!((picture.status, picture.header("content-type")), (200, Some("image/jpeg")));
    let decoded = image::load_from_memory(&picture.body).unwrap();
    assert_eq!((decoded.width(), decoded.height()), (480, 270));

    // The watch page plays the middle size unless another is picked; the download is the full one.
    let id = live.records("videos")[0].id.clone();
    let watch = get(addr, &format!("/watch/{id}"), None).await.text();
    assert!(watch.contains("<a href=\"/watch/") && watch.contains("?v=360\">360p</a> · <strong>720p</strong> · "), "{watch}");
    assert!(watch.contains(&format!("?v=0\">Full size</a> · <a href=\"/_file/{now}\">Download the video</a>")));
    let source = |page: &str| after(page, "<video controls", "src").to_owned();
    let (middle, small, full) = (
        source(&watch),
        source(&get(addr, &format!("/watch/{id}?v=360"), None).await.text()),
        source(&get(addr, &format!("/watch/{id}?v=0"), None).await.text()),
    );
    assert_eq!(full, format!("/_file/{now}"));
    assert!(middle != small && middle != full && small != full);
    assert_eq!(source(&get(addr, &format!("/watch/{id}?v=999"), None).await.text()), full, "an unknown size plays the full one");
    for (path, fill) in [(&small, 36u8), (&middle, 72), (&full, 0xEE)] {
        let file = get(addr, path, None).await;
        assert_eq!((file.status, file.header("content-type")), (200, Some("video/webm")));
        assert!(file.body.windows(4).any(|w| w == [0x1C, 0x53, 0xBB, 0x6B]), "it has cues");
        assert!(file.body.ends_with(&[fill; 100]));
    }

    // Removing the video removes all that was made from it.
    assert!(live.remove("videos", &id));
    for path in [&still, &small, &middle, &full] {
        assert_eq!(get(addr, path, None).await.status, 404);
    }
}
