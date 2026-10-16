//! What is made from an uploaded video: a picture for its card, smaller
//! copies that load faster over Tor, and an encoding that takes less room
//! than the upload.
//!
//! Decoding video is the riskiest thing done with a stranger's file, so it
//! is not done here. A [`Converter`] is handed the bytes and hands bytes
//! back; the one hosts use runs in a process of its own that can reach
//! neither the network nor any file. What comes back is still not trusted:
//! a picture is decoded and encoded afresh, and a video is only rearranged.

use hyper::body::Bytes;

use crate::blobs::{self, Staged, Writer};
use crate::{webm, Live};

/// What to make from a video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// One frame, as a PNG of the video's own size.
    Still,
    /// A WebM whose shorter side has this many pixels.
    Smaller(u32),
    /// A WebM of the same size as the video, up to 1080 pixels on the
    /// shorter side. Every upload is encoded this way before it is shown.
    Whole,
}

/// Turns one video into something else, without touching anything but the
/// bytes it is given.
pub trait Converter: Send + Sync + 'static {
    /// Feeds `input` to the conversion and passes what comes out to
    /// `output`, which answers whether it wants more. Returns whether the
    /// conversion ran to its end.
    fn convert(
        &self,
        job: Job,
        input: &mut (dyn Iterator<Item = Bytes> + Send),
        output: &mut (dyn FnMut(&[u8]) -> bool + Send),
    ) -> bool;
}

/// A frame is held in memory, so it is not allowed to be enormous.
const MAX_FRAME: usize = 64 * 1024 * 1024;
/// The smaller sizes offered, by the pixels of the shorter side.
const SIZES: [u32; 2] = [360, 720];

/// Runs one conversion to a video and makes the result seekable. `None` if
/// it failed or came out larger than `most`.
fn video(live: &Live, converter: &dyn Converter, job: Job, source: blobs::Source, size: u64, most: u64) -> Option<Staged> {
    let target = live.store().file_target();
    let mut writer = Writer::new(target.clone()).ok()?;
    let mut written = 0u64;
    let finished = converter.convert(job, &mut blobs::read(source, 0, size), &mut |piece| {
        written += piece.len() as u64;
        written <= most && writer.write(piece).is_ok()
    });
    if !finished || written == 0 || written > most {
        return None;
    }
    // What the converter wrote is kept only long enough to be rearranged.
    let piped = writer.finish().ok()?;
    let seekable = webm::with_cues(&target, blobs::staged_source(&target, &piped), piped.size);
    blobs::discard(&target, &piped.id);
    seekable
}

/// Makes everything that is made from one uploaded video.
///
/// The upload itself is never shown. It is encoded afresh first, which
/// leaves behind everything a camera or editing program wrote into it,
/// including what hides inside the pictures and sound themselves; only then
/// does the video appear, and the upload is deleted. A video that cannot be
/// encoded stays hidden. Pictures and smaller copies follow.
pub(crate) fn convert(live: &Live, converter: &dyn Converter, video_file: &str) {
    let site = live.site();
    let Some((info, source)) = live.store().file_unchecked(video_file) else { return };
    let target = live.store().file_target();

    let mut frame = Vec::new();
    let got = converter.convert(Job::Still, &mut blobs::read(source.clone(), 0, info.size), &mut |piece| {
        frame.extend_from_slice(piece);
        frame.len() <= MAX_FRAME
    });
    let pictured = got.then(|| blobs::still(&frame)).flatten();
    drop(frame);
    if let Some((picture, _, _)) = &pictured {
        if let Ok(staged) = blobs::store(&target, picture) {
            live.store().keep_still(&site, video_file, staged);
        }
    }

    // Encoded afresh whatever its size. A re-encoding may come out larger
    // than a small, already compressed upload, so some room is allowed.
    let most = info.size.saturating_mul(2).max(256 * 1024 * 1024);
    let Some(staged) = video(live, converter, Job::Whole, source, info.size, most) else {
        live.store().converted(video_file, true);
        return;
    };
    let Some(current) = live.store().replace_video(&site, video_file, staged) else { return };
    live.store().mark_clean(&current);
    live.store().converted(&current, false);

    // Smaller copies are made from the clean encoding, after it is showing.
    if site.limits.sizes {
        let Some(shorter) = pictured.map(|(_, width, height)| width.min(height)) else { return };
        let Some((clean, clean_source)) = live.store().file_unchecked(&current) else { return };
        for pixels in SIZES.into_iter().filter(|pixels| shorter * 10 > pixels * 11) {
            if let Some(staged) = video(live, converter, Job::Smaller(pixels), clean_source.clone(), clean.size, clean.size * 8 / 10) {
                live.store().keep_size(&site, &current, pixels, staged);
            }
        }
    }
}
