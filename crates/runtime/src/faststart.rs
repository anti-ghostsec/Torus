//! Moves an MP4's index to the front of the file.
//!
//! Phones and cameras write the index (`moov`) after the pictures and sound
//! (`mdat`), because they only know it once recording ends. A browser must
//! then fetch the end of the file before it can show anything, which over
//! Tor costs seconds per round trip. With the index first, playback starts
//! as soon as the first pieces arrive.
//!
//! Nothing is decoded: boxes are moved whole and the positions the index
//! records are corrected. Anything unusual leaves the file as it was.

use crate::blobs::{self, Source, Staged, Target, Writer};

/// An index larger than this is not held in memory to be moved.
const MAX_INDEX: u64 = 64 * 1024 * 1024;
const MAX_TOP_BOXES: usize = 64;
const MAX_DEPTH: usize = 8;

struct Top {
    kind: [u8; 4],
    start: u64,
    size: u64,
}

fn read_at(source: &Source, start: u64, length: u64) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(length as usize);
    for piece in blobs::read(source.clone(), start, length) {
        out.extend_from_slice(&piece);
    }
    (out.len() as u64 == length).then_some(out)
}

/// The boxes a file is made of, outermost level only.
fn top_level(source: &Source, total: u64) -> Option<Vec<Top>> {
    let mut boxes = Vec::new();
    let mut at = 0u64;
    while at < total {
        if boxes.len() >= MAX_TOP_BOXES || total - at < 8 {
            return None;
        }
        let head = read_at(source, at, 16.min(total - at))?;
        let kind = [head[4], head[5], head[6], head[7]];
        let size = match u32::from_be_bytes([head[0], head[1], head[2], head[3]]) {
            0 => total - at,
            1 => u64::from_be_bytes(head.get(8..16)?.try_into().ok()?),
            size => u64::from(size),
        };
        if size < 8 || size > total - at {
            return None;
        }
        boxes.push(Top { kind, start: at, size });
        at += size;
    }
    Some(boxes)
}

/// Adds `by` to every recorded position that lies before `limit`, in a run
/// of boxes held in memory. `None` if anything is malformed or would no
/// longer fit, in which case nothing may be used.
fn shift(mut boxes: &mut [u8], limit: u64, by: u64, depth: usize) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    while !boxes.is_empty() {
        if boxes.len() < 8 {
            return None;
        }
        let size = u32::from_be_bytes(boxes[..4].try_into().ok()?) as usize;
        // Sizes too large for 32 bits do not occur inside an index.
        if size < 8 || size > boxes.len() {
            return None;
        }
        let (this, rest) = boxes.split_at_mut(size);
        let kind: [u8; 4] = this[4..8].try_into().ok()?;
        let body = &mut this[8..];
        match &kind {
            b"trak" | b"mdia" | b"minf" | b"stbl" => shift(body, limit, by, depth + 1)?,
            b"stco" | b"co64" => {
                let width = if &kind == b"stco" { 4 } else { 8 };
                let count = u32::from_be_bytes(body.get(4..8)?.try_into().ok()?) as usize;
                let entries = body.get_mut(8..)?.get_mut(..count.checked_mul(width)?)?;
                for entry in entries.chunks_exact_mut(width) {
                    if width == 4 {
                        let position = u64::from(u32::from_be_bytes((&*entry).try_into().ok()?));
                        if position < limit {
                            entry.copy_from_slice(&u32::try_from(position + by).ok()?.to_be_bytes());
                        }
                    } else {
                        let position = u64::from_be_bytes((&*entry).try_into().ok()?);
                        if position < limit {
                            entry.copy_from_slice(&position.checked_add(by)?.to_be_bytes());
                        }
                    }
                }
            }
            _ => {}
        }
        boxes = rest;
    }
    Some(())
}

fn rewritten(target: &Target, source: &Source, total: u64) -> Option<Staged> {
    let boxes = top_level(source, total)?;
    let first = boxes.first().filter(|b| &b.kind == b"ftyp" && b.size <= 1024 * 1024)?;
    let count = |kind: &[u8; 4]| boxes.iter().filter(|b| &b.kind == kind).count();
    // Files cut into fragments keep positions elsewhere, and are left alone.
    if count(b"moov") != 1 || count(b"moof") != 0 {
        return None;
    }
    let index = boxes.iter().find(|b| &b.kind == b"moov")?;
    let data = boxes.iter().find(|b| &b.kind == b"mdat")?;
    if index.start < data.start || index.size > MAX_INDEX {
        return None;
    }
    let mut moov = read_at(source, index.start, index.size)?;
    // 64-bit box sizes are not expected on an index small enough to move.
    if u32::from_be_bytes(moov[..4].try_into().ok()?) as u64 != index.size {
        return None;
    }
    // Everything that stood between the start and the index moves back by
    // the index's length; what stood after it stays where it was.
    shift(&mut moov[8..], index.start, index.size, 0)?;

    let mut writer = Writer::new(target.clone()).ok()?;
    writer.write(&read_at(source, first.start, first.size)?).ok()?;
    writer.write(&moov).ok()?;
    for other in boxes.iter().skip(1).filter(|b| &b.kind != b"moov") {
        let mut copied = 0u64;
        for piece in blobs::read(source.clone(), other.start, other.size) {
            copied += piece.len() as u64;
            writer.write(&piece).ok()?;
        }
        if copied != other.size {
            return None;
        }
    }
    let staged = writer.finish().ok()?;
    (staged.size == total).then_some(staged)
}

/// Returns the file with its index in front: a new copy replacing the one
/// given, or the one given when there was nothing to do or it is not a file
/// this understands.
pub(crate) fn front_index(target: &Target, mut staged: Staged) -> Staged {
    let (source, held) = match (target, staged.memory.take()) {
        (Target::Disk { dir, key }, _) => (Source::Disk { path: dir.join(&staged.id), key: key.clone() }, None),
        (Target::Memory, contents) => {
            let contents = std::sync::Arc::new(contents.unwrap_or_default());
            (Source::Memory(contents.clone()), Some(contents))
        }
    };
    let moved = rewritten(target, &source, staged.size);
    drop(source);
    match moved {
        Some(moved) => {
            blobs::discard(target, &staged.id);
            moved
        }
        None => {
            staged.memory = held.map(|contents| std::sync::Arc::try_unwrap(contents).unwrap_or_else(|shared| (*shared).clone()));
            staged
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mp4_box(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut out = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(body);
        out
    }

    fn table(kind: &[u8; 4], positions: &[u64]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&(positions.len() as u32).to_be_bytes());
        for position in positions {
            if kind == b"stco" {
                body.extend_from_slice(&(*position as u32).to_be_bytes());
            } else {
                body.extend_from_slice(&position.to_be_bytes());
            }
        }
        mp4_box(kind, &body)
    }

    fn track(kind: &[u8; 4], positions: &[u64]) -> Vec<u8> {
        let stbl = mp4_box(b"stbl", &[mp4_box(b"stsd", b"about the codec"), table(kind, positions)].concat());
        mp4_box(b"trak", &mp4_box(b"mdia", &mp4_box(b"minf", &stbl)))
    }

    /// The positions an index records, in the order they appear.
    fn positions(file: &[u8]) -> Vec<u64> {
        let mut found = Vec::new();
        for (kind, width) in [(b"stco", 4usize), (b"co64", 8usize)] {
            let mut from = 0;
            while let Some(at) = file[from..].windows(4).position(|w| w == kind) {
                let body = from + at + 4;
                let count = u32::from_be_bytes(file[body + 4..body + 8].try_into().unwrap()) as usize;
                for entry in file[body + 8..body + 8 + count * width].chunks(width) {
                    let mut wide = [0u8; 8];
                    wide[8 - width..].copy_from_slice(entry);
                    found.push(u64::from_be_bytes(wide));
                }
                from = body;
            }
        }
        found
    }

    fn staged(file: &[u8]) -> Staged {
        blobs::store(&Target::Memory, file).unwrap()
    }

    #[test]
    fn an_index_at_the_end_moves_to_the_front_and_still_points_at_the_same_bytes() {
        let ftyp = mp4_box(b"ftyp", b"isom");
        let free = mp4_box(b"free", b"padding");
        let payload: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        let mdat = mp4_box(b"mdat", &payload);
        let first = (ftyp.len() + free.len() + 8) as u64;
        let wanted = [first, first + 1_000, first + 150_000];
        let moov = mp4_box(b"moov", &[mp4_box(b"mvhd", &[0; 20]), track(b"stco", &wanted[..2]), track(b"co64", &wanted[2..])].concat());
        // Something after the index too: it does not move, so positions in it must not change.
        let tail = mp4_box(b"free", b"the end");
        let file = [ftyp.clone(), free, mdat, moov.clone(), tail].concat();

        let moved = front_index(&Target::Memory, staged(&file));
        let out = moved.memory.unwrap();
        assert_eq!(out.len(), file.len());
        assert_eq!(&out[..ftyp.len()], &ftyp[..]);
        assert_eq!(&out[ftyp.len() + 4..ftyp.len() + 8], b"moov");
        assert!(out.ends_with(b"the end"));
        let now = positions(&out);
        assert_eq!(now.len(), 3);
        for (before, after) in wanted.iter().zip(&now) {
            assert_eq!(after - before, moov.len() as u64);
            assert_eq!(out[*after as usize..*after as usize + 64], file[*before as usize..*before as usize + 64]);
        }
    }

    #[test]
    fn files_that_need_nothing_or_make_no_sense_are_left_exactly_as_they_were() {
        let ftyp = mp4_box(b"ftyp", b"isom");
        let mdat = mp4_box(b"mdat", &[7; 5_000]);
        let moov = mp4_box(b"moov", &track(b"stco", &[100]));
        let same = |file: Vec<u8>| assert_eq!(front_index(&Target::Memory, staged(&file)).memory.unwrap(), file);

        // Already in front.
        same([ftyp.clone(), moov.clone(), mdat.clone()].concat());
        // Cut into fragments.
        same([ftyp.clone(), mdat.clone(), moov.clone(), mp4_box(b"moof", b"x")].concat());
        // Not boxes at all after the start.
        same([ftyp.clone(), vec![0xff; 3_000]].concat());
        // A table that claims more entries than it holds.
        let mut lying = table(b"stco", &[100]);
        lying[12..16].copy_from_slice(&1_000_000u32.to_be_bytes());
        let broken = mp4_box(b"moov", &mp4_box(b"trak", &mp4_box(b"mdia", &mp4_box(b"minf", &mp4_box(b"stbl", &lying)))));
        same([ftyp.clone(), mdat.clone(), broken].concat());
        // A position that would no longer fit in 32 bits.
        let mut far = track(b"stco", &[u64::from(u32::MAX) - 4]);
        assert!(shift(&mut far, u64::MAX, 10, 0).is_none());
        let mut near = track(b"stco", &[100]);
        assert!(shift(&mut near, u64::MAX, 10, 0).is_some());
        let _ = (ftyp, mdat);
    }
}
