//! Makes a WebM that was written to a pipe one a visitor can skip around in.
//!
//! A converter that may not touch the disk writes its result to a pipe, and
//! a WebM written that way lacks two things only known at the end: how long
//! it is, and the list of places playback can jump to (the cues). Without
//! them a browser shows no length and cannot seek. Here the file is read
//! once more and written out with both in front. Descriptive tags are left
//! out on the way. Nothing is decoded.

use crate::blobs::{self, Source, Staged, Target, Writer};

const EBML: u32 = 0x1A45_DFA3;
const SEGMENT: u32 = 0x1853_8067;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const CLUSTER: u32 = 0x1F43_B675;
const CUES: u32 = 0x1C53_BB6B;
const SEEK_HEAD: u32 = 0x114D_9B74;
const TAGS: u32 = 0x1254_C367;
const TIMECODE: u32 = 0xE7;
const SIMPLE_BLOCK: u32 = 0xA3;
const BLOCK_GROUP: u32 = 0xA0;
const BLOCK: u32 = 0xA1;
const REFERENCE: u32 = 0xFB;
const DURATION: u32 = 0x4489;
const TRACK_ENTRY: u32 = 0xAE;
const TRACK_NUMBER: u32 = 0xD7;
const TRACK_TYPE: u32 = 0x83;

/// The descriptions of the file and its tracks are held in memory; they are small.
const MAX_HEADER: u64 = 1024 * 1024;
const MAX_CLUSTERS: usize = 200_000;
/// More cues than this make the list itself slow to fetch.
const MAX_CUES: usize = 4_000;
const WINDOW: u64 = 128 * 1024;
/// One cue, written with fixed widths so its length is known beforehand.
const CUE_LEN: u64 = 27;

struct Head {
    id: u32,
    /// `None` when the element does not say how long it is.
    size: Option<u64>,
    /// How many bytes the id and size take.
    len: usize,
}

/// Reads an element's id and size from the bytes it starts with.
fn head_of(bytes: &[u8]) -> Option<Head> {
    let id_len = bytes.first()?.leading_zeros() as usize + 1;
    if id_len > 4 {
        return None;
    }
    let id = bytes.get(..id_len)?.iter().fold(0u32, |id, b| (id << 8) | u32::from(*b));
    let first = *bytes.get(id_len)?;
    let size_len = first.leading_zeros() as usize + 1;
    if size_len > 8 {
        return None;
    }
    let digits = bytes.get(id_len..id_len + size_len)?;
    let mut value = u64::from(first) & (0xff >> size_len);
    for byte in &digits[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    let unknown = value == (1u64 << (7 * size_len)) - 1;
    Some(Head { id, size: (!unknown).then_some(value), len: id_len + size_len })
}

/// The elements directly inside a run of bytes: id, the whole element, its contents.
fn children(mut bytes: &[u8]) -> Option<Vec<(u32, &[u8], &[u8])>> {
    let mut found = Vec::new();
    while !bytes.is_empty() {
        let head = head_of(bytes)?;
        let end = head.len.checked_add(usize::try_from(head.size?).ok()?)?;
        let whole = bytes.get(..end)?;
        found.push((head.id, whole, &whole[head.len..]));
        bytes = &bytes[end..];
    }
    Some(found)
}

fn number(bytes: &[u8]) -> Option<u64> {
    (bytes.len() <= 8).then(|| bytes.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
}

/// An element's id followed by its length, the length always eight bytes wide.
fn opening(id: u32, length: u64) -> Vec<u8> {
    let mut out: Vec<u8> = id.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    out.push(0x01);
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out
}

/// Reads small spans of a stored file without decrypting the same piece over and over.
struct Reader {
    source: Source,
    total: u64,
    window: Vec<u8>,
    start: u64,
}

impl Reader {
    fn bytes(&mut self, at: u64, count: u64) -> Option<&[u8]> {
        if count > WINDOW || at.checked_add(count)? > self.total {
            return None;
        }
        if at < self.start || at + count > self.start + self.window.len() as u64 {
            let length = WINDOW.min(self.total - at);
            self.window.clear();
            for piece in blobs::read(self.source.clone(), at, length) {
                self.window.extend_from_slice(&piece);
            }
            self.start = at;
            if (self.window.len() as u64) < count {
                return None;
            }
        }
        let from = (at - self.start) as usize;
        Some(&self.window[from..from + count as usize])
    }

    fn head(&mut self, at: u64) -> Option<Head> {
        let within = 12.min(self.total.checked_sub(at)?);
        head_of(self.bytes(at, within)?)
    }

    /// Where the contents of an element of unknown length end: at the next
    /// element that can only stand at the outermost level, or at `end`.
    fn extent(&mut self, from: u64, end: u64) -> Option<u64> {
        let mut at = from;
        while at < end {
            let head = self.head(at)?;
            if matches!(head.id, CLUSTER | CUES | TAGS | SEEK_HEAD | INFO | TRACKS) {
                break;
            }
            at = at.checked_add(head.len as u64)?.checked_add(head.size?)?;
        }
        (at <= end).then_some(at)
    }

    /// Reads through a cluster: the time it starts at, the latest time any
    /// block in it carries, and the time of the first picture of `track`
    /// that playback can start from, if it holds one.
    fn times(&mut self, from: u64, end: u64, track: u8) -> Option<(u64, u64, Option<u64>)> {
        let (mut start, mut latest, mut key) = (None, 0i64, None);
        let mut at = from;
        while at < end {
            let head = self.head(at)?;
            let (data, size) = (at + head.len as u64, head.size?);
            let finish = data.checked_add(size).filter(|finish| *finish <= end)?;
            match head.id {
                TIMECODE => start = number(self.bytes(data, size.min(9))?),
                SIMPLE_BLOCK | BLOCK_GROUP => {
                    // A block on its own says whether it can be started
                    // from. In a group, it can unless it refers to another.
                    let (mut block, mut starts) = (data, None);
                    if head.id == BLOCK_GROUP {
                        let (mut inner, mut found, mut refers) = (data, None, false);
                        while inner < finish {
                            let part = self.head(inner)?;
                            let part_data = inner + part.len as u64;
                            match part.id {
                                BLOCK => found = Some(part_data),
                                REFERENCE => refers = true,
                                _ => {}
                            }
                            inner = part_data.checked_add(part.size?)?;
                        }
                        let Some(found) = found else {
                            at = finish;
                            continue;
                        };
                        (block, starts) = (found, Some(!refers));
                    }
                    // A track number, the time relative to the cluster, and flags.
                    let lead = self.bytes(block, 4.min(finish.checked_sub(block)?))?;
                    if lead.len() < 4 || lead[0] & 0x80 == 0 {
                        return None;
                    }
                    let time = i64::from(i16::from_be_bytes([lead[1], lead[2]]));
                    latest = latest.max(time);
                    if key.is_none() && lead[0] & 0x7f == track && starts.unwrap_or(lead[3] & 0x80 != 0) {
                        key = Some(time);
                    }
                }
                _ => {}
            }
            at = finish;
        }
        let start = start?;
        Some((start, latest as u64, key.and_then(|key| start.checked_add_signed(key))))
    }
}

struct Cluster {
    data: u64,
    length: u64,
}

/// The number of the track that carries the pictures, or failing that the first.
fn video_track(tracks: &[u8]) -> Option<u8> {
    let mut first = None;
    for (id, _, entry) in children(tracks)? {
        if id != TRACK_ENTRY {
            continue;
        }
        let fields = children(entry)?;
        let field = |wanted: u32| fields.iter().find(|(id, ..)| *id == wanted).and_then(|(_, _, value)| number(value));
        let track = u8::try_from(field(TRACK_NUMBER)?).ok().filter(|n| (1..=127).contains(n))?;
        if field(TRACK_TYPE) == Some(1) {
            return Some(track);
        }
        first = first.or(Some(track));
    }
    first
}

/// Writes the file again with its length and its cues in front. `None` if
/// it is not laid out the way a converter writes to a pipe.
pub(crate) fn with_cues(target: &Target, source: Source, total: u64) -> Option<Staged> {
    let mut reader = Reader { source: source.clone(), total, window: Vec::new(), start: 0 };
    let first = reader.head(0)?;
    let preamble_len = first.len as u64 + first.size.filter(|size| first.id == EBML && *size <= 4096)?;
    let preamble = reader.bytes(0, preamble_len)?.to_vec();
    let segment = reader.head(preamble_len)?;
    if segment.id != SEGMENT {
        return None;
    }
    let mut at = preamble_len + segment.len as u64;
    let end = segment.size.map_or(total, |size| total.min(at.saturating_add(size)));

    let (mut info, mut tracks, mut clusters) = (None, None, Vec::new());
    while at < end {
        let head = reader.head(at)?;
        let data = at + head.len as u64;
        let finish = match (head.id, head.size) {
            (CLUSTER, None) => reader.extent(data, end)?,
            (_, Some(size)) => data.checked_add(size).filter(|finish| *finish <= end)?,
            _ => return None,
        };
        match head.id {
            CLUSTER => {
                if clusters.len() >= MAX_CLUSTERS {
                    return None;
                }
                clusters.push(Cluster { data, length: finish - data });
            }
            INFO | TRACKS if finish - data <= MAX_HEADER => {
                let mut held = Vec::with_capacity((finish - data) as usize);
                blobs::read(source.clone(), data, finish - data).for_each(|piece| held.extend_from_slice(&piece));
                if held.len() as u64 != finish - data {
                    return None;
                }
                *(if head.id == INFO { &mut info } else { &mut tracks }) = Some(held);
            }
            INFO | TRACKS => return None,
            // The old table of contents, padding, tags and any cues are left out.
            _ => {}
        }
        at = finish;
    }
    let (info, tracks) = (info?, tracks?);
    let track = video_track(&tracks)?;
    // A browser may only jump to where a picture can be decoded from
    // nothing: every cluster is read through to find those places.
    let mut length = 0u64;
    let mut starts = Vec::new();
    let mut place = 0u64;
    for cluster in &clusters {
        let (time, latest, key) = reader.times(cluster.data, cluster.data + cluster.length, track)?;
        length = length.max(time + latest);
        if let Some(key) = key {
            starts.push((key, place));
        }
        place += 12 + cluster.length;
    }
    if starts.is_empty() {
        return None;
    }
    let length = length as f64;

    let mut described: Vec<u8> = children(&info)?.into_iter().filter(|(id, ..)| *id != DURATION).flat_map(|(_, whole, _)| whole.to_vec()).collect();
    described.extend_from_slice(&[0x44, 0x89, 0x88]);
    described.extend_from_slice(&length.to_be_bytes());
    let info = [opening(INFO, described.len() as u64), described].concat();
    let tracks = [opening(TRACKS, tracks.len() as u64), tracks].concat();

    let every = starts.len().div_ceil(MAX_CUES);
    let starts: Vec<(u64, u64)> = starts.into_iter().step_by(every).collect();
    let cues_len = 12 + starts.len() as u64 * CUE_LEN;
    let mut cues = opening(CUES, starts.len() as u64 * CUE_LEN);
    let first = info.len() as u64 + tracks.len() as u64 + cues_len;
    for (time, place) in &starts {
        cues.extend_from_slice(&[0xBB, 0x99, 0xB3, 0x88]);
        cues.extend_from_slice(&time.to_be_bytes());
        cues.extend_from_slice(&[0xB7, 0x8D, 0xF7, 0x81, track, 0xF1, 0x88]);
        cues.extend_from_slice(&(first + place).to_be_bytes());
    }
    let position = first + place;

    let mut writer = Writer::new(target.clone()).ok()?;
    writer.write(&preamble).ok()?;
    writer.write(&opening(SEGMENT, position)).ok()?;
    writer.write(&info).ok()?;
    writer.write(&tracks).ok()?;
    writer.write(&cues).ok()?;
    for cluster in &clusters {
        writer.write(&opening(CLUSTER, cluster.length)).ok()?;
        let mut copied = 0u64;
        for piece in blobs::read(source.clone(), cluster.data, cluster.length) {
            copied += piece.len() as u64;
            writer.write(&piece).ok()?;
        }
        if copied != cluster.length {
            return None;
        }
    }
    writer.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn element(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        out.push(0x01);
        out.extend_from_slice(&(body.len() as u64).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        out
    }

    fn block(track: u8, time: i16, fill: u8) -> Vec<u8> {
        let mut body = vec![0x80 | track];
        body.extend_from_slice(&time.to_be_bytes());
        body.push(0x80);
        body.extend_from_slice(&[fill; 300]);
        element(&[0xA3], &body)
    }

    /// Sound first, then a picture that can be started from, then more sound.
    fn cluster(time: u16, fill: u8) -> Vec<u8> {
        [element(&[0xE7], &time.to_be_bytes()), block(1, 0, fill), block(2, 7, fill), block(1, 40, fill)].concat()
    }

    /// A cluster whose only picture depends on an earlier one.
    fn dependent(time: u16) -> Vec<u8> {
        let mut picture = block(2, 3, 9);
        picture[12] = 0;
        [element(&[0xE7], &time.to_be_bytes()), block(1, 0, 9), picture].concat()
    }

    fn piped() -> Vec<u8> {
        let preamble = element(&[0x1A, 0x45, 0xDF, 0xA3], &element(&[0x42, 0x82], b"webm"));
        let info = element(&[0x15, 0x49, 0xA9, 0x66], &[element(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]), element(&[0x4D, 0x80], b"muxer")].concat());
        let entry = |number: u8, kind: u8| element(&[0xAE], &[element(&[0xD7], &[number]), element(&[0x83], &[kind])].concat());
        let tracks = element(&[0x16, 0x54, 0xAE, 0x6B], &[entry(1, 2), entry(2, 1)].concat());
        let tags = element(&[0x12, 0x54, 0xC3, 0x67], b"SECRET title");
        // The segment, and its second cluster, do not say how long they are.
        let mut out = [preamble, vec![0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], info, tracks, tags].concat();
        out.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &cluster(0, 1)));
        out.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &dependent(2_500)));
        out.extend([vec![0x1F, 0x43, 0xB6, 0x75, 0xff], cluster(5_000, 2)].concat());
        out.extend(element(&[0x1F, 0x43, 0xB6, 0x75], &cluster(10_000, 3)));
        out
    }

    #[test]
    fn a_piped_file_gains_its_length_and_cues_and_loses_its_tags() {
        let file = piped();
        let total = file.len() as u64;
        let out = with_cues(&Target::Memory, Source::Memory(Arc::new(file)), total).unwrap().memory.unwrap();
        assert!(!out.windows(6).any(|w| w == b"SECRET"));

        let segment = head_of(&out[26..]).unwrap();
        assert_eq!((segment.id, segment.size), (SEGMENT, Some(out.len() as u64 - 26 - 12)));
        let inside = &out[38..];
        let parts = children(inside).unwrap();
        let ids: Vec<u32> = parts.iter().map(|(id, ..)| *id).collect();
        assert_eq!(ids, [INFO, TRACKS, CUES, CLUSTER, CLUSTER, CLUSTER, CLUSTER]);

        // The length: the last cluster's time plus its latest block's.
        let length = children(parts[0].2).unwrap().into_iter().find(|(id, ..)| *id == DURATION).unwrap().2;
        assert_eq!(f64::from_be_bytes(length.try_into().unwrap()), 10_040.0);

        // Every cue names the picture track and points at the start of a cluster with that time.
        let cues = children(parts[2].2).unwrap();
        assert_eq!(cues.len(), 3);
        for ((_, _, cue), time) in cues.iter().zip([0u64, 5_000, 10_000]) {
            // The cue carries the time of the picture, not of the cluster.
            let fields = children(cue).unwrap();
            assert_eq!(number(fields[0].2), Some(time + 7));
            let place = children(fields[1].2).unwrap();
            assert_eq!(number(place[0].2), Some(2));
            let at = number(place[1].2).unwrap() as usize;
            let found = head_of(&inside[at..]).unwrap();
            assert_eq!(found.id, CLUSTER);
            let (_, _, first) = children(&inside[at + found.len..at + found.len + found.size.unwrap() as usize]).unwrap()[0];
            assert_eq!(number(first), Some(time));
        }
    }

    #[test]
    fn anything_else_is_refused() {
        let refuse = |file: Vec<u8>| {
            let total = file.len() as u64;
            assert!(with_cues(&Target::Memory, Source::Memory(Arc::new(file)), total).is_none());
        };
        refuse(Vec::new());
        refuse(vec![0xff; 5_000]);
        refuse(piped()[..40].to_vec());
        let mut cut = piped();
        cut.truncate(cut.len() - 100);
        refuse(cut);
    }

    /// By hand, against a real converter's output:
    /// `TORUS_WEBM_IN=piped.webm TORUS_WEBM_OUT=out.webm cargo test -p torus-runtime --lib real_file -- --ignored`
    #[test]
    #[ignore = "needs a file made by a converter"]
    fn a_real_file_is_rewritten() {
        let file = std::fs::read(std::env::var("TORUS_WEBM_IN").unwrap()).unwrap();
        let total = file.len() as u64;
        let out = with_cues(&Target::Memory, Source::Memory(Arc::new(file)), total).unwrap();
        std::fs::write(std::env::var("TORUS_WEBM_OUT").unwrap(), out.memory.unwrap()).unwrap();
    }
}
