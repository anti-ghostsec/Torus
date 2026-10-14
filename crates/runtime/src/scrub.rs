//! Removes what a camera or editing program writes about itself into a
//! video file: where and when it was recorded, on what device, with what
//! software, under what title.
//!
//! The video is not re-encoded. The parts of the file that hold such details
//! are blanked in place, as the file streams past, so every other byte keeps
//! its position and the file plays exactly as before. What this cannot
//! reach is anything a camera embeds inside the compressed pictures or sound
//! themselves; removing that would take decoding and encoding the video again.
//!
//! Input that does not look like the format it claims is passed through
//! untouched rather than refused: this is a filter, not a validator.

/// The largest part of a file held in memory at once to be cleaned. An
/// index larger than this is passed through as it is.
const MAX_HELD: u64 = 32 * 1024 * 1024;

pub(crate) enum Scrubber {
    Mp4(Mp4),
    WebM(WebM),
}

impl Scrubber {
    pub fn new(content_type: &str) -> Self {
        if content_type == "video/webm" {
            Scrubber::WebM(WebM::default())
        } else {
            Scrubber::Mp4(Mp4::default())
        }
    }

    /// Takes the next piece of the file and appends what can be written so far to `out`.
    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) {
        match self {
            Scrubber::Mp4(mp4) => mp4.push(input, out),
            Scrubber::WebM(webm) => webm.push(input, out),
        }
    }

    /// Appends whatever was still being held back when the file ended.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let held = match self {
            Scrubber::Mp4(mp4) => &mut mp4.held,
            Scrubber::WebM(webm) => &mut webm.held,
        };
        out.append(held);
    }
}

/// What to do with the bytes that come next.
#[derive(Default)]
enum Next {
    /// Read the header of the next part.
    #[default]
    Header,
    /// Copy this many bytes as they are.
    Copy(u64),
    /// Replace this many bytes with zeros.
    Blank(u64),
    /// Hold this many bytes in total, then clean and write them.
    Hold(u64),
    /// Copy everything from here on.
    CopyRest,
}

/// Copies or blanks up to `left` bytes of `input`, returning how many were taken.
fn pass(input: &[u8], left: &mut u64, blank: bool, out: &mut Vec<u8>) -> usize {
    let take = (*left).min(input.len() as u64) as usize;
    if blank {
        out.resize(out.len() + take, 0);
    } else {
        out.extend_from_slice(&input[..take]);
    }
    *left -= take as u64;
    take
}

// MP4 and its relatives: a file is a sequence of boxes, each a 4-byte size,
// a 4-byte type and a body, and some boxes contain boxes.

#[derive(Default)]
pub(crate) struct Mp4 {
    next: Next,
    held: Vec<u8>,
}

/// Boxes that exist to carry descriptions: user data, metadata, and
/// vendor extensions (where XMP lives).
fn describes(kind: &[u8]) -> bool {
    matches!(kind, b"udta" | b"meta" | b"uuid")
}

impl Mp4 {
    fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            match &mut self.next {
                Next::CopyRest => {
                    out.extend_from_slice(input);
                    return;
                }
                Next::Copy(left) => {
                    input = &input[pass(input, left, false, out)..];
                    if *left == 0 {
                        self.next = Next::Header;
                    }
                }
                Next::Blank(left) => {
                    input = &input[pass(input, left, true, out)..];
                    if *left == 0 {
                        self.next = Next::Header;
                    }
                }
                Next::Hold(total) => {
                    let want = (*total - self.held.len() as u64).min(input.len() as u64) as usize;
                    self.held.extend_from_slice(&input[..want]);
                    input = &input[want..];
                    if self.held.len() as u64 == *total {
                        clean_boxes(&mut self.held[8..], 0);
                        out.append(&mut self.held);
                        self.next = Next::Header;
                    }
                }
                Next::Header => {
                    // 8 bytes, or 16 when the size is too large for 4.
                    let need = if self.held.len() >= 8 && self.held[..4] == [0, 0, 0, 1] { 16 } else { 8 };
                    let want = (need - self.held.len()).min(input.len());
                    self.held.extend_from_slice(&input[..want]);
                    input = &input[want..];
                    if self.held.len() < need || (need == 8 && self.held[..4] == [0, 0, 0, 1]) {
                        continue;
                    }
                    let short = u64::from(u32::from_be_bytes(self.held[..4].try_into().expect("4 bytes")));
                    let kind: [u8; 4] = self.held[4..8].try_into().expect("4 bytes");
                    let size = if need == 16 { u64::from_be_bytes(self.held[8..16].try_into().expect("8 bytes")) } else { short };
                    let body = size.checked_sub(need as u64);
                    self.next = match body {
                        // Size 0 means "to the end of the file"; a size
                        // smaller than its own header is not a box at all.
                        None => Next::CopyRest,
                        Some(body) if &kind == b"moov" && need == 8 && size <= MAX_HELD => {
                            // Keep the header in `held` and gather the rest.
                            let _ = body;
                            Next::Hold(size)
                        }
                        Some(body) if describes(&kind) => {
                            self.held[4..8].copy_from_slice(b"free");
                            out.append(&mut self.held);
                            if body == 0 { Next::Header } else { Next::Blank(body) }
                        }
                        Some(body) => {
                            out.append(&mut self.held);
                            if body == 0 { Next::Header } else { Next::Copy(body) }
                        }
                    };
                }
            }
        }
    }
}

/// How deep boxes are followed into one another. Real files go four or five
/// deep; a file built to nest thousands deep must not be able to exhaust
/// the stack.
const MAX_DEPTH: usize = 12;

/// Cleans a run of boxes held in memory, descending into those that hold
/// the tracks. Stops quietly at anything malformed.
fn clean_boxes(mut boxes: &mut [u8], depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    while boxes.len() >= 8 {
        let size = u32::from_be_bytes(boxes[..4].try_into().expect("4 bytes")) as usize;
        if size < 8 || size > boxes.len() {
            return;
        }
        let (this, rest) = boxes.split_at_mut(size);
        let (header, body) = this.split_at_mut(8);
        let kind: [u8; 4] = header[4..8].try_into().expect("4 bytes");
        match &kind {
            kind if describes(kind) => {
                header[4..8].copy_from_slice(b"free");
                body.fill(0);
            }
            b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf" | b"mvex" => clean_boxes(body, depth + 1),
            // When the file, the track and its media were made and changed.
            b"mvhd" | b"tkhd" | b"mdhd" => {
                let times = if body.first() == Some(&1) { 4..20 } else { 4..12 };
                if let Some(times) = body.get_mut(times) {
                    times.fill(0);
                }
            }
            _ => {}
        }
        boxes = rest;
    }
}

// WebM (Matroska): a file is a sequence of elements, each an identifier of
// 1 to 4 bytes, a size of 1 to 8 bytes and a body, and some contain elements.

const SEGMENT: u32 = 0x1853_8067;
const INFO: u32 = 0x1549_A966;
const TAGS: u32 = 0x1254_C367;
const ATTACHMENTS: u32 = 0x1941_A469;
const VOID: u8 = 0xEC;

#[derive(Default)]
pub(crate) struct WebM {
    next: Next,
    held: Vec<u8>,
}

/// An element's identifier, its body's size (`None` when declared unknown),
/// and how many bytes the two take. `None` until enough bytes are there;
/// `Err` when they are not a header.
fn element(bytes: &[u8]) -> Result<Option<(u32, Option<u64>, usize)>, ()> {
    let Some(&first) = bytes.first() else { return Ok(None) };
    let id_len = first.leading_zeros() as usize + 1;
    if id_len > 4 {
        return Err(());
    }
    let Some(id_bytes) = bytes.get(..id_len) else { return Ok(None) };
    let id = id_bytes.iter().fold(0u32, |id, b| (id << 8) | u32::from(*b));
    let Some(&lead) = bytes.get(id_len) else { return Ok(None) };
    let size_len = lead.leading_zeros() as usize + 1;
    if size_len > 8 {
        return Err(());
    }
    let Some(size_bytes) = bytes.get(id_len..id_len + size_len) else { return Ok(None) };
    let mut size = u64::from(lead) & ((1u64 << (8 - size_len)) - 1);
    for b in &size_bytes[1..] {
        size = (size << 8) | u64::from(*b);
    }
    let unknown = size == (1u64 << (7 * size_len)) - 1;
    Ok(Some((id, (!unknown).then_some(size), id_len + size_len)))
}

/// Turns the header of an element into the header of a "void" element (one
/// that players skip) of the same total length. Returns how many bytes of
/// the header itself become part of the void's body.
fn void_header(header: &mut [u8], body: u64) -> u64 {
    // One byte of identifier, then a size written with as many bytes as are
    // left, up to the 8 a size may have; any beyond that join the body.
    let size_len = (header.len() - 1).min(8);
    let extra = (header.len() - 1 - size_len) as u64;
    let size = body + extra;
    header[0] = VOID;
    let encoded = (size | (1u64 << (7 * size_len))).to_be_bytes();
    header[1..1 + size_len].copy_from_slice(&encoded[8 - size_len..]);
    header[1 + size_len..].fill(0);
    extra
}

impl WebM {
    fn push(&mut self, mut input: &[u8], out: &mut Vec<u8>) {
        while !input.is_empty() {
            match &mut self.next {
                Next::CopyRest => {
                    out.extend_from_slice(input);
                    return;
                }
                Next::Copy(left) => {
                    input = &input[pass(input, left, false, out)..];
                    if *left == 0 {
                        self.next = Next::Header;
                    }
                }
                Next::Blank(left) => {
                    input = &input[pass(input, left, true, out)..];
                    if *left == 0 {
                        self.next = Next::Header;
                    }
                }
                Next::Hold(total) => {
                    let want = (*total - self.held.len() as u64).min(input.len() as u64) as usize;
                    self.held.extend_from_slice(&input[..want]);
                    input = &input[want..];
                    if self.held.len() as u64 == *total {
                        if let Ok(Some((_, _, header))) = element(&self.held) {
                            clean_info(&mut self.held[header..]);
                        }
                        out.append(&mut self.held);
                        self.next = Next::Header;
                    }
                }
                Next::Header => {
                    self.held.push(input[0]);
                    input = &input[1..];
                    let (id, size, header) = match element(&self.held) {
                        Ok(Some(found)) => found,
                        Ok(None) => continue,
                        Err(()) => {
                            out.append(&mut self.held);
                            self.next = Next::CopyRest;
                            continue;
                        }
                    };
                    self.next = match (id, size) {
                        // The segment holds everything else: carry on inside it.
                        (SEGMENT, _) => {
                            out.append(&mut self.held);
                            Next::Header
                        }
                        (INFO, Some(body)) if header as u64 + body <= MAX_HELD => Next::Hold(header as u64 + body),
                        (TAGS | ATTACHMENTS, Some(body)) => {
                            // Any header bytes beyond what a void's own
                            // header needs are already zeroed and counted
                            // into its size.
                            void_header(&mut self.held, body);
                            out.append(&mut self.held);
                            if body == 0 { Next::Header } else { Next::Blank(body) }
                        }
                        (_, Some(body)) => {
                            out.append(&mut self.held);
                            if body == 0 { Next::Header } else { Next::Copy(body) }
                        }
                        // A part of unknown length runs to the end of the file.
                        (_, None) => {
                            out.append(&mut self.held);
                            Next::CopyRest
                        }
                    };
                }
            }
        }
    }
}

/// Cleans the body of the "info" element: the title, the date, file names,
/// and the names of the programs that wrote the file.
fn clean_info(mut body: &mut [u8]) {
    const DATE: u32 = 0x4461;
    const TITLE: u32 = 0x7BA9;
    const MUXING_APP: u32 = 0x4D80;
    const WRITING_APP: u32 = 0x5741;
    const FILE_NAME: u32 = 0x7384;
    const PREVIOUS_FILE_NAME: u32 = 0x003C_83AB;
    const NEXT_FILE_NAME: u32 = 0x003E_83BB;
    while let Ok(Some((id, Some(size), header))) = element(body) {
        let Some(total) = usize::try_from(size).ok().and_then(|size| header.checked_add(size)) else { return };
        if total > body.len() {
            return;
        }
        let (this, rest) = body.split_at_mut(total);
        let (head, content) = this.split_at_mut(header);
        match id {
            // Players expect these two to be present, so they are emptied rather than removed.
            MUXING_APP | WRITING_APP => content.fill(b' '),
            DATE | TITLE | FILE_NAME | PREVIOUS_FILE_NAME | NEXT_FILE_NAME => {
                void_header(head, size);
                content.fill(0);
            }
            _ => {}
        }
        body = rest;
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

    fn header_box(kind: &[u8; 4]) -> Vec<u8> {
        // Version 0, flags, created, modified, then other fields.
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        body.extend_from_slice(&0xFEED_FACEu32.to_be_bytes());
        body.extend_from_slice(&[7; 12]);
        mp4_box(kind, &body)
    }

    fn sample_mp4() -> Vec<u8> {
        let track = [header_box(b"tkhd"), mp4_box(b"mdia", &[header_box(b"mdhd"), mp4_box(b"hdlr", b"vide-handler")].concat())].concat();
        let moov = [
            header_box(b"mvhd"),
            mp4_box(b"udta", &mp4_box(b"\xa9xyz", b"+51.5007-000.1246/ SECRET-LOCATION")),
            mp4_box(b"trak", &track),
            mp4_box(b"meta", b"\0\0\0\0com.apple.quicktime.model SECRET-PHONE"),
        ]
        .concat();
        let pictures: Vec<u8> = (0..5000u32).map(|n| (n * 31 % 251) as u8).collect();
        [
            mp4_box(b"ftyp", b"isom\0\0\x02\0isomiso2"),
            mp4_box(b"uuid", b"<x:xmpmeta>SECRET-EDITOR</x:xmpmeta>"),
            mp4_box(b"moov", &moov),
            mp4_box(b"mdat", &pictures),
            mp4_box(b"udta", b"SECRET-TRAILER"),
        ]
        .concat()
    }

    fn run(mut scrubber: Scrubber, input: &[u8], piece: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in input.chunks(piece) {
            scrubber.push(chunk, &mut out);
        }
        scrubber.finish(&mut out);
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn an_mp4_loses_its_descriptions_and_keeps_everything_else_in_place() {
        let original = sample_mp4();
        let cleaned = run(Scrubber::new("video/mp4"), &original, original.len());
        assert_eq!(cleaned.len(), original.len(), "every byte must keep its position");
        for secret in [b"SECRET".as_slice(), b"51.5007", b"quicktime", b"xmpmeta", &0xDEAD_BEEFu32.to_be_bytes(), &0xFEED_FACEu32.to_be_bytes()] {
            assert!(contains(&original, secret) && !contains(&cleaned, secret));
        }
        // The pictures, the file type and the track structure are untouched.
        let pictures = original.windows(4).position(|w| w == b"mdat").unwrap();
        assert_eq!(cleaned[pictures..pictures + 5004], original[pictures..pictures + 5004]);
        for kept in [b"ftyp".as_slice(), b"moov", b"mvhd", b"trak", b"tkhd", b"mdia", b"mdhd", b"vide-handler", b"isomiso2"] {
            assert!(contains(&cleaned, kept), "lost {:?}", String::from_utf8_lossy(kept));
        }
        assert!(!contains(&cleaned, b"udta") && !contains(&cleaned, b"uuid") && !contains(&cleaned, b"meta"));

        // However the file is cut into pieces on arrival, the result is the same.
        for piece in [1, 2, 3, 7, 16, 100, 4096] {
            assert_eq!(run(Scrubber::new("video/mp4"), &original, piece), cleaned, "pieces of {piece}");
        }
    }

    /// A file built to nest boxes as deep as its size allows is handled
    /// without following it all the way down.
    #[test]
    fn absurdly_deep_nesting_is_not_followed() {
        // 200,000 boxes, each holding only the next: headers from the
        // outside in, then what the innermost one holds.
        let innermost = mp4_box(b"udta", b"SECRET at the bottom");
        let depth = 200_000;
        let mut nested = Vec::with_capacity(depth * 8 + innermost.len());
        for level in 0..depth {
            let size = (depth - level) * 8 + innermost.len();
            nested.extend_from_slice(&(size as u32).to_be_bytes());
            nested.extend_from_slice(b"trak");
        }
        nested.extend_from_slice(&innermost);
        let file = [mp4_box(b"ftyp", b"isom"), mp4_box(b"moov", &nested)].concat();
        let cleaned = run(Scrubber::new("video/mp4"), &file, 65_536);
        assert_eq!(cleaned.len(), file.len());
    }

    #[test]
    fn files_that_are_not_what_they_claim_pass_through_unharmed() {
        let noise: Vec<u8> = (0..3000u32).map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let cut_short = &sample_mp4()[..90];
        for input in [noise.as_slice(), cut_short, b"", b"\0\0\0\x08", &[0xff; 40]] {
            for kind in ["video/mp4", "video/webm"] {
                for piece in [1, 5, 4096] {
                    let out = run(Scrubber::new(kind), input, piece);
                    assert_eq!(out.len(), input.len(), "{kind}: the length changed");
                }
            }
        }
        assert_eq!(run(Scrubber::new("video/mp4"), &noise, 64), run(Scrubber::new("video/mp4"), &noise, 1));
    }

    fn ebml(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = id.to_vec();
        // Sizes are written with 2 bytes here, which real files also do.
        out.extend_from_slice(&(0x4000u16 | body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_webm_loses_its_descriptions_and_keeps_everything_else_in_place() {
        let info = [
            ebml(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]),
            ebml(&[0x4D, 0x80], b"SECRET-MUXER 1.2"),
            ebml(&[0x57, 0x41], b"SECRET-CAMERA-APP"),
            ebml(&[0x44, 0x61], &[1, 2, 3, 4, 5, 6, 7, 8]),
            ebml(&[0x7B, 0xA9], b"SECRET holiday title"),
        ]
        .concat();
        let pictures: Vec<u8> = (0..3000u32).map(|n| (n * 17 % 253) as u8).collect();
        let inside = [
            ebml(&[0x15, 0x49, 0xA9, 0x66], &info),
            ebml(&[0x16, 0x54, 0xAE, 0x6B], b"track entries stay"),
            ebml(&[0x12, 0x54, 0xC3, 0x67], b"tag: LOCATION=SECRET-PLACE"),
            ebml(&[0x1F, 0x43, 0xB6, 0x75], &pictures),
            ebml(&[0x19, 0x41, 0xA4, 0x69], b"attached SECRET-FILE.txt"),
        ]
        .concat();
        // A segment of unknown size, as live recordings have.
        let mut original = ebml(&[0x1A, 0x45, 0xDF, 0xA3], b"\x42\x82\x84webm");
        original.extend_from_slice(&[0x18, 0x53, 0x80, 0x67, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        original.extend_from_slice(&inside);

        let cleaned = run(Scrubber::new("video/webm"), &original, original.len());
        assert_eq!(cleaned.len(), original.len(), "every byte must keep its position");
        assert!(contains(&original, b"SECRET") && !contains(&cleaned, b"SECRET"));
        assert!(!contains(&cleaned, &[1, 2, 3, 4, 5, 6, 7, 8]), "the recording date survived");
        let at = original.windows(4).position(|w| w == [0x1F, 0x43, 0xB6, 0x75]).unwrap();
        assert_eq!(cleaned[at..at + 3006], original[at..at + 3006], "the pictures changed");
        assert!(contains(&cleaned, b"track entries stay") && contains(&cleaned, b"webm"));

        // What is left still reads as a well-formed run of elements.
        let mut rest = &cleaned[original.len() - inside.len()..];
        let mut seen = 0;
        while let Ok(Some((_, Some(size), header))) = element(rest) {
            rest = &rest[header + size as usize..];
            seen += 1;
        }
        assert_eq!((seen, rest.len()), (5, 0));

        for piece in [1, 2, 3, 7, 16, 100, 4096] {
            assert_eq!(run(Scrubber::new("video/webm"), &original, piece), cleaned, "pieces of {piece}");
        }
    }
}
