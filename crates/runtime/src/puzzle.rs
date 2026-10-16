//! Picture puzzles for forms, made without any script: the site draws a few
//! letters, bent and speckled, and the visitor types them back.
//!
//! This stops scripts written to flood any form they find. It does not stop
//! someone who sets out to read these pictures by machine, and nothing that
//! works without scripts can. Each puzzle is answered once, and only within
//! a few minutes of being made. Puzzles live in memory only: nothing about
//! them, or about who was shown which, is ever written down.

use std::collections::{HashMap, VecDeque};
use std::io::Cursor;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Letters that cannot be mistaken for one another, even bent.
const LETTERS: &[u8] = b"ACDEFHJKLMNPRTUVWXY34679";
const LENGTH: usize = 6;
/// How long a puzzle can be answered after it is made.
const LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Enough for a busy site. When full, the oldest puzzle goes first.
const MAX_OPEN: usize = 20_000;
const WIDTH: u32 = 240;
const HEIGHT: u32 = 80;

pub(crate) struct Puzzles {
    open: HashMap<String, (String, Instant)>,
    order: VecDeque<String>,
    /// Makes each picture's speckles unpredictable to anyone but this site.
    secret: [u8; 32],
}

impl Puzzles {
    pub(crate) fn new() -> Self {
        let mut secret = [0u8; 32];
        let _ = getrandom::getrandom(&mut secret);
        Self { open: HashMap::new(), order: VecDeque::new(), secret }
    }

    /// Makes a new puzzle and returns its id.
    pub(crate) fn make(&mut self) -> Option<String> {
        let now = Instant::now();
        while let Some(oldest) = self.order.front() {
            let stale = self.open.get(oldest).is_none_or(|(_, made)| now.duration_since(*made) > LIFETIME);
            if !stale && self.open.len() < MAX_OPEN {
                break;
            }
            let oldest = self.order.pop_front().expect("just looked");
            self.open.remove(&oldest);
        }
        let id = crate::blobs::random_id().ok()?;
        let mut random = [0u8; LENGTH];
        getrandom::getrandom(&mut random).ok()?;
        let answer: String = random.iter().map(|b| LETTERS[*b as usize % LETTERS.len()] as char).collect();
        self.open.insert(id.clone(), (answer, now));
        self.order.push_back(id.clone());
        Some(id)
    }

    /// Whether `typed` answers the puzzle `id`. Either way, that puzzle is
    /// used up: a wrong guess cannot be followed by another.
    pub(crate) fn solve(&mut self, id: &str, typed: &str) -> bool {
        let Some((answer, made)) = self.open.remove(id) else { return false };
        let typed: String = typed.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
        made.elapsed() <= LIFETIME && typed == answer
    }

    /// The picture for puzzle `id`, while it can still be answered. Always
    /// the same picture for the same puzzle, so reloading it shows nothing new.
    pub(crate) fn picture(&self, id: &str) -> Option<Vec<u8>> {
        let (answer, made) = self.open.get(id)?;
        if made.elapsed() > LIFETIME {
            return None;
        }
        let seed: [u8; 32] = Sha256::new().chain_update(self.secret).chain_update(id.as_bytes()).finalize().into();
        Some(draw(answer, Random::new(&seed)))
    }

    pub(crate) fn peek(&self, id: &str) -> Option<String> {
        self.open.get(id).map(|(answer, _)| answer.clone())
    }

    #[cfg(test)]
    pub(crate) fn answer(&self, id: &str) -> Option<String> {
        self.peek(id)
    }
}

/// A small generator for the drawing: unpredictable from outside because
/// it is seeded with the site's secret.
struct Random(u64);

impl Random {
    fn new(seed: &[u8; 32]) -> Self {
        Self(u64::from_le_bytes(seed[..8].try_into().expect("8 bytes")) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A whole number from `low` to `high`, both included.
    fn between(&mut self, low: i32, high: i32) -> i32 {
        low + (self.next() % (high - low + 1) as u64) as i32
    }
}

/// Five by seven dots for each letter that can appear.
fn glyph(letter: u8) -> [&'static str; 7] {
    match letter {
        b'A' => [" ### ", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
        b'C' => [" ####", "#    ", "#    ", "#    ", "#    ", "#    ", " ####"],
        b'D' => ["#### ", "#   #", "#   #", "#   #", "#   #", "#   #", "#### "],
        b'E' => ["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#####"],
        b'F' => ["#####", "#    ", "#    ", "#### ", "#    ", "#    ", "#    "],
        b'H' => ["#   #", "#   #", "#   #", "#####", "#   #", "#   #", "#   #"],
        b'J' => ["  ###", "   # ", "   # ", "   # ", "   # ", "#  # ", " ##  "],
        b'K' => ["#   #", "#  # ", "# #  ", "##   ", "# #  ", "#  # ", "#   #"],
        b'L' => ["#    ", "#    ", "#    ", "#    ", "#    ", "#    ", "#####"],
        b'M' => ["#   #", "## ##", "# # #", "# # #", "#   #", "#   #", "#   #"],
        b'N' => ["#   #", "##  #", "# # #", "#  ##", "#   #", "#   #", "#   #"],
        b'P' => ["#### ", "#   #", "#   #", "#### ", "#    ", "#    ", "#    "],
        b'R' => ["#### ", "#   #", "#   #", "#### ", "# #  ", "#  # ", "#   #"],
        b'T' => ["#####", "  #  ", "  #  ", "  #  ", "  #  ", "  #  ", "  #  "],
        b'U' => ["#   #", "#   #", "#   #", "#   #", "#   #", "#   #", " ### "],
        b'V' => ["#   #", "#   #", "#   #", "#   #", "#   #", " # # ", "  #  "],
        b'W' => ["#   #", "#   #", "#   #", "# # #", "# # #", "## ##", "#   #"],
        b'X' => ["#   #", "#   #", " # # ", "  #  ", " # # ", "#   #", "#   #"],
        b'Y' => ["#   #", "#   #", " # # ", "  #  ", "  #  ", "  #  ", "  #  "],
        b'3' => ["#### ", "    #", "    #", " ### ", "    #", "    #", "#### "],
        b'4' => ["#   #", "#   #", "#   #", "#####", "    #", "    #", "    #"],
        b'6' => [" ### ", "#    ", "#    ", "#### ", "#   #", "#   #", " ### "],
        b'7' => ["#####", "    #", "   # ", "  #  ", " #   ", " #   ", " #   "],
        b'9' => [" ### ", "#   #", "#   #", " ####", "    #", "    #", " ### "],
        _ => ["     "; 7],
    }
}

fn draw(answer: &str, mut random: Random) -> Vec<u8> {
    let (w, h) = (WIDTH as i32, HEIGHT as i32);
    let mut pixels = vec![0u8; (w * h) as usize];
    let put = |x: i32, y: i32, shade: u8, pixels: &mut Vec<u8>| {
        if (0..w).contains(&x) && (0..h).contains(&y) {
            pixels[(y * w + x) as usize] = shade;
        }
    };
    // A mottled background, never quite white.
    for y in 0..h {
        for x in 0..w {
            let shade = 225 + (random.next() % 31) as u8;
            put(x, y, shade, &mut pixels);
        }
    }
    let cell = 5;
    for (at, letter) in answer.bytes().enumerate() {
        let left = 14 + at as i32 * 36 + random.between(-4, 4);
        let top = random.between(4, 20);
        // Each letter leans its own way, by a different amount.
        let lean = random.between(-6, 6);
        let shade = random.between(10, 90) as u8;
        for (row, line) in glyph(letter).iter().enumerate() {
            for (col, dot) in line.bytes().enumerate() {
                if dot != b'#' {
                    continue;
                }
                let x0 = left + col as i32 * cell + lean * (3 - row as i32) / 3;
                let y0 = top + row as i32 * (cell + 2);
                for dy in 0..cell + 2 {
                    for dx in 0..cell {
                        put(x0 + dx + random.between(0, 1), y0 + dy, shade, &mut pixels);
                    }
                }
            }
        }
    }
    // Lines across the letters, and speckles everywhere.
    for _ in 0..6 {
        let (mut x, mut y) = (random.between(0, w - 1), random.between(0, h - 1));
        let (tx, ty) = (random.between(0, w - 1), random.between(0, h - 1));
        let shade = random.between(40, 140) as u8;
        let steps = (tx - x).abs().max((ty - y).abs()).max(1);
        let (sx, sy) = (x, y);
        for step in 0..=steps {
            x = sx + (tx - sx) * step / steps;
            y = sy + (ty - sy) * step / steps;
            put(x, y, shade, &mut pixels);
            put(x, y + 1, shade, &mut pixels);
        }
    }
    for _ in 0..900 {
        let (x, y) = (random.between(0, w - 1), random.between(0, h - 1));
        let shade = if random.next().is_multiple_of(2) { random.between(0, 120) } else { 255 } as u8;
        put(x, y, shade, &mut pixels);
    }
    let picture = image::GrayImage::from_raw(WIDTH, HEIGHT, pixels).expect("the size matches");
    let mut out = Cursor::new(Vec::new());
    picture.write_to(&mut out, image::ImageFormat::Png).expect("writing to memory");
    out.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_puzzle_is_answered_once_and_its_picture_is_steady() {
        let mut puzzles = Puzzles::new();
        let id = puzzles.make().unwrap();
        let answer = puzzles.answer(&id).unwrap();
        assert_eq!(answer.len(), LENGTH);
        let picture = puzzles.picture(&id).unwrap();
        assert!(picture.starts_with(b"\x89PNG"));
        assert_eq!(puzzles.picture(&id).unwrap(), picture, "the same puzzle shows the same picture");
        assert!(!picture.windows(LENGTH).any(|w| w == answer.as_bytes()), "the answer is not in the file");

        // Lowercase and spaces are forgiven; a second answer is not.
        let typed = format!(" {} ", answer.to_lowercase());
        assert!(puzzles.solve(&id, &typed));
        assert!(!puzzles.solve(&id, &answer), "a puzzle was answered twice");
        assert!(puzzles.picture(&id).is_none());

        // A wrong guess uses the puzzle up.
        let id = puzzles.make().unwrap();
        assert!(!puzzles.solve(&id, "WRONG!"));
        let answer = puzzles.answer(&id);
        assert!(answer.is_none());
        assert!(!puzzles.solve("nothing", ""));
    }

    #[test]
    fn open_puzzles_are_bounded() {
        let mut puzzles = Puzzles::new();
        let first = puzzles.make().unwrap();
        for _ in 0..MAX_OPEN + 10 {
            puzzles.make().unwrap();
        }
        assert!(puzzles.open.len() <= MAX_OPEN);
        assert!(puzzles.answer(&first).is_none(), "the oldest went first");
    }
}
