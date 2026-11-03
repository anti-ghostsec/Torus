//! Picture puzzles for forms, made without any script: the site draws a few
//! letters, bent and speckled, and the visitor types them back.
//!
//! This stops scripts written to flood any form they find. It does not stop
//! someone who sets out to read these pictures by machine, and nothing that
//! works without scripts can. Each puzzle is answered once, and only within
//! a few minutes of being made. Puzzles live in memory only: nothing about
//! them, or about who was shown which, is ever written down.
//!
//! Every page with a puzzle form makes a puzzle, so making one must cost
//! nothing that a visitor reloading a page in a loop could use up. A
//! puzzle's id therefore carries when it was made and a seal only this site
//! can make, and its answer is worked out again from the id whenever it is
//! needed. Nothing is kept for a puzzle until someone answers it, and then
//! only that it has been answered.

use std::collections::{HashSet, VecDeque};
use std::io::Cursor;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// Letters that cannot be mistaken for one another, even bent.
const LETTERS: &[u8] = b"ACDEFHJKLMNPRTUVWXY34679";
const LENGTH: usize = 6;
/// How long a puzzle can be answered after it is made.
const LIFETIME: Duration = Duration::from_secs(15 * 60);
/// The most puzzles remembered as answered at once. Each must be kept until
/// it could no longer be answered anyway, so that it cannot be answered
/// twice. When this many were answered within one lifetime, further answers
/// are refused until the oldest are forgotten: refusing is safe, forgetting
/// early would let one solved puzzle be used again and again.
const MAX_ANSWERED: usize = 100_000;
const WIDTH: u32 = 240;
const HEIGHT: u32 = 80;
/// An id: when it was made (seconds, 4 bytes, encrypted), 8 random bytes,
/// then the seal. The time is encrypted because, seen in plain, it would
/// tell anyone how long the site has been running, to the second: enough
/// to match its restarts against outages elsewhere.
const STAMPED: usize = 12;
const SEAL: usize = 12;

pub(crate) struct Puzzles {
    /// Puzzles that have been answered, rightly or not, oldest first, with
    /// when they were answered.
    answered: HashSet<[u8; STAMPED]>,
    order: VecDeque<([u8; STAMPED], Instant)>,
    /// When ids count their time from.
    born: Instant,
    /// Seals ids, and makes each picture's speckles and each answer
    /// unpredictable to anyone but this site.
    secret: [u8; 32],
}

impl Puzzles {
    pub(crate) fn new() -> Self {
        let mut secret = [0u8; 32];
        let _ = getrandom::getrandom(&mut secret);
        Self { answered: HashSet::new(), order: VecDeque::new(), born: Instant::now(), secret }
    }

    /// Makes a new puzzle and returns its id. Nothing is stored.
    pub(crate) fn make(&self) -> Option<String> {
        let mut stamped = [0u8; STAMPED];
        let made = u32::try_from(self.born.elapsed().as_secs()).ok()?;
        getrandom::getrandom(&mut stamped[4..]).ok()?;
        let mask = self.derive(b"time", &stamped[4..]);
        for (at, byte) in made.to_be_bytes().iter().enumerate() {
            stamped[at] = byte ^ mask[at];
        }
        let seal = self.derive(b"seal", &stamped);
        Some(stamped.iter().chain(&seal[..SEAL]).map(|b| format!("{b:02x}")).collect())
    }

    /// Whether `typed` answers the puzzle `id`. Either way, that puzzle is
    /// used up: a wrong guess cannot be followed by another.
    pub(crate) fn solve(&mut self, id: &str, typed: &str) -> bool {
        let Some(stamped) = self.open(id) else { return false };
        let now = Instant::now();
        while self.order.front().is_some_and(|(_, at)| now.duration_since(*at) > LIFETIME) {
            let (old, _) = self.order.pop_front().expect("just looked");
            self.answered.remove(&old);
        }
        if self.answered.len() >= MAX_ANSWERED {
            return false;
        }
        self.answered.insert(stamped);
        self.order.push_back((stamped, now));
        let typed: String = typed.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
        typed == self.answer_to(&stamped)
    }

    /// The picture for puzzle `id`, while it can still be answered. Always
    /// the same picture for the same puzzle, so reloading it shows nothing new.
    pub(crate) fn picture(&self, id: &str) -> Option<Vec<u8>> {
        let stamped = self.open(id)?;
        let seed = self.derive(b"picture", &stamped);
        Some(draw(&self.answer_to(&stamped), Random::new(&seed)))
    }

    pub(crate) fn peek(&self, id: &str) -> Option<String> {
        self.open(id).map(|stamped| self.answer_to(&stamped))
    }

    #[cfg(test)]
    pub(crate) fn answer(&self, id: &str) -> Option<String> {
        self.peek(id)
    }

    /// The made-and-random part of `id`, if this site made it, it has not
    /// expired and it has not been answered.
    fn open(&self, id: &str) -> Option<[u8; STAMPED]> {
        if id.len() != 2 * (STAMPED + SEAL) {
            return None;
        }
        let bytes: Vec<u8> = (0..id.len())
            .step_by(2)
            .map(|at| id.get(at..at + 2).and_then(|hex| u8::from_str_radix(hex, 16).ok()))
            .collect::<Option<_>>()?;
        let stamped: [u8; STAMPED] = bytes[..STAMPED].try_into().ok()?;
        let seal = self.derive(b"seal", &stamped);
        // Compared without stopping at the first difference.
        if seal[..SEAL].iter().zip(&bytes[STAMPED..]).fold(0, |acc, (a, b)| acc | (a ^ b)) != 0 {
            return None;
        }
        let mask = self.derive(b"time", &stamped[4..]);
        let made: [u8; 4] = std::array::from_fn(|at| stamped[at] ^ mask[at]);
        let made = Duration::from_secs(u64::from(u32::from_be_bytes(made)));
        let age = self.born.elapsed().checked_sub(made)?;
        (age <= LIFETIME && !self.answered.contains(&stamped)).then_some(stamped)
    }

    fn answer_to(&self, stamped: &[u8; STAMPED]) -> String {
        let random = self.derive(b"answer", stamped);
        random[..LENGTH].iter().map(|b| LETTERS[*b as usize % LETTERS.len()] as char).collect()
    }

    /// A value only this site can work out from an id, different for each use.
    fn derive(&self, purpose: &[u8], stamped: &[u8]) -> [u8; 32] {
        Sha256::new().chain_update(self.secret).chain_update(purpose).chain_update(stamped).finalize().into()
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
    fn making_puzzles_keeps_nothing_and_pushes_none_out() {
        let mut puzzles = Puzzles::new();
        let first = puzzles.make().unwrap();
        for _ in 0..50_000 {
            puzzles.make().unwrap();
        }
        assert!(puzzles.answered.is_empty());
        let answer = puzzles.answer(&first).expect("a flood of new puzzles pushed out an earlier one");
        assert!(puzzles.solve(&first, &answer));
    }

    #[test]
    fn only_ids_this_site_made_are_puzzles() {
        let puzzles = Puzzles::new();
        let id = puzzles.make().unwrap();
        // The same id with its seal changed, and an id from another site.
        let mut forged = id.clone().into_bytes();
        forged[40] = if forged[40] == b'0' { b'1' } else { b'0' };
        let forged = String::from_utf8(forged).unwrap();
        let other = Puzzles::new().make().unwrap();
        for id in [forged.as_str(), &other, "", "zz", &id[..46]] {
            assert!(puzzles.picture(id).is_none() && puzzles.answer(id).is_none(), "{id}");
        }
    }

    #[test]
    fn remembered_answers_are_bounded_and_full_means_refused() {
        let mut puzzles = Puzzles::new();
        for _ in 0..MAX_ANSWERED {
            let id = puzzles.make().unwrap();
            puzzles.solve(&id, "");
        }
        assert_eq!(puzzles.answered.len(), MAX_ANSWERED);
        // Nothing answered is forgotten early, so a new answer, even a
        // right one, is refused until the oldest expire.
        let id = puzzles.make().unwrap();
        let answer = puzzles.answer(&id).unwrap();
        assert!(!puzzles.solve(&id, &answer));
        assert_eq!(puzzles.answered.len(), MAX_ANSWERED);
    }
}
