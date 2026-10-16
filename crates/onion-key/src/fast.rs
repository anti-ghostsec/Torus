//! A faster search for a vanity address.
//!
//! Finding an address's text needs only the public key's `y` coordinate and
//! the sign of `x`, in their plain (affine) form. Turning a point into that
//! form costs a field inversion, about 270 multiplications: nearly all the
//! work. Here each thread walks many keys side by side in affine form,
//! stepping each by the base point, and inverts all their denominators
//! together (Montgomery's trick: one inversion and three multiplications per
//! number). Each key then costs about fifteen multiplications.
//!
//! The arithmetic is formally verified field code (fiat-crypto); the curve
//! formulas are the standard twisted Edwards ones. Whatever this finds is
//! checked again by the ordinary key code before it is used, so a mistake
//! here could only make the search miss, never hand out a wrong key.

use fiat_crypto::curve25519_64::{
    fiat_25519_add, fiat_25519_carry, fiat_25519_carry_mul, fiat_25519_carry_square, fiat_25519_from_bytes,
    fiat_25519_opp, fiat_25519_relax, fiat_25519_sub, fiat_25519_to_bytes, fiat_25519_loose_field_element,
    fiat_25519_tight_field_element,
};

/// A number modulo 2^255 - 19.
#[derive(Clone, Copy)]
pub(crate) struct Fe(fiat_25519_tight_field_element);

fn loose(a: &Fe) -> fiat_25519_loose_field_element {
    let mut out = fiat_25519_loose_field_element([0; 5]);
    fiat_25519_relax(&mut out, &a.0);
    out
}

fn tight(a: &fiat_25519_loose_field_element) -> Fe {
    let mut out = fiat_25519_tight_field_element([0; 5]);
    fiat_25519_carry(&mut out, a);
    Fe(out)
}

impl Fe {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut clear = *bytes;
        clear[31] &= 0x7f;
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_from_bytes(&mut out, &clear);
        Fe(out)
    }

    fn small(n: u32) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        Self::from_bytes(&bytes)
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        fiat_25519_to_bytes(&mut out, &self.0);
        out
    }

    pub(crate) fn mul(&self, other: &Fe) -> Fe {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_mul(&mut out, &loose(self), &loose(other));
        Fe(out)
    }

    fn square(&self) -> Fe {
        let mut out = fiat_25519_tight_field_element([0; 5]);
        fiat_25519_carry_square(&mut out, &loose(self));
        Fe(out)
    }

    pub(crate) fn add(&self, other: &Fe) -> Fe {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_add(&mut out, &self.0, &other.0);
        tight(&out)
    }

    pub(crate) fn sub(&self, other: &Fe) -> Fe {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_sub(&mut out, &self.0, &other.0);
        tight(&out)
    }

    fn neg(&self) -> Fe {
        let mut out = fiat_25519_loose_field_element([0; 5]);
        fiat_25519_opp(&mut out, &self.0);
        tight(&out)
    }

    /// `self` raised to a power given in little-endian bytes.
    fn pow(&self, exponent: &[u8; 32]) -> Fe {
        let mut result = Fe::small(1);
        for byte in exponent.iter().rev() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    fn equals(&self, other: &Fe) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    pub(crate) fn invert(&self) -> Fe {
        // p - 2 = 2^255 - 21
        let mut exponent = [0xffu8; 32];
        exponent[0] = 0xeb;
        exponent[31] = 0x7f;
        self.pow(&exponent)
    }
}

/// The curve's constant d = -121665 / 121666.
pub(crate) fn curve_d() -> Fe {
    Fe::small(121_665).neg().mul(&Fe::small(121_666).invert())
}

/// The point a compressed Edwards key stands for, as affine (x, y).
/// `None` if the bytes are not a point.
pub(crate) fn decompress(bytes: &[u8; 32], d: &Fe) -> Option<(Fe, Fe)> {
    let y = Fe::from_bytes(bytes);
    let one = Fe::small(1);
    let yy = y.square();
    let u = yy.sub(&one);
    let v = d.mul(&yy).add(&one);
    // x = sqrt(u / v), tried as (u/v)^((p+3)/8) = (u/v)^(2^252 - 2).
    let ratio = u.mul(&v.invert());
    let mut exponent = [0xffu8; 32];
    exponent[0] = 0xfe;
    exponent[31] = 0x0f;
    let mut x = ratio.pow(&exponent);
    if !v.mul(&x.square()).equals(&u) {
        // sqrt(-1) = 2^((p-1)/4) = 2^(2^253 - 5)
        let mut exponent = [0xffu8; 32];
        exponent[0] = 0xfb;
        exponent[31] = 0x1f;
        x = x.mul(&Fe::small(2).pow(&exponent));
        if !v.mul(&x.square()).equals(&u) {
            return None;
        }
    }
    if x.is_negative() != (bytes[31] >> 7 == 1) {
        x = x.neg();
    }
    Some((x, y))
}

/// The compressed form of an affine point: `y`, with the sign of `x` in the top bit.
pub(crate) fn compress(x: &Fe, y: &Fe) -> [u8; 32] {
    let mut out = y.to_bytes();
    out[31] |= (x.to_bytes()[0] & 1) << 7;
    out
}

/// Keys walked side by side, each stepped by the base point together.
pub(crate) struct Walk {
    pub xs: Vec<Fe>,
    pub ys: Vec<Fe>,
    /// The base point (x2, y2), and d * x2 * y2.
    base: (Fe, Fe),
    k: Fe,
    one: Fe,
    // Scratch space, kept between steps.
    denominators: Vec<Fe>,
    prefix: Vec<Fe>,
}

impl Walk {
    pub(crate) fn new(starts: Vec<(Fe, Fe)>, base: (Fe, Fe), d: &Fe) -> Self {
        let k = d.mul(&base.0).mul(&base.1);
        let (xs, ys) = starts.into_iter().unzip();
        Self { xs, ys, base, k, one: Fe::small(1), denominators: Vec::new(), prefix: Vec::new() }
    }

    /// Adds the base point to every key:
    /// x3 = (x1 y2 + y1 x2) / (1 + t), y3 = (y1 y2 + x1 x2) / (1 - t), t = d x1 x2 y1 y2.
    pub(crate) fn step(&mut self) {
        let count = self.xs.len();
        let (x2, y2) = self.base;
        self.denominators.clear();
        let mut tops = Vec::with_capacity(count * 2);
        for at in 0..count {
            let (x1, y1) = (self.xs[at], self.ys[at]);
            let t = self.k.mul(&x1).mul(&y1);
            tops.push(x1.mul(&y2).add(&y1.mul(&x2)));
            tops.push(y1.mul(&y2).add(&x1.mul(&x2)));
            self.denominators.push(self.one.add(&t));
            self.denominators.push(self.one.sub(&t));
        }
        // Montgomery's trick: every inverse from one inversion.
        self.prefix.clear();
        let mut running = self.one;
        for value in &self.denominators {
            self.prefix.push(running);
            running = running.mul(value);
        }
        let mut inverse = running.invert();
        for at in (0..self.denominators.len()).rev() {
            let this = inverse.mul(&self.prefix[at]);
            inverse = inverse.mul(&self.denominators[at]);
            self.denominators[at] = this;
        }
        for at in 0..count {
            self.xs[at] = tops[2 * at].mul(&self.denominators[2 * at]);
            self.ys[at] = tops[2 * at + 1].mul(&self.denominators[2 * at + 1]);
        }
    }
}
