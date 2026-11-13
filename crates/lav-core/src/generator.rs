//! Password generator backed by the OS CSPRNG.

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";

pub const MIN_LENGTH: usize = 4;
pub const MAX_LENGTH: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    fn sets(&self) -> Vec<Vec<char>> {
        [
            (self.lowercase, LOWER),
            (self.uppercase, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, chars)| {
            chars
                .chars()
                .filter(|c| !(self.exclude_ambiguous && AMBIGUOUS.contains(*c)))
                .collect()
        })
        .collect()
    }

    /// Upper bound on entropy in bits (length * log2(pool size)).
    pub fn entropy_bits(&self) -> f64 {
        let pool: usize = self.sets().iter().map(Vec::len).sum();
        if pool == 0 {
            0.0
        } else {
            self.length as f64 * (pool as f64).log2()
        }
    }
}

/// Generates a password containing at least one character from every enabled set.
pub fn generate(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    let sets = opts.sets();
    if sets.is_empty() {
        return Err(Error::InvalidGeneratorOptions(
            "enable at least one character set",
        ));
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) || opts.length < sets.len() {
        return Err(Error::InvalidGeneratorOptions("length out of range"));
    }
    let pool: Vec<char> = sets.iter().flatten().copied().collect();
    let mut rng = OsRng;

    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(opts.length));
    for set in &sets {
        chars.push(*set.choose(&mut rng).expect("non-empty set"));
    }
    while chars.len() < opts.length {
        chars.push(*pool.choose(&mut rng).expect("non-empty pool"));
    }
    chars.shuffle(&mut rng);
    Ok(Zeroizing::new(chars.iter().collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_sets() {
        let opts = PasswordOptions {
            length: 32,
            ..Default::default()
        };
        for _ in 0..50 {
            let pw = generate(&opts).unwrap();
            assert_eq!(pw.chars().count(), 32);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn excludes_ambiguous() {
        let opts = PasswordOptions {
            length: 200,
            exclude_ambiguous: true,
            ..Default::default()
        };
        let pw = generate(&opts).unwrap();
        assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn rejects_bad_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate(&none).is_err());
        assert!(generate(&PasswordOptions {
            length: 2,
            ..Default::default()
        })
        .is_err());
        assert!(generate(&PasswordOptions {
            length: 10_000,
            ..Default::default()
        })
        .is_err());
    }

    #[test]
    fn entropy_estimate() {
        let opts = PasswordOptions {
            length: 10,
            lowercase: false,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: false,
        };
        assert!((opts.entropy_bits() - 10.0 * 10f64.log2()).abs() < 1e-9);
    }
}
