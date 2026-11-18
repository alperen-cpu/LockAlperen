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

/// Pattern placeholders (KeePass "Generate using a pattern"):
/// `d` digit, `l` lowercase, `u` uppercase, `L` any letter, `a` lowercase or
/// digit, `U` uppercase or digit, `A` letter or digit, `s` symbol, `h` / `H`
/// hex digit (lower / upper case), `\x` the character `x` itself, `{n}`
/// repeats the previous item n times (1..=256). Any other character is used
/// as it is.
pub const PATTERN_HELP: &str = "d l u L a U A s h H \\x {n}";

fn pattern_set(c: char) -> Option<Vec<char>> {
    let join = |parts: &[&str]| parts.concat().chars().collect::<Vec<char>>();
    Some(match c {
        'd' => join(&[DIGITS]),
        'l' => join(&[LOWER]),
        'u' => join(&[UPPER]),
        'L' => join(&[LOWER, UPPER]),
        'a' => join(&[LOWER, DIGITS]),
        'U' => join(&[UPPER, DIGITS]),
        'A' => join(&[LOWER, UPPER, DIGITS]),
        's' => join(&[SYMBOLS]),
        'h' => "0123456789abcdef".chars().collect(),
        'H' => "0123456789ABCDEF".chars().collect(),
        _ => return None,
    })
}

/// One item of a parsed pattern: a set to draw from, or a fixed character.
enum Item {
    Set(Vec<char>),
    Literal(char),
}

fn parse_pattern(pattern: &str) -> Result<Vec<Item>> {
    let bad = |why| Err(Error::InvalidGeneratorOptions(why));
    let mut items: Vec<Item> = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(x) => items.push(Item::Literal(x)),
                None => return bad("pattern ends with \\"),
            },
            '{' => {
                let mut digits = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(d) if d.is_ascii_digit() && digits.len() < 4 => digits.push(d),
                        _ => return bad("bad {n} in pattern"),
                    }
                }
                let n: usize = digits
                    .parse()
                    .map_err(|_| Error::InvalidGeneratorOptions("bad {n}"))?;
                let Some(last) = items.pop() else {
                    return bad("{n} with nothing before it");
                };
                if n == 0 || n > MAX_LENGTH {
                    return bad("{n} out of range");
                }
                for _ in 1..n {
                    items.push(match &last {
                        Item::Set(s) => Item::Set(s.clone()),
                        Item::Literal(x) => Item::Literal(*x),
                    });
                }
                items.push(last);
            }
            _ => items.push(match pattern_set(c) {
                Some(set) => Item::Set(set),
                None => Item::Literal(c),
            }),
        }
        if items.len() > MAX_LENGTH {
            return bad("pattern too long");
        }
    }
    if items.is_empty() {
        return bad("empty pattern");
    }
    Ok(items)
}

/// Generates a password from a pattern (see [`PATTERN_HELP`]). At most
/// [`MAX_LENGTH`] characters.
pub fn generate_pattern(pattern: &str) -> Result<Zeroizing<String>> {
    let items = parse_pattern(pattern)?;
    let mut rng = OsRng;
    let mut out = Zeroizing::new(String::with_capacity(items.len() * 4));
    for item in &items {
        out.push(match item {
            Item::Set(s) => *s.choose(&mut rng).expect("sets are never empty"),
            Item::Literal(c) => *c,
        });
    }
    Ok(out)
}

/// Upper bound on the entropy of a pattern, in bits (0 if it is invalid).
pub fn pattern_entropy_bits(pattern: &str) -> f64 {
    parse_pattern(pattern)
        .map(|items| {
            items
                .iter()
                .map(|i| match i {
                    Item::Set(s) => (s.len() as f64).log2(),
                    Item::Literal(_) => 0.0,
                })
                .sum()
        })
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_follows_the_placeholders() {
        for _ in 0..50 {
            let pw = generate_pattern(r"uu-d{4}\l").unwrap();
            let c: Vec<char> = pw.chars().collect();
            assert_eq!(c.len(), 8);
            assert!(c[0].is_ascii_uppercase() && c[1].is_ascii_uppercase());
            assert_eq!(c[2], '-');
            assert!(c[3..7].iter().all(|d| d.is_ascii_digit()));
            assert_eq!(c[7], 'l', "escaped placeholder is literal");
        }
        assert_eq!(generate_pattern("h{32}").unwrap().len(), 32);
        assert!((pattern_entropy_bits("d{3}") - 3.0 * 10f64.log2()).abs() < 1e-9);
        assert_eq!(pattern_entropy_bits("abc{"), 0.0);
    }

    #[test]
    fn bad_patterns_are_refused() {
        for p in ["", "{3}", "d{0}", "d{999}", "d{x}", "d{3", "x\\", "d{256}d"] {
            assert!(generate_pattern(p).is_err(), "{p:?}");
        }
        assert!(generate_pattern("d{256}").is_ok());
    }

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
