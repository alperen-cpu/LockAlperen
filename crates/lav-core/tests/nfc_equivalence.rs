//! M6 (PR-1): the allocation-free password normalization must produce exactly
//! what `unicode-normalization`'s `nfc()` produces, for every input. A single
//! difference would derive a different key for some password.

use lav_core::testing::nfc_password;
use unicode_normalization::UnicodeNormalization;

fn reference(s: &str) -> String {
    s.nfc().collect()
}

fn check(s: &str) {
    assert_eq!(
        nfc_password(s).as_str(),
        reference(s),
        "mismatch for {:?}",
        s.chars()
            .map(|c| format!("U+{:04X}", c as u32))
            .collect::<Vec<_>>()
    );
}

#[test]
fn every_scalar_value_alone() {
    for cp in 0..=0x10FFFFu32 {
        if let Some(c) = char::from_u32(cp) {
            let mut buf = [0u8; 4];
            check(c.encode_utf8(&mut buf));
        }
    }
}

#[test]
fn known_hard_cases() {
    for s in [
        "",
        "parola",
        "pa\u{015F}",  // precomposed s-cedilla
        "pas\u{0327}", // decomposed
        "\u{0130}stanbul \u{0131}\u{011F}\u{00FC}\u{015F}\u{00F6}\u{00E7}",
        "I\u{0307}stanbul",
        "\u{212B}",                 // singleton: ANGSTROM -> A-ring
        "A\u{030A}",                // composes
        "\u{0958}",                 // composition exclusion (stays decomposed)
        "\u{0915}\u{093C}",         // must NOT compose (exclusion)
        "\u{0344}",                 // non-starter decomposition
        "\u{1100}\u{1161}",         // Hangul L+V
        "\u{1100}\u{1161}\u{11A8}", // L+V+T
        "\u{AC00}\u{11A8}",         // LV + T
        "\u{AC01}\u{11A8}",         // LVT + T (no composition)
        "a\u{0323}\u{0302}",        // dot below + circumflex
        "a\u{0302}\u{0323}",        // reordered
        "e\u{0302}\u{0301}\u{0323}",
        "\u{1F00}\u{0345}\u{0300}", // Greek with ypogegrammeni
        "\u{03B1}\u{0313}\u{0300}\u{0345}",
        "a\u{0308}\u{0301}\u{0308}\u{0301}", // blocked composition
        "\u{0301}\u{0300}leading marks",
        "a\u{05B0}\u{05B1}\u{0591}", // Hebrew, mixed ccc
        "Q\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}\u{0306}",
        "\u{0F71}\u{0F72}\u{0F74}\u{0F73}", // Tibetan
        "\u{1E9B}\u{0323}",
        "e\u{0301}\u{034F}\u{0301}", // CGJ blocks
        "\u{1D15E}\u{1D165}",        // musical symbols (exclusion)
        "\u{2ADC}",                  // forking (exclusion)
        "\u{1F468}\u{200D}\u{1F469}",
    ] {
        check(s);
    }
}

#[test]
fn random_strings() {
    let pool: Vec<char> = [
        0x41u32, 0x61, 0x45, 0x65, 0x4F, 0x6F, 0x55, 0x75, 0x49, 0x69, 0x53, 0x73, 0x43, 0x63,
        0x47, 0x67, 0x51, 0x20, 0x31, 0x130, 0x131, 0x15F, 0x11F, 0xFC, 0xF6, 0xE7, 0xC5, 0x212B,
        0x300, 0x301, 0x302, 0x303, 0x304, 0x306, 0x307, 0x308, 0x30A, 0x30C, 0x313, 0x314, 0x323,
        0x327, 0x328, 0x331, 0x345, 0x344, 0x34F, 0x1100, 0x1161, 0x11A8, 0x11C2, 0xAC00, 0xAC01,
        0xD7A3, 0x3B1, 0x3B5, 0x3C9, 0x1F00, 0x1F80, 0x915, 0x93C, 0x958, 0x5D0, 0x5B0, 0x5B4,
        0x591, 0xF71, 0xF72, 0xF73, 0xF80, 0x1E9B, 0x1EC7, 0x4E00, 0x1F600, 0x200D, 0x1D15E,
        0x1D165, 0x2ADC, 0x0338, 0x3D, 0x2260,
    ]
    .iter()
    .map(|c| char::from_u32(*c).unwrap())
    .collect();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..60_000 {
        let len = (next() % 24) as usize;
        let s: String = (0..len)
            .map(|_| pool[(next() % pool.len() as u64) as usize])
            .collect();
        check(&s);
    }
}
