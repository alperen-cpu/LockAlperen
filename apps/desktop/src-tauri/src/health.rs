//! "Parola sağlığı": weak, reused and expired passwords.
//!
//! Computed in Rust; the WebView receives counts and per-entry issue labels,
//! never a password. "Weak" is a simple estimate (length and character
//! classes), NOT a dictionary or pattern check: "Password123!" passes it.
//! The UI says so.

use std::collections::HashMap;

use lav_core::Entry;
use serde::Serialize;

/// Below this many bits (length × log2(pool of the classes used)) a
/// password counts as weak. 60 bits ~ 10 random mixed-case+digit chars.
pub const WEAK_BITS: f64 = 60.0;
/// Shorter than this is always weak, whatever the classes.
pub const MIN_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Issue {
    Weak,
    Reused,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryIssues {
    pub id: String,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Entries with a password (the ones that are checked).
    pub checked: usize,
    pub weak: usize,
    pub reused: usize,
    pub expired: usize,
    /// Share of checked entries with no issue, 0-100.
    pub ok_percent: u8,
    /// Only entries that have at least one issue.
    pub entries: Vec<EntryIssues>,
}

/// Estimated bits for a password judged by its length and classes only.
pub fn estimate_bits(pw: &str) -> f64 {
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
    let mut len = 0usize;
    for c in pw.chars() {
        len += 1;
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            _ => other = true,
        }
    }
    let pool = [(lower, 26), (upper, 26), (digit, 10), (other, 33)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| n)
        .sum::<u32>();
    if pool == 0 {
        return 0.0;
    }
    len as f64 * f64::from(pool).log2()
}

pub fn is_weak(pw: &str) -> bool {
    pw.chars().count() < MIN_LEN || estimate_bits(pw) < WEAK_BITS
}

#[cfg(test)]
pub fn check(entries: &[Entry], now: i64) -> Report {
    check_refs(&entries.iter().collect::<Vec<_>>(), now)
}

/// Same as [`check`], over a chosen subset (e.g. without the recycle bin).
pub fn check_refs(entries: &[&Entry], now: i64) -> Report {
    // Counts by password, borrowing the strings (no copies of secrets).
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for e in entries {
        let pw = e.password.expose();
        if !pw.is_empty() {
            *seen.entry(pw).or_default() += 1;
        }
    }
    let mut report = Report {
        checked: 0,
        weak: 0,
        reused: 0,
        expired: 0,
        ok_percent: 100,
        entries: Vec::new(),
    };
    for e in entries {
        let pw = e.password.expose();
        if pw.is_empty() {
            continue;
        }
        report.checked += 1;
        let mut issues = Vec::new();
        if is_weak(pw) {
            issues.push(Issue::Weak);
            report.weak += 1;
        }
        if seen.get(pw).copied().unwrap_or(0) > 1 {
            issues.push(Issue::Reused);
            report.reused += 1;
        }
        if e.expires.is_some_and(|t| t <= now) {
            issues.push(Issue::Expired);
            report.expired += 1;
        }
        if !issues.is_empty() {
            report.entries.push(EntryIssues {
                id: e.id.to_string(),
                issues,
            });
        }
    }
    if report.checked > 0 {
        let ok = report.checked - report.entries.len();
        report.ok_percent = ((ok * 100) / report.checked) as u8;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(pw: &str, expires: Option<i64>) -> Entry {
        let mut e = Entry::new(lav_core::VaultData::new("t").root, "x");
        e.password = pw.into();
        e.expires = expires;
        e
    }

    #[test]
    fn weak_estimate() {
        assert!(is_weak("kisa"));
        assert!(is_weak("aaaaaaaaaaaa"), "12 lowercase = 56 bits");
        assert!(!is_weak("aaaaaaaaaaaaaa"), "14 lowercase = 65 bits");
        assert!(!is_weak("t7#Qv!mR2^zLp9@xW4nK"));
        // Documented limit: patterns are not detected.
        assert!(!is_weak("Password123!"));
    }

    #[test]
    fn report_counts_and_never_contains_passwords() {
        let es = vec![
            entry("ortak-parola-uzun-123", None),
            entry("ortak-parola-uzun-123", None),
            entry("kisa", None),
            entry("t7#Qv!mR2^zLp9@xW4nK", Some(100)),
            entry("t7#Qv!mR2^zLp9@xW4nX", Some(10_000)),
            entry("", None),
        ];
        let r = check(&es, 1_000);
        assert_eq!(r.checked, 5, "empty password not checked");
        assert_eq!((r.weak, r.reused, r.expired), (1, 2, 1));
        assert_eq!(r.entries.len(), 4);
        assert_eq!(r.ok_percent, 20);
        let json = serde_json::to_string(&r).unwrap();
        for e in &es {
            let pw = e.password.expose();
            assert!(pw.is_empty() || !json.contains(pw));
        }
    }

    #[test]
    fn empty_vault_is_fully_ok() {
        let r = check(&[], 0);
        assert_eq!((r.checked, r.ok_percent), (0, 100));
    }
}
