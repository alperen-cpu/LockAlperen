//! Auto-type (SECURITY.md "Otomatik yazma"): types username, Tab, password,
//! Enter into another window ONLY after that window is verified.
//!
//! Verification: the target is the window the user switches to within
//! WAIT, it must belong to another process, and its title must contain the
//! entry's title or the URL's host. Typing stops at once if the foreground
//! window changes. Limit: a window title can be chosen by any program, so
//! this protects against typing into the WRONG window by mistake, not
//! against a malicious program imitating the right one.
#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    VIRTUAL_KEY, VK_RETURN, VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

pub const WAIT: Duration = Duration::from_secs(10);

pub const NO_TARGET: &str = "10 saniye içinde başka bir pencereye geçilmedi; hiçbir şey yazılmadı.";
pub const WRONG_TARGET: &str = "Hedef pencerenin başlığı bu kaydın adını ya da sitesini \
     içermiyor; güvenlik için hiçbir şey yazılmadı.";
pub const INTERRUPTED: &str = "Yazarken pencere değişti; yazma durduruldu.";

/// What is typed, after the entry's values are filled in. Text is wiped
/// when the steps are dropped.
pub enum Step {
    Text(zeroize::Zeroizing<String>),
    Tab,
    Enter,
    Delay(Duration),
}

/// KeePass's default sequence.
pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
/// Longest sequence accepted, and the longest total `{DELAY}`.
pub const MAX_SEQUENCE_CHARS: usize = 1000;
pub const MAX_TOTAL_DELAY_MS: u64 = 30_000;

pub const BAD_SEQUENCE: &str = "Otomatik yazma dizisi geçersiz. Kullanılabilenler: {USERNAME} \
     {PASSWORD} {TITLE} {URL} {NOTES} {TOTP} {S:Alan adı} {TAB} {ENTER} {SPACE} {DELAY 500} \
     {{} {}}; en fazla 1000 karakter ve toplam 30 sn bekleme.";

/// A value of the entry that a sequence can type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqField {
    Username,
    Password,
    Title,
    Url,
    Notes,
    Totp,
    Custom(String),
}

/// One item of a parsed auto-type sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Text(String),
    Field(SeqField),
    Tab,
    Enter,
    Delay(u64),
}

/// Parses a KeePass-style sequence. Empty = [`DEFAULT_SEQUENCE`].
pub fn parse_sequence(seq: &str) -> Result<Vec<Token>, &'static str> {
    let seq = if seq.trim().is_empty() {
        DEFAULT_SEQUENCE
    } else {
        seq
    };
    if seq.chars().count() > MAX_SEQUENCE_CHARS {
        return Err(BAD_SEQUENCE);
    }
    let mut out: Vec<Token> = Vec::new();
    let mut text = String::new();
    let mut total_delay = 0u64;
    let chars: Vec<char> = seq.chars().collect();
    let flush = |text: &mut String, out: &mut Vec<Token>| {
        if !text.is_empty() {
            out.push(Token::Text(std::mem::take(text)));
        }
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '{' {
            text.push(c);
            continue;
        }
        // "{{}" and "{}}" are a literal brace.
        if i + 1 < chars.len() && chars[i + 1] == '}' && matches!(chars[i], '{' | '}') {
            text.push(chars[i]);
            i += 2;
            continue;
        }
        let Some(len) = chars[i..].iter().position(|&d| d == '}') else {
            return Err(BAD_SEQUENCE);
        };
        if len > 128 {
            return Err(BAD_SEQUENCE);
        }
        let name: String = chars[i..i + len].iter().collect();
        i += len + 1;
        let upper = name.trim().to_uppercase();
        let token = match upper.as_str() {
            "SPACE" => {
                text.push(' ');
                continue;
            }
            "USERNAME" => Token::Field(SeqField::Username),
            "PASSWORD" => Token::Field(SeqField::Password),
            "TITLE" => Token::Field(SeqField::Title),
            "URL" => Token::Field(SeqField::Url),
            "NOTES" => Token::Field(SeqField::Notes),
            "TOTP" => Token::Field(SeqField::Totp),
            "TAB" => Token::Tab,
            "ENTER" => Token::Enter,
            _ => {
                if let Some(rest) = upper
                    .strip_prefix("DELAY")
                    .map(|r| r.trim_start_matches(['=', ' ']))
                {
                    let ms: u64 = rest.trim().parse().map_err(|_| BAD_SEQUENCE)?;
                    total_delay += ms;
                    if total_delay > MAX_TOTAL_DELAY_MS {
                        return Err(BAD_SEQUENCE);
                    }
                    Token::Delay(ms)
                } else if upper.starts_with("S:") {
                    // Keep the custom field's own spelling.
                    let field = name.trim()[2..].trim().to_owned();
                    if field.is_empty() {
                        return Err(BAD_SEQUENCE);
                    }
                    Token::Field(SeqField::Custom(field))
                } else {
                    return Err(BAD_SEQUENCE);
                }
            }
        };
        flush(&mut text, &mut out);
        out.push(token);
    }
    flush(&mut text, &mut out);
    Ok(out)
}

/// Which windows an entry may type into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The title must contain one of these (entry title, site host).
    Markers(Vec<String>),
    /// The entry's own window rule (`*` = any text, `?` = one character),
    /// matched against the whole title, ignoring case.
    Pattern(String),
}

pub const BAD_WINDOW_RULE: &str = "Pencere kuralında joker karakterler dışında en az 3 harf ya da \
     rakam olmalı (örnek: *Banka*).";

/// A window rule must name something: at least 3 letters or digits besides
/// the wildcards, so "*" alone can never match every window.
pub fn window_rule_ok(rule: &str) -> bool {
    rule.chars().filter(|c| c.is_alphanumeric()).count() >= 3
}

impl Target {
    pub fn matches(&self, window_title: &str) -> bool {
        match self {
            Target::Markers(m) => title_matches(window_title, m),
            Target::Pattern(p) => window_rule_ok(p) && glob(p, window_title),
        }
    }
}

/// Lowercase for comparing, with the Turkish i's folded together (İ, I, ı
/// and i match each other; plain `to_lowercase` turns İ into i + a
/// combining dot, so "GİRİŞ" would not match "giriş").
pub fn fold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'İ' | 'I' | 'ı' => out.push('i'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Case-insensitive wildcard match of the whole text (`*`, `?`).
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = fold(pattern).chars().collect();
    let t: Vec<char> = fold(text).chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Lowercased words the target title must contain one of.
pub fn expected_markers(title: &str, url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let t = fold(title.trim());
    if t.chars().count() >= 3 {
        out.push(t);
    }
    let host = url::Url::parse(url.trim())
        .ok()
        .or_else(|| url::Url::parse(&format!("https://{}", url.trim())).ok())
        .and_then(|u| u.host_str().map(str::to_lowercase));
    if let Some(h) = host {
        let h = h.strip_prefix("www.").unwrap_or(&h).to_owned();
        // "github.com" -> also accept "github" (browsers show page titles).
        if let Some(first) = h.split('.').next() {
            if first.chars().count() >= 3 {
                out.push(first.to_owned());
            }
        }
        if h.chars().count() >= 3 {
            out.push(h);
        }
    }
    out
}

pub fn title_matches(window_title: &str, markers: &[String]) -> bool {
    let w = fold(window_title);
    !markers.is_empty() && markers.iter().any(|m| w.contains(m.as_str()))
}

pub fn window_title(h: HWND) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buffer and its length are passed together.
    let n = unsafe { GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub fn pid_of(h: HWND) -> u32 {
    let mut pid = 0u32;
    // SAFETY: valid out-pointer.
    unsafe { GetWindowThreadProcessId(h, &mut pid) };
    pid
}

/// Waits for the user to switch to another program's window and verifies
/// it. Returns that window.
pub fn wait_for_target(target: &Target) -> Result<HWND, &'static str> {
    let me = std::process::id();
    let start = Instant::now();
    while start.elapsed() < WAIT {
        // SAFETY: no preconditions.
        let fg = unsafe { GetForegroundWindow() };
        if !fg.is_null() && pid_of(fg) != me {
            // Give the window a moment to settle (title of a new tab etc.).
            std::thread::sleep(Duration::from_millis(400));
            // SAFETY: no preconditions.
            if unsafe { GetForegroundWindow() } != fg {
                continue;
            }
            return if target.matches(&window_title(fg)) {
                Ok(fg)
            } else {
                Err(WRONG_TARGET)
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(NO_TARGET)
}

/// How long to wait for a site we opened ourselves to load and show a
/// matching title (a cold browser start can be slow).
pub const WAIT_OPENED: Duration = Duration::from_secs(25);
/// Extra time after the title matches, so the page can put the cursor in
/// its login form before we type.
const SETTLE_OPENED: Duration = Duration::from_millis(1500);

pub const OPENED_WRONG_TARGET: &str =
    "Site açıldı ama tarayıcı penceresinin başlığı bu kaydın adını \
     ya da sitesini içermiyor; güvenlik için hiçbir şey yazılmadı.";
pub const OPENED_NO_TARGET: &str =
    "Site 25 saniye içinde açılmadı ya da tarayıcı öne gelmedi; hiçbir şey yazılmadı.";

/// After we opened the entry's site in the browser: waits until another
/// program's foreground window has a matching title (the page title shows
/// up only once the page loads), lets the page settle, and checks again.
/// The same title rule as [`wait_for_target`]; only the waiting differs.
pub fn wait_for_opened_site(target: &Target) -> Result<HWND, &'static str> {
    let me = std::process::id();
    let start = Instant::now();
    let mut saw_other = false;
    while start.elapsed() < WAIT_OPENED {
        // SAFETY: no preconditions.
        let fg = unsafe { GetForegroundWindow() };
        if !fg.is_null() && pid_of(fg) != me {
            saw_other = true;
            if target.matches(&window_title(fg)) {
                std::thread::sleep(SETTLE_OPENED);
                // SAFETY: no preconditions.
                if unsafe { GetForegroundWindow() } == fg && target.matches(&window_title(fg)) {
                    return Ok(fg);
                }
                continue;
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err(if saw_other {
        OPENED_WRONG_TARGET
    } else {
        OPENED_NO_TARGET
    })
}

fn key(vk: VIRTUAL_KEY, scan: u16, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) {
    // SAFETY: slice pointer and length passed together; INPUT size given.
    unsafe {
        SendInput(
            inputs.len() as u32,
            inputs.as_ptr(),
            std::mem::size_of::<INPUT>() as i32,
        )
    };
}

/// Types the steps into `target`, checking before every key that it is
/// still the foreground window.
pub fn type_into(target: HWND, steps: &[Step]) -> Result<(), &'static str> {
    let still = || unsafe { GetForegroundWindow() } == target;
    for step in steps {
        match step {
            Step::Text(s) => {
                for unit in s.encode_utf16() {
                    if !still() {
                        return Err(INTERRUPTED);
                    }
                    send(&[
                        key(0, unit, KEYEVENTF_UNICODE),
                        key(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
                    ]);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Step::Delay(d) => {
                std::thread::sleep(*d);
                if !still() {
                    return Err(INTERRUPTED);
                }
            }
            Step::Tab | Step::Enter => {
                if !still() {
                    return Err(INTERRUPTED);
                }
                let vk = if matches!(step, Step::Tab) {
                    VK_TAB
                } else {
                    VK_RETURN
                };
                send(&[key(vk, 0, 0), key(vk, 0, KEYEVENTF_KEYUP)]);
                std::thread::sleep(Duration::from_millis(30));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequences_parse() {
        use SeqField::*;
        assert_eq!(
            parse_sequence("").unwrap(),
            vec![
                Token::Field(Username),
                Token::Tab,
                Token::Field(Password),
                Token::Enter
            ]
        );
        assert_eq!(
            parse_sequence("{USERNAME}{ENTER}{DELAY 1500}{password}{TOTP}{enter}").unwrap(),
            vec![
                Token::Field(Username),
                Token::Enter,
                Token::Delay(1500),
                Token::Field(Password),
                Token::Field(Totp),
                Token::Enter
            ]
        );
        assert_eq!(
            parse_sequence("a{SPACE}b{{}{}}{S:PIN Kodu}{DELAY=10}").unwrap(),
            vec![
                Token::Text("a b{}".into()),
                Token::Field(Custom("PIN Kodu".into())),
                Token::Delay(10)
            ]
        );
        for bad in [
            "{NOPE}",
            "{USERNAME",
            "{DELAY x}",
            "{DELAY 40000}",
            "{S:}",
            &"x".repeat(1001),
        ] {
            assert!(parse_sequence(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn window_rules() {
        let t = Target::Pattern("*Banka*Giriş*".into());
        assert!(t.matches("Ziraat BANKA - giriş sayfası - Edge"));
        assert!(!t.matches("Banka hesap özeti"));
        assert!(glob("a?c", "ABC") && !glob("a?c", "abbc"));
        // A rule that names nothing never matches (it would match everything).
        assert!(!Target::Pattern("*".into()).matches("anything"));
        assert!(!Target::Pattern("*a*".into()).matches("a"));
        assert!(!window_rule_ok("**?*") && window_rule_ok("*abc*"));
    }

    #[test]
    fn markers_from_title_and_url() {
        let m = expected_markers("GitHub", "https://www.github.com/login");
        assert!(m.contains(&"github".to_owned()));
        assert!(m.contains(&"github.com".to_owned()));
        assert_eq!(
            expected_markers("ab", ""),
            Vec::<String>::new(),
            "too short"
        );
        assert!(expected_markers("", "mail.example.com").contains(&"mail.example.com".to_owned()));
    }

    #[test]
    fn title_check() {
        let m = expected_markers("GitHub", "https://github.com");
        assert!(title_matches(
            "Sign in to GitHub · GitHub - Microsoft Edge",
            &m
        ));
        assert!(!title_matches("Banka Giriş - Google Chrome", &m));
        assert!(!title_matches("anything", &[]), "no markers: never type");
    }
}
