//! Automatic locking on Linux (SECURITY.md, "Otomatik kilit"): the events
//! and the idle time the Windows code in src/autolock.rs gets from Win32,
//! here from D-Bus. Works on Wayland and X11.
//!
//! Lock events (any one locks):
//! - screen locked: `org.gnome.ScreenSaver` / `org.freedesktop.ScreenSaver`
//!   `ActiveChanged(true)` on the session bus; logind `Session.Lock` and
//!   `LockedHint` becoming true on the system bus;
//! - sleep: logind `PrepareForSleep(true)`;
//! - shutdown or logout: logind `PrepareForShutdown(true)`;
//! - switched away (another user's session in front): our logind session's
//!   `Active` becoming false.
//!
//! Idle time, first source that answers: GNOME (Mutter `IdleMonitor`),
//! KDE (`org.freedesktop.ScreenSaver.GetSessionIdleTime`), then logind's
//! `IdleHint` (set by the desktop after its own idle delay). With none of
//! them the idle lock cannot work; this is reported once on stderr and the
//! event locks above still do.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use zbus::blocking::{Connection, MessageIterator};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::Reason;

const LOGIN1: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const SESSION: &str = "org.freedesktop.login1.Session";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

fn session_bus() -> Option<&'static Connection> {
    static BUS: OnceLock<Option<Connection>> = OnceLock::new();
    BUS.get_or_init(|| Connection::session().ok()).as_ref()
}

fn system_bus() -> Option<&'static Connection> {
    static BUS: OnceLock<Option<Connection>> = OnceLock::new();
    BUS.get_or_init(|| Connection::system().ok()).as_ref()
}

/// Our logind session: the one this process belongs to, else the one named
/// by `XDG_SESSION_ID`.
fn own_session() -> Option<&'static OwnedObjectPath> {
    static PATH: OnceLock<Option<OwnedObjectPath>> = OnceLock::new();
    PATH.get_or_init(|| {
        let c = system_bus()?;
        let by_pid = c
            .call_method(
                Some(LOGIN1),
                LOGIN1_PATH,
                Some(MANAGER),
                "GetSessionByPID",
                &std::process::id(),
            )
            .ok()
            .and_then(|r| r.body().deserialize::<OwnedObjectPath>().ok());
        by_pid.or_else(|| {
            let id = std::env::var("XDG_SESSION_ID").ok()?;
            c.call_method(
                Some(LOGIN1),
                LOGIN1_PATH,
                Some(MANAGER),
                "GetSession",
                &id.as_str(),
            )
            .ok()?
            .body()
            .deserialize::<OwnedObjectPath>()
            .ok()
        })
    })
    .as_ref()
}

// ----- idle time -----

fn mutter_idle(c: &Connection) -> Option<Duration> {
    let reply = c
        .call_method(
            Some("org.gnome.Mutter.IdleMonitor"),
            "/org/gnome/Mutter/IdleMonitor/Core",
            Some("org.gnome.Mutter.IdleMonitor"),
            "GetIdletime",
            &(),
        )
        .ok()?;
    let ms: u64 = reply.body().deserialize().ok()?;
    Some(Duration::from_millis(ms))
}

fn freedesktop_idle(c: &Connection) -> Option<Duration> {
    let reply = c
        .call_method(
            Some("org.freedesktop.ScreenSaver"),
            "/org/freedesktop/ScreenSaver",
            Some("org.freedesktop.ScreenSaver"),
            "GetSessionIdleTime",
            &(),
        )
        .ok()?;
    let ms: u32 = reply.body().deserialize().ok()?;
    Some(Duration::from_millis(u64::from(ms)))
}

fn session_property(c: &Connection, session: &OwnedObjectPath, name: &str) -> Option<OwnedValue> {
    c.call_method(
        Some(LOGIN1),
        session.as_str(),
        Some(PROPERTIES),
        "Get",
        &(SESSION, name),
    )
    .ok()?
    .body()
    .deserialize::<OwnedValue>()
    .ok()
}

fn monotonic_micros() -> Option<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer.
    #[allow(unsafe_code)]
    let r = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if r != 0 {
        return None;
    }
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec).ok()?;
    Some(secs.saturating_mul(1_000_000) + nanos / 1000)
}

/// Idle time from logind's hint. Not idle (zero) until the desktop sets the
/// hint, then the time since it was set.
pub fn idle_from_hint(hint: bool, since_monotonic_us: u64, now_monotonic_us: u64) -> Duration {
    if !hint {
        return Duration::ZERO;
    }
    Duration::from_micros(now_monotonic_us.saturating_sub(since_monotonic_us))
}

fn logind_idle() -> Option<Duration> {
    let (c, s) = (system_bus()?, own_session()?);
    let hint = match &*session_property(c, s, "IdleHint")? {
        Value::Bool(b) => *b,
        _ => return None,
    };
    let since = match &*session_property(c, s, "IdleSinceHintMonotonic")? {
        Value::U64(t) => *t,
        _ => return None,
    };
    Some(idle_from_hint(hint, since, monotonic_micros()?))
}

/// System-wide time since the last user input (see the module comment).
pub fn system_idle() -> Duration {
    let found = session_bus()
        .and_then(|c| mutter_idle(c).or_else(|| freedesktop_idle(c)))
        .or_else(logind_idle);
    match found {
        Some(idle) => idle,
        None => {
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                eprintln!("LockAlperen: no idle-time source on D-Bus; idle lock is off");
            }
            Duration::ZERO
        }
    }
}

// ----- events -----

type Callback = Arc<dyn Fn(Reason) + Send + Sync>;
type Mapper = fn(&zbus::Message) -> Option<Reason>;

fn signal_rule(
    interface: &'static str,
    member: &'static str,
    path: Option<&str>,
) -> zbus::Result<zbus::MatchRule<'static>> {
    let mut rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(interface)?
        .member(member)?;
    if let Some(p) = path {
        rule = rule.path(p.to_owned())?;
    }
    Ok(rule.build())
}

/// Calls `on` for every matching signal, on a thread of its own. True once
/// the subscription is in place.
fn listen(
    conn: &Connection,
    rule: zbus::Result<zbus::MatchRule<'static>>,
    map: Mapper,
    on: &Callback,
) -> bool {
    let Ok(rule) = rule else {
        return false;
    };
    let (conn, on) = (conn.clone(), on.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("lav-autolock".into())
        .spawn(move || {
            let messages = match MessageIterator::for_match_rule(rule, &conn, None) {
                Ok(m) => {
                    let _ = tx.send(true);
                    m
                }
                Err(_) => {
                    let _ = tx.send(false);
                    return;
                }
            };
            for msg in messages.flatten() {
                if let Some(reason) = map(&msg) {
                    on(reason);
                }
            }
        });
    spawned.is_ok() && rx.recv().unwrap_or(false)
}

fn bool_arg(msg: &zbus::Message) -> Option<bool> {
    msg.body().deserialize::<bool>().ok()
}

fn on_sleep(msg: &zbus::Message) -> Option<Reason> {
    bool_arg(msg)?.then_some(Reason::Suspend)
}

fn on_shutdown(msg: &zbus::Message) -> Option<Reason> {
    bool_arg(msg)?.then_some(Reason::LoggedOff)
}

fn on_screensaver(msg: &zbus::Message) -> Option<Reason> {
    bool_arg(msg)?.then_some(Reason::SessionLocked)
}

fn on_session_lock(_: &zbus::Message) -> Option<Reason> {
    Some(Reason::SessionLocked)
}

/// What a change of our logind session's properties means.
pub fn session_change(interface: &str, changed: &HashMap<String, OwnedValue>) -> Option<Reason> {
    if interface != SESSION {
        return None;
    }
    if matches!(changed.get("LockedHint").map(|v| &**v), Some(Value::Bool(true))) {
        return Some(Reason::SessionLocked);
    }
    if matches!(changed.get("Active").map(|v| &**v), Some(Value::Bool(false))) {
        return Some(Reason::Disconnected);
    }
    None
}

fn on_session_properties(msg: &zbus::Message) -> Option<Reason> {
    let (interface, changed, _): (String, HashMap<String, OwnedValue>, Vec<String>) =
        msg.body().deserialize().ok()?;
    session_change(&interface, &changed)
}

/// Starts the listeners once. None if nothing could be subscribed to (no
/// D-Bus at all); idle locking does not depend on this.
pub fn watch(on_lock: impl Fn(Reason) + Send + Sync + 'static) -> Option<()> {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return None; // already running
    }
    let on: Callback = Arc::new(on_lock);
    let mut any = false;
    if let Some(c) = system_bus() {
        any |= listen(c, signal_rule(MANAGER, "PrepareForSleep", None), on_sleep, &on);
        any |= listen(
            c,
            signal_rule(MANAGER, "PrepareForShutdown", None),
            on_shutdown,
            &on,
        );
        if let Some(s) = own_session() {
            let path = Some(s.as_str());
            any |= listen(c, signal_rule(SESSION, "Lock", path), on_session_lock, &on);
            any |= listen(
                c,
                signal_rule(PROPERTIES, "PropertiesChanged", path),
                on_session_properties,
                &on,
            );
        }
    }
    if let Some(c) = session_bus() {
        for interface in ["org.gnome.ScreenSaver", "org.freedesktop.ScreenSaver"] {
            any |= listen(
                c,
                signal_rule(interface, "ActiveChanged", None),
                on_screensaver,
                &on,
            );
        }
    }
    any.then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_hint() {
        assert_eq!(idle_from_hint(false, 0, 10_000_000), Duration::ZERO);
        assert_eq!(
            idle_from_hint(true, 4_000_000, 10_000_000),
            Duration::from_secs(6)
        );
        // A hint "from the future" (clock oddity) is not idle time.
        assert_eq!(idle_from_hint(true, 11_000_000, 10_000_000), Duration::ZERO);
    }

    #[test]
    fn session_changes() {
        let props = |k: &str, v: bool| {
            let v = Value::from(v).try_to_owned().unwrap();
            HashMap::from([(k.to_owned(), v)])
        };
        assert_eq!(
            session_change(SESSION, &props("LockedHint", true)),
            Some(Reason::SessionLocked)
        );
        assert_eq!(
            session_change(SESSION, &props("Active", false)),
            Some(Reason::Disconnected)
        );
        // Unlocking or coming back never unlocks anything.
        assert_eq!(session_change(SESSION, &props("LockedHint", false)), None);
        assert_eq!(session_change(SESSION, &props("Active", true)), None);
        assert_eq!(session_change("other.Interface", &props("Active", false)), None);
    }

    #[test]
    fn idle_is_measurable_without_a_desktop() {
        // CI has no desktop session: whatever the sources say, it answers.
        assert!(system_idle() < Duration::from_secs(60 * 60 * 24 * 365 * 100));
    }
}
