//! The Google Drive refresh token on Linux: kept in the user's keyring
//! through the Secret Service D-Bus API (GNOME Keyring on Ubuntu, KWallet on
//! KDE), the counterpart of DPAPI on Windows (src/gdrive.rs).
//!
//! The token itself never touches our files: `protect` stores it in the
//! default keyring collection and returns a fixed marker, which is what the
//! settings file keeps; `unprotect` turns the marker back into the token by
//! asking the keyring. The keyring unlocks with the login password; if it is
//! locked, the desktop asks for its password.
//!
//! The "plain" transfer is used on the session bus, as most clients do: any
//! program of the same user could ask the keyring for the item anyway
//! (documented limit, as DPAPI has the same one).

use std::collections::HashMap;

use zbus::blocking::{Connection, MessageIterator};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

/// What the settings file stores instead of the token.
pub const MARKER: &[u8] = b"lav-secret-service-v1";

const SERVICE: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const DEFAULT_COLLECTION: &str = "/org/freedesktop/secrets/aliases/default";
const LABEL: &str = "LockAlperen: Google Drive erişimi";

fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", "com.alperen.lockalperen"),
        ("purpose", "gdrive-refresh-token"),
    ])
}

fn call<B, R>(conn: &Connection, path: &str, iface: &str, method: &str, body: &B) -> zbus::Result<R>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
    R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
{
    let reply = conn.call_method(Some(SERVICE), path, Some(iface), method, body)?;
    reply.body().deserialize::<R>()
}

fn open_session(conn: &Connection) -> zbus::Result<OwnedObjectPath> {
    let (_, session): (OwnedValue, OwnedObjectPath) = call(
        conn,
        SERVICE_PATH,
        "org.freedesktop.Secret.Service",
        "OpenSession",
        &("plain", Value::from("")),
    )?;
    Ok(session)
}

/// Shows a keyring prompt (unlock password) and waits for the answer.
/// Returns false if the user dismissed it.
fn prompt(conn: &Connection, path: &OwnedObjectPath) -> zbus::Result<bool> {
    if path.as_str() == "/" {
        return Ok(true);
    }
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.Secret.Prompt")?
        .member("Completed")?
        .path(path.as_str())?
        .build();
    // Subscribed before the prompt is shown, so the answer cannot be missed.
    let mut answers = MessageIterator::for_match_rule(rule, conn, Some(1))?;
    // Window id "": the keyring shows its own dialog.
    conn.call_method(
        Some(SERVICE),
        path.as_str(),
        Some("org.freedesktop.Secret.Prompt"),
        "Prompt",
        &"",
    )?;
    match answers.next() {
        Some(msg) => {
            let (dismissed, _): (bool, OwnedValue) = msg?.body().deserialize()?;
            Ok(!dismissed)
        }
        None => Ok(false),
    }
}

/// Unlocks `items` (asking the user if needed). False if they said no.
fn unlock(conn: &Connection, items: Vec<OwnedObjectPath>) -> zbus::Result<bool> {
    let (_, p): (Vec<OwnedObjectPath>, OwnedObjectPath) = call(
        conn,
        SERVICE_PATH,
        "org.freedesktop.Secret.Service",
        "Unlock",
        &items,
    )?;
    prompt(conn, &p)
}

fn store(data: &[u8]) -> zbus::Result<bool> {
    let conn = Connection::session()?;
    let session = open_session(&conn)?;
    if !unlock(&conn, vec![OwnedObjectPath::try_from(DEFAULT_COLLECTION)?])? {
        return Ok(false);
    }
    let properties: HashMap<&str, Value> = HashMap::from([
        ("org.freedesktop.Secret.Item.Label", Value::from(LABEL)),
        (
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes()),
        ),
    ]);
    let secret = (session, Vec::<u8>::new(), data.to_vec(), "text/plain");
    let (item, p): (OwnedObjectPath, OwnedObjectPath) = call(
        &conn,
        DEFAULT_COLLECTION,
        "org.freedesktop.Secret.Collection",
        "CreateItem",
        &(properties, secret, true),
    )?;
    if item.as_str() == "/" {
        return prompt(&conn, &p);
    }
    Ok(true)
}

fn load() -> zbus::Result<Option<Zeroizing<Vec<u8>>>> {
    let conn = Connection::session()?;
    let session = open_session(&conn)?;
    let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = call(
        &conn,
        SERVICE_PATH,
        "org.freedesktop.Secret.Service",
        "SearchItems",
        &attributes(),
    )?;
    let item = match (unlocked.first(), locked.first()) {
        (Some(item), _) => item.clone(),
        (None, Some(item)) => {
            if !unlock(&conn, vec![item.clone()])? {
                return Ok(None);
            }
            item.clone()
        }
        (None, None) => return Ok(None),
    };
    let (_, _, value, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = call(
        &conn,
        item.as_str(),
        "org.freedesktop.Secret.Item",
        "GetSecret",
        &session,
    )?;
    Ok(Some(Zeroizing::new(value)))
}

/// Stores `data` in the keyring; returns the marker to keep in its place.
pub fn protect(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    match store(data) {
        Ok(true) => Ok(MARKER.to_vec()),
        _ => Err(super::PROTECT_FAILED),
    }
}

/// Reads the token back from the keyring. Anything but our marker (a DPAPI
/// blob copied from Windows, a damaged file) or a missing item means the
/// account has to be connected again.
pub fn unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if data != MARKER {
        return Err(super::EXPIRED);
    }
    match load() {
        Ok(Some(token)) => Ok(token),
        _ => Err(super::EXPIRED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs no keyring: refused before any D-Bus call.
    #[test]
    fn only_our_marker_is_looked_up() {
        assert_eq!(unprotect(b"").err(), Some(super::super::EXPIRED));
        assert_eq!(unprotect(b"refresh-token").err(), Some(super::super::EXPIRED));
        let mut other = MARKER.to_vec();
        other.push(b'x');
        assert_eq!(unprotect(&other).err(), Some(super::super::EXPIRED));
    }
}
