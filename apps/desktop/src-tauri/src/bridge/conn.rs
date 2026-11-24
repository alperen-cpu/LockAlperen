//! One browser-extension connection: Noise handshake, pairing, requests.
//!
//! Wire format (the same on the browser's native-messaging stdio and on our
//! socket; the native host only relays): a 4-byte little-endian length,
//! then UTF-8 JSON (`{"t":"hs","d":base64}` during the handshake,
//! `{"t":"m","d":base64}` after it, `{"t":"err","e":code}` for refusals
//! before encryption exists). Frames over [`MAX_FRAME`] end the connection.
//!
//! Security (docs/research/rakipler-eklenti-2016-2026.md §3.5):
//! - Noise_XX_25519_AESGCM_SHA256 via `snow`: mutual authentication with
//!   static keys, forward secrecy, AEAD with counter nonces (no replay, no
//!   reordering). No custom crypto; the extension's implementation is
//!   tested against this one (`noise_interop` test).
//! - Pairing: the user compares a 6-digit code derived from the handshake
//!   hash, shown in the extension and in the app's dialog, and approves in
//!   the app. A MITM has different handshake hashes on each side, so the
//!   codes differ. Nothing is ever authenticated by process identity.
//! - The extension asks only about one origin at a time and gets only the
//!   entries that match it (decided here, `origin.rs`). The first fill of an
//!   entry on a site asks the user in the app.
//! - Locked vault: only "locked" comes back; unlocking happens in the app.
//! - Requests are small, typed and rate limited; revoking a pairing or
//!   turning the integration off ends live sessions at their next request.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::origin::Origin;

pub const PATTERN: &str = "Noise_XX_25519_AESGCM_SHA256";
pub const PROLOGUE: &[u8] = b"lockalperen-bridge-v1";
pub const MAX_FRAME: usize = 64 * 1024;
const MAX_REQUEST: usize = 4 * 1024;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const RATE_MAX: usize = 40;
const MAX_LOGINS: usize = 50;

/// Reads one frame; `None` on a clean end of stream.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes())?;
    w.write_all(bytes)?;
    w.flush()
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    t: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    e: Option<String>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn send(w: &mut impl Write, t: &str, data: &[u8]) -> io::Result<()> {
    use base64::Engine;
    let env = Envelope {
        t: t.to_owned(),
        d: Some(b64().encode(data)),
        e: None,
    };
    write_frame(w, &serde_json::to_vec(&env).map_err(io::Error::other)?)
}

fn send_err(w: &mut impl Write, code: &str) -> io::Result<()> {
    let env = Envelope {
        t: "err".to_owned(),
        d: None,
        e: Some(code.to_owned()),
    };
    write_frame(w, &serde_json::to_vec(&env).map_err(io::Error::other)?)
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Reads an envelope of type `t` and returns its decoded data.
fn recv(r: &mut impl Read, t: &str) -> io::Result<Option<Vec<u8>>> {
    use base64::Engine;
    let Some(frame) = read_frame(r)? else {
        return Ok(None);
    };
    let env: Envelope = serde_json::from_slice(&frame).map_err(|_| bad("bad envelope"))?;
    if env.t != t {
        return Err(bad("unexpected message"));
    }
    let d = env.d.ok_or(bad("no data"))?;
    b64().decode(d).map(Some).map_err(|_| bad("bad base64"))
}

/// An entry offered for the page (no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub id: String,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

/// Refusals the extension shows (codes, not text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Locked,
    NoMatch,
    Denied,
    Busy,
    NoTotp,
}

impl Refusal {
    fn code(self) -> &'static str {
        match self {
            Refusal::Locked => "locked",
            Refusal::NoMatch => "no_match",
            Refusal::Denied => "denied",
            Refusal::Busy => "busy",
            Refusal::NoTotp => "no_totp",
        }
    }
}

pub struct Credentials {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

/// What a connection needs from the app (the real one is in `mod.rs`).
pub trait Host {
    fn enabled(&self) -> bool;
    fn app_private_key(&self) -> Zeroizing<Vec<u8>>;
    /// The pairing id of a known extension key (and marks it used).
    fn paired(&self, key: &[u8]) -> Option<String>;
    fn still_paired(&self, id: &str) -> bool;
    /// Asks the user (the code is also shown in the extension); on yes,
    /// stores the pairing and returns its id.
    fn confirm_pairing(&self, key: &[u8], code: &str) -> Result<String, Refusal>;
    fn locked(&self) -> bool;
    fn logins(&self, origin: &Origin) -> Result<Vec<Login>, Refusal>;
    /// Asks the user on the first fill of this entry on this site.
    fn credentials(&self, pair: &str, id: &str, origin: &Origin) -> Result<Credentials, Refusal>;
    fn totp(&self, pair: &str, id: &str, origin: &Origin) -> Result<Zeroizing<String>, Refusal>;
}

/// The code both sides show: 6 digits from the handshake hash.
pub fn pairing_code(handshake_hash: &[u8]) -> String {
    let n = u32::from_be_bytes([
        handshake_hash[0],
        handshake_hash[1],
        handshake_hash[2],
        handshake_hash[3],
    ]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

#[derive(Deserialize)]
struct Hello {
    v: u32,
    intent: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u32,
    op: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    entry: Option<String>,
}

fn noise_err(_: snow::Error) -> io::Error {
    bad("noise")
}

/// Serves one connection until it closes. Errors end the connection.
pub fn serve<S: Read + Write>(stream: &mut S, host: &impl Host) -> io::Result<()> {
    let params: snow::params::NoiseParams = PATTERN.parse().map_err(noise_err)?;
    let key = host.app_private_key();
    let mut hs = snow::Builder::new(params)
        .local_private_key(&key)
        .map_err(noise_err)?
        .prologue(PROLOGUE)
        .map_err(noise_err)?
        .build_responder()
        .map_err(noise_err)?;
    drop(key);
    let mut buf = vec![0u8; MAX_FRAME];

    // -> e (payload: {"v":1,"intent":"pair"|"use"}, not encrypted yet)
    let Some(m1) = recv(stream, "hs")? else {
        return Ok(());
    };
    if !host.enabled() {
        return send_err(stream, "disabled");
    }
    let n = hs.read_message(&m1, &mut buf).map_err(noise_err)?;
    let hello: Hello = serde_json::from_slice(&buf[..n]).map_err(|_| bad("bad hello"))?;
    if hello.v != 1 {
        return send_err(stream, "version");
    }
    let pairing = match hello.intent.as_str() {
        "pair" => true,
        "use" => false,
        _ => return Err(bad("bad intent")),
    };
    // <- e, ee, s, es
    let n = hs.write_message(&[], &mut buf).map_err(noise_err)?;
    send(stream, "hs", &buf[..n])?;
    // -> s, se
    let Some(m3) = recv(stream, "hs")? else {
        return Ok(());
    };
    hs.read_message(&m3, &mut buf).map_err(noise_err)?;
    let remote = hs.get_remote_static().ok_or(bad("no remote key"))?.to_vec();
    let code = pairing_code(hs.get_handshake_hash());
    let mut t = hs.into_transport_mode().map_err(noise_err)?;

    fn reply(
        t: &mut snow::TransportState,
        stream: &mut impl Write,
        value: serde_json::Value,
    ) -> io::Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(&value).map_err(io::Error::other)?);
        let mut out = vec![0u8; plain.len() + 64];
        let n = t.write_message(&plain, &mut out).map_err(noise_err)?;
        send(stream, "m", &out[..n])
    }

    let pair = match host.paired(&remote) {
        Some(id) => {
            reply(
                &mut t,
                stream,
                serde_json::json!({ "id": 0, "ok": true, "paired": true }),
            )?;
            id
        }
        None if pairing => match host.confirm_pairing(&remote, &code) {
            Ok(id) => {
                reply(
                    &mut t,
                    stream,
                    serde_json::json!({ "id": 0, "ok": true, "paired": true }),
                )?;
                id
            }
            Err(r) => {
                let e = if r == Refusal::Busy {
                    "busy"
                } else {
                    "rejected"
                };
                return reply(
                    &mut t,
                    stream,
                    serde_json::json!({ "id": 0, "ok": false, "error": e }),
                );
            }
        },
        None => {
            return reply(
                &mut t,
                stream,
                serde_json::json!({ "id": 0, "ok": false, "error": "not_paired" }),
            );
        }
    };

    let mut recent: Vec<Instant> = Vec::new();
    loop {
        let Some(sealed) = recv(stream, "m")? else {
            return Ok(());
        };
        if sealed.len() > MAX_REQUEST + 16 {
            return Err(bad("request too large"));
        }
        let mut plain = Zeroizing::new(vec![0u8; sealed.len()]);
        let n = t.read_message(&sealed, &mut plain).map_err(noise_err)?;
        let req: Request = serde_json::from_slice(&plain[..n]).map_err(|_| bad("bad request"))?;

        if !host.enabled() || !host.still_paired(&pair) {
            let e = if host.enabled() {
                "not_paired"
            } else {
                "disabled"
            };
            return reply(
                &mut t,
                stream,
                serde_json::json!({ "id": req.id, "ok": false, "error": e }),
            );
        }
        let now = Instant::now();
        recent.retain(|at| now.duration_since(*at) < RATE_WINDOW);
        if recent.len() >= RATE_MAX {
            reply(
                &mut t,
                stream,
                serde_json::json!({ "id": req.id, "ok": false, "error": "rate" }),
            )?;
            continue;
        }
        recent.push(now);

        let answer = handle(host, &pair, &req);
        let value = match answer {
            Ok(v) => v,
            Err(r) => serde_json::json!({ "ok": false, "error": r.code() }),
        };
        let mut value = value;
        value["id"] = req.id.into();
        reply(&mut t, stream, value)?;
    }
}

fn handle(host: &impl Host, pair: &str, req: &Request) -> Result<serde_json::Value, Refusal> {
    let origin = || {
        req.origin
            .as_deref()
            .and_then(Origin::of_page)
            .ok_or(Refusal::NoMatch)
    };
    let entry = || {
        req.entry
            .as_deref()
            .filter(|e| e.len() <= 80)
            .ok_or(Refusal::NoMatch)
    };
    match req.op.as_str() {
        "status" => Ok(serde_json::json!({ "ok": true, "locked": host.locked() })),
        "logins" => {
            let o = origin()?;
            let mut list = host.logins(&o)?;
            list.truncate(MAX_LOGINS);
            Ok(serde_json::json!({ "ok": true, "origin": o.serialize(), "logins": list }))
        }
        "fill" => {
            let c = host.credentials(pair, entry()?, &origin()?)?;
            Ok(serde_json::json!({
                "ok": true,
                "username": c.username.as_str(),
                "password": c.password.as_str(),
            }))
        }
        "totp" => {
            let code = host.totp(pair, entry()?, &origin()?)?;
            Ok(serde_json::json!({ "ok": true, "code": code.as_str() }))
        }
        _ => Err(Refusal::NoMatch),
    }
}

// Unix sockets stand in for the transport; the protocol itself is the same
// on every platform.
#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An in-memory host: one paired key, one entry for https://site.com.
    pub struct Fake {
        pub enabled: bool,
        pub key: [u8; 32],
        pub paired: RefCell<Vec<Vec<u8>>>,
        pub approve_pairing: bool,
        pub approve_fill: bool,
        pub locked: bool,
        pub shown_codes: RefCell<Vec<String>>,
        pub asked_fill: RefCell<u32>,
    }

    impl Fake {
        pub fn new() -> Fake {
            Fake {
                enabled: true,
                key: [9u8; 32],
                paired: RefCell::new(Vec::new()),
                approve_pairing: true,
                approve_fill: true,
                locked: false,
                shown_codes: RefCell::new(Vec::new()),
                asked_fill: RefCell::new(0),
            }
        }
    }

    impl Host for Fake {
        fn enabled(&self) -> bool {
            self.enabled
        }
        fn app_private_key(&self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(self.key.to_vec())
        }
        fn paired(&self, key: &[u8]) -> Option<String> {
            self.paired
                .borrow()
                .iter()
                .any(|k| k == key)
                .then(|| super::super::store::pair_id(key))
        }
        fn still_paired(&self, _: &str) -> bool {
            true
        }
        fn confirm_pairing(&self, key: &[u8], code: &str) -> Result<String, Refusal> {
            self.shown_codes.borrow_mut().push(code.to_owned());
            if self.approve_pairing {
                self.paired.borrow_mut().push(key.to_vec());
                Ok(super::super::store::pair_id(key))
            } else {
                Err(Refusal::Denied)
            }
        }
        fn locked(&self) -> bool {
            self.locked
        }
        fn logins(&self, o: &Origin) -> Result<Vec<Login>, Refusal> {
            if self.locked {
                return Err(Refusal::Locked);
            }
            let site = Origin::of_entry("https://site.com").unwrap();
            Ok(if site.fills(o) {
                vec![Login {
                    id: "0:e1".into(),
                    title: "Site".into(),
                    username: "ali".into(),
                    has_totp: false,
                }]
            } else {
                vec![]
            })
        }
        fn credentials(&self, _: &str, id: &str, o: &Origin) -> Result<Credentials, Refusal> {
            if self.locked {
                return Err(Refusal::Locked);
            }
            if id != "0:e1" || !Origin::of_entry("https://site.com").unwrap().fills(o) {
                return Err(Refusal::NoMatch);
            }
            *self.asked_fill.borrow_mut() += 1;
            if !self.approve_fill {
                return Err(Refusal::Denied);
            }
            Ok(Credentials {
                username: Zeroizing::new("ali".into()),
                password: Zeroizing::new("gizli".into()),
            })
        }
        fn totp(&self, _: &str, _: &str, _: &Origin) -> Result<Zeroizing<String>, Refusal> {
            Err(Refusal::NoTotp)
        }
    }

    /// The extension's side, with snow (the JS one is tested in
    /// `noise_interop`).
    pub struct Client {
        pub stream: std::os::unix::net::UnixStream,
        pub t: Option<snow::TransportState>,
        pub code: String,
        pub app_key: Vec<u8>,
        next: u32,
    }

    impl Client {
        pub fn connect(
            stream: std::os::unix::net::UnixStream,
            key: &[u8],
            intent: &str,
        ) -> io::Result<(Client, serde_json::Value)> {
            let mut stream = stream;
            let mut hs = snow::Builder::new(PATTERN.parse().unwrap())
                .local_private_key(key)
                .unwrap()
                .prologue(PROLOGUE)
                .unwrap()
                .build_initiator()
                .unwrap();
            let mut buf = vec![0u8; MAX_FRAME];
            let hello = serde_json::json!({ "v": 1, "intent": intent }).to_string();
            let n = hs.write_message(hello.as_bytes(), &mut buf).unwrap();
            send(&mut stream, "hs", &buf[..n])?;
            let frame = read_frame(&mut stream)?.ok_or(bad("closed"))?;
            let env: Envelope = serde_json::from_slice(&frame).unwrap();
            if env.t == "err" {
                return Ok((
                    Client {
                        stream,
                        t: None,
                        code: String::new(),
                        app_key: vec![],
                        next: 1,
                    },
                    serde_json::json!({ "err": env.e }),
                ));
            }
            use base64::Engine;
            let m2 = b64().decode(env.d.unwrap()).unwrap();
            hs.read_message(&m2, &mut buf).map_err(noise_err)?;
            let app_key = hs.get_remote_static().unwrap().to_vec();
            let n = hs.write_message(&[], &mut buf).unwrap();
            send(&mut stream, "hs", &buf[..n])?;
            let code = pairing_code(hs.get_handshake_hash());
            let t = hs.into_transport_mode().unwrap();
            let mut c = Client {
                stream,
                t: Some(t),
                code,
                app_key,
                next: 1,
            };
            let first = c.read()?;
            Ok((c, first))
        }

        pub fn read(&mut self) -> io::Result<serde_json::Value> {
            let sealed = recv(&mut self.stream, "m")?.ok_or(bad("closed"))?;
            let mut out = vec![0u8; sealed.len()];
            let n = self
                .t
                .as_mut()
                .unwrap()
                .read_message(&sealed, &mut out)
                .map_err(noise_err)?;
            Ok(serde_json::from_slice(&out[..n]).unwrap())
        }

        pub fn call(&mut self, mut req: serde_json::Value) -> io::Result<serde_json::Value> {
            req["id"] = self.next.into();
            self.next += 1;
            let plain = req.to_string();
            let mut out = vec![0u8; plain.len() + 64];
            let n = self
                .t
                .as_mut()
                .unwrap()
                .write_message(plain.as_bytes(), &mut out)
                .unwrap();
            send(&mut self.stream, "m", &out[..n])?;
            self.read()
        }
    }

    pub fn ext_key(seed: u8) -> Vec<u8> {
        // Any 32 bytes are a valid X25519 private key.
        vec![seed; 32]
    }

    fn run(host: Fake, f: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static) -> Fake {
        let (mut a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let client = std::thread::spawn(move || f(b));
        let _ = serve(&mut a, &host);
        drop(a);
        client.join().unwrap();
        host
    }

    #[test]
    fn pairing_shows_the_same_code_on_both_sides_then_use_works() {
        let host = Fake::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let host = run(host, move |s| {
            let (c, first) = Client::connect(s, &ext_key(1), "pair").unwrap();
            assert_eq!(first["paired"], true);
            tx.send(c.code.clone()).unwrap();
        });
        let ext_code = rx.recv().unwrap();
        assert_eq!(
            host.shown_codes.borrow().as_slice(),
            std::slice::from_ref(&ext_code)
        );
        assert_eq!(ext_code.len(), 7);

        // A second connection is a normal session: no dialog, requests work.
        let host = run(host, |s| {
            let (mut c, first) = Client::connect(s, &ext_key(1), "use").unwrap();
            assert_eq!(first["ok"], true);
            let r = c.call(serde_json::json!({ "op": "status" })).unwrap();
            assert_eq!(r["locked"], false);
            let r = c
                .call(serde_json::json!({ "op": "logins", "origin": "https://www.site.com/login" }))
                .unwrap();
            assert_eq!(r["logins"][0]["username"], "ali");
            assert!(
                r["logins"][0].get("password").is_none(),
                "no secrets in the list"
            );
            let r = c
                .call(serde_json::json!({ "op": "fill", "origin": "https://site.com", "entry": "0:e1" }))
                .unwrap();
            assert_eq!(r["password"], "gizli");
            assert_eq!(r["id"], 3);
        });
        assert_eq!(
            host.shown_codes.borrow().len(),
            1,
            "no second pairing dialog"
        );
    }

    #[test]
    fn unknown_extension_gets_nothing() {
        run(Fake::new(), |s| {
            let (mut c, first) = Client::connect(s, &ext_key(2), "use").unwrap();
            assert_eq!(first["error"], "not_paired");
            assert!(
                c.call(serde_json::json!({ "op": "status" })).is_err(),
                "closed"
            );
        });
    }

    #[test]
    fn rejected_pairing_and_disabled_bridge() {
        let mut host = Fake::new();
        host.approve_pairing = false;
        let host = run(host, |s| {
            let (_, first) = Client::connect(s, &ext_key(3), "pair").unwrap();
            assert_eq!(first["error"], "rejected");
        });
        assert!(host.paired.borrow().is_empty());

        let mut host = Fake::new();
        host.enabled = false;
        run(host, |s| {
            let (_, first) = Client::connect(s, &ext_key(3), "pair").unwrap();
            assert_eq!(first["err"], "disabled");
        });
    }

    #[test]
    fn other_sites_locked_vault_and_denied_fill() {
        let mut host = Fake::new();
        host.paired.borrow_mut().push(snow_public(&ext_key(4)));
        host.approve_fill = false;
        let host = run(host, |s| {
            let (mut c, _) = Client::connect(s, &ext_key(4), "use").unwrap();
            for page in [
                "https://evil.site.com",
                "http://site.com",
                "https://site.com.evil.net",
            ] {
                let r = c
                    .call(serde_json::json!({ "op": "logins", "origin": page }))
                    .unwrap();
                assert_eq!(r["logins"].as_array().unwrap().len(), 0, "{page}");
                let r = c
                    .call(serde_json::json!({ "op": "fill", "origin": page, "entry": "0:e1" }))
                    .unwrap();
                assert_eq!(r["error"], "no_match", "{page}");
            }
            let r = c
                .call(serde_json::json!({ "op": "fill", "origin": "file:///etc/passwd", "entry": "0:e1" }))
                .unwrap();
            assert_eq!(r["error"], "no_match");
            let r = c
                .call(serde_json::json!({ "op": "fill", "origin": "https://site.com", "entry": "0:e1" }))
                .unwrap();
            assert_eq!(r["error"], "denied");
        });
        assert_eq!(
            *host.asked_fill.borrow(),
            1,
            "asked only for the matching site"
        );

        let mut host = Fake::new();
        host.paired.borrow_mut().push(snow_public(&ext_key(4)));
        host.locked = true;
        run(host, |s| {
            let (mut c, _) = Client::connect(s, &ext_key(4), "use").unwrap();
            let r = c.call(serde_json::json!({ "op": "status" })).unwrap();
            assert_eq!(r["locked"], true);
            let r = c
                .call(serde_json::json!({ "op": "logins", "origin": "https://site.com" }))
                .unwrap();
            assert_eq!(r["error"], "locked");
        });
    }

    #[test]
    fn malformed_requests_end_the_connection() {
        let host = Fake::new();
        host.paired.borrow_mut().push(snow_public(&ext_key(5)));
        run(host, |s| {
            let (mut c, _) = Client::connect(s, &ext_key(5), "use").unwrap();
            // Unknown field: refused by the typed parser, connection closed.
            let r = c.call(serde_json::json!({ "op": "status", "path": "/etc/passwd" }));
            assert!(r.is_err());
        });
        // Oversized frame.
        run(Fake::new(), |mut s| {
            s.write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
                .unwrap();
            let mut b = [0u8; 1];
            assert_eq!(s.read(&mut b).unwrap_or(0), 0, "closed without reply");
        });
    }

    #[test]
    fn requests_are_rate_limited() {
        let host = Fake::new();
        host.paired.borrow_mut().push(snow_public(&ext_key(6)));
        run(host, |s| {
            let (mut c, _) = Client::connect(s, &ext_key(6), "use").unwrap();
            let mut limited = 0;
            for _ in 0..(RATE_MAX + 5) {
                let r = c.call(serde_json::json!({ "op": "status" })).unwrap();
                if r["error"] == "rate" {
                    limited += 1;
                }
            }
            assert_eq!(limited, 5);
        });
    }

    /// The extension's Noise code (apps/browser-extension/noise.js, run by
    /// Node) against this responder: handshake, pairing code, requests and
    /// a tampered message. Skipped without `node` unless LAV_REQUIRE_NODE
    /// is set (CI sets it).
    #[test]
    fn noise_interop() {
        use std::process::{Command, Stdio};
        struct Pipe(std::process::ChildStdout, Option<std::process::ChildStdin>);
        impl Read for Pipe {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for Pipe {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.1.as_mut().ok_or(io::ErrorKind::BrokenPipe)?.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.1.as_mut().ok_or(io::ErrorKind::BrokenPipe)?.flush()
            }
        }
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../browser-extension/test/interop.mjs");
        let child = Command::new("node")
            .arg(&script)
            .arg("pair")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(_) if std::env::var_os("LAV_REQUIRE_NODE").is_none() => {
                eprintln!("noise_interop skipped: node not found");
                return;
            }
            Err(e) => panic!("node: {e}"),
        };
        let mut pipe = Pipe(child.stdout.take().unwrap(), child.stdin.take());
        let host = Fake::new();
        let r = serve(&mut pipe, &host);
        assert!(r.is_err(), "the tampered message must end the connection");
        pipe.1 = None; // close node's stdin
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "node: {err}");
        assert!(err.contains("OK"), "{err}");
        let code = err
            .lines()
            .find_map(|l| l.strip_prefix("CODE "))
            .expect("code line");
        assert_eq!(host.shown_codes.borrow().as_slice(), [code.to_owned()]);
    }

    #[test]
    fn pairing_code_format() {
        assert_eq!(pairing_code(&[0, 0, 0, 0]), "000 000");
        assert_eq!(pairing_code(&[0, 1, 226, 64]), "123 456");
    }

    pub fn snow_public(private: &[u8]) -> Vec<u8> {
        // X25519 base-point multiplication via a throwaway handshake.
        let mut i = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(private)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut r = snow::Builder::new(PATTERN.parse().unwrap())
            .local_private_key(&[1u8; 32])
            .unwrap()
            .build_responder()
            .unwrap();
        let mut b = vec![0u8; 1024];
        let mut p = vec![0u8; 1024];
        let n = i.write_message(&[], &mut b).unwrap();
        r.read_message(&b[..n], &mut p).unwrap();
        let n = r.write_message(&[], &mut b).unwrap();
        i.read_message(&b[..n], &mut p).unwrap();
        let n = i.write_message(&[], &mut b).unwrap();
        r.read_message(&b[..n], &mut p).unwrap();
        r.get_remote_static().unwrap().to_vec()
    }
}
