//! Release check, run by .github/workflows/release.yml after signing:
//!
//!   cargo run --example verify_release -- <installer.exe> <version>
//!
//! Verifies `<installer>.sig` against the public key built into the app
//! (tauri.conf.json) exactly as the updater will, and that the signature names
//! `<version>`. A release signed with any other key would be refused by every
//! installed copy, so it must never be published.

use base64::Engine;
use minisign_verify::{PublicKey, Signature};

fn b64_text(s: &str) -> Result<String, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| format!("base64: {e}"))?;
    String::from_utf8(raw).map_err(|e| format!("utf-8: {e}"))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [installer, version] = args.as_slice() else {
        return Err("usage: verify_release <installer.exe> <version>".into());
    };
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
        .map_err(|e| format!("tauri.conf.json: {e}"))?;
    let pubkey = conf["plugins"]["updater"]["pubkey"]
        .as_str()
        .filter(|k| !k.trim().is_empty())
        .ok_or("tauri.conf.json has no updater pubkey")?;
    let pk = PublicKey::decode(&b64_text(pubkey)?).map_err(|e| format!("pubkey: {e}"))?;
    let sig_file = format!("{installer}.sig");
    let sig_text = std::fs::read_to_string(&sig_file).map_err(|e| format!("{sig_file}: {e}"))?;
    let sig = Signature::decode(&b64_text(&sig_text)?).map_err(|e| format!("signature: {e}"))?;
    let data = std::fs::read(installer).map_err(|e| format!("{installer}: {e}"))?;
    // `false`: no legacy (non-prehashed) signatures; the CLI does not make them.
    pk.verify(&data, &sig, false)
        .map_err(|e| format!("signature does not verify with the app's public key: {e}"))?;
    let signed = sig
        .trusted_comment()
        .split('\t')
        .find_map(|f| f.strip_prefix("version:"))
        .ok_or("signature does not name a version (requireSignedVersion would reject it)")?;
    if signed != version {
        return Err(format!("signed for version {signed}, releasing {version}"));
    }
    println!("OK: {installer} is signed with the app's key for version {version}");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("verify_release: {e}");
        std::process::exit(1);
    }
}
