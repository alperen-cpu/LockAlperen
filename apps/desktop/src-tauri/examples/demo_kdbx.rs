//! Writes a throw-away KeePass (KDBX 4) file for trying the import by hand.
//! Usage: cargo run --example demo_kdbx -- <path.kdbx> <password>
//! (uses the dev-only `save_kdbx4` feature; never with real data).

use keepass::{Database, DatabaseKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(password)) = (args.next(), args.next()) else {
        eprintln!("usage: demo_kdbx <path.kdbx> <password>");
        std::process::exit(2);
    };
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        for (title, user, url) in [
            ("Banka", "alperen", "https://banka.example"),
            ("E-posta", "alperen@example.com", "https://mail.example"),
        ] {
            let mut e = root.add_entry();
            e.set_unprotected("Title", title);
            e.set_unprotected("UserName", user);
            e.set_protected("Password", "keepass-demo-parola-1");
            e.set_unprotected("URL", url);
        }
    }
    {
        let mut root = db.root_mut();
        let mut g = root.add_group();
        g.name = "Sosyal".into();
        let mut e = g.add_entry();
        e.set_unprotected("Title", "Mastodon");
        e.set_protected("Password", "kisa");
        e.set_unprotected("otp", "otpauth://totp/m?secret=JBSWY3DPEHPK3PXP");
    }
    let mut f = std::fs::File::create(&path)?;
    db.save(&mut f, DatabaseKey::new().with_password(&password))?;
    println!("wrote {path}");
    Ok(())
}
