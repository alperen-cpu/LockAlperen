//! Writes a throw-away demo vault for trying the UI by hand.
//! Usage: cargo run --example demo_vault -- <path.lav> <password>
//! Never use this with real data: the password is a command-line argument.

use lav_core::{Entry, KdfParams, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(password)) = (args.next(), args.next()) else {
        eprintln!("usage: demo_vault <path.lav> <password>");
        std::process::exit(2);
    };
    let mut v = Vault::create("Demo kasa", &password, None, KdfParams::default())?;
    let work = v.data.add_group(v.data.root, "İş")?;
    for (group, title, user, url) in [
        (v.data.root, "GitHub", "alperen", "https://github.com"),
        (
            v.data.root,
            "E-posta",
            "alperen@example.com",
            "https://mail.example.com",
        ),
        (work, "Jira", "a.abursum", "https://jira.example.com"),
        (
            work,
            "<script>alert(1)</script>",
            "xss@test",
            "javascript:alert(1)",
        ),
    ] {
        let mut e = Entry::new(group, title);
        e.username = user.into();
        e.url = url.into();
        e.password = "demo-secret-must-not-reach-the-webview".into();
        v.data.add_entry(e)?;
    }
    v.save_file(path.as_ref())?;
    println!("wrote {path}");
    Ok(())
}
