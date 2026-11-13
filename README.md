# LockAlperen 🔒

Windows için yerel, açık kaynaklı ve sade bir parola yöneticisi. KeePass'e modern bir alternatif.

- **Yerel ve çevrimdışı:** Sunucu yok, hesap yok. Kasanız tek bir `.lav` dosyasıdır.
- **Modern kriptografi:** Argon2id, HKDF-SHA256 ve XChaCha20-Poly1305 ([format](docs/FORMAT.md))
- **Site ikonları:** Favicon'lar doğrudan sitenin kendisinden, güvenli şekilde alınır (üçüncü taraf servis yok)
- **KeePass'ten kolay geçiş:** `.kdbx` içe aktarma *(yakında)*
- **Açık kaynak:** MIT lisansı

> ⚠️ Proje erken geliştirme aşamasındadır. Gerçek parolalarınızı henüz yalnızca bu uygulamaya emanet etmeyin.

## Durum

| Faz | Kapsam | Durum |
|---|---|---|
| 0 | Format belgesi, tehdit modeli, repo | ✅ |
| 1 | `lav-core`: format, kriptografi, veri modeli, parola üretici | ✅ |
| 1b | Güvenlik sıkılaştırması ([SECURITY.md](SECURITY.md)), `lav-favicon` | ✅ |
| 2 | Masaüstü uygulama (Tauri 2 + React): [apps/desktop](apps/desktop/README.md) | 🚧 iskelet |
| 3 | KeePass (KDBX 3.1/4) ve CSV içe aktarma | ⏳ |
| 4 | TOTP, auto-type, Windows Hello, sızıntı kontrolü | ⏳ |

## Geliştirme

```sh
cargo test           # tüm testler
cargo clippy --all-targets
cargo test -p lav-favicon -- --ignored   # gerçek ağ testi
cargo audit          # bağımlılık güvenlik taraması
```

## Belgeler

- [Dosya formatı](docs/FORMAT.md)
- [Tehdit modeli](docs/THREAT_MODEL.md)
- [Güvenlik ve KeePass açıklarıyla karşılaştırma](SECURITY.md)
