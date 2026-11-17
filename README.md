# LockAlperen 🔒

Windows için yerel, açık kaynaklı ve sade bir parola yöneticisi. KeePass'e modern bir alternatif.

- **Yerel:** Sunucu yok, hesap yok, telemetri yok. Kasanız, istediğiniz yerde duran tek bir şifreli
  `.lav` dosyasıdır ve hiçbir sunucuya gönderilmez.
- **Modern kriptografi:** Argon2id, HKDF-SHA256 ve XChaCha20-Poly1305 ([format](docs/FORMAT.md))
- **KeePass'ten geçiş:** `.kdbx` (KDBX 4) dosyalarını içe aktarma
- **Günlük kullanım:** Kayıt ekleme ve düzenleme, klasör ağacı (sürükle-bırak ile taşıma), parola
  üretici, TOTP kodları, parola sağlığı, ekler, özel alanlar ve kayıt geçmişi
- **Otomatik yazma:** Düğmeyle ya da global kısayolla (varsayılan `Ctrl+Alt+A`); yalnızca başlığı
  doğrulanan pencereye yazar
- **Sistem tepsisi:** Kapatınca tepside çalışmaya devam eder; site adresleri tek tıkla tarayıcıda açılır
- **Güvenlik:** Otomatik kilit (boşta kalınca, Win+L ve uyku), pano seçilen sürede (varsayılan 12 sn) temizlenir ve pano
  geçmişine alınmaması için işaretlenir, pencere ekran görüntüsünde görünmez ([SECURITY.md](SECURITY.md))
- **Site ikonları:** Favicon'lar doğrudan sitenin kendisinden, güvenli şekilde alınır (üçüncü taraf
  servis yok)
- **Uygulama içi güncelleme:** Yeni sürüm, imzası doğrulanarak kurulu sürümün üzerine kurulur
  ([nasıl çalışır](docs/UPDATES.md))
- **Açık kaynak:** MIT lisansı

> ⚠️ İlk sürümler yayında, ama proje hâlâ genç. Kasanızın yedeğini alın ve en önemli
> parolalarınızı şimdilik yalnızca bu uygulamaya emanet etmeyin.

## Kurulum

1. [Releases](https://github.com/alperen-cpu/LockAlperen/releases/latest) sayfasından
   `LockAlperen_x.y.z_x64-setup.exe` dosyasını indirip çalıştırın. Yönetici yetkisi gerekmez.
2. Kurulum dosyasında Windows kod imzası yok. Bu yüzden SmartScreen "tanınmayan uygulama" uyarısı
   verebilir: **Ek bilgi → Yine de çalıştır**.
3. Sonraki sürümler uygulama açılınca önerilir ve tek tıkla kurulur. Kasa dosyalarınız ve
   ayarlarınız korunur. Bu denetim Ayarlar'dan kapatılabilir.

Ağa çıkan yalnızca iki işlem var: site ikonlarının indirilmesi ve GitHub'dan sürüm denetimi.

## Durum

| Faz | Kapsam | Durum |
|---|---|---|
| 0 | Format belgesi, tehdit modeli, repo | ✅ |
| 1 | `lav-core`: format, kriptografi, veri modeli, parola üretici | ✅ |
| 1b | Güvenlik sıkılaştırması ([SECURITY.md](SECURITY.md)), `lav-favicon` | ✅ |
| 2 | Masaüstü uygulama (Tauri 2 + React): [apps/desktop](apps/desktop/README.md) | ✅ |
| 3 | KeePass içe aktarma (KDBX 4), CSV dışa aktarma | ✅ KDBX 3.1 ve CSV içe aktarma yok |
| 4 | TOTP, otomatik yazma (düğme ve global kısayol) | ✅ |
| 5 | İmzalı sürümler ve uygulama içi güncelleme ([UPDATES.md](docs/UPDATES.md)) | ✅ |
| 6 | Sistem tepsisi, tek örnek, klasör taşıma, siteyi tarayıcıda açma | ✅ |

**Bilinçli olarak yapılmayanlar ve eksikler:**
- Windows Hello yok (proje sahibinin kararı).
- Sızıntı kontrolü yok.
- Site ikonu indirme kapatılamıyor (şirket proxy'si kasadaki siteleri görebilir).
- Windows kod imzası yok.
- Mobil uygulama ve senkron sunucusu planlanmıyor.

Ayrıntılı liste: [apps/desktop/README.md](apps/desktop/README.md).

## Geliştirme

```sh
cargo test           # çekirdek testleri
cargo clippy --all-targets
cargo test -p lav-favicon -- --ignored   # gerçek ağ testi
cargo audit          # bağımlılık güvenlik taraması

cd apps/desktop      # masaüstü uygulama (ayrı Cargo çalışma alanı)
npm ci
npm run tauri dev
```

Sürüm yayınlama: `node scripts/set-version.mjs x.y.z`, ardından `vx.y.z` etiketini gönderin.
Adımlar [docs/UPDATES.md](docs/UPDATES.md)'de.

## Belgeler

- [Dosya formatı](docs/FORMAT.md)
- [Tehdit modeli](docs/THREAT_MODEL.md)
- [Güvenlik ve KeePass açıklarıyla karşılaştırma](SECURITY.md)
- [Güncellemeler ve sürüm yayınlama](docs/UPDATES.md)
- [Masaüstü uygulamanın güvenlik kararları](apps/desktop/README.md)
- [Sürüm notları](CHANGELOG.md)
- [Üçüncü taraf bildirimleri](THIRD_PARTY_NOTICES.md) (Font Awesome simgeleri, CC BY 4.0)
