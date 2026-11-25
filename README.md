# LockAlperen 🔒

Windows ve Linux (Ubuntu masaüstü) için yerel, açık kaynaklı bir parola yöneticisi; KeePass'e
modern bir alternatif. Sunucu, hesap ve telemetri yok. Kasanız, istediğiniz yerde duran tek bir
şifreli `.lav` dosyasıdır.

> ⚠️ Proje hâlâ genç. Kasanızın yedeğini alın ve en önemli parolalarınızı şimdilik yalnızca bu
> uygulamaya emanet etmeyin.

**İçindekiler:** [Özellikler](#özellikler) · [Kurulum](#kurulum) ·
[Windows ve Linux farkları](#windows-ve-linux-farkları) · [Ağ bağlantıları](#ağ-bağlantıları) ·
[Güvenlik](#güvenlik) · [Durum](#durum) · [Geliştirme](#geliştirme) · [Belgeler](#belgeler)

## Özellikler

**Kasa**
- Argon2id, HKDF-SHA256 ve XChaCha20-Poly1305 ile şifrelenmiş tek dosya ([format](docs/FORMAT.md))
- Ana parola ve isteğe bağlı anahtar dosyası
- Birden fazla kasa sekmelerde aynı anda açık kalabilir
- Başka bir kasayla birleştirme (KeePass "Synchronize")

**Kayıtlar**
- Klasör ağacı, sürükle-bırakla taşıma, Geri Dönüşüm Kutusu
- Kayıt geçmişi, ekler, özel alanlar, etiketler, renkler, son kullanma tarihi
- Parola üretici (profiller ve desenler), TOTP kodları, parola sağlığı raporu
- Site ikonları, doğrudan sitenin kendisinden alınır (üçüncü taraf servis yok)

**Günlük kullanım**
- Liste, kompakt, kart ve tablo görünümleri; açık ve koyu tema
- Kopyalama Ctrl+C ile yapılır: fare hangi kullanıcı adı ya da parolanın üzerindeyse o kopyalanır.
  KeePass kısayolları da var (Ctrl+B, Ctrl+U, Ctrl+E, Delete).
- Pencere kapatılınca uygulama arka planda çalışmaya devam eder: Windows'ta saatin yanındaki,
  Ubuntu'da üst çubuktaki simgeden açılır
- **Tarayıcı eklentisi (Chrome, Chromium, Brave, Edge; şimdilik yalnızca Linux):** giriş
  bilgilerini açık siteye doldurur ([ayrıntılar](apps/browser-extension/README.md))
- **Otomatik yazma (yalnızca Windows):** Bir düğmeyle ya da genel kısayolla (varsayılan
  `Ctrl+Alt+A`) çalışır. Yalnızca başlığı doğrulanan pencereye yazar.

**KeePass ile uyum**
- KeePass (KDBX 4) içe ve dışa aktarma
- Alan referansları (`{REF:…}`), kayda özel otomatik yazma dizileri, KeePass seçenekleri
- CSV dışa aktarma ve yazdırılabilir acil durum sayfası

**Yedek ve güncelleme**
- İsteğe bağlı Google Drive yedeği: Drive'a yalnızca şifreli kasa dosyası gider
- Uygulama içi güncelleme: yeni sürüm, imzası doğrulanarak kurulur ([nasıl çalışır](docs/UPDATES.md))

**Güvenlik**
- Otomatik kilit: boşta kalınca, ekran kilitlenince, uykuda ve oturum kapanınca
- Pano seçilen sürede temizlenir (varsayılan 12 sn) ve pano geçmişine alınmaz
- Windows'ta pencere ekran görüntüsünde ve ekran paylaşımında görünmez
- Uygulamanın dosyaları yalnızca sizin kullanıcınıza açıktır
- Ayrıntılar: [Güvenlik](#güvenlik)

## Kurulum

Bütün dosyalar [Releases](https://github.com/alperen-cpu/LockAlperen/releases/latest)
sayfasında. Sonraki sürümler uygulama açılınca önerilir ve tek tıkla kurulur; kasa dosyalarınız
ve ayarlarınız korunur. Bu denetim Ayarlar'dan kapatılabilir.

### Windows

1. `LockAlperen_x.y.z_x64-setup.exe` dosyasını indirip çalıştırın. Yönetici yetkisi gerekmez.
2. Kurulum dosyasında Windows kod imzası yok. Bu yüzden SmartScreen "tanınmayan uygulama"
   uyarısı verebilir: **Ek bilgi → Yine de çalıştır**.

### Linux (Ubuntu 22.04 ve sonrası, x86-64)

- **`.deb` (önerilen):**

  ```sh
  sudo apt install ./LockAlperen_x.y.z_amd64.deb
  ```

  Güncellemede yönetici parolası sorulur.
- **AppImage:** `LockAlperen_x.y.z_amd64.AppImage` dosyasını indirin, `chmod +x` ile
  çalıştırılabilir yapın ve açın. Kurulum ve yönetici izni gerekmez.

### Tarayıcı eklentisi (isteğe bağlı, Linux)

1. LockAlperen'de **Ayarlar › Tarayıcı eklentisi › "Tarayıcı eklentisine izin ver"** seçeneğini
   açın ve tarayıcıyı yeniden başlatın.
2. Tarayıcıda `chrome://extensions` › **Geliştirici modu** › **Paketlenmemiş öğe yükle** ›
   `apps/browser-extension` klasörünü seçin.
3. Eklenti simgesinden **Masaüstü uygulamasıyla eşleştir** deyin. İki tarafta görünen 6 haneli kod
   aynıysa masaüstünde **Eşleştir**'e basın.

Eklenti ana parolanızı hiçbir zaman sormaz; kasa yalnızca masaüstü uygulamasında açılır.

## Windows ve Linux farkları

| | Windows | Linux |
|---|---|---|
| Otomatik yazma ve genel kısayollar | Var | **Yok.** Wayland, başka bir pencereye tuş göndermeye izin vermiyor. Kopyalayıp yapıştırın. |
| Ekran görüntüsünden gizleme | Var | **Yok.** X11'de de Wayland'de de böyle bir ayar yok. |
| Tarayıcı eklentisi | Henüz yok | Var |
| Otomatik kilit | Boşta kalma, Win+L, uyku, oturum kapatma | Boşta kalma (GNOME/KDE), ekran kilidi, uyku, kapanma, kullanıcı değiştirme |
| Arka plan simgesi | Saatin yanında | Üst çubukta. Ubuntu'da hazır gelir; başka masaüstlerinde AppIndicator uzantısı gerekebilir. |
| Google erişiminin saklandığı yer | DPAPI ile şifreli | Sistem anahtarlığı (GNOME Keyring / KWallet) |

## Ağ bağlantıları

Uygulama yalnızca şu durumlarda ağa çıkar:
- **Site ikonları:** doğrudan sitenin kendisinden indirilir. Siteler ve ağınız (örneğin şirket
  proxy'si) kasanızda hangi sitelerin olduğunu görebilir. Otomatik indirme **Ayarlar › Veri**'den
  kapatılabilir. İçe aktarılan kayıtların ikonları hiçbir zaman kendiliğinden indirilmez; yalnızca
  "Eksik ikonları şimdi indir" düğmesiyle.
- **Sürüm denetimi:** GitHub'dan yapılır; Ayarlar'dan kapatılabilir.
- **Google Drive yedeği:** yalnızca hesap bağlanırsa. Drive'a yalnızca şifreli kasa dosyası
  gider.

Tarayıcı eklentisi ağ kullanmaz. Uygulamayla yalnızca sizin kullanıcınıza açık bir yerel soketten,
şifreli olarak konuşur.

## Güvenlik

- [SECURITY.md](SECURITY.md): güvenlik özellikleri ve KeePass açıklarıyla karşılaştırma
- [docs/SECURITY_COMPARISON_2026-11.md](docs/SECURITY_COMPARISON_2026-11.md): rakiplerde son 10
  yılda çıkan açıklarla karşılaştırma, pentest sonuçları ve açık kalan maddeler
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): neye karşı korur, neye karşı korumaz

Bir açık bulursanız lütfen herkese açık bir issue yerine [SECURITY.md](SECURITY.md)'deki yoldan
bildirin.

## Durum

| Alan | Durum |
|---|---|
| Kasa formatı, kriptografi, çekirdek kütüphane (`lav-core`) | ✅ |
| Masaüstü uygulaması (Windows) | ✅ |
| KeePass içe ve dışa aktarma (KDBX 4) | ✅ KDBX 3.1 ve CSV içe aktarma yok |
| İmzalı sürümler ve uygulama içi güncelleme | ✅ |
| Linux (Ubuntu): `.deb` ve AppImage | ✅ CI'da derlenip test ediliyor. Gerçek masaüstünde kısmen denendi. |
| Tarayıcı eklentisi (Chromium, yalnızca doldurma) | 🚧 Protokol testli, gerçek tarayıcıda denenmesi sürüyor. Windows desteği yok. |

**Bilinçli olarak yapılmayanlar:** Windows Hello, mobil uygulama ve senkron sunucusu.
**Henüz olmayanlar:** sızıntı kontrolü, Windows kod imzası, Linux'ta otomatik yazma.

## Geliştirme

| Klasör | İçerik |
|---|---|
| `crates/lav-core` | Kasa formatı, kriptografi, veri modeli, parola üretici |
| `crates/lav-favicon` | Site ikonlarını güvenli indirme ve yeniden kodlama |
| `apps/desktop` | Masaüstü uygulaması (Tauri 2 + React); [README](apps/desktop/README.md) |
| `apps/browser-extension` | Chromium eklentisi; [README](apps/browser-extension/README.md) |
| `fuzz` | libFuzzer hedefleri |
| `prototypes/r1-rollback` | Geri alma tespiti prototipi (üretimde kullanılmıyor) |
| `docs` | Format, tehdit modeli, güvenlik incelemeleri, sürüm süreci |

```sh
cargo test                      # çekirdek testleri
cargo clippy --all-targets
cargo audit                     # bağımlılık güvenlik taraması

cd apps/desktop                 # masaüstü uygulaması (ayrı Cargo çalışma alanı)
npm ci
npm run tauri dev
```

Linux'ta derlemek için gereken paketler ve diğer ayrıntılar
[apps/desktop/README.md](apps/desktop/README.md)'de.

**Sürüm yayınlama:** `apps/desktop` içinde `node scripts/set-version.mjs x.y.z` çalıştırın,
ardından `vx.y.z` etiketini gönderin. İş akışı paketleri imzalayıp taslak bir sürüm oluşturur.
Adımlar [docs/UPDATES.md](docs/UPDATES.md)'de.

## Belgeler

- [Sürüm notları](CHANGELOG.md)
- [Dosya formatı](docs/FORMAT.md)
- [Tehdit modeli](docs/THREAT_MODEL.md)
- [Güvenlik](SECURITY.md) ve [rakip karşılaştırması](docs/SECURITY_COMPARISON_2026-11.md)
- [Güncellemeler ve sürüm yayınlama](docs/UPDATES.md)
- [Masaüstü uygulamasının güvenlik kararları](apps/desktop/README.md)
- [Tarayıcı eklentisi](apps/browser-extension/README.md)
- [Üçüncü taraf bildirimleri](THIRD_PARTY_NOTICES.md) (Font Awesome simgeleri, CC BY 4.0)

Lisans: MIT.
