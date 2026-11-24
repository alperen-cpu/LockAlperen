# LockAlperen masaüstü uygulaması

Tauri 2 (Rust) + React 19. Windows ve Linux (Ubuntu masaüstü). Bu belge geliştiriciler ve güvenlik
incelemesi yapanlar içindir: kodun nasıl düzenlendiği, her konuda hangi güvenlik kararının
alındığı ve neyin doğrulanıp neyin doğrulanmadığı.

**İçindekiler:** [Geliştirme](#geliştirme) · [Kod yapısı](#kod-yapısı) ·
[Güvenlik kararları](#güvenlik-kararları) · [Linux](#linux) · [Doğrulananlar](#doğrulananlar) ·
[Doğrulanmayanlar ve sınırlar](#doğrulanmayanlar-ve-sınırlar) · [Henüz yapılmayanlar](#henüz-yapılmayanlar)

## Geliştirme

```sh
cd apps/desktop
npm ci
npm run tauri dev                      # Vite + uygulama
cd src-tauri && cargo test             # masaüstü testleri
LAV_REQUIRE_NODE=1 cargo test bridge   # tarayıcı köprüsü (Node gerekir; CI'da zorunlu)
```

- **Deneme kasası:** `cargo run --example demo_vault -- demo.lav <parola>`. Yalnızca deneme
  içindir; parola komut satırında görünür.
- **Kurulu uygulamayla yan yana çalıştırma:** Uygulama tek örnek çalışır. Kurulu sürüm açıkken
  geliştirme sürümünü ayrı bir kimlikle başlatın:
  `npm run tauri dev -- --config '{"identifier":"com.alperen.lockalperen.dev"}'`
- **Linux'ta derleme için:**

  ```sh
  sudo apt install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev \
    libssl-dev build-essential file patchelf
  ```

`src-tauri` ayrı bir Cargo çalışma alanıdır: Tauri bağımlılıkları çekirdeğin `Cargo.lock`
dosyasına ve `cargo deny` politikasına girmez. CI masaüstünü Windows (MSVC) ve Ubuntu 22.04'te
derler, test eder ve Linux paketlerini oluşturur.

## Kod yapısı

`src-tauri/src/`:

| Modül | Görev |
|---|---|
| `lib.rs` | Tauri komutları (WebView'in çağırabildiği 81 komut), uygulama kurulumu |
| `session.rs`, `tabs.rs` | Açık kasa oturumu; sekmeler (en fazla 8 kasa) |
| `import.rs`, `export.rs` | KeePass içe ve dışa aktarma, HTML |
| `totp.rs`, `health.rs` | TOTP kodları, parola sağlığı |
| `clipboard.rs`, `autolock.rs`, `hardening.rs`, `hotkey.rs`, `autotype.rs`, `startup.rs`, `browser.rs`, `titlebar.rs` | İşletim sistemiyle konuşan Windows modülleri |
| `linux/` | Aynı modüllerin Linux karşılıkları, aynı fonksiyon adlarıyla ([Linux](#linux)) |
| `tray.rs`, `lockicon.rs` | Sistem simgesi ve kilit rozeti |
| `settings.rs`, `recent.rs`, `private.rs` | Ayar ve son kasalar dosyaları; yalnızca kullanıcıya açık dosya yazma |
| `gdrive.rs`, `update.rs` | Google Drive yedeği, uygulama içi güncelleme |
| `bridge/` | Tarayıcı eklentisi köprüsü ([eklenti README'si](../browser-extension/README.md)) |

`src/` (React): `App.tsx` ana ekran, `Editor.tsx` kayıt düzenleyici, `Settings.tsx` ayarlar,
`VaultTools.tsx` kasa araçları, `api.ts` Rust komutlarının tipleri.

## Güvenlik kararları

### WebView ve Rust arasındaki sınır

| Konu | Karar |
|---|---|
| IPC yüzeyi | WebView yalnızca uygulamanın kendi komutlarını çağırabilir: 81 komut, tek tek `capabilities/main.json`'da listeli. Core, dosya sistemi, shell ve diyalog yetkisi yok. Komutlar `build.rs`'te tanımlı; yetki verilmeyen komut reddedilir. |
| Dosya yolları | Kasa yolu yalnızca Rust'ta tutulur, dosya seçme penceresini Rust açar. WebView hiç yol göndermez; böylece WebView'e enjekte edilen bir betik başka bir dosyayı açtıramaz. |
| Sırlar | Liste yanıtında parola, not, TOTP, özel alan ve ek **yok** (`EntrySummary`). IPC'ye giden JSON'u bir test kontrol ediyor. Tablodaki parola sütunu yalnızca nokta gösterir. |
| Ana parola | React state'inde tutulmaz: kontrolsüz input, gönderilirken okunup hemen temizlenir. Rust'ta `Zeroizing<String>` içinde. |
| CSP | `default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `img-src 'self' data:` (site ikonları), `connect-src` yalnızca Tauri IPC, `frame-src 'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`. Web fontu ve uzak içerik yok. |
| XSS | Bütün metinler React ile düz metin olarak basılır, `innerHTML` yok. `<script>` başlıklı bir kayıtla elle denendi. Kayıt renkleri Rust'ta yalnızca `#rrggbb` olarak kabul edilir. |
| Navigasyon | Uygulama dışına (uzak site, `file:`) gezinme engellenir (`navigation_allowed`, testli). Dışarıdan dosya bırakma kapalı (`dragDropEnabled: false`). |
| Geliştirici araçları | Tauri'nin `devtools` özelliği açık değil; inceleyici yalnızca debug derlemede var. **Release derlemede doğrulanmadı.** |
| Hata mesajı | Kilit açma hatalarının hepsi tek bir genel mesaj (`is_unlock_failure`). Dosya okunamazsa ayrı bir mesaj. |

### Kasa ve kimlik bilgileri

| Konu | Karar |
|---|---|
| Yeni kasa | Kaydetme penceresini Rust açar, `.lav` uzantısı eklenir. Parola en az 8 karakter (çekirdeğin kuralı). **Var olan dosyanın üzerine asla yazılmaz**; arada dosya oluşursa çekirdeğin kilit altındaki kontrolü reddeder. Varsayılan KDF: Argon2id 64 MiB, 3 geçiş. |
| Kilit | Kilitlemek kasayı bırakır; anahtarları ve içeriği `lav-core` siler. Başarısız bir yeniden deneme ya da yeni dosya seçmek de kilitler. |
| Anahtar sayfaları | `lav-core` türetilmiş anahtarı `VirtualLock`/`mlock` ile RAM'de kilitler. Yalnızca anahtar sayfası kilitli; çözülmüş içerik kilitli değil, hazırda bekletme tüm belleği diske yazar. |
| Anahtar dosyası | Kilit açmada isteğe bağlı; Rust'taki pencereyle seçilir, yolu Rust'ta kalır. Yanlış ya da gereksiz anahtar dosyası da aynı genel hatayı verir. |
| Kayıt düzenleme | Değişiklik önce verinin **kopyasına** uygulanır ve diske yazılır; yazma başarısızsa bellek eski hâline döner. Dosya başka yerde değiştirildiyse (`FileChangedOnDisk`) üzerine yazılmaz. `EntryForm` bırakılırken silinir, `Debug` çıktısında gizlidir. Önceki sürüm geçmişe girer. |
| Ana parola değiştirme | Mevcut parola yeniden istenir (KeePassXC CVE-2023-35866). Yeni tuz ve anahtar; eski `.bak` silinir. Kayıt başarısız olursa eski parola geri konur. |
| Kasa ayarları | Ad, açıklama, geçmiş sınırı (0–100), Argon2id gücü, anahtar dosyası. Kimlik bilgisi değişiklikleri ana parolayı yeniden ister. |
| Parola üretici | Çekirdeğin `OsRng` tabanlı üreticisi; WebView yalnızca ayarları gönderir. Profiller en fazla 30; geçersiz desen atılır. |
| TOTP | RFC 6238: SHA-1/256/512, 6–8 hane, 1–300 sn periyot. Gizli anahtar Rust'ta kalır; WebView'e yalnızca o anki kod gider. HMAC RustCrypto'dan; RFC test vektörleriyle sınanıyor. HOTP yok. |
| Parola sağlığı | Rust'ta hesaplanır; WebView'e yalnızca sayılar ve etiketler gider. **Zayıflık tahmini basittir:** uzunluk × log2(karakter türleri); sözlük kelimelerini tanımaz ("Password123!" zayıf sayılmaz) ve arayüz bunu söyler. Sızıntı kontrolü yok. |
| Alan referansları | `{REF:…}` yalnızca Rust'ta, kopyalama, gösterme ve otomatik yazma anında çözülür; en fazla 4 düzey. |
| Arama | Başlık, kullanıcı adı, site ve etiketler arayüzde aranır. Notlar ve özel alanlar Rust'ta aranır, yalnızca eşleşen kimlikler döner. |
| Gizli değerleri gösterme | Parola, gizli özel alanlar ve notlar yalnızca tıklanınca istenir. 15 sn sonra, başka kayıt seçilince ya da kilitlenince ekrandan düşer. Bu sırada WebView belleğindedir ve silinemez. |

### İçe aktarma, dışa aktarma ve dosyalar

| Konu | Karar |
|---|---|
| KeePass içe aktarma | Dosya güvenilmez sayılır. `keepass` crate'ine vermeden önce dış başlığı **kendimiz** okuruz: yalnızca KDBX 4, en fazla 64 MiB. KDF sınırları da kontrol edilir: Argon2 ≤ 1 GiB, ≤ 100 iterasyon; AES-KDF ≤ 300 milyon tur. Sınır olmasa kötü niyetli bir dosya, parola denenmeden önce sınırsız bellek ya da süre harcatabilirdi. Çözüldükten sonra da sınırlar var: kayıt, klasör, derinlik, alan ve ek boyutu. Sonuç **yeni bir üst klasöre** eklenir; hata olursa kasa değişmez. |
| Dışa aktarma | CSV, KDBX 4 ve yazdırılabilir HTML. Hepsi ana parolayı yeniden ister. CSV hücreleri formül olarak çalışmaz (`= + - @` önekli). HTML'de her değer kaçışlı, CSP `default-src 'none'`. Dosyalar şifresizdir ve arayüz bunu söyler. |
| Ekler | Eklenecek dosya Rust'taki pencereyle seçilir (en fazla 16 MiB, kasada şifreli). Kaydederken önerilen ad temizlenir: yalnızca son parça kalır, kontrol ve yön değiştirme karakterleri atılır. Kaydedilen dosya **şifresizdir**. |
| Dosya izinleri | Kasa, `.bak`, `.lock`, ayarlar, son kasalar, Drive deposu, köprü deposu, dışa aktarmalar, ekler, anahtar dosyası ve otomatik başlatma dosyası Unix'te **0600**, uygulamanın klasörleri **0700** (`private.rs`, testli). Windows'ta kullanıcı klasörlerinin varsayılan ACL'i geçerli. |
| Ayarlar | `settings.json` (Windows'ta `%LOCALAPPDATA%\com.alperen.lockalperen\`, Linux'ta `~/.local/share/com.alperen.lockalperen/`). Değerler sabit listelerle sınırlı. Boşta kilit 1–60 dk olabilir, "asla" seçeneği yok. Geçersiz değer varsayılana döner. Tetikleyici ya da betik yok (KeePass CVE-2023-24055). |
| Son kasalar | `recent.json`: en fazla 5 kayıt, yalnızca yol ve zaman. Bozuk ya da 64 KiB'tan büyük dosya boş liste sayılır. WebView sıra numarası gönderir, yolu Rust çözer. |

### İşletim sistemi

| Konu | Karar |
|---|---|
| Pano | Kopyalamayı Rust yapar; değer WebView'e gitmez. Windows'ta pano geçmişi, bulut panosu ve izleyiciler için üç işaret konur. Linux'ta `x-kde-passwordManagerHint: secret` konur. Seçilen sürede (5–90 sn, varsayılan 12) ve kilitlenince pano temizlenir, ama **yalnızca hâlâ bizim içeriğimiz duruyorsa**. |
| Otomatik kilit | Kararı Rust verir; WebView kilidi açık tutamaz. Boşta kalma sistem genelindeki son girdiden ölçülür. Ekran kilidi, uyku, oturum kapatma ve kullanıcı değiştirme de kilitler; her durumda pano da temizlenir. Debug derlemede `LAV_IDLE_SECS` ile kısaltılabilir. |
| Süreç sertleştirme (Windows) | DLL'ler yalnızca SYSTEM32'den yüklenir. Süreç DACL'ı yalnızca sorgula/bekle/sonlandır izni verir. Pencere ekran görüntüsünden hariç tutulur (`WDA_EXCLUDEFROMCAPTURE`). *Doğrulandı:* başka süreçten bellek okuma reddediliyor (hata 5). **Sınır:** aynı kullanıcı DACL'ı değiştirebilir; yöneticiler atlar. |
| Süreç sertleştirme (Linux) | Ana süreçte `PR_SET_DUMPABLE=0` ve core dump 0. WebKitGTK'nın alt süreçleri (`WebKitWebProcess`, `WebKitNetworkProcess`) `exec` ile başladığı için bu bayrak onlara geçmez; gösterilen parola ve düzenlenen kayıt da bu süreçlerin belleğinde. Bu yüzden `nodump/nodump.c` küçük bir kütüphaneye derlenir ve paketle gelir (`.deb`: `/usr/lib/LockAlperen`, root'a ait; AppImage: salt okunur imaj). Uygulama açılırken bu kütüphaneyi `LD_PRELOAD`'a ekler; kütüphane yalnızca adı `WebKit` ile başlayan süreçlerde aynı bayrağı kapatır. Tarayıcı açılırken kullanıcının kendi `LD_PRELOAD`'u geri verilir. Doğrulandı: alt süreçlerin `/proc/<pid>/mem` dosyası root'a geçiyor, `environ` okunamıyor. |
| Siteyi açma | WebView yalnızca kayıt kimliğini gönderir; adresi Rust okur. Yalnızca `http`/`https` açılır. `file:`, `javascript:`, `ms-…:` ve UNC yolları reddedilir. Adresteki kullanıcı bilgisi atılır. Testli. |
| Otomatik yazma (Windows) | Hedef pencere doğrulanmadan yazmaz: başka bir süreç olmalı ve başlıkta kayıt adı ya da site geçmeli. Pencerenin programı Windows ya da Program Files klasöründe olmalı veya geçerli bir Authenticode imzası taşımalı (`wintarget.rs`). Genel kısayol yazılımla gönderilmişse (`LLKHF_INJECTED`) hiçbir şey yazılmaz (`hotkey.rs`). Pencere değişirse durur. Kısayolla yazmada tam olarak bir kayıt eşleşmeli. Diziler kaydetmeden önce denetlenir: en fazla 1000 karakter, toplam 30 sn bekleme. |
| Tek örnek | İkinci açılış yeni süreç başlatmaz, mevcut pencereyi öne getirir; argümanları yok sayılır. |
| Sistem simgesi | Kapat düğmesi pencereyi gizler, uygulama simgede çalışmaya devam eder. Bu ayar kapatılabilir, varsayılanı açık. Simgenin menüsünde göster, kilitle, kilitle ve çık var. Simge oluşturulamazsa pencere hiç gizlenmez. |
| Kilit rozeti | Kasa kilitliyken simgenin köşesinde kırmızı kilit görünür. Kilit durumu 300 ms'de bir okunur; böylece her kilitleme yolu yakalanır. Linux'ta Dock simgesi değiştirilemez; rozet yalnızca üst çubukta görünür. Ubuntu'nun AppIndicator eklentisi değişen simgeyi çizmediği için simge her değişiklikte yenisiyle değiştirilir. |

### Ağ

| Konu | Karar |
|---|---|
| Güncellemeler | Açılışta (kapatılabilir) ya da elle denetlenir; kurulum Rust'ın açtığı yerel bir sistem penceresinde onaylanır (WebView'deki bir betik onaylayamaz). Bağlantı HTTPS'tir. İmza, gömülü anahtarla minisign ile doğrulanır ve sürüme bağlıdır. Eski sürüme düşürme yok; indirme yalnızca bu reponun Releases'ından. Kurulumdan önce kasa kilitlenir. Ayrıntı: [docs/UPDATES.md](../../docs/UPDATES.md). |
| Site ikonları | **Otomatik** (Ayarlar › Veri'den kapatılabilir): kilit açıldıktan ve kaydettikten sonra, ikonu olmayan kayıtlar için. İçe aktarılan kayıtlar hiçbir zaman otomatik değil; yalnızca "Eksik ikonları şimdi indir" ile. `lav-favicon` yalnızca HTTPS kullanır. DNS'i sabitler ve özel ya da iç IP adreslerini engeller. Her yönlendirmeyi yeniden denetler. Boyut ve süre sınırlıdır. Resim yeniden kodlanır. **Gizlilik:** siteler ve ağ, kasada hangi sitelerin olduğunu görebilir. |
| Google Drive yedeği | İsteğe bağlı. OAuth 2.0 masaüstü akışı kullanılır: dönüş `127.0.0.1`'e, PKCE S256 ve `state` ile. Kapsam yalnızca `drive.file`. Yenileme anahtarı Windows'ta DPAPI ile, Linux'ta Secret Service'te saklanır. Yalnızca şifreli `.lav` dosyası yüklenir. İndirilen yedek, kasa başlığı doğrulanmazsa yazılmaz. |
| Tarayıcı köprüsü | Ağ portu yok: kullanıcıya özel Unix soketi, Noise XX ile şifreli ve eşleştirmeli. Ayrıntı: [eklenti README'si](../browser-extension/README.md). |

### Arayüz

| Konu | Karar |
|---|---|
| Klasörler | Girintili ağaç. Sürükle-bırak ya da "Taşı" menüsüyle taşınır. Çekirdek döngü oluşturacak taşımaları reddeder. Klasör simgeleri Font Awesome Free'den yol verisi olarak çizilir, çalışma zamanı kodu yok. |
| Geri Dönüşüm Kutusu | Silinen kayıt ya da klasör önce kutuya gider. Kutudan silmek ve "Boşalt" **kalıcıdır**; iki kez onay ister. Kutudaki kayıtlar TOTP, sağlık ve otomatik yazmaya girmez. |
| Silme onayı | Ne gideceğini ve kalıcı olup olmadığını söyler. Odak "Vazgeç"te başlar; Enter tek başına silmez. |
| Görünüm | Liste, kompakt, kart, tablo; açık ve koyu tema. Duyarlı düzen: üç sütun, çekmece ya da tek sütun. En küçük pencere 380×480. |
| Kısayollar | Fare bir değerin üzerindeyken Ctrl+C o değeri kopyalar; WebView yalnızca kimliği gönderir. Ctrl+B, Ctrl+U, Ctrl+E, Delete. Tam liste Ayarlar › Klavye kısayolları'nda. |
| Sekmeler | Her sekme ayrı bir oturumdur. Kilitleme hepsini kilitler. Aynı dosya iki sekmede açılamaz. Kapatılan sekmenin panoya kopyaladığı değer silinir. |

## Linux

Aynı uygulama Ubuntu 22.04 ve sonrasında (Wayland ve X11) çalışır. İşletim sistemiyle konuşan
modüllerin Linux karşılıkları `src-tauri/src/linux/` altındadır.

| Windows | Linux |
|---|---|
| Pano: `SetClipboardData`, geçmiş/bulut işaretleri | GTK panosu, `x-kde-passwordManagerHint: secret` |
| Otomatik kilit: `GetLastInputInfo`, oturum ve güç mesajları | D-Bus: Mutter/KDE boşta kalma (yoksa logind), ekran koruyucu, logind `Lock`, `PrepareForSleep`, `PrepareForShutdown` |
| Süreç DACL'ı, `SetDefaultDllDirectories`, WER dışlaması | `PR_SET_DUMPABLE=0` (WebKit alt süreçleri dahil), core dump 0 |
| Ekran görüntüsünden gizleme | Yok (X11 ve Wayland'de böyle bir ayar yok) |
| Google erişim anahtarı: DPAPI | Secret Service (GNOME Keyring / KWallet) |
| Açılışta başlat: HKCU `Run` | `~/.config/autostart/com.alperen.lockalperen.desktop` (0600) |
| Siteyi aç: `ShellExecuteW` | `xdg-open` |
| Tarayıcı eklentisi: **yok** | Unix soketi + native messaging manifestleri (`src/bridge/`) |
| Otomatik yazma, genel kısayollar | **Yok.** Wayland başka pencereye tuş göndermeye izin vermiyor; arayüz bu seçenekleri göstermiyor. |

**Paketler:** `.deb` (bağımlılıklar: WebKitGTK 4.1, `libayatana-appindicator3-1`, `xdg-utils`) ve
AppImage. Ubuntu 22.04'te derlenir, 22.04 ve sonrasında çalışır.

## Doğrulananlar

**Otomatik testler (2026-11-24, Linux):**
- Masaüstü: 122 test. Bunların arasında tarayıcı köprüsünün JS ve Rust tarafının birbirine karşı
  sınandığı Noise testi de var.
- Çekirdek: 146 test.
- `cargo fmt`, `clippy -D warnings` ve `cargo audit` temiz; `npm audit --omit=dev` temiz.

**CI (her commit'te):** Windows (MSVC) ve Ubuntu 22.04'te derleme, testler, Linux paketleri,
libFuzzer hedefleri ve bağımlılık taraması.

**Elle ve otomasyonla denenenler (Windows):**
- **Kasa:** kasa açma, yanlış parolada genel mesaj, liste, arama, Ctrl+L, XSS başlığının düz metin
  görünmesi.
- **İçe aktarma:** KeePass içe aktarma (yanlış ve doğru parola). Testlerde gerçek bir KDBX 4
  dosyası, aşırı KDF ayarlarının hesaplama yapılmadan reddi ve 300 bozuk dosyada panik
  olmaması sınanıyor.
- **Pano:** 13 sn sonra temizleniyor; sonradan kopyalanan içerik korunuyor.
- **Otomatik kilit:** `LAV_IDLE_SECS=20` ile denendi. Win+L'yi proje sahibi doğruladı.
- **TOTP:** Python'la bağımsız hesaplanan kodla aynı çıktı.
- **Arka plan ve otomatik yazma:** Sistem simgesi, tek örnek, otomatik yazma kısayolu (tek eşleşme
  yazıyor; çoklu eşleşme, eşleşme yokluğu ve kilitli kasa yazmıyor), sürükle-bırak.

**Linux'ta denenenler:**
- Uygulama Ubuntu masaüstünde çalıştı.
- Kilit durumu değişince üst çubuğa doğru simge bildiriliyor (D-Bus `NewIcon` izlendi).
- Tarayıcı köprüsünde gerçek native host üzerinden uçtan uca bağlantı kuruluyor. Eşleştirilmemiş
  eklenti `not_paired` dışında bir şey alamıyor.

## Doğrulanmayanlar ve sınırlar

- **Linux masaüstünde elle denenmesi gerekenler:**
  - Üst çubuktaki simgenin kilitte değiştiğinin gözle görülmesi.
  - Eklentinin gerçek Chrome'da eşleştirilip doldurması.
  - Ekran kilidi ve uykuda kilitlenme.
  - Pano yöneticisiyle pano davranışı.
  - `.deb`/AppImage güncellemesi.
- **Windows:**
  - Pano geçmişi işaretlerinin Win+V'de gerçekten gizlendiği gözle kontrol edilmedi.
  - Uyku sonrası kilitlenme elle denenmedi.
  - Caps Lock uyarısı elle denenmedi.
  - "Windows ile başlat" kayıt defteri testi çalıştırılmadı.
- **Bellek:** WebView ve JavaScript dizeleri ile Tauri'nin ara tamponları silinemez. Gösterilen ya
  da düzenlenen değerler WebView belleğinde kalır.
- **Pano:** Windows'un bıraktığı pano belleği bizim tarafımızdan silinmez; pano açıkken başka bir
  program içeriği okuyabilir.
- **KeePass:** `keepass` crate'inin çözdüğü verinin bellekte silinip silinmediği doğrulanmadı.
  Sıkıştırılmış içerik en fazla 384 MiB'a açılır (gzip bombası); bunun için `keepass` crate'inin
  yamalı bir kopyası kullanılıyor (`src-tauri/vendor/keepass/LOCKALPEREN.md`). Geçmiş ve özel
  ikonlar aktarılmıyor.
- **KDF satırı:** Kilit açma ekranındaki satır henüz doğrulanmamış başlıktan okunuyor; yalnızca
  bilgi amaçlı.

Açık güvenlik maddelerinin tam listesi:
[docs/SECURITY_COMPARISON_2026-11.md](../../docs/SECURITY_COMPARISON_2026-11.md).

## Henüz yapılmayanlar

- **Tarayıcı eklentisi Windows'ta:** named pipe ve kayıt defteri tarafı yazılmadı.
- **Linux'ta otomatik yazma ve genel kısayollar:** X11 (XTest) ve yeni GNOME'larda (GlobalShortcuts
  portalı) yapılabilir.
- **Kod imzası:** Windows kurulum dosyası imzasız.
- **Windows Hello:** proje sahibinin kararıyla yapılmıyor.
- **Sızıntı kontrolü:** ağ erişimi gerektiriyor, henüz yok.
