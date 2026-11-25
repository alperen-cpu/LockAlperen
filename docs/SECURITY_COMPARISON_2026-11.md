# Rakiplerin açıkları ve LockAlperen (2016–2026), 2026-11-24

Son 10 yılda rakip parola yöneticilerinde çıkan açıklar sınıf sınıf incelendi ve LockAlperen'in her
sınıftaki durumu kodda kontrol edildi. Ham notlar ve kaynaklar:

- `docs/research/rakipler-masaustu-2016-2026.md`: 62 kayıt (KeePass, KeePassXC, KeePassRPC,
  KeePassDX, KeeWeb, Bitwarden masaüstü, 1Password 7/8, Enpass, Dashlane, LastPass, Password Safe).
- `docs/research/rakipler-eklenti-2016-2026.md`: 48 açık ve 5 araştırma (tarayıcı eklentileri,
  otomatik doldurma, masaüstü–tarayıcı köprüleri, bulut). Eklentimiz için 38 MUST/SHOULD kuralı
  içerir.
- `docs/research/pentest-2026-11-24.md`: bu kod tabanına beyaz kutu inceleme.

**Doğrulama notu:** Kayıtlar NVD, MITRE, satıcı duyurusu ya da araştırmacı yazısından kontrol edildi.
Şunlar ayrıca elle doğrulandı:
- CVE-2026-118673 (KeePassXC native messaging sınır dışı yazma, 2.8.0'da düzeltildi)
- CVE-2026-69150 (KeePassXC KDB içe aktarmada use-after-free)
- CVE-2026-4158 / ZDI-26-215 (KeePassXC OpenSSL yapılandırma arama yolu)
- Tóth'un DEF CON 33 "DOM tabanlı eklenti clickjacking" çalışması: 11 yöneticiden 10'unda giriş
  bilgisi sızıyordu.

"Disputed" işaretli CVE'leri satıcılar tehdit modeli dışı saydı; burada yine de test durumu olarak
kullanıldılar.

Durum anahtarı:
- **Var:** kodda var, test ya da elle doğrulama yapıldı.
- **Düzeltildi:** bu incelemede düzeltildi; testi eklendi.
- **Açık:** henüz yapılmadı.
- **Elle test:** otomatik test edilemiyor; aşağıdaki listede.

## Özet

| Sınıf | Rakiplerde ne oldu | LockAlperen | Durum |
|---|---|---|---|
| A. Bellekte kalan sırlar | KeePass CVE-2023-32784 (her tuş için kalan dize), KeePassXC CVE-2024-33900/33901, Bitwarden CVE-2023-38840, Enpass CVE-2024-9203, ISE 2019 (1Password, Dashlane, LastPass) | Ana parola ve anahtarlar `Zeroizing`/`zeroize` içinde; anahtar sayfaları `mlock` (`key_pages_locked` testi); kilitlenince oturum düşer. Linux'ta ana süreç `PR_SET_DUMPABLE=0`, core dump 0. WebKit alt süreçleri (gösterilen parola, düzenlenen kayıt) `exec` yüzünden dump alınabilir durumdaydı (pentest #1); artık `LD_PRELOAD` ile yüklenen küçük bir kütüphane onlarda da `PR_SET_DUMPABLE=0` yapıyor. | Düzeltildi. |
| B. Pano | KeePass/Fedora CVE-2022-0725 (pano içeriği journal'a düştü), Win+V geçmişi ve bulut panosu | Windows'ta üç işaret (geçmiş/bulut/izleyici). Linux'ta `x-kde-passwordManagerHint: secret`. Süre dolunca yalnızca hâlâ bizim içeriğimizse temizlenir. | Var. Linux'ta pano yöneticisiyle elle test. |
| C. Yerel IPC ve uç noktalar | KeePassRPC CVE-2020-16271/16272 (WebSocket kimlik doğrulama), 1Password CVE-2024-42219 ve CVE-2022-29868 (süreç kimliğine güven), KeePassXC CVE-2026-118673 | Dinleyen port yok. 78 IPC komutu tek tek izinli; fs/shell/dialog yetkisi yok; yol Rust'ta kalır. OAuth dönüşü yalnızca `127.0.0.1:0`, `state` ve PKCE ile, tek kullanımlık. | Var. |
| D. Dosya ayrıştırma | KeePassDX XXE CVE-2018-1000835, KeePass CVE-2026-86776 (devasa başlık ayırma), KeePassXC CVE-2026-69150 (UAF), ek adı ile klasör dışına çıkma (KeePassXC 2.7.12) | `.lav`: KDF sınırları KDF çalışmadan önce, başlık doğrulanır (key commitment v2). KDBX: boyut ve KDF ön kontrolü; quick-xml dış varlık çözmez. `keepass` crate'inin gzip açması sınırsızdı (pentest #4); yamalı kopyada 384 MiB sınırı var. Ek adları artık temizleniyor. | Düzeltildi. |
| E. Kripto ve KDF | LastPass ve Bitwarden düşük PBKDF2 sayısı, 1Password CVE-2020-10256 (zayıf RNG), sıkıştırma yan kanalı (USENIX '24, KeePassXC), Bitwarden PIN kaba kuvvet | Argon2id; açarken ve oluştururken alt sınır (19 MiB, 2 geçiş) ve üst sınır. Rastgelelik OsRng. `.lav` sıkıştırma kullanmaz. PIN ile hızlı açma yok. | Var. |
| F. Güncelleme ve tedarik zinciri | KeePass CVE-2016-5119 (imzasız HTTP), sahte Bitwarden kurulumu, Bitwarden CLI npm (2026), 1Password CVE-2024-42218 (eski sürüme düşürme), KeeLoader | HTTPS, depoya sabitli adres, minisign imzası, `requireSignedVersion`, eski sürüme düşürme yok (pentest doğruladı). Güncellemeyi kurma WebView'den tetiklenebiliyordu (pentest #6); artık Rust'ın açtığı yerel bir sistem penceresinde onaylanıyor. Windows kurulum dosyası Authenticode imzasız. | Var. Kod imzası açık. |
| G. Otomatik yazma ve pencere hedefleme | KeePass (pencere adı taklit edilebilir), NDSS '26 "Vault Raider" (KeePassXC, 1Password, LastPass) | Yalnızca Windows. Eşleşme pencere adıyla. Birden fazla eşleşme ya da hiç eşleşme yoksa hiçbir şey yazılmaz; Ctrl basılıysa yazılmaz. Pencerenin programı Windows ya da Program Files klasöründe olmalı veya geçerli Authenticode imzası taşımalı. Genel kısayol yazılımla gönderilmişse (`LLKHF_INJECTED`) reddedilir. | Var. İmzalı zararlıya karşı yok. |
| H. Yapılandırma oynama ve yeniden doğrulama | KeePass CVE-2023-24055 (tetikleyiciyle dışa aktarma), 1Password `settings.json` (DEF CON 2024), KeePassXC CVE-2023-35866, CSV formül enjeksiyonu CVE-2019-20184 | Tetikleyici ya da betik yok; geçersiz ayar varsayılana düşer; boşta kilit "asla" olamaz. Dışa aktarma, ana parola ve KDF değişikliği ana parolayı yeniden ister. CSV hücreleri tırnaklı ve `= + - @` önekli. Dosyalar 0664 idi; artık 0600. | Var. İzinler düzeltildi. |
| I. DLL ve kütüphane arama yolu | Dashlane CVE-2017-11657, KeePassXC CVE-2026-4158 (OpenSSL yapılandırması), KeePass eklenti önbelleği | `SetDefaultDllDirectories(SYSTEM32)`. OpenSSL yok, `reqwest` rustls kullanır. Eklenti sistemi yok. | Var. Procmon ile elle test. |
| J. WebView ve uzak içerik | Bitwarden Cure53 BWN-08-014/013 ve BWN-01-006 (URI ile kod çalıştırma), Enpass CVE-2024-26362 (notta HTML), KeeWeb | Katı CSP (`unsafe-inline` yok); `innerHTML` yok. Renk yalnızca `#rrggbb`. Yalnızca http/https açılır, `xdg-open` argv ile çağrılır. Favicon yalnızca Rust tarafında indirilir: HTTPS, DNS sabitleme, özel IP'ler engelli, resim yeniden kodlanır. İçe aktarılan kayıtların ikonu artık yalnızca istenince indiriliyor (pentest #5); otomatik indirme Ayarlar'dan kapatılabilir. | Var. |
| K. Yerel anahtar saklama | Bitwarden CVE-2023-27706 (biyometri anahtarı Credential Manager'da) | Kasa anahtarı hiç saklanmaz. Yalnızca Drive yenileme anahtarı saklanır: Windows'ta DPAPI, Linux'ta Secret Service. Bunlara aynı kullanıcı erişebilir; bu belgelendi. | Var. |
| L. Ekran görüntüsü | Rakiplerde CVE yok; KeePassXC ve Bitwarden bunu sertleştirme olarak sunuyor | Windows'ta `WDA_EXCLUDEFROMCAPTURE`. Linux'ta mümkün değil; belgelendi. | Var. |
| M. Kilit ve oturum | ISE 2019: kilitten sonra düz metin kalıyordu | Boşta kalma, ekran kilidi, uyku ve kapanmada kilit. Kilit kararını Rust verir. | Var. Linux'ta elle test. |
| N. Windows çökme dökümleri | Enpass 2017 (WER dökümünde kasa verisi) | Linux'ta core dump 0 (WebKit alt süreçleri dahil). Windows'ta program WER dışlama listesinde (`WerAddExcludedApplication`) ve döküm alınırsa yığın dışarıda (`WER_FAULT_REPORTING_FLAG_NOHEAP`). | Var. WebView2 süreçleri dışlanmıyor. |
| O. Bağımlılıklar | Bitwarden ve 1Password'da gömülü kütüphane açıkları (libwebp CVE-2023-4863) | `url` 2.5.8, RUSTSEC-2026-0592 açığını taşıyordu; iki çalışma alanında da 2.5.9'a yükseltildi. Diğer uyarılar `SECURITY.md`'de gerekçeli. | Düzeltildi. |

## Bu incelemede yapılan düzeltmeler

1. **Dosya izinleri 0600/0700** (pentest #2, sınıf H). Kasa, `.bak`, `.lock`, ayarlar, son
   kasalar, Drive deposu, dışa aktarmalar (CSV/KDBX/HTML), kaydedilen ekler, anahtar dosyası ve
   otomatik başlatma `.desktop` dosyası artık yalnızca kullanıcıya açık. Önceden umask 0002 ile 0664
   idi: grup üyeleri kasayı değiştirebilir, `.desktop` dosyasıyla açılışta kod çalıştırabilirdi.
   Kod: `apps/desktop/src-tauri/src/private.rs` ve `crates/lav-core/src/vault.rs`. Test:
   `private::tests`.
2. **Ek adı temizleme** (sınıf D, KeePassXC 2.7.12 ile aynı açık). Kaydetme penceresine önerilen
   ad, kasadan gelen ada güvenmez. Yalnızca son parça kalır; kontrol karakterleri ve bidi karakterleri
   (`fatura‮fdp.exe` gibi) atılır; Windows'ta yasak karakterler `_` olur. Test:
   `attachment_names_cannot_leave_the_chosen_folder_or_disguise_themselves`.
3. **`url` 2.5.9** (RUSTSEC-2026-0592). `cargo audit` yeniden temiz.

## İkinci turda kapatılanlar (2026-11-24)

| # | Konu | Ne yapıldı | Kod |
|---|---|---|---|
| 1 | WebKit alt süreçleri dump alınabilir (Linux) | `nodump/nodump.c` paketle gelir, uygulama onu `LD_PRELOAD`'a ekler; yalnızca `WebKit*` süreçlerinde `PR_SET_DUMPABLE=0` yapar. Gerçek uygulamada doğrulandı: `/proc/<pid>/mem` root'a geçti, `environ` okunamıyor. | `src/linux/hardening.rs`, `nodump/` |
| 2 | Windows çökme dökümleri | WER dışlama listesi ve yığınsız döküm bayrağı. | `src/hardening.rs` |
| 3 | Güncelleme kurma yeniden doğrulamasız | Rust'ın açtığı yerel onay penceresi; WebView onaylayamaz. Ana parola değil, çünkü güncelleme kilit ekranında da önerilir. | `src/confirm.rs`, `src/update.rs` |
| 4 | İçe aktarılan kayıtlar için otomatik favicon | İçe aktarılan kayıtlar `icon_on_request` ile işaretlenir; yalnızca düğmeyle indirilir. Otomatik indirme Ayarlar'dan kapatılabilir. | `lav-core` `Entry`, `src/import.rs`, `src/lib.rs` |
| 5 | KDBX gzip bombası | `keepass` 0.17.0'ın yamalı kopyası: açılan veri en fazla 384 MiB. | `vendor/keepass` |
| 6 | Otomatik yazmada pencere taklidi (Windows) | Hedef programın klasörü ya da imzası denetlenir; yazılımla gönderilen kısayol reddedilir. | `src/wintarget.rs`, `src/hotkey.rs` |

## Açık kalanlar

| # | Konu | Neden önemli | Gereken |
|---|---|---|---|
| 7 | Windows kod imzası | Sahte kurulum dosyasıyla saldırılar (Bitwarden ZenRAT, KeeLoader). | Authenticode sertifikası (proje sahibinin kararı: SignPath Foundation, Certum açık kaynak sertifikası ya da Azure Trusted Signing). |
| 8 | Windows'ta yeni korumaların elle testi | 2, 6 ve kısayol kancası yalnızca Windows hedefiyle derlenip CI'da test edildi. | Gerçek Windows'ta: imzalı/imzasız hedef pencere, gerçek ve sentetik kısayol, WER kaydı. |

## Elle test listesi (gerçek masaüstünde)

- [ ] **Bellek (A):** Benzersiz bir test parolasıyla aç, kopyala, kilitle. Ana süreç ve WebKit
  süreçlerinin `gcore` dökümünde `strings` ile ara. Beklenen: ana süreçte kilitten sonra iz yok;
  WebView'de kalanlar belgelenmeli.
- [ ] **Pano (B):** CopyQ ya da GNOME pano eklentisiyle kopyalanan parola geçmişe düşmemeli;
  `journalctl` içinde bulunmamalı.
- [ ] **Kilit (M):** Ekran kilidi, uyku ve kullanıcı değiştirmede kasa kilitlenmeli; üst çubuktaki
  simge kırmızı kilide dönmeli.
- [ ] **Windows:** Procmon ile DLL arama yolu (I), Win+V (B), ekran görüntüsü (L).
- [ ] **Güncelleyici (F):** mitmproxy ile imzasız, farklı anahtarla imzalı ve eski sürüm `latest.json`
  denemeleri.

## Tarayıcı eklentisi

Rakiplerin en çok açık verdiği yer eklentiler ve masaüstü köprüleri (sınıf C, F, D, J). Eklenti
(`apps/browser-extension`, Chromium, yalnızca doldurma) bu kurallara göre yazıldı. Hangi kuralın
nasıl uygulandığı `apps/browser-extension/README.md`'deki tabloda; protokol testleri
`bridge::conn` ve `noise_interop`'ta. Uygulanan MUST kuralları:
- Dinleyen port yok; yalnızca native messaging.
- Kriptografik eşleştirme; kullanıcı her iki tarafta da kısa kodu karşılaştırır.
- Tam köken eşleşmesi.
- Çapraz kökenli ya da sandbox çerçevelere doldurma yok.
- Sayfa açılınca otomatik doldurma yok.
- Doldurma yalnızca araç çubuğu, kısayol ya da sağ tık menüsünden.
- TOTP ayrı bir eylemle.
- Eklenti ana parolayı asla sormaz.
- Eklentiden gelen veri `{REF:}` olarak çözülmez.
