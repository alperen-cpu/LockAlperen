# LockAlperen masaüstü (Faz 2: iskelet)

Tauri 2 + React 19. Görünüm, "LockAlperen Ekran Taslakları" tasarımındaki kilit açma ve ana
ekranı izliyor. Çalışanlar: kasa aç, listele, kilitle, kullanıcı adı/parola kopyala, parolayı göster, otomatik kilit, yeni kasa oluştur, son kasalar, kayıt ekle/düzenle/sil, parola üretici.

## Geliştirme

```sh
cd apps/desktop
npm ci
npm run tauri dev          # Vite + uygulama
cd src-tauri && cargo test # oturum ve navigasyon testleri
```

Denemek için örnek kasa: `cargo run --example demo_vault -- demo.lav <parola>` (yalnızca deneme;
parola komut satırında görünür).

`src-tauri` ayrı bir Cargo çalışma alanıdır. Tauri bağımlılıkları çekirdeğin `Cargo.lock`
dosyasına, `cargo deny` politikasına ve Linux CI'ına girmez. CI'da ayrı bir Windows (MSVC) işi
var.

## Güvenlik kararları (bu adımda uygulananlar)

| Konu | Uygulama |
|---|---|
| IPC yüzeyi | WebView'e açık yalnızca 4 komut var: `pick_vault_file`, `unlock`, `lock`, `list_entries` (`capabilities/main.json`). Core, dosya sistemi, shell ya da diyalog yetkisi yok. Komutlar `build.rs`'te tanımlı, yetki verilmeyen komut reddedilir. |
| Dosya yolu | Kasa yolu yalnızca Rust tarafında tutulur. Dosya seçme penceresini Rust açar. WebView hiçbir zaman yol göndermez, bu yüzden WebView'e enjekte edilen bir betik başka bir dosyayı açtıramaz. |
| Sırlar | Liste yanıtında parola, not, TOTP, özel alan ve ek **yok** (`EntrySummary`). Test, IPC'ye giden JSON'u kontrol ediyor. |
| Ana parola | React state'inde tutulmaz. Kontrolsüz input kullanılır, gönderilirken okunup hemen temizlenir. Rust tarafında `Zeroizing<String>` içinde tutulur. |
| Hata mesajı | Kilit açma hatalarının hepsi tek bir Türkçe mesaj (`is_unlock_failure`). Dosya okunamazsa ayrı bir mesaj. |
| CSP | `default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `frame-src 'none'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`. Web fontu ve uzak içerik yok. |
| Navigasyon | Uygulama dışındaki bir adrese (uzak site, `file:`) gezinme engellenir (`navigation_allowed`, test var). |
| Geliştirici araçları | Tauri'nin `devtools` özelliği açık değil, bu yüzden inceleyici yalnızca debug derlemede var. **Release derlemede doğrulanmadı.** |
| XSS | Bütün metinler React ile düz metin olarak basılır, `innerHTML` yok. `<script>` başlıklı bir kayıtla elle denendi. |
| Pano | Kopyalamayı Rust yapar; değer WebView'e gitmez. Pano geçmişi (Win+V), bulut panosu ve izleyiciler için üç işaret (`ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0`) konur. 12 sn sonra ve kilitlenince pano temizlenir, ama **yalnızca hâlâ bizim içeriğimiz duruyorsa** (sıra numarası kontrolü). `unsafe` kod yalnızca `src/clipboard.rs`'te. |
| Parolayı göster | Yalnızca tıklanınca Rust'tan istenir; 15 sn sonra, başka kayıt seçilince ya da kilitlenince ekrandan ve React state'inden düşer. Bu sırada parola WebView belleğindedir (silinemez). |
| Otomatik kilit | Kararı Rust verir; WebView yalnızca geri sayımı gösterir ve kilidi açık tutamaz. **Boşta kalma:** sistem genelinde son klavye ya da fare girdisinden itibaren 5 dk (`GetLastInputInfo`). Debug derlemede `LAV_IDLE_SECS` ile kısaltılabilir, release derlemede bu değişken yok sayılır. **Windows olayları:** kendi gizli penceremiz şunları alır: Win+L, konsol ya da uzak bağlantının kesilmesi, oturum kapatma (`WM_WTSSESSION_CHANGE`) ve uyku (`PBT_APMSUSPEND`). Her durumda pano da temizlenir. `unsafe` kod `src/autolock.rs`'te. |
| Yeni kasa | Kaydetme penceresini Rust açar; yol Rust'ta kalır, `.lav` uzantısı eklenir. Parola ve tekrarı Rust'ta karşılaştırılır, en az 8 karakter (çekirdeğin kuralı). **Var olan dosyanın üzerine asla yazılmaz:** önce varlık kontrolü yapılır; arada dosya oluşursa çekirdeğin `save_file` kilidi altındaki kontrolü reddeder. "Üzerine yaz" seçeneği bilinçli olarak yok. Varsayılan KDF: Argon2id 64 MiB, 3 geçiş. |
| Son kasalar | `%LOCALAPPDATA%\com.alperen.lockalperen\recent.json`: en fazla 5 kayıt, yalnızca yol ve son açılma zamanı (ad, içerik ya da sır yok). Kasanın yanında ya da roaming profilde değil. Geçici dosya + rename ile yazılır; bozuk ya da 64 KiB'tan büyük dosya boş liste sayılır. WebView sıra numarası gönderir, yolu Rust çözer. "Listeden kaldır" dosyayı silmez. |
| Kayıt düzenleme | Değişiklik önce verinin **kopyasına** uygulanır ve diske kaydedilir; kayıt başarısız olursa bellek eski hâline döner (ekranda diske yazılmamış değişiklik görünmez). Dosya başka yerde değiştirildiyse (`FileChangedOnDisk`) üzerine yazılmaz. Düzenleyici açıkken parola ve notlar WebView'dedir (düzenlemenin doğası); Rust tarafındaki `EntryForm` bırakılırken silinir ve `Debug` çıktısında gizlidir. Önceki sürüm çekirdeğin geçmişine (son 20) girer. Silme iki adımlı onay ister. |
| Parola üretici | Çekirdeğin `OsRng` tabanlı üreticisi; WebView yalnızca ayarları gönderir. Gösterilen entropi yaklaşık değerdir (her kümeden en az bir karakter zorunluluğu hesaba katılmaz). |
| Kilit | Kilitlemek kasayı bırakır; anahtarları ve içeriği `lav-core` siler. Başarısız bir yeniden deneme ya da yeni dosya seçmek de kilitler. |

## Doğrulananlar

- `cargo test`: 29 test (Windows, GNU araç zinciri). Gerçek panoyu kullanan 2 test
  (`cargo test -- --ignored --test-threads=1`) elle çalıştırıldı ve geçti: üç işaret konuyor,
  temizleniyor, sonradan kopyalanan içerik silinmiyor.
- Düzenleyici elle denendi: Ctrl+N, alanlar, Ctrl+S; kayıt listeye ve diske geldi. Testler: ekle
  ve yeniden aç, düzenle/sil, **başka biri dosyayı değiştirdiyse bellek ve disk değişmiyor**, başlık,
  klasör ve kimlik kontrolleri, üretici ayarları, `Debug` gizliliği.
- Son kasalar elle denendi: oluşturulan kasa listeye yazıldı; uygulama yeniden açılınca seçili
  geldi ve parolayla açıldı.
- Yeni kasa elle denendi: kaydetme penceresi, parolalar uyuşmayınca mesaj, oluşturunca boş kasa
  açılıyor ve dosya diskte. Testler: kaydet-aç-yeniden aç, ad/tekrar/uzunluk kontrolleri, var olan
  dosyanın baytlarının değişmemesi.
- Otomatik kilit elle denendi (`LAV_IDLE_SECS=20`): geri sayım göründü, süre dolunca kasa
  kilitlendi ve bildirim çıktı. Gizli pencereye gönderilen gerçek mesajlarla (kilitlenme, uyku)
  kilitleme testi var.
- Pano elle de denendi: kopya → 13 sn sonra boş; araya kullanıcı kopyası girince korunuyor;
  Ctrl+L panoyu hemen temizliyor.
- `cargo clippy -D warnings` ve `fmt` temiz. `npm audit` 0 açık.
- `cargo audit`: bilinen açık yok. İki uyarı var: `proc-macro-error` bakımsız, `glib` unsound. İkisi
  de yalnızca Linux GTK yolunda; `cargo tree` ile Windows hedefinde olmadıkları doğrulandı.
- **Elle denenenler (debug derleme, Windows 10, GNU):**
  - dosya seçme;
  - yanlış parolada genel mesaj ve alanın temizlenmesi;
  - ardından doğru parolayla açma;
  - liste, klasör filtresi ve arama;
  - Ctrl+L ile kilitleme;
  - XSS başlığının düz metin görünmesi.

## Doğrulanmayanlar / bilinen sınırlar

- **Release derleme ve MSVC:** yerelde yalnızca debug ve GNU ile derlendi. MSVC sonucunu CI işi
  gösterecek.
- **GNU bağlayıcı uyarısı:** "multiple non-default manifests". Dosya seçme penceresi çalıştı;
  release ya da MSVC'de bu uyarı beklenmiyor ama doğrulanmadı.
- **Caps Lock uyarısı:** otomasyonla denenemedi, elle denenmeli.
- **IPC tamponları:** parola JSON olarak WebView'den Rust'a gider. WebView/JS dizgileri ve
  Tauri'nin ara tamponları silinemez. Bu, SECURITY.md'de belirtilen bilinen sınır.
- **Anahtar dosyası** desteklenmiyor. Kasa anahtar dosyası istiyorsa ekranda bir uyarı gösteriliyor.
- **Pano:** Windows'un `EmptyClipboard` ile bıraktığı bellek bizim tarafımızdan silinmez; pano
  açıkken başka bir program içeriği okuyabilir. Pano geçmişi işaretlerinin Win+V'de gerçekten
  gizlendiği elle (Win+V açılarak) **kontrol edilmedi**; yalnızca işaretlerin konduğu doğrulandı.
- **Win+L ve uyku:** Windows'un bu mesajları gizli pencereye gerçekten gönderdiği **elle
  doğrulanmadı** (oturumu kilitlemek otomasyonla yapılmadı). Denemek için: kasayı aç, Win+L'ye
  bas, geri dön; kasa kilitli olmalı.
- **Boşta kalma süresi** şimdilik sabit (5 dk), ayarı yok.
- **KDF satırı** ("Argon2id · 64 MiB · 3 geçiş") henüz doğrulanmamış header'dan okunuyor; yalnızca
  bilgi amaçlı.

## Tasarımda olup henüz yapılmayanlar

Sırayla ele alınacak. Her biri SECURITY.md "Faz 2" listesindeki ilgili maddeyle birlikte yapılacak:

- **Ekran yakalamadan hariç tutma** (`WDA_EXCLUDEFROMCAPTURE`), `VirtualLock`,
  `SetDefaultDllDirectories`, süreç DACL'ı.
- **Diğer ekranlar ve özellikler:**
  - özel alanlar, ekler ve geçmişi görüntüleme (düzenleyicide henüz yok);
  - TOTP;
  - parola sağlığı;
  - KeePass içe aktarma;
  - Windows Hello.
- **Tasarımdaki iki ifade bilinçli olarak alınmadı:**
  - "Kasanız bu bilgisayardan hiç çıkmaz": kasa OneDrive'daysa doğru değil.
  - "Sızıntılarda bulunmadı": ağ erişimi gerektiriyor ve bu özellik henüz yok.
