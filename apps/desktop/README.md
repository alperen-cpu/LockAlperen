# LockAlperen masaüstü (Faz 2: iskelet)

Tauri 2 + React 19. Görünüm, "LockAlperen Ekran Taslakları" tasarımındaki kilit açma ve ana
ekranı izliyor. Bu ilk adımda yalnızca **kasa aç → listele → kilitle** çalışıyor.

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
| Kilit | Kilitlemek kasayı bırakır; anahtarları ve içeriği `lav-core` siler. Başarısız bir yeniden deneme ya da yeni dosya seçmek de kilitler. |

## Doğrulananlar

- `cargo test`: 9 test (Windows, GNU araç zinciri).
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
- **KDF satırı** ("Argon2id · 64 MiB · 3 geçiş") henüz doğrulanmamış header'dan okunuyor; yalnızca
  bilgi amaçlı.

## Tasarımda olup henüz yapılmayanlar

Sırayla ele alınacak. Her biri SECURITY.md "Faz 2" listesindeki ilgili maddeyle birlikte yapılacak:

- **Parolayı göster ve kopyala:** pano geçmişi ve bulut panosu dışında tutulacak, süre dolunca
  temizlenecek.
- **Otomatik kilit:** boşta kalınca, Windows kilitlenince, oturum değişince ve uyku moduna
  geçilince. Geri sayım göstergesi de bununla gelecek.
- **Ekran yakalamadan hariç tutma** (`WDA_EXCLUDEFROMCAPTURE`), `VirtualLock`,
  `SetDefaultDllDirectories`, süreç DACL'ı.
- **Diğer ekranlar ve özellikler:**
  - kayıt ekleme, düzenleme ve kaydetme;
  - parola üretici;
  - TOTP;
  - son kasalar (L2 ile yerel veri dizini);
  - parola sağlığı;
  - KeePass içe aktarma;
  - Windows Hello.
- **Tasarımdaki iki ifade bilinçli olarak alınmadı:**
  - "Kasanız bu bilgisayardan hiç çıkmaz": kasa OneDrive'daysa doğru değil.
  - "Sızıntılarda bulunmadı": ağ erişimi gerektiriyor ve bu özellik henüz yok.
