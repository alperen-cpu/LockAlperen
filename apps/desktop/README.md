# LockAlperen masaüstü

Tauri 2 + React 19. Görünüm, "LockAlperen Ekran Taslakları" tasarımındaki kilit açma ve ana
ekranı izliyor. Çalışanlar: kasa aç, listele, kilitle, kullanıcı adı/parola kopyala, parolayı göster, otomatik kilit, yeni kasa oluştur, son kasalar, kayıt ekle/düzenle/sil, klasörler, parola üretici, TOTP kodları, parola sağlığı, KeePass (KDBX 4) içe aktarma, CSV dışa aktarma, anahtar dosyası, özel alanlar, ekler, kayıt geçmişi, otomatik yazma, site ikonları, ana parola değiştirme, uygulama içi güncelleme.

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

## Güvenlik kararları

| Konu | Uygulama |
|---|---|
| IPC yüzeyi | WebView yalnızca uygulamanın kendi komutlarını çağırabilir (43 komut, tek tek `capabilities/main.json`'da listeli). Core, dosya sistemi, shell ya da diyalog yetkisi yok. Komutlar `build.rs`'te tanımlı, yetki verilmeyen komut reddedilir. |
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
| TOTP | RFC 6238; SHA-1/256/512, 6–8 hane, 1–300 sn periyot; base32 anahtar ya da `otpauth://totp/` bağlantısı (HOTP desteklenmez). Gizli anahtar Rust'ta kalır; WebView'e yalnızca o anki kod ve kalan süre gider (listede yalnızca `hasTotp`). HMAC RustCrypto'dan (`hmac`, `sha1`, `sha2`); kendi kodumuz yalnızca RFC'nin kesme adımı ve base32 çözümü, ikisi de RFC test vektörleriyle sınanıyor. Düzenleyicide anahtar görünür (düzenleme için). Geçersiz anahtar kaydedilmez. |
| Parola sağlığı | Rust'ta hesaplanır; WebView'e yalnızca sayılar ve kayıt başına etiket (zayıf/tekrar/süresi dolmuş) gider. Tekrar kontrolü parolaları kopyalamadan, ödünç alarak karşılaştırır. **Zayıflık tahmini basittir:** uzunluk × log2(kullanılan karakter türleri), 60 bitin altı ya da 10 karakterden kısa = zayıf. Sözlük kelimeleri ve kalıplar tanınmaz ("Password123!" zayıf sayılmaz); arayüz bunu söylüyor. Ağ kullanılmaz; sızıntı kontrolü yok. |
| KeePass içe aktarma | Dosya güvenilmez kabul edilir. `keepass` crate'ine vermeden önce dış başlığı **kendimiz** okuruz: yalnızca KDBX 4, en fazla 64 MiB, KDF sınırları (Argon2 ≤ 1 GiB bellek, ≤ 100 iterasyon, ≤ 16 paralellik; AES-KDF ≤ 300 milyon tur). Crate bu parametreleri sınırlamıyor; sınır olmasa kötü niyetli bir dosya, parola denenmeden önce sınırsız bellek ya da süre harcatabilirdi. Çözüldükten sonra kayıt (50.000), klasör (10.000), derinlik (64), alan (1 MiB), ek (16 MiB, toplam 256 MiB) sınırları; KeePass Geri Dönüşüm Kutusu ve geçmiş aktarılmaz; sonuç `repair_structure`'dan geçer ve **yeni bir üst klasöre** eklenir. Hata durumunda kasa değişmez. KeePass dosyası değiştirilmez. Anahtar dosyası henüz desteklenmiyor. |
| Süreç sertleştirme | Başlangıçta, hiçbir sır yokken: `SetDefaultDllDirectories(SYSTEM32)`; süreç DACL'ı yalnızca sorgula/bekle/sonlandır (bellek okuma yok). Pencere `WDA_EXCLUDEFROMCAPTURE` ile ekran görüntüsü ve paylaşımdan hariç (debug derlemede `LAV_ALLOW_CAPTURE=1` ile kapatılabilir; release'te yok sayılır). `unsafe` kod `src/hardening.rs`'te. *Doğrulandı:* başka süreçten `OpenProcess(VM_READ)` ve `ALL_ACCESS` reddediliyor (hata 5), `taskkill` çalışıyor, ekran görüntüsünde pencere yok; debug ve release derlemede. **Sınır:** aynı kullanıcı DACL'ı yeniden yazabilir, yöneticiler (`SeDebugPrivilege`) atlar. |
| Anahtar sayfaları | `lav-core` türetilmiş anahtar ayırmasını `VirtualLock`/`mlock` ile RAM'de kilitler (`region` crate'i; çekirdekte `unsafe` yok). Yalnızca anahtar sayfası; çözülmüş içerik kilitli değil, hibernate tüm belleği yazar. |
| Anahtar dosyası | Kilit açmada isteğe bağlı; dosya Rust'taki pencereyle seçilir, yolu Rust'ta kalır. Başka kasa seçilince unutulur. Gereksiz anahtar dosyası da aynı genel hatayı verir. |
| Özel alanlar, ekler, geçmiş | Ayrıntıda gizli alan değerleri ve notlar gönderilmez; tıklanınca tek tek istenir, 15 sn sonra düşer. Kopyalama Rust'ta (pano kuralları aynı). Ekler "Kaydet…" ile diske **şifresiz** yazılır (arayüz söylüyor). Geçmiş yalnızca üst veri gösterir. Düzenleyicide özel alan ekle/sil; `fields` gönderilmezse mevcut alanlar korunur. |
| Ayarlar | `%LOCALAPPDATA%\...\settings.json`: otomatik kilit süresi ve açılışta güncelleme denetimi; geçersiz değer varsayılana (5 dk) düşer, eksik alan varsayılanını alır (eski dosyadaki değerler korunur). |
| Güncellemeler | `tauri-plugin-updater`: açılışta (kapatılabilir) ya da Ayarlar'dan elle denetlenir; kurulum onayla. HTTPS, gömülü anahtarla minisign doğrulaması, imza sürüme bağlı, sürüm düşürme yok, indirme adresi bu reponun Releases'ı. Kurulumdan önce kasa kilitlenir ve pano temizlenir. WebView yalnızca `check_update`/`install_update` çağırabilir. Ayrıntı: [docs/UPDATES.md](../../docs/UPDATES.md). |
| Klasörler | Oluştur, yeniden adlandır, sil. Silme klasörü, alt klasörlerini **ve içindeki kayıtları** siler: arayüz sayıyı gösterir, iki kez onay ister. Ana klasör silinemez. |
| Ana parola değiştirme | Mevcut parola yeniden istenir (KeePassXC CVE-2023-35866 dersi). Yeni tuz ve anahtar; eski `.bak` silinir. Kayıt başarısız olursa eski parola geri konur (bellek ve disk aynı kalır). Anahtar dosyası varsa korunur. |
| Dışa aktarma | CSV; ana parola yeniden doğrulanır; hücreler kaçışlanır ve formül olarak çalışmaz; dosya şifresizdir (arayüz söyler). |
| Otomatik yazma | Hedef pencere doğrulanmadan yazmaz (başka süreç + başlıkta kayıt adı ya da site). Pencere değişirse durur. `unsafe` kod `src/autotype.rs`'te. |
| Site ikonları | **Otomatik** (proje sahibinin kararı): kilit açıldıktan ve bir kayıt kaydedildikten sonra arka planda, ikonu olmayan kayıtlar için. `lav-favicon` ile doğrudan siteye bağlanılır (üçüncü taraf servis yok), yalnızca açık internet adresleri, boyut ve süre sınırlı; resim yeniden kodlanmış PNG olarak kasada şifreli saklanır. Her kayıt uygulama açıkken bir kez denenir. **Gizlilik sonucu:** siteler ve ağ (ör. şirket proxy'si, DNS), kasada hangi sitelerin olduğunu görebilir. CSP'ye yalnızca `img-src data:` eklendi. |
| Geçmiş ve ekler | Eski sürüm iki onayla geri yüklenir; şimdiki hâl geçmişe eklenir (kayıp yok). Ek ekleme: dosya Rust'taki pencereyle seçilir, en fazla 16 MiB, kasada şifreli. |
| Kilit | Kilitlemek kasayı bırakır; anahtarları ve içeriği `lav-core` siler. Başarısız bir yeniden deneme ya da yeni dosya seçmek de kilitler. |

## Doğrulananlar

- `cargo test`: 50 test (masaüstü) + çekirdekte sayfa kilidi testi (Windows, GNU araç zinciri). Gerçek panoyu kullanan 2 test
  (`cargo test -- --ignored --test-threads=1`) elle çalıştırıldı ve geçti: üç işaret konuyor,
  temizleniyor, sonradan kopyalanan içerik silinmiyor.
- KeePass içe aktarma elle denendi: yanlış parolada genel mesaj; doğru parolayla 3 kayıt, 1 klasör,
  1 TOTP aktarıldı, sağlık kartı güncellendi. Testler: gerçek KDBX 4 dosyası (crate'in kendi
  yazıcısıyla, yalnızca testte), yanlış parola, KDBX 3.1 ve rastgele dosyanın reddi, **aşırı KDF
  ayarlarının hiçbir hesaplama yapılmadan reddi**, 300 rastgele bozulmuş dosyada panik olmaması
  (mutasyon testi; libFuzzer değil).
- Sertleştirme, özel alan, gizli değer gösterme, geçmiş ve ayarlar elle denendi (ekran görüntüleri
  ile). Anahtar dosyası birim testlerle (gerekli/yanlış/taşınmama) sınandı, arayüzde elle
  denenmedi.
- Parola sağlığı elle denendi: demo kasada aynı parolayı kullanan 4 kayıt "Tekrar" olarak
  işaretlendi, oran %0. Testler: tahmin sınırları, sayımlar, rapor JSON'unda parola olmaması.
- TOTP elle denendi: uygulamadaki kod, Python'un `hmac` kütüphanesiyle bağımsız hesaplanan değerle
  aynı (810016, aynı saniye). RFC 6238 Ek B vektörlerinin hepsi (SHA-1/256/512, 6 zaman) ve RFC
  4648 base32 vektörleri testte.
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

- **MSVC:** yerelde GNU ile derlendi. Release derlemesi (GNU, LTO) yerelde derlendi ve çalıştırıldı:
  konsol penceresi yok, sertleştirme etkin. MSVC sonucunu CI işi gösterir.
- **GNU bağlayıcı uyarısı:** "multiple non-default manifests". Dosya seçme penceresi çalıştı;
  release ya da MSVC'de bu uyarı beklenmiyor ama doğrulanmadı.
- **Caps Lock uyarısı:** otomasyonla denenemedi, elle denenmeli.
- **IPC tamponları:** parola JSON olarak WebView'den Rust'a gider. WebView/JS dizgileri ve
  Tauri'nin ara tamponları silinemez. Bu, SECURITY.md'de belirtilen bilinen sınır.
- **Anahtar dosyası:** kilit açma, yeni kasa ve KeePass içe aktarmada destekleniyor (içe aktarmanın anahtar dosyası kasanınkinden ayrı tutulur).
- **Pano:** Windows'un `EmptyClipboard` ile bıraktığı bellek bizim tarafımızdan silinmez; pano
  açıkken başka bir program içeriği okuyabilir. Pano geçmişi işaretlerinin Win+V'de gerçekten
  gizlendiği elle (Win+V açılarak) **kontrol edilmedi**; yalnızca işaretlerin konduğu doğrulandı.
- **Win+L:** proje sahibi elle doğruladı (2026-11-15): Win+L sonrası kasa kilitli. **Uyku** elle
  denenmedi.
- **Boşta kalma süresi** Ayarlar'dan seçilir (1–60 dk; "asla" bilinçli olarak yok).
- **KeePass:** başlık okuyucumuz için libFuzzer hedefi yok (masaüstü crate'i yalnızca Windows'ta
  derleniyor, fuzz CI'ı Linux'ta); yerine mutasyon testi var. `keepass` crate'inin çözdüğü
  verinin bellekte silinip silinmediği crate'e bağlı, doğrulanmadı. Geçmiş, otomatik yazma ve
  özel ikonlar aktarılmıyor.
- **KDF satırı** ("Argon2id · 64 MiB · 3 geçiş") henüz doğrulanmamış header'dan okunuyor; yalnızca
  bilgi amaçlı.

## Henüz yapılmayanlar

- **Windows Hello:** proje sahibinin kararıyla yapılmıyor.
- **Kod imzası:** sertifika gerekiyor. Kurulum dosyası (NSIS) imzasız.
- **Klasör taşıma:** klasörler oluşturulup yeniden adlandırılıp silinebiliyor; başka klasörün altına taşınamıyor (kayıtlar düzenleyiciden taşınabiliyor).
- **Tasarımdaki iki ifade bilinçli olarak alınmadı:**
  - "Kasanız bu bilgisayardan hiç çıkmaz": kasa OneDrive'daysa doğru değil.
  - "Sızıntılarda bulunmadı": ağ erişimi gerektiriyor ve bu özellik henüz yok.
