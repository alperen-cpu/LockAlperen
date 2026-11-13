# LockAlperen Güvenlik Denetim Raporu — Kasım 2026

| | |
|---|---|
| **Kapsam** | `lav-core` (format, kriptografi, anahtar yönetimi, veri modeli, dosya işlemleri, yedekler), `lav-favicon` (ağ, HTML ve resim işleme), CI ve bağımlılıklar |
| **Kapsam dışı (henüz yok)** | Masaüstü arayüzü (Tauri/WebView2), IPC, pano, oturum ve otomatik kilit, loglama altyapısı, KeePass içe aktarma. Bunlar yazılmadığı için **denetlenemedi**. Gereksinimleri bölüm 6'da |
| **Referanslar** | OWASP ASVS 5.0 (V11 Kriptografi, V14 Veri koruma, V5 Dosya işleme, V15 Güvenli kodlama ve mimari, V16 Loglama ve hata yönetimi), NIST SP 800-218 SSDF (PW.4, PW.7, PW.8, PW.9, PS.1, PS.2, RV.1–RV.3), OWASP Password Storage Cheat Sheet |
| **Yöntem** | 1) Kendi kod incelemem. 2) Önceki bulguları görmeden çalışan bağımsız bir inceleme ajanı. 3) Diğer parola yöneticilerinin açıkları üzerine araştırma. 4) Her bulgu için düzeltmeden önce başarısız olan bir regresyon testi. 5) Canlı süreç belleği taraması. 6) Serbest bırakılan bellek bloklarını tarayan özel bir allocator. 7) Mutasyon tabanlı fuzz testi ve property testleri. 8) `cargo audit`, `cargo deny`, `clippy -D warnings` |

> **Okuma notu.** "Doğrulandı" yalnızca açığı bir testle ya da gerçek saldırı simülasyonuyla
> kanıtladığım bulgular için kullanılıyor. Kod okumaya dayanan ama gösterilemeyen riskler
> "Teorik" olarak işaretli. Yapılmayan testler bölüm 5'te açıkça yazılı.

---

## 1. Yönetici özeti

- **19 bulgu** var: **0 kritik, 0 yüksek, 7 orta, 9 düşük, 3 bilgi.**
- **17'si testle doğrulandı ve düzeltildi.**
  - 1'i (LA-19) yalnızca kod okumasıyla tespit edilip düzeltildi, saldırı testi yapılamadı.
  - 1'i (LA-02) **yeniden üretilemedi.** Yalnızca savunma derinliği olarak sıkılaştırıldı.
- **Bu turda benim eklediğim kodda 2 ciddi hata çıktı.** Bunları bağımsız inceleme yakaladı: LA-09 (hazırlanmış bir dosya bütün kasayı silebiliyordu) ve LA-11 (yarış durumunda değişiklik kaybı). Bu, her değişikliğin bağımsız bir gözle incelenmesi gerektiğini gösteriyor (bölüm 7).
- **Değiştirilmeyenler:** Kriptografik mimari (algoritmalar, anahtar türetme zinciri, dosya formatı) **değiştirilmedi**. Yalnızca KDF parametrelerinin alt ve üst sınırları sıkılaştırıldı. Format değişikliği gerektiren iki öneri sizin onayınızı bekliyor (R1, R2).
- **Test durumu:** 61 test geçiyor, 0 başarısız. Bunlara ek olarak gerçek ağa çıkan 1 test var, ayrıca çalıştırıldığında o da geçiyor.

## 2. Bulgular

Önem dereceleri, uygulamanın yerel ve tek kullanıcılı tehdit modeline göre verildi.

| ID | Önem | Bulgu | Durum | Kanıt (önce → sonra) |
|---|---|---|---|---|
| LA-01 | **Orta** | 4 KiB'tan uzun notlar ve ekler, kasa kilitlendikten sonra süreç belleğinde kalıyordu (CVE-2023-32784 sınıfı). Sebep: ciborium uzun alanları büyüyen bir tamponla okuyor ve eski kopyaları silmeden serbest bırakıyordu | Düzeltildi | Canlı süreç belleği taraması: not parçası **2.672 → 0** sonuç (3 tekrar, kontrol kanaryaları pozitif) |
| LA-03 | **Orta** | Yeni bir kasa, var olan bir kasa dosyasının üzerine sessizce yazılabiliyordu. Aynı dosyayı açan iki örnekten biri diğerinin değişikliklerini siliyordu (veri kaybı) | Düzeltildi | `la03_*` testleri başarısız → geçti |
| LA-09 | **Orta** | Kök ile aynı kimliğe sahip ikinci bir klasör içeren hazırlanmış bir dosyada, bir alt klasörü silmek **bütün kasayı** siliyordu. İleride gelecek KDBX içe aktarma da aynı yolu kullanacağı için gerçekçi bir risk. *Bu turda eklenen kodda bağımsız inceleme buldu* | Düzeltildi | `la09_*` başarısız → geçti |
| LA-10 | **Orta** | Yapı onarımı ve klasör silme karesel karmaşıklıktaydı. 1,6 MB'lık hazırlanmış bir dosya kilit açmayı **70 sn** donduruyordu | Düzeltildi (doğrusal) | `la10`: 5 sn zaman aşımı → 20.000 klasörlük zincir anında işleniyor |
| LA-11 | **Orta** | LA-03 düzeltmesindeki "dosya değişti mi" kontrolü ile yazma işlemi atomik değildi. Aynı anda kaydeden iki yazıcı ikisi de "başarılı" sayılabiliyordu. *Bağımsız inceleme buldu* | Düzeltildi (kaydetme süresince özel OS kilidi) | `la11`: 15 turda ikisi de başarılı → hiçbir turda ikisi birden başarılı değil |
| LA-16 | **Orta** | `HTTPS_PROXY` ortam değişkeni favicon modülünün IP kontrollerini ve DNS sabitlemesini tamamen devre dışı bırakıyordu. Şirket ağlarında bu değişken yaygın olarak tanımlıdır | Düzeltildi (`no_proxy`) | `la16`: sahte proxy bağlantı aldı → almadı |
| LA-15 | Düşük | Arama sırasında küçük harfe çevrilen notlar, Türkçe "İ" çevrilirken büyüyünce silinmemiş kopyalar bırakıyordu | Düzeltildi | Serbest bırakılan blokları tarayan allocator: 2 sonuç → 0 |
| LA-04 | Düşük | Geçici dosya adı tahmin edilebilirdi (`.tmp`) ve önceden oluşturulmuş bir dosyanın üzerine yazılıyordu | Düzeltildi (rastgele ad ve `create_new`) | `la04` başarısız → geçti |
| LA-05 | Düşük | Klasör yapısında bir döngü varsa `delete_group` sonsuz döngüye giriyordu | Düzeltildi | `la05`: takılıyordu → geçti |
| LA-06 | Düşük | `Debug` çıktısı log ve panic mesajlarına başlık, kullanıcı adı ve URL yazıyordu | Düzeltildi | `la06` başarısız → geçti |
| LA-07 | Düşük | Yeni kasa OWASP minimumunun (19 MiB, 2 geçiş) altındaki KDF ayarlarıyla oluşturulabiliyordu | Düzeltildi | `la07` başarısız → geçti |
| LA-12 | Düşük | Hazırlanmış bir başlık, doğrulama başarısız olmadan önce 4 GiB bellek ve 100 geçişlik KDF işi yaptırabiliyordu (yerel DoS) | Düzeltildi (üst sınır 1 GiB ve 20 geçiş) | `la12` başarısız → geçti |
| LA-14 | Düşük | Çökmeden kalan geçici dosyalar (eski parolayla şifrelenmiş olabilir) hiç silinmiyordu | Düzeltildi | `la14` başarısız → geçti |
| LA-17 | Düşük | IPv6 içine gömülü yerel adresler (`::127.0.0.1`, NAT64, 6to4, `fec0::`) engellenmiyordu | Düzeltildi | `la17` başarısız → geçti |
| LA-08 | Düşük | Favicon, şirket içi adreslere varsayılan olarak bağlanıyordu (hazırlanmış bir URL ile yerel ağ yoklanabilirdi) | Düzeltildi (varsayılan kapalı, isteğe bağlı açılır) | `la08` başarısız → geçti |
| LA-19 | Düşük | Argon2'nin çalışma belleği silinmeden serbest bırakılıyordu. Son blok ana anahtarı yeniden hesaplamaya yeter | Düzeltildi (`zeroize` ve kendi silinen belleğimiz) | **Teorik.** Kod ve `cargo tree` ile doğrulandı, saldırı testi yapılmadı |
| LA-18 | Bilgi | `sanitize_image(…, 0)` çöküyordu (panic) | Düzeltildi | `la18` başarısız → geçti |
| LA-13 | Bilgi | Hata mesajında şema numarası 16 bite kırpılıyordu | Düzeltildi | `la13` başarısız → geçti |
| LA-02 | Bilgi | Serde hata mesajlarının şifresi çözülmüş içerikten alıntı yapma ihtimali | **Yeniden üretilemedi.** ciborium 0.2.2 yalnızca türü yazıyor ("invalid type: string"). Yine de hatalar artık hiçbir içerik taşımıyor | `la02` (savunma derinliği testi) |

**Tedarik zinciri (SSDF PS.1/PS.2):**

- **Düzeltildi:**
  - CI'daki Actions sürümleri artık commit SHA'larına sabit.
  - Bütün derlemeler `--locked` ile çalışıyor.
  - Araç sürümleri sabitlendi.
  - `persist-credentials: false` eklendi.
  - `cargo deny` (lisans, kaynak, yasaklı paket, advisory) eklendi.
  - Release derlemede `overflow-checks = true` açıldı.

## 3. Doğrulanmış güçlü yanlar

Bunları kanıtla kontrol ettim.

- **Şifrelemenin bütünlüğü:**
  - Başlığın tamamı AEAD'e "associated data" olarak veriliyor.
  - Her kayıtta 192 bitlik yeni bir nonce kullanılıyor.
  - Yanlış parola ile kurcalanmış dosya aynı hatayı veriyor.
  - Bunlar testlerle doğrulandı: her bayt çevirme, kesme ve başlık değiştirme denemesi reddediliyor.
- **Bellek:**
  - Gerçekçi bir oturumdan (oluştur, kaydet, aç, düzenle, kilitle) sonra canlı süreç belleğinde ana parola, kayıt parolaları ve notlar için **0** sonuç çıktı.
  - Serbest bırakılan her bloğu tarayan allocator testinde de **0** sonuç çıktı.
  - Her iki testte de kontrol kanaryaları bulundu. Yani tarayıcıların bu tür izleri görebildiği kanıtlı ve "0" sonucu anlamlı.
- **Fuzz:** 200.000 tur çalıştırıldı, çökme ya da değişmez ihlali yok.
  - Başlık için 1 milyon mutasyon.
  - Şifresi çözülmüş içerik için 200.000 mutasyon, bunların 28.308'i geçerli olarak çözüldü.
  - Resim için 200.000 mutasyon, 43.839'u kabul edildi.
  - URL ve HTML için 600.000 rastgele girdi.
  - Rastgele klasör grafikleri üzerinde onarım property testi.
- **Bağımlılıklar:** `cargo audit` 1490 advisory ile tarandı, açık yok. Tek uyarı `fxhash`'in bakımsız olması (açık değil). `cargo deny` temiz.
- **Statik analiz:** `clippy -D warnings` ve `rustfmt --check` temiz. Çekirdekte `#![forbid(unsafe_code)]` var.

## 4. Açık kalan riskler

| ID | Önem | Risk | Neden açık | Öneri |
|---|---|---|---|---|
| R1 | Orta (senkronda) | **Geri alma (rollback):** Dosyaya yazabilen biri (ele geçmiş OneDrive hesabı, sürüm geçmişi) **eski ama geçerli** bir kasayı geri koyabilir. Örneğin değiştirilmiş bir parolayı geri getirebilir | Yerel durum saklamak gerektiriyor (uygulama katmanı), ideal çözüm format alanı da gerektiriyor | Payload'a artan bir `generation` sayacı eklemek, uygulamada en son görülen değeri saklayıp düşerse uyarmak. **Onayınızı bekliyor** (format ekleri) |
| R2 | Düşük (çevrimdışı) | **Anahtar bağlayıcılık yok:** XChaCha20-Poly1305 anahtara bağlayıcı (key-committing) değil. "Partitioning oracle" saldırıları teorik olarak mümkün | Format v2, yani kriptografik değişiklik gerektiriyor | Başlığa `HMAC(HKDF(master, "commit"), header)` alanı eklemek ve çözmeden önce sabit sürede doğrulamak. **Onayınızı bekliyor** |
| R3 | Düşük | SHA-256 durumu (parolanın son bloğu) ve HKDF/HMAC durumu yığında (stack) silinmeden kalabiliyor | RustCrypto bu tipler için `zeroize` sunmuyor. Çözüm ya format değişikliği ya da `unsafe` kod gerektiriyor | Canlı bellek taramasında 0 sonuç çıktı, ama her zamanlama için kanıtlanamıyor |
| R4 | Düşük | Kasa açıkken anahtar bellekte duruyor ve pagefile ya da hiberfil'e yazılabilir | Uygulama katmanı (`VirtualLock`) | Faz 2 |
| R5 | Düşük | `.lock` kilidi yalnızca LockAlperen örnekleri arasında geçerli. OneDrive kontrol ile yeniden adlandırma arasındaki dar pencerede dosyayı değiştirebilir | OneDrive kilitlere uymuyor | Parmak izi kontrolü değişikliği büyük ölçüde yakalıyor. Pencere birkaç ms |
| R6 | Bilgi | Okuma tamponu, şifresiz içerik büyüklüğünde açılıyor (LA-01 düzeltmesi). Büyük eklerde bellek kullanımı iki katına çıkıyor | Bilinçli bir takas | Ekler büyürse akışlı (streaming) bir format düşünülebilir |
| R7 | Bilgi | DNS zaman aşımı `getaddrinfo` iş parçacığını iptal etmiyor | tokio sınırı | Toplam 20 sn'lik bir üst sınır eklendi |

## 5. Yapılamayan veya sınırlı yapılan testler

- **Kapsama güdümlü fuzz (cargo-fuzz/libFuzzer) yerelde çalıştırılamadı.**
  - Windows MSVC'de `__start___sancov_cntrs` linker hatası alındı ve ASan runtime yüklü değil.
  - Docker Desktop çalışmıyordu. Sisteminizi değiştirmemek için başlatmadım.
  - Bu yüzden 5 hedef `fuzz/` altında hazır ve **Linux CI'da her hedef 120 sn çalışacak şekilde ayarlandı, ama henüz hiç çalışmadı.**
  - Yerelde yalnızca kapsama güdümsüz mutasyon fuzz testi yapıldı.
- **Bellek taramasının sınırları:**
  - Süreç taraması, kilitlemeden hemen sonraki anı kapsıyor. Daha önce serbest bırakılıp üzerine yazılmış izleri göremez.
  - Allocator testi Rust heap'ini kesin olarak kapsıyor ama yığını (stack) ve işletim sistemi tamponlarını kapsamıyor.
  - Pagefile ve hiberfil test edilmedi.
- **LA-19 (Argon2 belleği)** saldırıyla doğrulanmadı. Yalnızca kod ve bağımlılık özellikleri incelendi.
- **Arayüz, IPC, pano, otomatik kilit, loglama ve KDBX içe aktarma** henüz yok, bu yüzden test edilemedi.
- **Bağımsız üçüncü taraf denetimi** yapılmadı. Yapay zekâ incelemesi bunun yerini tutmaz.

## 6. Henüz yazılmamış bileşenler için zorunlu gereksinimler

Diğer parola yöneticilerinde çıkmış açıklardan çıkarıldı. Tam liste ve kaynaklar SECURITY.md'de.

- **Tauri/WebView2:**
  - Bütün bilinen CVE'leri kapatan güncel bir Tauri 2.x sürümü kullanılacak (araştırma ajanı Windows'a özgü bir köken karışıklığı açığı olarak CVE-2026-42184'ü buldu. Bu, benim bilgi kesim tarihimden sonra ve ajanın OSV kaynağına dayanıyor).
  - Uzak sayfaya gezinme ve iframe olmayacak. `default-src 'self'; frame-src 'none'` CSP uygulanacak.
  - fs ve shell eklentileri olmayacak. En dar yetkiler (capabilities) kullanılacak.
- **XSS'ten IPC'ye yükselme:** İçe aktarılan başlık ve notlar yalnızca metin olarak gösterilecek, `innerHTML` kullanılmayacak. Dışa aktarma ve anahtar değişikliği için ana parola yeniden sorulacak.
- **Pano:** Windows pano geçmişi ve bulut panosu için üç hariç tutma biçimi işaretlenecek. Pano yalnızca hâlâ bizim içeriğimiz duruyorsa temizlenecek.
- **Hızlı kilit açma (Windows Hello):** Bitwarden CVE-2023-27706'nın dersi: yalnızca DPAPI yetmez. TPM'e ya da Windows Hello `KeyCredential` imzasına bağlanacak.
- **KDBX içe aktarma:** Yalnızca KDBX 4 desteklenecek. Her uzunluk alanına üst sınır konacak (KeePass CVE-2026-86776 ve hashcat KDBX açığı dersleri). Fuzz hedefi yazılacak ve içe aktarılan veri `repair_structure`'dan geçirilecek.
- **WebView2 depolaması:** localStorage, IndexedDB ve önbellekte sır ya da URL tutulmayacak. Release derlemede geliştirici araçları kapalı olacak.
- **Dağıtım:** Kurulum dosyası kod imzalı olacak. SHA-256 değerleri tek bir resmi adreste yayınlanacak (KeeLoader kampanyasının dersi).

## 7. Sürdürülebilirlik: yeni açıkların oluşmasını önleyen yapı

1. **Her bulgunun kalıcı bir regresyon testi var** (`tests/security_regressions*.rs`, `freed_memory.rs`, `lav-memtest`). Aynı açık geri gelirse CI kırılır.
2. **CI kapıları (SSDF PW.8, RV.1):** fmt, `clippy -D warnings`, testler, 200.000 turluk mutasyon fuzz, haftalık `cargo audit` ve `cargo deny`, Linux'ta libFuzzer.
3. **Gizli tipler (SecretString/SecretBytes):** Gizli değerler yalnızca `.expose()` ile okunabiliyor, bu da denetlemeyi kolaylaştırıyor. `Debug` çıktısı hiçbir zaman içerik göstermiyor.
4. **Ağ ve çekirdek ayrımı:** Çekirdek ağa dokunmuyor. Bütün ağ kodu ayrı bir crate'te.
5. **Süreç önerisi:**
   - Kriptografi, dosya ve bellek koduna dokunan her PR bağımsız bir incelemeden geçmeli. Bu turda bağımsız inceleme, benim kendi yazdığım iki hatayı yakaladı.
   - Bir sürüm çıkmadan önce `cargo test -p lav-memtest` Windows'ta çalıştırılmalı.
   - Arayüz bittikten sonra bu rapor arayüz, IPC ve pano için genişletilmeli.
   - Halka açık sürümden önce bağımsız bir üçüncü taraf denetimi yaptırılmalı.

## 8. Değiştirilen ve eklenen dosyalar

- **Düzeltmeler:** `crates/lav-core/src/{vault,model,crypto,error}.rs`, `crates/lav-core/Cargo.toml` (argon2 `zeroize`), `crates/lav-favicon/src/lib.rs`
- **Testler:** `crates/lav-core/tests/{security_regressions,security_regressions_review,freed_memory,fuzz_smoke}.rs`, `crates/lav-favicon/tests/{security_regressions,fuzz_smoke}.rs`, `crates/lav-memtest/` (canlı bellek saldırı simülasyonu), `fuzz/` (5 libFuzzer hedefi)
- **Süreç:** `.github/workflows/ci.yml`, `deny.toml`, `Cargo.toml` (`overflow-checks`)

**API değişiklikleri (bilerek yapıldı):**

- `save_file` artık yabancı ya da değişmiş bir dosyanın üzerine yazmayı reddediyor ve `FileChangedOnDisk` hatası veriyor. Kullanıcı onay verirse `save_file_overwrite` ile yazılabiliyor.
- `<kasa>.lock` dosyası oluşturuluyor.
- KDF sınırları artık 19 MiB – 1 GiB ve 2–20 geçiş. Henüz gerçek bir kasa dosyası olmadığı için geriye dönük uyumluluk sorunu yok.
