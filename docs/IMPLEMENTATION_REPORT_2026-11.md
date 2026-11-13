# Uygulama Raporu: Aşama 1, Aşama 2 (R2 / format v2) ve Aşama 3 (R1 prototipi)

Tarih: 2026-11-13. Kaynak karar: `docs/CRYPTO_REVIEW_R1_R2.md` §4.

Ortam: Windows 10, `rustc 1.100.0`, `x86_64-pc-windows-gnu` (WinLibs MinGW 16.2). CI'daki MSVC
araç zincirinde **çalıştırılmadı**.

---

## Aşama 1: Formatı değiştirmeyen sıkılaştırmalar

| Değişiklik | Yer |
|---|---|
| Payload tam olarak tek bir CBOR değeri olmalı. Fazladan bayt varsa `Serialization` döner | `vault.rs` `unlock` |
| Header anahtar dosyası istemiyorsa verilen anahtar dosyası `UnexpectedKeyFile` ile reddedilir, KDF çalışmaz | `vault.rs`, `error.rs` |
| Tek genel kullanıcı mesajı: `Error::is_unlock_failure`, `Error::user_message`, `UNLOCK_FAILED_MESSAGE` | `error.rs` |

**Genel mesaj kapsamı:** Parola, anahtar dosyası, header, commitment, AEAD, şema ve CBOR hatalarının
hepsi aynı mesajı verir. Yalnızca `Io` ve `FileTooLarge` kendi mesajlarını korur, çünkü parolaya
bağlı değildirler. Ayrıntılı hata türleri testler ve tanılama için çekirdekte duruyor. Kullanıcı
arayüzü henüz yok, bu yüzden arayüzün `user_message()` kullanması **gerekiyor** (bu, arayüz
yazılırken uyulması gereken bir kural).

**Test önce yazıldı:** `tests/hardening_stage1.rs` düzeltmeden önce derlenmedi (8 hata). Fazla bayt
kontrolü geçici olarak kapatıldığında 3 test başarısız oldu, açıldığında hepsi geçti.

## Aşama 2: Key commitment (R2), format v2

| Gereksinim | Uygulama |
|---|---|
| Argon2id çıktısından HKDF ile ayrı, amaca özel anahtar | `commit_key = HKDF(master, "LKAV v2 key commitment")` (`DerivedKeys::from_master`) |
| Güvenlikle ilgili bütün header alanları HMAC-SHA256'ya bağlı | `HMAC(commit_key, "LKAV-commit v2" ‖ header[0..78])`: magic, version, cipher, kdf, flags, Argon2 parametreleri, salt, nonce |
| Sabit sürede karşılaştırma | `subtle` tabanlı `crypto::ct_eq`, tam 32 bayt |
| Çözmeden önce doğrulama | Payload anahtarı yalnızca `DerivedKeys::verified_payload_key` ile alınabiliyor. Açılış yolu başka bir yol kullanmıyor |
| v1'e geri dönüş yolu yok | `version != 2` Argon2'den önce `UnsupportedVersion` ile reddedilir. v1 okuyucusu yok |
| Gereksiz mimari değişiklik yok | Argon2id, XChaCha20-Poly1305, payload HKDF `info`'su ve AAD (artık 110 bayt) aynı. Yalnızca bir HKDF çıktısı ve bir HMAC eklendi |

Yeni doğrudan bağımlılık: `hmac 0.12` (zaten `hkdf` üzerinden `Cargo.lock`'taydı, yeni sürüm yok).

### Offline parola tahmini üzerindeki etki

Ölçüm (`tests/commitment_cost.rs`, release, bu makine):

| İşlem | Süre |
|---|---|
| Argon2id varsayılan (64 MiB, t=3, p=4) | 165,9 ms |
| Commitment doğrulama (HMAC) | 1,65 µs |
| AEAD doğrulama + çözme, 1 MiB | 1 835 µs |
| AEAD doğrulama, 1 baytlık mesaj | 1,20 µs |

Değerlendirme:

- Commitment yalnızca Argon2id çıktısından türetiliyor. Argon2'yi atlayan bir kısayol yok.
  Salt kasa başına rastgele olduğu için ön hesaplama ya da çoklu hedefte toplu işlem de mümkün değil.
- Tahmin başına ek maliyet yaklaşık %0,001. Saldırgan bugün bile Poly1305 etiketini ya da bilinen
  CBOR başlangıcını ilk blokta kontrol ederek mikro saniye düzeyinde bir doğrulayıcıya sahip.
  Commitment bu doğrulayıcıyı belirgin biçimde ucuzlatmıyor. En kötü durumda, büyük bir kasada
  tam etiket kontrolüne göre kazanç yaklaşık %1 (1,8 ms / 166 ms). Bilinen düz metin yöntemine
  göre ise sıfıra yakın.
- **Sonuç:** Kaba kuvvet maliyetini Argon2id belirlemeye devam ediyor. Bu bir ölçüm ve
  argümandır, biçimsel bir kanıt değildir.

### Testler

- `tests/format_v2.rs`, 18 test:
  - yerleşim
  - yanlış parola ve anahtar dosyası
  - commitment'ın her bitinin çevrilmesi
  - sıfırlanmış ve kısaltılmış commitment
  - header alanı kurcalama
  - commitment taşıma (dosyalar arası ve aynı kasanın iki kaydı arası)
  - **AEAD açısından geçerli ama commitment'ı başka bir anahtara ait dosya** (R2 regresyonu)
  - bütün kısaltmalar
  - gerçek bir v1 dosyası ve sürüm etiketi değiştirilmiş v1 dosyası
  - KAT'ler
  - KDF girdisine bağımlılık
- **KAT değerleri bağımsız hesaplandı:** HKDF/HMAC katmanı Python `hashlib`/`hmac` ile, uçtan uca
  vektör ise `argon2-cffi` (referans C uygulaması) ile.
- **Mutasyon kontrolü:** Commitment karşılaştırması geçici olarak her zaman "doğru" döndürüldüğünde
  2 özel test başarısız oldu. Diğer kurcalama testleri yine geçti, çünkü commitment AEAD AAD'sinde
  de var (iki katman).
- Mevcut testlerin **assertion'ları değişmedi**. Yalnızca dosya üreten yardımcılar
  (`encrypt_raw_payload`, LA-12'deki `Header` değişmezi) v2'ye uyarlandı.

### v1'in kaldırılmasının etkileri

Ayrıntı `docs/FORMAT.md` "v1'in kaldırılması" bölümünde. Özet:

- v1 `.lav` ve `.bak` dosyaları bu sürümle açılamaz, otomatik dönüştürme yok.
- Yayınlanmış dosya olmadığı için kullanıcı etkisi beklenmiyor. Geliştirme kopyaları `f3ef659`
  ile açılıp yeniden oluşturulmalı.

### Doğrulanmamış olanlar

- Gerçek bir Poly1305 çoklu anahtar çakışması bu oturumda **yeniden üretilmedi**. Önceki PoC artık
  mevcut değil. Regresyon testi bunun yerine aynı özelliği doğrudan test ediyor: AEAD ikinci bir
  anahtar altında geçerli olsa bile commitment uyuşmazsa dosya reddediliyor.
- `hmac` crate'inin iç durumunun (commitment anahtarından türeyen ipad/opad) bırakılırken sıfırlanıp
  sıfırlanmadığı doğrulanmadı. `lav-memtest` geçiyor ama özellikle bu değeri aramıyor.
- Commitment karşılaştırmasının sabit süreli olduğu `subtle` kullanımına dayanıyor. Zamanlama ölçümü
  yapılmadı.
- `cargo fuzz` (libFuzzer) çalıştırılmadı (Linux gerektiriyor). `header_parse` hedefi v2 header'ını
  otomatik olarak kapsıyor. `fuzz_smoke` release modunda `LAV_FUZZ_ITERS=200000` ile geçti.

## Aşama 3: R1 prototipi

Üretim koduna alınmadı. Ayrıntılı bulgular `prototypes/r1-rollback/README.md` içinde.

## Test sonuçları (son çalıştırma)

`cargo test --locked --all`: **113 geçti, 0 başarısız, 2 yok sayıldı**. Yok sayılanlar:
`lav-favicon`'daki mevcut ağ testi ve bilgi amaçlı `commitment_cost`.
Ek olarak: R1 property testi 2000 adımla release modunda geçti, `cargo fmt --check` temiz.

`cargo clippy -p lav-core -p lav-memtest -p r1-rollback-proto --all-targets -D warnings` temiz.

**Bilinen ve bu işten bağımsız sorun:** `cargo clippy --all-targets` workspace genelinde
`lav-favicon/src/lib.rs:407` (`unnecessary_sort_by`, clippy 1.100'de yeni bir lint) yüzünden
başarısız. Bu değişiklikten önce de vardı, dokunulmadı. CI'daki clippy adımı bu yüzden kırmızı olabilir.

---

## Bağımsız son denetim (2026-11-13)

Önceki sonuçları görmeyen iki ayrı inceleme yapıldı:
- kriptografi ve bellek
- R1 ve Windows

Sınıflar:
- **DOĞRULANDI:** kodla ya da bağımlılık kaynağında gösterildi.
- **TEORİK:** akıl yürütmeyle bulundu, gösterilmedi.
- **TEST EDİLEMEDİ:** bu ortamda denenemedi.

### R2 / format v2

Commitment atlatılamıyor ve v1'e düşürme yolu yok:
- Yalnızca `unlock` şifre çözüyor ve anahtarı `verified_payload_key` üzerinden alıyor.
- MAC, diskteki ham baytları kapsıyor. Ayrıştırma ile MAC girdisi arasında fark ya da uzunluk
  belirsizliği yok.
- HMAC anahtarı her zaman 32 bayt. HKDF `info` dizgileri ayrı.

| Bulgu | Sınıf | Önem | Durum |
|---|---|---|---|
| `Serialization` ve `InvalidKdfParams` kaydetme/oluşturma yolunda da üretiliyor ve kullanıcıya "açılamadı" deniyor | DOĞRULANDI (okuma) | Düşük / kullanılabilirlik | **Kısmen düzeltildi:** `seal` artık `Error::Encode` döndürüyor, test eklendi. `create`/`change_credentials` için `InvalidKdfParams` aynı kaldı (mevcut LA-07 testi bu varyantı bekliyor). Bu durum, uygulamanın kendi parametre hatası olarak belgelendi |
| `DerivedKeys::payload_key()` ve `crypto::decrypt` `pub`. Crate dışındaki bir çağıran commitment'sız çözebilir | DOĞRULANDI (okuma) | Bilgi | Açık. Kapatmak test yardımcılarının değişmesini gerektiriyor |
| Hata türüne göre zamanlama farkı (commitment uyuşmazlığı mı, AEAD hatası mı) | TEORİK | Bilgi | Kabul edildi. Kazancı ihmal edilebilir |
| Kötü niyetli header, commitment kontrolünden önce Argon2'yi en fazla 1 GiB / 20 geçişle çalıştırabilir | TEORİK | Bilgi | Tasarım gereği (LA-12 sınırı) |

### Bellek

| Bulgu | Sınıf | Önem | Durum |
|---|---|---|---|
| `hmac 0.12`, `hkdf 0.12`, `sha2 0.10` ve `blake2 0.10` iç durumlarını sıfırlamıyor. Release derlemede yığında PRK, payload anahtarı, commitment anahtarı ve parola baytları bulundu | DOĞRULANDI (yığın taraması + kaynak) | Düşük-orta | **Açık.** HKDF ve SHA-256 için v1'den beri var, HMAC commitment ile yeni kopyalar eklendi. Önerilen önlem `zeroize` ile güvenli bir yığın temizliği. Etkisi derleyiciye bağlı, `lav-memtest`'e yığın testi eklenerek doğrulanmalı. Karar bekliyor |
| `DerivedKeys` taşındıkça (move) eski kopyalar kalıyor | DOĞRULANDI (okuma) | Düşük | Açık. `Box` ile yerinde doldurma önerildi |
| Uzun birleşik karakter dizilerinde NFC normalleştirmesi parola karakterlerini silinmeden serbest bırakılan heap bloklarında bırakıyor | DOĞRULANDI (ayırıcı taraması) | Düşük | Açık. Nadir bir girdi |
| ciborium'un belirsiz uzunluklu metin yolunda düz metin kopyaları kalıyor | TEORİK | Düşük | Açık. `seal` bu yolu hiç üretmiyor |
| XChaCha `subkey` ve Poly1305 durumu sıfırlanmıyor | DOĞRULANDI (kaynak) | Düşük | Açık. Dosya başına anahtar |

### R1 prototipi

9 bulgu testle doğrulandı (`prototypes/r1-rollback/tests/review_adversarial.rs`). Ayrıntılar
`prototypes/r1-rollback/README.md` içinde. README'deki üç iddia çürütüldü ve düzeltildi:
1. "Yeni salt'lı sahte dosya her cihazda onay ister."
2. "Kilit kayıp güncellemeyi önler."
3. "Önceki yuva her zaman bir önceki adımdır."

Prototip **üretime alınmadı ve düzeltilmedi.** Bulgular, üretime geçmeden önceki tasarım gereksinimleri.

### Windows (bu makinede deneyle doğrulananlar)

- Hedef FILE_SHARE_DELETE olmadan açıksa `rename` 5 (ACCESS_DENIED), kaynak tutuluyorsa 32
  hatası veriyor. `is_transient` içinde 5'in olması bu yüzden gerekli.
- `File::lock` LockFileEx kullanıyor ve kilit zorunlu (mandatory). Süreç öldürülünce hemen
  bırakılıyor. Büyük/küçük harf farkı olan yollar aynı kilidi paylaşıyor.
- **Tutulan kilit dosyası silinebiliyor ya da üzerine yazılabiliyor**, ardından ikinci bir kilit
  alınabiliyor. Bu, `lav-core`'un senkron klasöründeki `<kasa>.lock` dosyasını da etkiliyor
  (TEORİK, OneDrive ile denenmedi).
- Salt okunur bir hedef ya da dizin hedefi için `rename_with_retry` boşuna yaklaşık 1,5 sn
  yeniden deniyor.

**Teorik (`lav-core`, değişikliklerimden önce de vardı):**
- `.bak` kopyası `fsync` yapılmadan rename ediliyor.
- `SaveLock` yolu metinden türetiliyor; 8.3 kısa adlar, hard link ve symlink farklı kilit dosyaları
  üretir.
- `lock()` süresiz bekleyebiliyor.
- `disk_state` yol karşılaştırması büyük/küçük harfe duyarlı (güvenli yönde hata).

**Test edilemedi:**
- gerçek elektrik kesintisi ve NTFS'nin rename'leri diske yazma sırası (MOVEFILE_WRITE_THROUGH yok)
- gerçek OneDrive ve antivirüs tutma süreleri
- bulut yer tutucu (placeholder) hataları
- SMB/ağ sürücüsü davranışı
- junction ve symlink (ayrıcalık gerekiyor)
- std'nin `rename` uygulamasının kaynağı (rust-src kurulu değil). İçe aktarılan sembollere göre
  `MoveFileExW(REPLACE_EXISTING)` kullanılıyor gibi.

### CI

- `lav-favicon/src/lib.rs:407`: `sort_by` → `sort_by_key(Reverse)`. İkisi de kararlı (stable)
  sıralama, davranış aynı.
- `equal_sized_icons_keep_document_order` testi eklendi; eski ve yeni kodla geçiyor.
- Workspace genelinde `cargo clippy --all-targets -D warnings` temiz.

### Son test durumu

`cargo test --locked --all` (Windows, GNU araç zinciri): **116 geçti, 0 başarısız, 11 yok sayıldı**.
- Yok sayılanlar: 9 bulgu gösterim testi, 1 ağ testi, 1 ölçüm testi.
- `-- --include-ignored` ile `review_adversarial` 10/10 geçiyor.

Linux: test çalıştırılmadı (WSL yok). `lav-core`, `lav-memtest` ve prototip için Linux hedefinde `cargo check` ve `clippy` temiz. `lav-favicon` Linux için denetlenemedi (`ring` bir C çapraz derleyici istiyor).

---

## PR-1: Bellek güvenliği (2026-11-13)

Tasarım: `docs/FIX_DESIGN_2026-11.md` §1 ve §4.1–4.3. R2/v2 kriptografisi **değişmedi**: aynı
algoritmalar, aynı HKDF `info` dizgileri, aynı KAT değerleri.

### Önce: Linux CI

`.github/workflows/ci.yml`: `test` işi artık `windows-latest` ve `ubuntu-latest` matrisinde
çalışıyor. `lav-memtest` süreç taraması yalnızca Windows'ta derleniyor.

### Önce başarısız olan testler (düzeltmeden önce çalıştırıldı)

| # | Test | Düzeltmeden önce | Sonra |
|---|---|---|---|
| M1/M2 | `lav-memtest` `derived_keys_do_not_survive_key_derivation` (release) | MASTER_KEY 63, PAYLOAD_KEY 42, COMMIT_KEY 76 parça eşleşmesi → **başarısız** | 0 eşleşme, geçti |
| M3 | `derived_keys_do_not_survive_unlock_and_moves` (release) | PAYLOAD_KEY 147, COMMIT_KEY 139, MASTER_KEY 63 → **başarısız** | 0, geçti |
| M4 | 3 `compile_fail` doctest (`payload_key` E0624, ham `decrypt` E0308, `encrypt` E0603) | Kod derleniyordu → **başarısız** | Beklenen hata koduyla derlenmiyor, geçti |
| M5 | `tests/nfc_memory.rs` (taramalı ayırıcı) | "Q + 6 işaret (NFC_QC=Maybe)" → **başarısız**. Detektörün kontrol testi pozitif | 0, geçti |
| M6 | `tests/nfc_equivalence.rs` | Fonksiyon yoktu (derleme hatası) | Bütün kod noktaları, 30 zor durum ve 60 000 rastgele dizi kütüphanenin `nfc()` çıktısıyla aynı |

Ölçülen `lav-memtest` sayıları 12 baytlık **parça** eşleşmeleridir. 32 baytlık bir anahtarın
21 parçası olduğu için, örneğin 63 eşleşme yaklaşık 3 tam kopya demektir.

**Mutasyon kontrolü:** `scrubbed` içinden `scrub_stack()` çağrısı çıkarıldığında M1 ve M3 yeniden
başarısız oluyor. PRK_OPAD, COMMIT_KEY ve XCHACHA_SUBKEY bulunuyor. Yani testler yığın
temizliğinin etkisini ölçüyor.

**Mevcut bir hata bulundu ve düzeltildi:** `lav-memtest`'in iki mevcut testi **release** derlemede
hiç geçmiyordu. Tarayıcının kontrol değeri olan `CANARY` ayırması (`forget(String::from(..))`)
LTO tarafından eleniyordu. `black_box` eklendi; assertion'lar aynı.

### Yapılan düzeltmeler

- **Yığın temizliği (en iyi çaba):** `crypto::scrubbed` hassas işi `#[inline(never)]` bir
  çerçevede çalıştırıyor, ardından 64 KiB'ı `zeroize` ile siliyor. Kullanıldığı yerler:
  `derive_keys`, `DerivedKeys::from_master`, `commitment`, `encrypt`, `decrypt`,
  `CompositeKey::new`, `Vault::unlock`, `seal`, `verify_credentials`. `unsafe` yok.
- **`DerivedKeys(Box<KeyPair>)`:** `KeyPair` için `Zeroize` + `ZeroizeOnDrop`. HKDF doğrudan heap'e
  yazıyor; taşıma yalnızca işaretçiyi taşıyor.
- **SHA-256 özetleri** doğrudan `CompositeKey` tamponuna yazılıyor (dönüş kopyası yok).
- **API daraltma:**
  - `crypto::decrypt` yalnızca `VerifiedKey` kabul ediyor; bu türü yalnızca `verified_payload_key`
    üretebiliyor.
  - `payload_key()` ve `encrypt` artık `pub(crate)`.
  - Testler için `test-utils` özelliği eklendi (`lav_core::testing`, kendine dev-dependency ile
    açılıyor).
- **NFC:** `is_nfc_quick` yalnızca **Yes** derse normalleştirme atlanıyor. **Maybe** ve **No**,
  heap ayırmayan yola gidiyor. Bu yol kütüphanenin karakter düzeyi tablolarını kullanıyor; UAX #15
  sıralama ve birleştirme adımları yerinde, tam boyutlu ve kendini silen tamponlarla yapılıyor.

### Sonuçlar

- `cargo test --locked --all` (Windows, GNU): **125 geçti, 0 başarısız, 11 yok sayıldı.** R1
  inceleme testleri `--include-ignored` ile 10/10.
- **Release:**
  - `lav-memtest` 4/4 test 5 ardışık çalıştırmada geçti; debug derlemede de geçti.
  - `freed_memory`, `nfc_memory`, `nfc_equivalence` ve `format_v2` geçti.
- **KAT:** 4 değer (HKDF/HMAC ve uçtan uca Argon2id) önceki değerlerle bayt bayt aynı.
- `cargo fmt --check` ve workspace genelinde `clippy -D warnings` temiz (Windows). Linux hedefinde
  `lav-core`, `lav-memtest` ve prototip için clippy temiz.
- **Maliyet:** Commitment doğrulaması 1,65 µs'den yaklaşık 21 µs'ye çıktı (64 KiB silme). Argon2
  (170 ms) yanında yaklaşık %0,01. Saldırganın offline tahmin maliyetini etkilemez.

### Kalan riskler

- **Yığın temizliği garanti değildir.** Bu sonuç yalnızca rustc 1.100, GNU araç zinciri ve
  Windows x86_64 için ölçüldü. Kapsamadığı yerler:
  - yazmaçlar;
  - çağıranın kendi çerçevesi;
  - başka iş parçacıkları (Argon2 `parallel` özelliği kapalı);
  - 64 KiB'tan derin zincirler.
- CI'daki **MSVC** araç zinciri ve **Linux** için ölçüm yok. Süreç taraması yalnızca Windows'ta var;
  Linux karşılığı yazılmadı.
- Süreç taraması, işlem sırasında pagefile ya da hiberfil.sys'e yazılmış olabilecek kopyaları
  göremez.
- Arayüz katmanındaki parola kopyaları (metin kutusu, IME, pano) kapsam dışı. `password: &str`
  çağıranın belleğidir.
- `test-utils` özelliği workspace test derlemelerinde özellik birleştirmesi (feature unification)
  nedeniyle açılıyor. Normal `cargo build` ve bağımlı uygulamalarda açılmıyor; açılmaması için
  uygulama tarafında `cargo tree -e features` ile kontrol edilmeli.
- ciborium'un belirsiz uzunluklu metin yolu (TEORİK, düşük) açık.
- `hmac`, `hkdf` ve `sha2` iç durumları ancak PR-3'teki (RustCrypto yeni nesil) yükseltmeyle ve
  temizlikle **birlikte** azalır; yükseltme tek başına yetmez (§1.1).

---

## PR-2: Windows/Linux dosya güvenliği (2026-11-13)

Tasarım: `docs/FIX_DESIGN_2026-11.md` §2, §4.4 ve §4.5. Uygulanan düzeltmeler: L1 (kilit) ve B1
(yedek kalıcılığı), ayrıca W3 (doğrulanmış yedek) ve W6 (`canonicalize`). Kriptoya (R2/v2)
**dokunulmadı**; `crypto.rs` bu PR'da değişmedi. R1 prototipi üretime taşınmadı.

### Test altyapısı (davranış değişikliği olmadan önce)

`SaveEvent` olayları ve iş parçacığına özel bir kanca (`save_hook`) eklendi. Kanca yalnızca
`#[cfg(test)]` derlemede var; normal derlemede bu çağrılar boş bir `Ok(())`'a derleniyor. Kanca
iki iş için kullanılıyor: olayların sırasını kaydetmek ve seçilen adımda çökme taklit etmek. İki
yeni hata türü eklendi: `SaveBusy` ve `LockLost`.

### Önce başarısız olan testler (`crates/lav-core/src/vault_save_tests.rs`)

| # | Test | Düzeltmeden önce (Windows) | Sonra |
|---|---|---|---|
| T1 | Tutulan kilit dosyası silinemez / üzerine rename yapılamaz | **Başarısız** (silindi) | Geçti |
| T2 | Kilit, commit'ten önce kaybolursa `LockLost`, ana dosya değişmez | `#[cfg(unix)]`, burada çalışmadı | Linux hedefinde derleniyor ve clippy temiz; **çalıştırılmadı** (CI'da çalışacak) |
| T3 | Meşgul kilitte `SaveBusy` (süresiz bekleme yok) | **Başarısız** (kilit bırakılana kadar bekledi) | Geçti |
| T4 | Sıra: `.bak` fsync → rename → dizin flush → ana dosya → dizin flush (2 varyant) | **Başarısız** (fsync ve flush yoktu) | Geçti |
| T5 | Doğrulamadan sonra dosya değişirse iptal; yedek = doğrulanmış baytlar | **Başarısız** (yabancı sürüm ezildi, yedeğe yabancı sürüm girdi) | Geçti |
| T6 | Her adımda çökme: ana dosya eski ya da yeni; yedek tutarlı; eski parolalı yedek yeni parolalı kasanın yanında kalmıyor (2 varyant) | Geçiyordu (regresyon ağı) | Geçti |
| T7' | Bekleyen ikinci örnek `SaveBusy` alıyor ve ilk örneğin geçici dosyasına dokunmuyor | **Başarısız** (bekledi) | Geçti |
| T8 | Büyük/küçük harf farklı yol aynı dosya sayılıyor (Windows) | **Başarısız** (`FileChangedOnDisk`) | Geçti |
| T9 | Mevcut LA-03, LA-04, LA-11, LA-14 | Geçiyordu | Geçti; assertion'lar değişmedi |

**Tasarımdan sapma (T7):** Yaş eşiği ("10 dakikadan yeni geçici dosyayı silme") mevcut LA-14
assertion'ıyla çelişiyor; LA-14 taze bir `.tmp` dosyasının silinmesini bekliyor. Bu yüzden eşik
**uygulanmadı**. Aynı yerel risk (devam eden bir kaydın geçici dosyasının silinmesi) artık kilitle
kapanıyor; T7' bunu test ediyor. OneDrive'ın başka bir makineden getirdiği geçici dosyalar TEORİK
risk olarak kalıyor.

### Doğrulama sonuçları

- `cargo test --locked --all` (Windows 10, GNU araç zinciri): **134 geçti, 0 başarısız,
  11 yok sayıldı.**
- **Eşzamanlılık:** kayıt testleri (T1–T8) ve LA-11 (15 tur eşzamanlı kayıt) **10 ardışık
  çalıştırmada** 10/10 geçti.
- **Kilit kaybı:**
  - Windows'ta, tutulan kilidin silinmesi ya da üzerine rename yapılması engelleniyor (T1).
  - Unix'te kayıp tespit ediliyor (T2), ama yalnızca derlendi.
- **Süreç çökmesi:** Bütün adımlarda simüle edildi (T6). Kilit, süreç ölünce işletim sistemi
  tarafından bırakılıyor (önceki deneyde E7, Windows).
- **Yedeğin kalıcılığı:**
  - Sıra T4 ile doğrulandı.
  - Doğrulanmış içerik T5 ile doğrulandı.
  - Fiziksel kalıcılık (güç kesintisi) **test edilmedi**.
- **Diğer:**
  - PR-1 bellek testleri release'te 4/4, KAT'ler aynı.
  - fmt temiz; clippy workspace genelinde (Windows) ve Linux hedefinde temiz.

### Test edilemeyenler (açıkça)

- **Gerçek güç kesintisi:** Ne `fsync` ne dizin flush ne de NTFS rename'inin günlüğe yazılması
  fiziksel olarak test edildi. Windows'ta dizin `FlushFileBuffers`'ının rename'i kalıcı yaptığı
  belgelenmemiş.
- **OneDrive:**
  - Kilit dosyasının eşitlenmesi.
  - Tutulan kilidi değiştirmeye çalışırken OneDrive'ın davranışı (yeniden deneme, uyarı, çakışma
    kopyası).
  - Bulut yer tutucu (placeholder) hataları.
  - Başka makinenin geçici dosyaları.
  - OneDrive'ın doğrulama ile commit arasındaki mikro saniyelik pencerede dosya değiştirmesi.
- **Ağ sürücüleri (SMB/NFS):** `LockFileEx`/`flock` semantiği, dizin flush desteği ve rename
  atomikliği. Dizin flush'ta "desteklenmiyor" dışındaki bir hata (örneğin erişim reddi) bu
  sürücülerde kaydı başarısız yapabilir.
- **Linux:**
  - Bu makinede hiçbir Linux testi çalıştırılmadı (WSL ve Docker yok).
  - T2, inode kontrolü ve dizin `fsync` yolu yalnızca derlendi.
  - Linux CI işi eklendi ama henüz çalışmadı; dal push edilmesi gerekiyor.
- **MSVC araç zinciri:** CI'daki Windows işi MSVC kullanıyor; burada GNU ile test edildi.

### Kalan riskler

- **Unix'te kilit kontrolü ile rename arasında küçük bir pencere** kalıyor (§4.4). Kilidin
  senkron klasörünün dışına taşınması (L2) gerçek çözüm; masaüstü uygulamasıyla birlikte yapılmalı.
- **Kilit dosyası hâlâ senkron klasöründe.** OneDrive bunu eşitler. Tutulurken değiştiremez, ama
  kullanıcıya senkron uyarısı gösterebilir. Bu da L2 ile çözülür.
- **Makineler arası kilit yok.** Makineler arası çakışmaları ancak R1 yakalar.
- **Maliyet:** Kayıt başına ek olarak yedek dosyası `fsync`'i, iki dizin flush'ı ve bir yeniden
  okuma var. 512 MiB'lık bir dosyada yedek kopyası belirgin süre ekler (ölçülmedi).

---

## Ek: CI sonuçları (2026-11-13)

Yukarıdaki "Linux'ta çalıştırılmadı" ve "MSVC sonucu görülmedi" ifadeleri yazıldıkları anki
durumu anlatıyor. Dal push edildikten sonra CI, commit `10f2272` üzerinde iki kez çalıştı:
[43474412721](https://github.com/alperen-cpu/LockAlperen/actions/runs/43474412721) (push) ve
[43479266434](https://github.com/alperen-cpu/LockAlperen/actions/runs/43479266434) (PR #1).

Test sayıları push çalışmasından; PR çalışmasında da bütün işler geçti.

| İş | Sonuç |
|---|---|
| test (ubuntu-latest) | Geçti: 135 geçti, 0 başarısız, 11 yok sayıldı. `vault::save_tests::t2_lock_lost_before_commit_aborts_the_save ... ok`; T3–T7 de geçti |
| test (windows-latest, MSVC) | Geçti: 140 geçti, 0 başarısız, 11 yok sayıldı. T1 ve T8 dahil |
| fuzz (5 hedef), supply-chain | Geçti |

Böylece T2, Unix inode kontrolü ve dizin `fsync` yolu Linux'ta **çalıştırıldı**. Değişmeyenler:

- Bellek testleri (`lav-memtest`, 4/4) CI'da Windows/MSVC **debug** derlemesinde de geçti.
  Release ölçümü yalnızca yerelde Windows/GNU ile yapıldı; MSVC release ve Linux için ölçüm yok.
- Gerçek güç kesintisi, OneDrive ve ağ sürücüleri hâlâ test edilmedi.
- PR #1, merge commit `d22967c` ile `main`'e birleştirildi.
