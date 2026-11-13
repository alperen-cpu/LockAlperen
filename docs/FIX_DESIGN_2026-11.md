# Düzeltme Tasarımı: Bellek Güvenliği ve Windows Dosya Güvenliği

> **Durum (2026-11-13):** Linux CI ve **PR-1 (bellek) uygulandı**, sonuçlar için `docs/IMPLEMENTATION_REPORT_2026-11.md` PR-1 bölümüne bakın. **PR-2 (dosya, L1 + B1) uygulandı**, aynı raporun PR-2 bölümüne bakın. PR-3 yalnızca tasarım. Kaynak: `docs/IMPLEMENTATION_REPORT_2026-11.md`
> "Bağımsız son denetim" bölümünün açık bulguları.
>
> **Sınıflar:**
> - **DOĞRULANDI:** Bu makinede kodla ya da bağımlılık kaynağında gösterildi.
> - **TEORİK:** Akıl yürütmeyle.
> - **TEST EDİLEMEDİ:** Bu ortamda denenemedi.
>
> **Bu tasarım için ek doğrulamalar** (2026-11-13, Windows 10 19045, NTFS, rustc 1.100.0 gnu):
> - crates.io'daki güncel sürümler ve özellik listeleri sorgulandı.
> - `hkdf 0.13.0`, `hmac 0.13.0` ve `sha2 0.11.1` kaynakları okundu.
> - Windows davranışları depo dışında küçük bir deneme programıyla ölçüldü
>   (`scratchpad/winprobe`, P1–P6).

---

## 1. Bellek güvenliği

### 1.1 Sorun ve istismar yolu

**Saldırgan:** Kasa kilitlendikten sonra süreç belleğinin bir kopyasını ele geçiren biri.
Örnekler: crash dump / WER raporu, hiberfil.sys, pagefile, bellek dökümü alan bir araç, ya da
süreci sonradan okuyan yerel kod.

> Kasa **açıkken** süreç belleğini okuyabilen saldırgan zaten kapsam dışıdır (THREAT_MODEL).
> Bu bölüm, "kilitledikten sonra iz kalmasın" garantisiyle ilgilidir.

| Kalıntı | Nerede | Elde edilen | Sınıf |
|---|---|---|---|
| HKDF ara anahtarı (PRK) | yığın, `hkdf 0.12` `extract` dönüşü | PRK, master'a eşdeğer. Dosyanın parolası kırılmadan çözülür | DOĞRULANDI (denetim yığın taraması: 1 kopya) |
| Payload anahtarı | yığın, HKDF `output`/`prev` ve dönüş kopyaları | O kasanın tüm kayıtları (salt değişene kadar) | DOĞRULANDI (`unlock` sonrası 1 kopya) |
| Commitment anahtarı | yığın, HMAC `buf` = anahtar ⊕ ipad/opad | Tek başına içerik açmaz | DOĞRULANDI (5 kopya) |
| Parola baytları | yığın, SHA-256 blok tamponu (`CompositeKey::new`) | Ana parola düz metin | DOĞRULANDI (1 kopya) |
| Argon2 BLAKE2b durumu (composite içerir) | yığın, `blake2 0.10` | composite, yani SHA-256(parola) | DOĞRULANDI (kaynak okuma; taramada görülmedi) |
| XChaCha `subkey` | yığın, `chacha20 0.9` | O dosyanın tek nonce'u için anahtar | DOĞRULANDI (kaynak okuma) |
| `DerivedKeys` taşıma kopyaları | yığın / `Vault` taşınırken | payload ve commitment anahtarı | DOĞRULANDI (kod okuma) |
| NFC normalleştirmesi | **heap**, ≥5 karakterlik birleşik dizi, serbest bırakılıyor | parola karakterleri (UTF-32) | DOĞRULANDI (taramalı ayırıcı) |
| `DerivedKeys::payload_key()` / `crypto::decrypt` `pub` | API | Crate dışında commitment'sız şifre çözme | DOĞRULANDI (kod okuma) |

**Kök neden:**
- `hmac 0.12`, `hkdf 0.12`, `sha2 0.10`, `digest 0.10` ve `blake2 0.10` hiç `Drop`/`zeroize`
  içermiyor.
- **Güncel sürümler de tek başına yetmiyor (DOĞRULANDI):**
  - `hmac 0.13.0` `zeroize` özelliğiyle iç durumunu sıfırlıyor, ama `new_from_slice` içindeki yerel
    `buf` (anahtar ⊕ pad, `src/block_api.rs:53-68`) **sıfırlanmıyor**.
  - `hkdf 0.13.0`'ın kendi `zeroize` özelliği yok. `expand_multi_info` içindeki `output` ve `prev`
    (`src/lib.rs:135-166`) ve `extract` dönüşündeki PRK sıfırlanmıyor.
  - `sha2 0.11.1` yalnızca çekirdek durumu sıfırlıyor (`block_api.rs:92-104`). Blok tamponu
    (`block-buffer 0.11`, özellik listesi boş) kapsam dışı.

### 1.2 Çözüm seçenekleri

| | Seçenek | Kapsadığı | Maliyet / risk |
|---|---|---|---|
| **S** | **Yığın temizliği.** Hassas işlemler `#[inline(never)]` bir iç fonksiyona alınır. Dönüşte, aynı derinlikte, `zeroize` ile 64 KiB'lık yerel bir dizi silinir | Bütün kütüphane kalıntıları (hmac `buf`, hkdf `prev`/`output`/PRK, SHA-256 bloğu, BLAKE2b, subkey) | Küçük, `unsafe` gerektirmez. Etkinliği derleyici yerleşimine bağlı, bu yüzden testle doğrulanmalı |
| **B** | **`DerivedKeys` heap'te, tek kopya.** `Box<Inner>` içinde tutulur, HKDF çıktısı doğrudan kutuya yazılır | Taşıma kopyaları | Küçük |
| **V** | **Tür düzeyinde ayrım.** `decrypt` yalnızca `VerifiedKey` kabul eder; `payload_key()` `pub(crate)` olur; testler için `test-utils` özelliği eklenir | Commitment'sız çözme yolu | Test **yardımcılarının** gövdesi değişir (assertion'lar değişmez) |
| **U** | **RustCrypto yeni nesil:** `sha2 0.11`, `hmac 0.13`, `hkdf 0.13`, `argon2 0.6`, `chacha20poly1305 0.11`, `zeroize` özellikleriyle | İç durumların çoğu | Büyük API değişikliği (generic-array → hybrid-array). MSRV 1.88. **Tek başına yetmez** (§1.1) |
| **N** | **NFC kısa yolu:** `is_nfc_quick` "Evet" derse normalleştirme atlanır | NFC parolaların hepsi, yani pratikte neredeyse hepsi | Küçük |
| **A** | **Silen global ayırıcı:** her serbest bırakmada bloğu sıfırlar. Uygulama binary'sinde, `unsafe` izinli küçük bir crate | NFC'nin geri kalanı, ciborium dahil bütün heap kalıntıları | `unsafe` + biraz performans. Kütüphane kullanıcılarını kapsamaz |
| H | HKDF tek blok olarak elle yazılır: `HMAC(PRK, info‖0x01)` | hkdf kalıntıları | "Kendi kriptomuzu yazmayız" ilkesine aykırı. KAT'ler korur ama **önerilmez** |

**Öneri:**
1. **S + B + V + N** birlikte, tek bir PR'da (küçük ve test edilebilir).
2. **U** ayrı bir PR'da. Kriptonun değişmediğinin kanıtı mevcut KAT'lerin aynen geçmesi olur.
3. **A**, masaüstü uygulamasıyla birlikte gelir.

**S'nin ayrıntısı (önemli):** `hmac`'in `new_from_slice` fonksiyonu `#[inline(always)]`. Bu yüzden
`buf`, çağıranın kendi çerçevesine yerleşebilir. Temizlik yalnızca *dönülmüş* çağrıların
çerçevelerini kapsadığı için yapı şöyle olmalı:

```
pub fn derive_keys(..) -> Result<DerivedKeys> {
    let mut out = DerivedKeys::new_zeroed();      // Box, heap
    let r = derive_keys_inner(.., &mut out);      // #[inline(never)]: Argon2 + HKDF + HMAC burada
    scrub_stack();                                // #[inline(never)]: [0u8; 64 KiB].zeroize() + black_box
    r.map(|()| out)
}
```

Aynı kalıp şu noktalara uygulanır:
- `CompositeKey::new` (NFC + SHA-256)
- `DerivedKeys::commitment` / `verified_payload_key` (HMAC)
- `unlock` (decrypt + CBOR)
- `seal` (encrypt)
- `verify_credentials`

`zeroize` volatile yazma kullanır, bu yüzden optimizasyonda silinmez. Kod `unsafe` gerektirmez.

**V'nin ayrıntısı:**
- `crypto::decrypt(key: &VerifiedKey, ..)`. `VerifiedKey` yalnızca `verified_payload_key` ile
  oluşturulabilir.
- `encrypt` `pub(crate)` olur.
- `lav-core` kendine `[dev-dependencies] lav-core = { path = ".", features = ["test-utils"] }`
  ile bağlanır. `test-utils` altında `testing::{encrypt_raw, decrypt_raw, payload_key}` açılır.
- Etkilenen test yardımcıları: `tests/common/mod.rs`, `security_regressions.rs`,
  `security_regressions_review.rs`, `format_v2.rs` (6 çağrı), `commitment_cost.rs`.
  **Assertion'lara dokunulmaz**, ama dosyalar değişir. Uygulamadan önce onayınız gerekir.

### 1.3 Windows ve Linux

| | Windows | Linux |
|---|---|---|
| Yığın temizliği (S) | Aynı çalışır. Ana iş parçacığı yığını 1 MiB, 64 KiB temizlik güvenli | Aynı. Varsayılan yığın 8 MiB |
| Uzun süre kalan kopyalar | pagefile, hiberfil.sys, WER crash dump | swap, core dump (`ulimit -c`), `/proc/<pid>/mem` |
| Ek önlem (kapsam dışı) | `VirtualLock`, WER'den hariç tutma (`unsafe` FFI) | `mlock`, `prctl(PR_SET_DUMPABLE, 0)` (`unsafe` FFI) |
| Bellek testi altyapısı | `lav-memtest` ReadProcessMemory ile **çalışıyor** | `lav-memtest`'in Linux yolu **bu makinede denenmedi** |

### 1.4 Önce başarısız olması gereken testler

| # | Test | Nerede | Bugün | Düzeltmeden sonra |
|---|---|---|---|---|
| M1 | Kurban süreç `derive_keys` + `drop` yapar, sonra bekler. Tarayıcı, **testin kendi hesapladığı** PRK, payload anahtarı, commitment anahtarı ve `master`'ı arar (master `argon2` dev-dependency'si ile hesaplanır) | `lav-memtest` yeni senaryo | ≥1 eşleşme (denetimde gösterildi) | 0 |
| M2 | `CompositeKey::new(PW)` + drop sonrası parola baytları (UTF-8 ve UTF-16) | `lav-memtest` | ≥1 | 0 |
| M3 | `Vault::unlock` + bir `Vault` taşıma + drop sonrası payload anahtarı | `lav-memtest` | ≥1 | 0 |
| M4 | `compile_fail` doctest: `DerivedKeys::payload_key` ve ham `crypto::decrypt` crate dışından **derlenmemeli** | `crypto.rs` doc | derleniyor (test başarısız) | derlenmiyor |
| M5 | Taramalı ayırıcı. Parola `"Q" + 6 birleşik işaret` (NFC) **ve** NFD Vietnamca → serbest bırakılan bloklarda UTF-32 izi | `tests/freed_memory.rs` benzeri yeni dosya | 1 eşleşme | NFC girdide 0. NFD girdide A olmadan ≥1 kalır (**belgelenir**) |
| M6 | Değişmezlik: mevcut KAT'ler, NFC/NFD eşdeğerlik testi ve bütün format testleri **aynen** geçer | mevcut | geçiyor | geçiyor |

### 1.5 Sınırlamalar ve test edilemeyenler

- **S sezgiseldir.** Derleyici, tamponu temizlenen bölgenin dışına (örneğin çağıranın çerçevesine)
  yerleştirebilir. M1–M3 bunu yalnızca test edilen derleme profili ve hedef için doğrular.
  Her araç zinciri güncellemesinde testin yeniden çalışması gerekir.
- **CPU yazmaçları** (SIMD dahil) güvenli Rust'ta temizlenemez.
- **N**, NFC olmayan girdide (NFD olarak yazılmış parola) heap izini bırakmaya devam eder.
  Tam çözüm A'dır.
- **Uygulama katmanındaki kopyalar** bu tasarımın kapsamı dışında: arayüz metin kutusu, pano,
  IME tamponu ve işletim sisteminin giriş kuyruğu.
- **Linux bellek taraması** bu makinede çalıştırılamadı (WSL yok). CI'daki `test` işi yalnızca
  `windows-latest` üzerinde çalışıyor (§3).

---

## 2. Windows dosya güvenliği

### 2.1 Sorunlar ve istismar yolları

| # | Sorun | İstismar / sonuç | Sınıf |
|---|---|---|---|
| W1 | `<kasa>.lock`, std'nin varsayılan paylaşım kipiyle (READ\|WRITE\|**DELETE**) açılıyor | Kilit tutulurken dosya silinebiliyor ya da üzerine rename yapılabiliyor. İkinci örnek yeni bir kilit alıyor, iki kayıt aynı anda yürüyor. Kayıp güncelleme olur ya da `remove_stale_temps` öbür örneğin `.tmp` dosyasını siler. Kilit senkron klasöründe olduğu için OneDrive da silebilir | DOĞRULANDI (denetim E12/E13; bu tasarımda P2 ile tekrarlandı) |
| W2 | `.bak`, `fs::copy` ile ve `fsync` olmadan yazılıp rename ediliyor, ardından ana dosya değiştiriliyor | Güç kesintisinde ana dosya yeni, `.bak` boş ya da çöp kalabilir. Yedek ihtiyaç anında işe yaramaz | TEORİK |
| W3 | `.bak`, parmak izi kontrolünden **sonra** dosya yeniden okunarak kopyalanıyor | Kontrol ile kopya arasında OneDrive dosyayı başka bir cihazın sürümüyle değiştirirse: `.bak` o sürümü alır, ana dosya bizim sürümümüzle ezilir ve doğrulanmamış bir sürüm sessizce yedeğe gider | TEORİK |
| W4 | `lock()` süresiz bekliyor | Asılı kalan bir örnek, kaydı sonsuza kadar kilitler | TEORİK |
| W5 | `remove_stale_temps` yaştan bağımsız siliyor | Kilit bozulursa ya da OneDrive başka makinenin `.tmp` dosyasını getirirse, devam eden bir kayıt bozulur | TEORİK |
| W6 | `disk_state` yolu harfe duyarlı karşılaştırılıyor | `Vault.lav` ile açılıp `VAULT.lav` ile kaydedilince sahte `FileChangedOnDisk` (güvenli yönde hata) | TEORİK |
| W7 | Dizin `fsync` edilmiyor | Linux'ta rename'ler güç kesintisinde kaybolabilir. Windows'ta NTFS günlüğünün zamanlamasına bağlı | TEORİK |

### 2.2 Kilit (W1, W4): seçenekler

| | Seçenek | Windows | Linux | API değişikliği |
|---|---|---|---|---|
| **L1** | **Paylaşım kipinden DELETE çıkarılır** (`OpenOptionsExt::share_mode(READ\|WRITE)`) + `try_lock` ve süre sınırı + commit'ten önce kimlik yeniden doğrulaması | **DOĞRULANDI (P1/P6):** tutulurken aynı süreçten ya da başka süreçten silme 32, üzerine rename 5 ile başarısız. İkinci bir açıcı dosyayı açabiliyor ama `try_lock` başarısız oluyor | `flock` danışma niteliğinde, `unlink` engellenemez. Bu yüzden commit'ten önce yoldaki dosyanın `(dev, ino)` değeri kilitli tanıtıcınınkiyle karşılaştırılır; farklıysa `LockLost` |  Yok |
| L2 | Kilit `%LOCALAPPDATA%` (Linux: `$XDG_STATE_HOME`) altında, anahtarı `SHA-256(canonicalize(yol))` | Senkron klasörüne hiç yazılmaz, OneDrive kilide dokunamaz. `canonicalize` harf ve uzun ad farkını gideriyor (**DOĞRULANDI P4**) | aynı | Var: kilit dizini parametresi |
| L3 | `ReplaceFileW` / `LockFileEx` doğrudan FFI ile | En fazla kontrol | — | `unsafe` crate gerekir |

**Öneri:** Hemen L1 (çekirdek API'si değişmez). L2, masaüstü uygulaması yerel veri dizinini
belirlediğinde yapılır. L3 önerilmez.

L1'in ayrıntısı:
- Kilit `share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)` ile açılır. Sabitler 1 ve 2; `windows-sys`
  gerekmez, `OpenOptionsExt` kararlı ve güvenli bir API.
- `try_lock` 50 ms aralıklarla, örneğin en fazla 10 sn denenir. Sonra yeni bir hata döner:
  `Error::SaveBusy`.
- Son rename'den hemen önce, kilit yolunun hâlâ tutulan dosyayı gösterdiği doğrulanır:
  - Linux'ta `MetadataExt::{dev, ino}` ile.
  - Windows'ta DELETE paylaşımı kapalı olduğu için yol değiştirilemez. Kontrol yine de derinlemesine
    savunma olarak kalır.
  - Ek kontrol: `vault` dosyasının parmak izi rename'den hemen önce yeniden okunur (W3'ün penceresini
    daraltır).

**OneDrive notu:** L1 ile, kilit tutulurken OneDrive kilit dosyasını değiştiremez. OneDrive bunu
yeniden deneyebilir ya da bir senkron uyarısı gösterebilir. Kilit dosyasının senkron klasöründe
bulunmasının yan etkilerini (yüklenmesi, çakışma kopyaları) ancak L2 ortadan kaldırır.
**TEST EDİLEMEDİ:** gerçek OneDrive.

### 2.3 Yedeğin kalıcılığı (W2, W3, W7): seçenekler

| | Seçenek | Artı | Eksi |
|---|---|---|---|
| **B1** | **Doğrulanmış baytlar** `.bak.<hex>.tmp` dosyasına yazılır (`create_new`) → `sync_all` → rename → dizin flush → **ancak bundan sonra** ana dosya rename edilir → dizin flush | `.bak` diske yazılmadan ana dosya değişmez. Yedek, parmak izi doğrulanmış sürümdür (W3 kapanır) | Kayıt başına bir tam kopya. 512 MiB'a kadar dosyada süre artar |
| B2 | Eski dosyaya hard link verilir → `.bak` | Veri kopyası yok, eski veri zaten kalıcı | FAT/exFAT ve ağ paylaşımlarında yok. OneDrive ile davranışı bilinmiyor. Yedek kurcalanırsa ana dosyayla aynı inode paylaşılır |
| B3 | Önce ana dosya `.bak` adına taşınır, sonra yeni dosya yerine konur | Kopya yok | Arada **ana dosya hiç yok**. OneDrive bunu silme olarak eşitleyebilir. **Reddedildi** |
| B4 | `ReplaceFileW(lpBackupFileName)` | Windows'un yerleşik "yedekle ve değiştir" işlemi | `unsafe` FFI. Belgelenmiş ara hata durumları var (`ERROR_UNABLE_TO_MOVE_REPLACEMENT`). Linux karşılığı yok |

**Öneri: B1.** Yeni kayıt sırası (hepsi kilit altında):

```
1. bytes = seal()
2. cur = oku(yol); parmak_izi(cur) == disk_state değilse → FileChangedOnDisk
3. tmp     ← bytes          (create_new, write, sync_all)
4. backup_is_stale ise:  remove(.bak)          → dizin flush
   değilse ve yol varsa: bak_tmp ← cur (doğrulanmış baytlar; create_new, write, sync_all)
                         rename(bak_tmp → .bak) → dizin flush
5. kilit kimliği hâlâ bizim mi?  parmak_izi(oku(yol)) hâlâ cur mu?   değilse → iptal, tmp silinir
6. rename(tmp → yol) → dizin flush
7. disk_state güncellenir; yalnızca **10 dakikadan eski** sahipsiz .tmp dosyaları silinir (W5)
```

Herhangi bir adım 5'ten önce başarısız olursa ana dosya **değişmez**.

Dizin flush:
- **Linux:** `File::open(dir)?.sync_all()`.
- **Windows:** Dizin `custom_flags(FILE_FLAG_BACKUP_SEMANTICS)` ve **yazma** erişimiyle açılıp
  `sync_all()` çağrılır.
  - **DOĞRULANDI (P3):** Yazma erişimiyle `Ok`, salt okuma erişimiyle hata 5.
  - **TEST EDİLEMEDİ:** Bunun rename'i gerçekten diske yazdırıp yazdırmadığı.
- "Desteklenmiyor" türündeki hatalar (ağ sürücüsü, FAT) için politika: **veri `sync_all` hatası
  kesin hata**, dizin flush hatası Windows'ta uyarı, Linux'ta kesin hata.

### 2.4 Senaryo değerlendirmesi (B1 + L1 ile)

| Senaryo | Windows | Linux | Sınıf |
|---|---|---|---|
| İki örnek aynı anda kaydediyor | Kilit karşılıklı dışlama sağlar, kilit dosyası silinemez. İkincisi `SaveBusy` alır ya da sıra bekler, sonra `FileChangedOnDisk` alır | `flock` + inode kontrolü. Kilit silinirse ilk örnek commit'ten önce `LockLost` ile iptal eder | Windows: tasarım P1/P6 ile doğrulandı. Linux: TEORİK |
| Farklı makineler OneDrive üzerinden | Kilit makineler arasında yayılmaz (hiçbir zaman yayılmadı). Koruma parmak izi kontrolü ve gelecekte R1 | aynı | TEORİK |
| Süreç adım 3–5 arasında çöker | Ana dosya eski. Artık `.tmp`/`.bak.tmp` dosyaları 10 dk sonra temizlenir. Kilit işletim sistemi tarafından bırakılır | aynı. `flock` kapanışta bırakılır | Windows: kilit bırakılması DOĞRULANDI (E7). Linux: TEORİK |
| Süreç adım 6'dan sonra çöker | Ana dosya yeni, `.bak` eski ve kalıcı | aynı | TEORİK |
| Güç kesintisi, adım 3–5 | Ana dosya eski ve sağlam. `.bak` yeni ya da eski (her ikisi de geçerli) | aynı | **TEST EDİLEMEDİ** |
| Güç kesintisi, adım 6 sırasında | Rename ya oldu ya olmadı (NTFS metadata günlüğü), ana dosya eski ya da yeni. `.bak`'in verisi adım 4'te diske yazıldı | `ext4`'te `data=ordered` + dizin `fsync` ile aynı garanti | **TEST EDİLEMEDİ** |
| Güç kesintisi, flush'tan sonra | Kalıcı | Kalıcı | **TEST EDİLEMEDİ** (dizin flush'ın Windows'taki etkisi) |
| Parola değişikliği + çökme | Adım 4'te eski parolalı `.bak` silinir. Çökme olursa ana dosya eski parolalı kalır (yedek yok, güvenli yön) | aynı | TEORİK |

### 2.5 Önce başarısız olması gereken testler

Kayıt yolu adım adım test edilebilsin diye `vault.rs` içine yalnızca `#[cfg(test)]` altında
derlenen bir **adım kancası** eklenir: `fn(Step) -> io::Result<()>`. Kanca her adımda çağrılır ve
hata döndürerek çökme taklit eder. Üretim kodunda kanca derlenmez.

| # | Test | Platform | Bugün | Sonra |
|---|---|---|---|---|
| T1 | Kilit tutulurken `fs::remove_file(lock)` ve `fs::rename(x, lock)` başarısız olmalı | `#[cfg(windows)]` birim testi | **Ok** (başarısız) | Hata 32 / 5 |
| T2 | A kilidi tutar, kilit yolu silinir, B kilidi alır → A'nın commit'i `LockLost` ile iptal olmalı. Ana dosyada yalnızca B'nin sürümü olmalı | `#[cfg(unix)]` (Windows'ta T1 bunu imkânsız kılar) | A devam eder (başarısız) | `LockLost` |
| T3 | Bir iş parçacığı kilidi tutar, `save_file` süre sınırı içinde `SaveBusy` dönmeli (bekçi iş parçacığıyla) | her ikisi | Süresiz bekler (başarısız) | `SaveBusy` |
| T4 | Kanca olayları sıralı kaydedilir: `SyncBakTmp` < `RenameBak` < `SyncDir` < `RenameMain` | her ikisi | `SyncBakTmp` yok (başarısız) | Sıra tutar |
| T5 | Parmak izi kontrolünden sonra kanca `yol`'a başka baytlar yazar. Kayıt `FileChangedOnDisk` ile iptal olmalı, ya da `.bak` == doğrulanmış baytlar olmalı **ve** ana dosya ezilmemeli | her ikisi | Sessizce ezer (başarısız) | İptal |
| T6 | Her adımda çökme enjeksiyonu. Değişmezler: ana dosya eski ya da yeni geçerli bir kasadır (hiç eksik ya da yarım değil); `.bak` varsa eski baytlara eşittir ve eski parolayla açılır | her ikisi | Büyük ölçüde geçer (regresyon ağı) | Geçer |
| T7 | `mtime` = şimdi olan yabancı bir `vault.lav.<16hex>.tmp` dosyası kayıttan sonra **kalmalı**. `set_modified` ile 1 saat eskitilmiş olanı silinmeli | her ikisi | Taze dosya silinir (başarısız) | Kalır |
| T8 | `Vault.lav` ile açılıp `VAULT.lav` ile kaydedildiğinde sahte `FileChangedOnDisk` olmamalı (`canonicalize`) | `#[cfg(windows)]` | `FileChangedOnDisk` (başarısız) | Ok |
| T9 | Mevcut LA-03/LA-04/LA-11/LA-14 testleri **aynen** geçmeli | mevcut | geçiyor | geçiyor |

### 2.6 Sınırlamalar ve test edilemeyenler

- **Gerçek güç kesintisi** hiçbir platformda test edilemedi.
  - "NTFS rename'i atomiktir" yaygın bir kabul, ama Microsoft'un biçimsel bir garantisi değil.
  - `MOVEFILE_WRITE_THROUGH` (`unsafe` FFI) kullanılmıyor.
  - Dizin `FlushFileBuffers`'ının rename'i diske yazdırdığı **doğrulanmadı**.
- **OneDrive, antivirüs ve bulut yer tutucu dosyalar** denenmedi: tutma süreleri, `ERROR_CLOUD_*`
  hataları, kilit dosyasının eşitlenmesi.
- **Ağ sürücüleri (SMB):** kilit ve rename semantiği farklı olabilir. Dizin flush desteklenmeyebilir.
- **Junction, symlink ve hard link:** symlink oluşturmak ayrıcalık gerektiriyor (hata 1314), 8.3
  adlar bu birimde üretilmiyor. Bu yüzden takma adlarla aynı kasaya erişim yalnızca L2 +
  `canonicalize` ile kısmen ele alınır.
- **Linux davranışı** (`flock`, `unlink`, dizin `fsync`) bu makinede **hiç çalıştırılmadı**.
- **Makineler arası kilit yok.** Bu sınır kalıcıdır. Makineler arası çakışmaları ancak R1 tespit eder.

---

## 3. CI ve uygulama sırası

1. **CI'ya Linux test işi eklenmeli.** Bugün `cargo test` yalnızca `windows-latest` üzerinde
   çalışıyor; Linux'ta yalnızca fuzz işi var. T2 ve M1–M3'ün Linux yolları ancak böyle çalışır.
2. **PR-1 (bellek):** S + B + V + N, testler M1–M6. V için test yardımcılarının değiştirilmesine
   onay gerekir.
3. **PR-2 (dosya):** L1 + B1 + W5/W6, testler T1–T9.
4. **PR-3:** RustCrypto yeni nesil (U). Mevcut KAT'ler aynen geçmeli. Ardından M1–M3 yeniden
   çalıştırılır.
5. **Masaüstü uygulamasıyla birlikte:** A (silen ayırıcı), L2 (yerel kilit dizini), R1 tasarımının
   denetim bulgularıyla güncellenmiş hâli.

---

## 4. Uygulama öncesi netleştirmeler (2026-11-13, kararlarınızdan sonra)

Kararlar:
1. Test yardımcıları değişebilir; assertion'lar ve güvenlik beklentileri değişmez.
2. Önce Linux CI eklenir.
3. PR-1, PR-2 ve PR-3 ayrı kalır.
4. R1 üretime taşınmaz.

### 4.1 Yığın temizliği bir garanti değil, en iyi çaba (best-effort) önlemidir

- 64 KiB'lık temizlik yalnızca, dönülmüş çağrıların kullandığı yığın bölgesinin **muhtemelen**
  silinmesini sağlar. Şu durumlarda etkisizdir:
  - derleyici bir değeri çağıranın çerçevesine yerleştirirse;
  - bir değer yazmaçlarda ya da SIMD yazmaçlarında kalırsa;
  - başka bir iş parçacığının yığınında kalırsa (Argon2 `parallel` özelliği kapalı, şu an tek iş
    parçacığı);
  - 64 KiB'tan derin bir çağrı zinciri olursa.
- **Hiçbir belgede ya da hata mesajında "anahtarlar bellekten silinir" garantisi verilmez.**
  İfade şöyle olur: "kalıntılar en iyi çabayla azaltılır, release derlemesinde ölçülür".
- M1–M3 **release** derlemesinde çalıştırılır. Sonuç yalnızca o araç zinciri, hedef ve profil için
  geçerlidir. Debug derlemede başarısız olması güvenlik iddiası anlamına gelmez; hedef release'tir.

### 4.2 `Box` tek başına temizlik sağlamaz: `DerivedKeys` ve geçici kopyaların envanteri

`Box`, yalnızca *taşıma* sırasında oluşan yığın kopyalarını önler. Silme işlemini `Drop` yapar.
Tasarım:
- `struct KeyPair { payload: [u8; 32], commitment: [u8; 32] }` için `Zeroize` + `ZeroizeOnDrop`.
- `pub struct DerivedKeys(Box<KeyPair>)`. Kutu bırakılırken önce `KeyPair` silinir, sonra bellek
  serbest bırakılır.
- Kutu **önce sıfırlarla** ayrılır; HKDF çıktısı doğrudan kutunun alanlarına yazılır. Böylece
  türetilmiş anahtarın yığında tam bir kopyası hiç oluşmaz (kütüphanelerin iç kopyaları hariç,
  bkz. tablo).

| Geçici değer | Bugün | PR-1 sonrası |
|---|---|---|
| Argon2 `master` | `Zeroizing<[u8;32]>` yığında; drop'ta silinir | Aynı, ama `#[inline(never)]` iç fonksiyonda; dönüşte yığın temizliği |
| Argon2 iç değerleri (BLAKE2b durumu, `hash`) | silinmiyor (`blake2 0.10`) | yığın temizliği (en iyi çaba); PR-3'te `blake2 0.11 zeroize` |
| Argon2 bellek blokları | kendi `Zeroizing<Vec<Block>>` | aynı |
| HKDF PRK, `Hkdf` iç HMAC durumu, `output`/`prev` | silinmiyor (`hkdf 0.12` / `0.13`) | yığın temizliği |
| HKDF çıktısı (anahtarlar) | yığındaki `Zeroizing` → `DerivedKeys` içine **taşınıyor** (kopya kalıyor) | doğrudan heap'teki `KeyPair`'e yazılır |
| HMAC (commitment) `buf` = anahtar ⊕ pad | silinmiyor (`hmac 0.12` ve `0.13`) | iç fonksiyon + yığın temizliği |
| Parolanın SHA-256'sı | `sha256()` `Zeroizing` döndürüyor; **dönüş taşıması kopya bırakıyor** | özet doğrudan `CompositeKey` tamponuna yazılır (`finalize_into`) |
| SHA-256 blok tamponu (parola baytları) | silinmiyor (`sha2 0.10`) | iç fonksiyon + yığın temizliği |
| XChaCha `subkey`, Poly1305 durumu | silinmiyor | `encrypt`/`decrypt` iç fonksiyon + yığın temizliği |
| `Vault` taşınması | 64 bayt anahtar kopyası | yalnızca işaretçi taşınır |

### 4.3 NFC: quick-check'in `Maybe` sonucu

- `is_nfc_quick` **Yes / No / Maybe** döndürür. Yalnızca **Yes**, metnin NFC olduğunu kanıtlar.
  **Maybe asla Yes gibi değerlendirilmez.**
- **Bulgu:** Birleşebilen işaretlerin çoğu (U+0300–U+0304 gibi) NFC_QC=Maybe değerindedir.
  Denetimde gösterilen sızıntı tam olarak bu durumdu. Yani "Yes ise atla, değilse kütüphanenin
  `nfc()` yineleyicisini kullan" yaklaşımı **gösterilen sızıntıyı kapatmaz.**
- **Karar:**
  - Yes → normalleştirme atlanır.
  - No ya da Maybe → **heap ayırmayan** bir NFC yolu kullanılır. Bu yol yine `unicode-normalization`
    kütüphanesinin kendi karakter düzeyi tablolarını kullanır: `char::decompose_canonical`,
    `char::canonical_combining_class`, `char::compose`.
  - Bizim yazdığımız kısım yalnızca UAX #15'in sıralama ve birleştirme adımlarıdır. Bu adımlar,
    kütüphanenin kendi `Recompositions` durum makinesiyle aynı mantıktadır. Unicode tabloları
    yazılmaz.
  - Çalışma şekli:
    - İki geçiş: önce ayrışmış uzunluk sayılır, sonra tam o kapasitede bir
      `Zeroizing<Vec<char>>` ayrılır. Kapasite aşılmadığı için yeniden ayırma (realloc) olmaz.
    - Kanonik sıralama için yerinde, kararlı ve bellek ayırmayan bir eklemeli sıralama kullanılır.
      std'nin `sort_by_key` fonksiyonu tampon ayırabilir.
    - Birleştirme yerinde yapılır. Sonuç, tam boyutlu bir `Zeroizing<String>`'e yazılır.
- **Doğruluk güvencesi (M6'nın parçası):** Kütüphanenin `nfc()` çıktısıyla farklılık testi.
  - Tek karakter olarak tüm kod noktaları.
  - Bilinen zor durumlar: bileşim istisnaları, tekil eşlemeler, Hangul LV+T, engellenmiş
    işaretler.
  - On binlerce rastgele dizi.
  - Mevcut NFC/NFD eşdeğerlik testi ve KAT'ler aynen geçmeli.
- **Kalan risk:** Birleştirme mantığında bir hata, bazı parolaların farklı bir anahtar üretmesine
  yol açar. Bu yüzden farklılık testi PR'ın kabul şartıdır.

### 4.4 Linux: inode kontrolü ile rename arasındaki TOCTOU (PR-2 tasarımı)

- Sıra şu: `fstat(kilit) == stat(yol)?` → `rename(tmp, kasa)`. İki adım arasında bir sync istemcisi
  ya da başka bir süreç kilit dosyasını silebilir ve ikinci bir örnek yeni bir kilit alabilir.
  **Son inode kontrolü tek başına yeterli değildir.** Pencereyi küçültür ama kapatmaz. POSIX'te
  "kilit hâlâ bendeyse rename et" diye atomik bir işlem yoktur.
- Pencerenin sonucu iki örneğin aynı anda rename etmesidir. Rename atomik olduğu için dosya
  bozulmaz; kaybedenin değişikliği sessizce kaybolur (kayıp güncelleme).
- **Gerçek önlem, kilidi silinemez bir yere koymak:**
  - **L2-Linux:** kilit `$XDG_STATE_HOME` (yoksa `~/.local/state`) altında, `0700` izinli bir
    dizinde tutulur, anahtarı `SHA-256(canonicalize(yol))`. Bu dizine sync istemcileri (Dropbox,
    Syncthing, rclone) yazmaz. Silebilecek tek taraf aynı kullanıcının yerel kodudur; bu da kapsam
    dışıdır.
  - **Alternatif:** kasa dizininin kendisi `flock` ile kilitlenir. İçi dolu bir dizin silinemez.
    Ancak dizin yeniden adlandırılabilir; yol tabanlı `rename(tmp, yol)` başka bir dizine düşer.
    Tam çözüm, `openat`/`renameat` ile dizin tanıtıcısına göre işlem yapmak, yani `rustix` ya da
    `libc` bağımlılığı. Bu da çekirdekte yeni bir bağımlılık ve `unsafe` tartışması demek.
- **PR-2 önerisi (güncellendi):**
  - Windows: L1 (DELETE paylaşımı olmadan; tutulurken silinemediği doğrulandı).
  - Linux: L2 (kilit senkron klasörünün dışında) + inode kontrolü (yalnızca **tespit**) +
    rename'den hemen önce parmak izinin yeniden okunması.
  - Kalan pencere (sync istemcisi ana dosyayı tam o mikrosaniyelerde değiştirirse) belgelenir.
    Makineler arası çakışmayı zaten yalnızca R1 yakalar.

### 4.5 Dosya ve dizin `fsync` garantileri (ayrı ayrı)

**Windows** (std `sync_all` ve `sync_data` → `FlushFileBuffers`):

| İşlem | Belgelenmiş / gözlenen | Garanti | Sınıf |
|---|---|---|---|
| `File::sync_all` | Dosya verisini ve meta verisini cihaza yazdırır, aygıt önbelleğine flush gönderir | Aygıt flush'a uyarsa veri kalıcıdır. "Write caching / buffer flushing'i kapat" ilkesi ya da yalan söyleyen bir disk bunu bozar | Belgelenmiş; güç kesintisiyle TEST EDİLEMEDİ |
| Dizin handle'ında `sync_all` (BACKUP_SEMANTICS + yazma erişimi) | `Ok` dönüyor (**DOĞRULANDI P3**); salt okuma erişimiyle hata 5 | Rename kaydını diske yazdırdığı **belgelenmemiş ve doğrulanmamış** | TEST EDİLEMEDİ |
| `fs::rename` (MoveFileExW, REPLACE_EXISTING) | NTFS meta veri günlüğü; eski ya da yeni ad | Atomiklik yaygın kabul, ama biçimsel olarak belgelenmemiş. Kalıcılık günlük flush zamanına bağlı. `MOVEFILE_WRITE_THROUGH` kullanılmıyor | TEORİK |
| FAT/exFAT, SMB | Günlük yok / sunucuya bağlı | Garanti yok | TEST EDİLEMEDİ |

**Linux** (std `sync_all` → `fsync`, `sync_data` → `fdatasync`):

| İşlem | Garanti | Not |
|---|---|---|
| `fsync(dosya)` | Dosya verisi ve inode kalıcı | **Dizin girdisi dahil değil** |
| `fsync(dizin)` | O dizindeki oluşturma ve rename girdileri kalıcı | Rename'den sonra **zorunlu**. `File::open(dir)?.sync_all()` |
| `rename` | POSIX'e göre atomik (eski ya da yeni) | Kalıcılık ancak dizin `fsync`'i ile |
| `fsync` hatası (EIO) | Sayfalar "temiz" işaretlenebilir; yeniden denenen `fsync` yanlışlıkla başarı dönebilir ("fsyncgate") | **Her `fsync` hatası o kayıt için kesin hatadır, yeniden denenmez.** Aynı kural Windows'ta da uygulanır |
| ext4 `data=ordered`, `auto_da_alloc` | Rename ile değiştirmede veriyi önce yazmaya çalışır | Bir sezgisel kural, garanti değil. Açık `fsync` yine gerekli |
| NFS / FUSE | Sunucuya ya da sürücüye bağlı | TEST EDİLEMEDİ |

Her iki platformda da kural aynı: **veri `fsync` hatası kesin hatadır.** Dizin flush hatası:
- Linux'ta kesin hatadır.
- Windows'ta, semantiği doğrulanmadığı için, yalnızca "desteklenmiyor" türündeki hatalarda uyarıya
  düşer; diğer hatalar kesin hatadır.
