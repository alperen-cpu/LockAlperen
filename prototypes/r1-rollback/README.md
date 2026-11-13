# R1 Prototipi: Rollback ve Çatal Tespiti

> **PROTOTİP.** Üretim kodu değildir. `lav-core` bu crate'i kullanmaz, kasa formatı değişmedi.
> Amaç, `docs/CRYPTO_REVIEW_R1_R2.md` §1'deki tasarımı (version vector + yerel durum + emekli
> kimlik bilgileri) üretime almadan önce test etmektir.

## Ne modelleniyor

| Parça | Dosya | Not |
|---|---|---|
| Version vector | `src/vv.rs` | Cihaz başına `(sayaç, kayıt etiketi)` |
| Yerel durum deposu | `src/store.rs` | İki yuvalı atomik yazım, SHA-256 sağlama, özel kilit |
| Karar mantığı | `src/lib.rs` `evaluate` | Saf fonksiyon |
| Cihaz akışı | `src/lib.rs` `Device` | open / confirm / save, çökme enjeksiyonu |
| Kasa dosyası | `SimVault` | **Şifresiz simülasyon.** Gerçek formatta bu alanlar AEAD ile doğrulanmış payload'da olurdu |

## Testler

- `tests/scenarios.rs`: 23 senaryo. Her test başında **PROTECTION**, **LIMITATION** ya da **FINDING** yazar.
- `tests/property.rs`: rastgele kayıt, senkron, saldırgan tekrar oynatması ve çökme dizileri
  (5 tohum × `R1_PROP_STEPS`, varsayılan 300; 2000 adımla da çalıştırıldı).
  - Güvenlik özelliği: cihaz, referansının altında ya da onunla karşılaştırılamayan bir dosyayı
    hiçbir zaman sessizce kabul etmez, referansı geri gitmez.
  - Canlılık: dürüst ve sıralı kullanımda, çökmeler olsa bile, yanlış alarm çıkmaz.

## Bulgular (prototipin tasarıma kattıkları)

1. **"Önce kasa, sonra durum" tek başına yetmiyor.** Bu sıra yanlış rollback alarmını önlüyor.
   Ancak cihaz kimliği kopyalanma tespitiyle birlikte, aradaki her çökme sahte bir "klonlanmış
   cihaz" alarmına dönüşüyor (`without_intent_record_a_crash_looks_like_a_cloned_device`).
   **Çözüm:** Kayıttan önce yerel duruma bir *niyet kaydı* `(sayaç, etiket)` yazılır. Sıra şöyle:
   niyet → kasa → onay.
2. **Dosya hash'i kendi kaydını tanımaya yetmiyor.** Property testi bunu ilk çalıştırmada buldu:
   A kasayı yazar, çöker. B onun üstüne kaydeder. A kendi sayacını görür ama hash farklıdır ve
   sahte alarm verir. **Çözüm:** Version vector'daki her cihaz girdisi, her kayıtta rastgele
   üretilen bir **kayıt etiketi** taşır. Etiket, başka cihazlar dosyanın üstüne kaydetse bile
   korunur. Yan kazanç: aynı sayaçla yazan bir klon da `DeviceIdReused` olarak yakalanır.
   Eski parolayı bilen bir saldırgan yeni dosyaları çözemediği için yeni etiketleri de bilemez.
3. **Emekli kimlik kontrolü `(salt, commitment)` ile değil, salt ile yapılmalı.** v2 commitment'ı
   nonce'u da kapsıyor ve **her kayıtta değişiyor**, bu yüzden bir parolayı tanımlayamaz. Salt
   yalnızca parola değişince yenilendiği için kimlik bilgisi dönemini tanımlar. Ayrıca `vault_id`
   şifreli payload'da olduğu ve kilit açılmadan bilinmediği için emekli salt listesi kasa başına
   değil, **cihaz genelinde** tutulmalı.
4. **Yerel durum için `HKDF(master)` ile MAC (özgün tasarım) uygulanabilir değil.** Kilit açmadan
   önce yapılan kontrol bu durumu okumak zorunda, ama o noktada master yok. Ayrıca bu dizine
   yazabilen biri dizini silebilir de (sonuç: TOFU). Bu yüzden MAC yerel saldırgana karşı bir şey
   katmıyor. Prototip **SHA-256 sağlama + iki yuva** kullanıyor: amaç kazara bozulmayı tespit
   etmek. Yerel saldırgan kapsam dışı kalıyor.
5. **Atomik yerel durum güncellemesi** (test edilen yaklaşım):
   - İki yuva dönüşümlü yazılır, her biri `tmp + fsync + rename` ile ve nesil numarasıyla.
   - En yeni yuva bozuksa bir önceki geçerli yuva kullanılır ve `Degraded` olarak **gösterilir**.
     Normal işleyişte önceki yuva bir önceki adımdır (çoğunlukla niyet kaydı). **Düzeltme
     (bağımsız denetim T2):** Bu, yazılacak yuvanın nesil paritesiyle seçilmesine dayanıyor. Elle
     kopyalanmış ya da geri yüklenmiş bir yuva pariteyi bozarsa garanti kalmıyor. Ayrıca güç
     kesintisinde NTFS birden fazla rename'i kaybedebilir (T5, test edilemedi).
   - İki yuva da bozuksa sonuç `Untrusted` olur. Sessizce "ilk kullanım" sayılmaz, açık bir
     sıfırlama gerekir.
   - Oku-değiştir-yaz özel bir dosya kilidi altında yapılır. 8 iş parçacığı × 10 güncellemede
     kayıp yok. **Düzeltme (bağımsız denetim F9, doğrulandı):** std dosyaları FILE_SHARE_DELETE
     ile açıyor. Bu yüzden tutulan kilit dosyası silinebiliyor ya da üzerine rename yapılabiliyor.
     Bu durumda ikinci örnek yeni bir kilit alıyor ve bir güncelleme kayboluyor. Kilit tek başına
     kayıp güncellemeyi **önlemiyor**.
6. **Yerel durum kaybolursa cihaz yeni bir kimlik alır.** Böylece eski kimliğin sayaçları asla
   yeniden kullanılmaz.
7. **Sızmış eski parola:** Bunu bilen biri tamamen geçerli dosyalar üretebilir. Tasarım ancak
   şunları sağlar:
   - Değişikliği görmüş cihaz eski salt'lı dosyayı kilit açmadan durdurur.
   - Yeni salt'lı sahte dosya, `vault_id`'si bilinen kasada ve vektör ilerlemiş göründüğünde
     `CredentialChanged` (onay gerekli) verir. **Düzeltme (bağımsız denetim F2 ve F5,
     doğrulandı):** Bu her cihazda geçerli **değil**. Yeni bir `vault_id` taşıyan sahte dosya
     `FirstUse` olarak sessizce kabul ediliyor. Vektör karşılaştırılamazsa kimlik değişikliği
     `Fork` altında gizleniyor ve `confirm()` gerçek salt'ı emekliye ayırıyor.
   - Değişikliği **görmemiş** bir cihaz, eski salt'lı sahte dosyayı **sessizce kabul eder**
     (`forged_file_with_leaked_old_password`).
8. **Kullanılabilirlik maliyeti:** Başka bir cihazda yapılan meşru bir parola değişikliği de
   `CredentialChanged` onayı ister.

## Bağımsız denetim bulguları (2026-11-13), üretimden önce çözülmeli

`tests/review_adversarial.rs` içindeki 9 test, bulguları **mevcut hatalı davranışı doğrulayarak**
gösteriyor. Bu testler `#[ignore]` ile işaretli ve `-- --ignored` ile çalıştırıldığında hepsi geçiyor.
Düzeltildiklerinde bu testler ters çevrilmeli.

| # | Önem | Bulgu | Gereken tasarım değişikliği |
|---|---|---|---|
| F1 | Orta | Klon, aynı sayaç ama farklı etiketle üçüncü cihazda sessizce kabul ediliyor (düzenleme kaybı) | Her cihaz girdisinde aynı sayaç ve farklı etiket görülürse Fork/DeviceIdReused verilmeli |
| F2 | Orta-düşük | Yeni `vault_id`'li sahte dosya, parolayı değiştiren cihazda `FirstUse` olarak sessizce kabul ediliyor | Yerel durumda yol → `vault_id` bağı tutulmalı. Bilinen yolda bilinmeyen `vault_id` sessiz olmamalı |
| F3 | Düşük-orta (DoS) | Sayaç `u64::MAX` olursa her kayıt panic ile çöküyor | Sayaç üst sınırı (≈2⁴⁸) ve `checked_add` |
| F4 | Orta | Geride kalan cihazdan gelen zehirli sayaç, parolayı değiştiren cihazı kilitliyor | F3 sınırı. `confirm` reddedilen sayaçları birleştirmemeli |
| F5 | Orta | Kimlik değişikliği Fork/Rollback altında gizleniyor; `confirm` gerçek salt'ı emekliye ayırıyor | Kimlik değişikliği ayrı bir bayrak olmalı. Salt yalnızca açık onayla emekliye ayrılmalı, geri alınabilmeli |
| F6 | Düşük | Çökme sonrası geri alınan dosyada bekleyen niyet sessizce siliniyor (son düzenleme kaybı) | `pending` varken `F[me] < c` ise "son kayıt kaybolmuş olabilir" uyarısı verilmeli |
| F7 | Düşük | İki uygulama örneği tek `pending` yuvasını eziyor ve sahte klon alarmı çıkıyor | niyet → yazma → onay tek bir kilit altında yapılmalı |
| F8 | Düşük | Durum geçici dosya adı PID'ye dayanıyor; PID yeniden kullanılırsa güncelleme başarısız | Rastgele ad, yeniden deneme, temizlik |
| F9 | Düşük-orta | Tutulan kilit dosyası silinebiliyor ve güncelleme kayboluyor | `share_mode`'da DELETE olmamalı. Kilitten sonra dosya kimliği kontrol edilmeli |

Teorik olanlar (testle gösterilmedi):
- **T1:** Eski `base` ile kayıt yapılabiliyor.
- **T2:** Yuva paritesi bozulabiliyor; eşit nesil sessizce kabul ediliyor.
- **T3:** `Degraded` notu yalnızca bir kez görünüyor.
- **T4:** Prototipin `write_atomic`'i sabit `.tmp` adı kullanıyor.

## Doğrulanmış sınırlar (testlerle belgelendi, çözülmedi)

- Version vector yalnızca **bu cihazın gördüğü** sürümlerle karşılaştırılabilir. B'nin
  referansından yeni olan bir sürüme yapılan rollback B'de fark edilmez
  (`rollback_newer_than_devices_reference_is_not_detected`).
- İlk kullanım ya da durumu silinmiş cihaz: TOFU.
- Parola değişikliğini görmemiş cihaz eski dosyanın tekrar oynatılmasını kabul eder.

## Doğrulanmadı / prototipin kapsamı dışında

- **Gerçek elektrik kesintisi** test edilmedi. Çökmeler süreç içinde ve belirli noktalarda
  simüle edildi. "Yırtık yuva" simülasyonu, verinin diske ulaşmadığı durumu taklit ediyor.
- Windows'ta `rename`'in mevcut dosyanın üzerine atomik yazdığı **varsayıldı**. Dizin `fsync`'i
  Windows'ta yok. Bu, gerçek donanımda doğrulanmadı.
- **Gerçek OneDrive** kullanılmadı. Çakışma kopyası dosya kopyalanarak simüle edildi.
- İçerik birleştirme (merge) prototiplenmedi. Yalnızca vektör birleştirme var.
- Kayıt etiketi prototipte `RandomState` ile üretiliyor. Üretimde `OsRng` kullanılmalı.
- TPM sayacı, `%LOCALAPPDATA%` dışındaki konumlar ve arayüz (uyarı metinleri, salt okunur açma)
  denenmedi.
