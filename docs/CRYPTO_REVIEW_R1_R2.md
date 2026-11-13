# Kriptografi ve Mimari İncelemesi: R1 (Rollback) ve R2 (Anahtar Bağlayıcılık)

> **Durum (2026-11-13 güncellemesi):** 1. aşama sıkılaştırmaları ve R2 (format v2, key commitment)
> **uygulandı**, bkz. `docs/FORMAT.md` ve `docs/IMPLEMENTATION_REPORT_2026-11.md`. R1 yalnızca
> bağımsız bir prototip olarak var (`prototypes/r1-rollback`), üretim koduna alınmadı.
> Aşağıdaki metin özgün analizdir.
> **Yöntem:** Kendi analizim, önerilerimi görmeden çalışan bağımsız bir inceleme ajanının
> analizi (bölüm 3) ve R2 için iki ayrı, çalışan kavram kanıtı (PoC). "Kanıtlandı" ifadesi yalnızca
> kodla gösterilen şeyler için kullanılıyor.

---

## 1. R1: Rollback (geri alma) koruması

### 1.1 Tehdit ve gerçek zarar

Saldırgan, eşitlenen dosyaya yazabilen biri:

- ele geçirilmiş bir OneDrive hesabı ya da sürüm geçmişi,
- klasörü paylaşan kötü niyetli bir cihaz,
- eski bir `.bak` dosyası.

Bu kişi, **eski ama orijinal** bir kasa dosyasını geri koyar. Dosya gerçekten bizim ürettiğimiz bir dosya olduğu için AEAD doğrulamasından sorunsuz geçer.

En ciddi zarar senaryosu:

1. Ana parolanız sızdı ve siz parolayı değiştirdiniz.
2. Saldırgan dosyayı parola değişikliğinden önceki sürüme döndürür. O sürüm **sızan eski parolayla** şifrelidir.
3. Yeni parolanız tutmaz. Siz eski parolayı denersiniz, kasa açılır.
4. Bundan sonra eklediğiniz her yeni sır, **saldırganın bildiği anahtarla** kaydedilir.

Diğer zararlar:

- Değiştirilmiş site parolaları eski hâline döner.
- İptal edilmiş erişim bilgileri geri gelir.
- Son düzenlemeler sessizce kaybolur.

> **Not:** Rollback **gizliliği** doğrudan bozmaz. Saldırgan eski dosyayı zaten elinde tutuyor. Asıl zarar **bütünlükte** ve kasanın ele geçmiş bir anahtarla yeniden kullanılmasında.

### 1.2 "Sayaç kasa dosyasının içinde olursa saldırgan eski sayacı da geri yükleyebilir mi?"

**Evet. Sayaç tek başına rollback'i engellemez.** Eski dosya kendi eski sayacıyla birlikte, tutarlı ve doğrulanmış bir bütündür. Dosyanın içindeki hiçbir değer, kendisinin "en yeni" olduğunu kanıtlayamaz.

Rollback ancak saldırganın geri alamayacağı **ikinci bir referansla** karşılaştırılarak tespit edilebilir. Sayaç dosyanın içinde kalır, ama "en yüksek görülen değer" saldırganın erişemediği bir yerde tutulur.

### 1.3 Güvenilir referans nerede tutulmalı?

| Yer | Senkron saldırganına karşı | Not |
|---|---|---|
| Kasa ile aynı klasör | ❌ | Saldırgan onu da geri alır |
| `%APPDATA%` (Roaming) | ⚠️ | Kurumsal "roaming profile" kullanılıyorsa sunucuya eşitlenir |
| `HKCU` kayıt defteri | ⚠️ | `NTUSER.DAT` roaming profile ile taşınır |
| Credential Manager | ⚠️ | "Enterprise" kalıcılıkta dolaşır, boyut sınırları var |
| **`%LOCALAPPDATA%`** | ✅ | **Önerilen.** Senkronize edilmez, roaming değildir. OneDrive Known Folder Move bu klasörü kapsamaz |
| TPM NV monotonik sayacı | ✅✅ | Disk imajını geri yükleyen yerel yöneticiye bile dayanır. Ancak karmaşık: yönetici yetkisi ya da owner yetkilendirmesi gerekebilir, yazma ömrü sınırlı. **Şimdilik gerekmiyor** |
| Sunucu ya da şeffaflık günlüğü | ✅✅ | Çok cihaz için tek tam çözüm, ama "sunucusuz" tasarımla çelişiyor |

### 1.4 Önerilen tasarım (iki incelemenin birleşimi)

Benim ilk taslağım tek bir `generation` sayacı ve son 16 sürümün listesine (`ancestors`) dayanıyordu. Bağımsız inceleme bunun yerine **cihaz başına sayaç (version vector)** önerdi. Bu daha güçlü, çünkü:

- Çatalı, yani iki cihazın birbirinden habersiz kaydetmesini, N sürüm sınırı olmadan **kesin** tespit eder.
- OneDrive çakışma kopyalarını doğal olarak tanır.
- Bilinçli geri yüklemeyi "ileri bir adım" olarak modelleyebilir.

Aşağıdaki birleşik tasarım bunu esas alıyor.

**Kasanın içine eklenecek alanlar** (şifreli ve doğrulanmış payload, header'da düz metin meta veri yok):

| Alan | Anlamı |
|---|---|
| `vault_id` | 128 bit, kasa oluşturulurken bir kez rastgele üretilir. Parola değişince korunur |
| `vv` | `device_id → bu cihazın kaç kez kaydettiği` haritası (version vector) |
| `last_writer` | Son kaydeden cihazın kimliği ve görünen adı |
| `saved_at` | Kayıt zamanı. **Yalnızca gösterim** için, hiçbir güvenlik kararı saate dayanmaz |

**Cihaza özel durum** (`%LOCALAPPDATA%\LockAlperen\state\`, atomik yazılır, senkron klasörüne asla konmaz):

| Alan | Anlamı |
|---|---|
| `device_id` | Bu cihazın rastgele kimliği |
| Kasa başına (anahtar `SHA-256(vault_id)`) | Son görülen `vv` ve o dosyanın SHA-256'sı |
| **Emekli kimlik bilgileri** | Bu cihazda yapılan ya da görülen parola değişikliklerinden kalan eski `(salt, commitment)` çiftleri. Commitment R2'den gelir |
| MAC | `HKDF(master, "LKAV device-state")` ile. Yalnızca bozulmaya karşı. Bu dosyaya yazabilen biri yerel saldırgandır ve kapsam dışıdır |

**Kilit açılmadan ÖNCE:** Header'daki `(salt, commitment)` emekli listesindeyse açılış durdurulur: *"Bu dosya, <tarih> günü değiştirdiğiniz eski ana parolayı kullanıyor."* Yalnızca açık ve bilinçli bir onayla devam edilebilir.

Bu adım 1.1'deki **en kötü senaryoyu** kilit açma ve şifre çözme yapılmadan engeller. Bu ancak R2'deki commitment değeriyle mümkün, çünkü salt tek başına parolayı tanımlamaz.

**Kilit açıldıktan sonra** dosyadaki `vv` (F) cihazdaki `vv` (L) ile karşılaştırılır:

| Durum | Karar |
|---|---|
| Bu cihazda kayıt yok | İlk kullanım (TOFU). Kabul edilir, "bu cihazda ilk kez" bilgisi ve "son kaydeden: cihaz, tarih" gösterilir |
| Her cihaz için F ≥ L | **OK.** Doğrusal ilerleme, durum güncellenir |
| Herhangi bir cihaz için F < L | **ROLLBACK.** Güçlü uyarı verilir, otomatik kayıt kapanır, salt okunur açılır |
| Ne F ≥ L ne de F ≤ L | **ÇATAL.** Eşzamanlı çevrimdışı düzenleme ya da saldırı. Birleştirme önerilir |
| F = L ama dosya hash'i farklı | **ÇATAL.** Dürüst cihazlar bunu üretemez |

**Kaydederken:**

- `vv_yeni = max(L, F)` alınır ve bu cihazın sayacı 1 artırılır.
- Önce kasa yazılır, **sonra** cihaz durumu. Tersi yapılırsa araya giren bir çökme yanlış rollback alarmı üretir.

**Bilinçli geri yükleme** ayrı bir eylemdir (".bak'tan geri yükle"):

1. Ana parola yeniden sorulur.
2. Eski dosya açılır.
3. Birleşik `vv + 1` ile kaydedilir.

Böylece geri yükleme ileri bir adım sayılır ve diğer cihazlarda alarm üretmez.

**OneDrive çakışma kopyaları** (`Kişisel-PC2.lav` gibi) karşılaştırılamayan `vv` taşıdığı için tanınır. Kayıt UUID'si ve `modified` alanıyla birleştirilebilir.

### 1.5 Garanti ve sınırlar

**Kesin garantiler:**

- **Tek bilgisayar ve yerel durum:** Bu bilgisayar, kendi açtığı ya da kaydettiği bir sürümden **daha eski** ya da **ondan çatallanmış** bir sürümü hiçbir zaman sessizce kabul etmez. Uygulamanın `.bak` dosyası ve OneDrive sürüm geçmişi de buna dahil.
- **Emekli parola:** Parola değişikliğini yapmış ya da görmüş bir cihaz, eski parolalı dosyayı kilit açılmadan önce yakalar.

**Tespit EDİLEMEYENLER (tasarım gereği):**

- **Çok cihazlı kullanım:** Her cihaz yalnızca kendi gördüğü kadarını korur. B cihazının son gördüğü durumdan daha yeni bir sürüme yapılan rollback B'de fark edilmez. Saldırgan A'nın en yeni kayıtlarını B'den saklayabilir.
- **Çatal bölme:** Saldırgan cihazları ayrı geçmişlere bölebilir. Bu, cihazlardan biri karşılaştırılamayan bir `vv` gördüğü anda ortaya çıkar. Sunucusuz bir tasarımda daha fazlası mümkün değil: güvenilir ortak bir kanal olmadan en fazla çatal tutarlılığı (fork consistency) sağlanabilir (SUNDR, Li, Krohn, Mazières, Shasha, OSDI 2004).
- **Yeni cihaz ya da silinmiş yerel durum:** İlk kullanım kör noktası (TOFU).
- **Yerel durumu da geri alabilen saldırgan:** Yerel yönetici ya da disk imajı. Buna karşı yalnızca TPM sayacı korur, ve bu kapsam dışı.

**Hafifletme:** Her kilit açılışında doğrulanmış olarak *"Son kayıt: <tarih>, <cihaz>"* gösterilir. Böylece ilk kullanımda bile bir insan eski bir kasayı fark edebilir.

### 1.6 Alternatifler

| Seçenek | Rollback | Çatal | Eski parolaya dönüş | Yorum |
|---|---|---|---|---|
| Yalnızca dosya içi sayaç | ❌ | ❌ | ❌ | Sadece kazara geri yüklemeyi gösterir |
| Yalnızca yerel dosya parmak izi | ⚠️ | ⚠️ | ❌ | Her değişiklik alarm verir, çok cihazda kullanılamaz |
| Tek sayaç + son N hash + yerel işaret (ilk taslağım) | ✅ | ⚠️ (N sınırı) | ❌ | Yeterli ama zayıf |
| **Version vector + yerel durum + emekli kimlik bilgileri** | ✅ | ✅ | ✅ (değişikliği gören cihazda, kilit açmadan önce) | **Önerilen** |
| \+ TPM NV sayacı | ✅✅ | ✅ | ✅ | Yerel yöneticiye karşı. Kurumsal ihtiyaç doğarsa |
| Sunucu ya da şeffaflık günlüğü | ✅✅✅ | ✅✅ | ✅✅ | Ürün felsefesine aykırı |

### 1.7 Format ve uyumluluk

- **Payload:** `vault_id`, `vv`, `last_writer` ve `saved_at` eklenir. `schema` 2 olur ve alanlar **zorunlu** olur.
- **Header:** Değişmez. Emekli kimlik bilgisi kontrolü R2'nin header'a eklediği commitment alanını kullanır.
- **Cihaz durumu:** Yeni bir yerel dosya. Formatın parçası değil ama kendi sürüm numarası olmalı.
- **Uyumluluk:** Yayınlanmış dosya olmadığı için yük yok. Payload doğrulanmış olduğu için saldırgan alanları silerek eski bir kasa taklit edemez.

### 1.8 Yeni riskler

- **Yanlış alarm yorgunluğu:** Alarm salt okunur açma, tarih ve cihaz gösterimi şeklinde olmalı. Uygulamayı tamamen durduran bir engel olmamalı.
- **Meta veri:** `vault_id`, cihaz sayısı ve kayıt sayısı yalnızca şifreli payload'da durmalı. Yerel durum dosyası "bu cihazda bir kasa var" bilgisini ele verir.
- **Saat:** Hiçbir karar saate dayanmaz.
- **Karmaşıklık:** Birleştirme mantığı veri kaybı hatalarına açıktır. Birleştirme her iki tarafı da koruyan, kayıt bazında ve testlerle sınırlanmış bir işlem olmalı.

### 1.9 Uygulanırsa gerekli testler

1. Üç sürüm kaydedilir, ortadaki sürümün baytları geri konur: **Rollback**.
2. `.bak` ya da herhangi bir eski orijinal dosya açılır: **Rollback**. Bilinçli geri yükleme akışından sonra alarm çıkmaz ve `vv` artar.
3. Eşit `vv` ama farklı hash: **Çatal**.
4. Aynı tabandan iki çevrimdışı düzenleme: **Çatal**. Birleştirme her iki düzenlemeyi de korur ve sonuçtaki `vv` ikisini de kapsar.
5. **Emekli kimlik bilgisi:** Parola değiştirildikten sonra eski dosya **KDF çalışmadan önce** durdurulur. Eski parolayla açma denemesi açık onay olmadan mümkün değildir.
6. İki ayrı durum dizini (iki cihaz) kullanılır. Geride kalan cihaz yeni sürümü kabul eder, önde olan cihaz eskisini reddeder. Kör nokta da bir testle **belgelenir**.
7. Durum dosyası kurcalanır: "durum güvenilmez" uyarısı verilir, sessizce kabul edilmez. Durum dosyası silinirse TOFU olarak işaretlenir ve arayüzde gösterilir.
8. Aynı yolda farklı `vault_id`: yanlış alarm çıkmaz.
9. Kasa yazıldıktan sonra, durum yazılmadan önce çökme: alarm çıkmaz. Durum yazılırken çökme: eski ya da yeni durum kalır, asla daha geride bir durum kalmaz.
10. Durum dosyası hiçbir zaman kasanın klasörüne yazılmaz.
11. Property testi: rastgele kayıt, geri yükleme ve çatal dizilerinde dedektör hiçbir zaman L'nin altına düşen bir `vv`'yi kabul etmez.

---

## 2. R2: Anahtar bağlayıcılık (key commitment)

### 2.1 Teknik neden

XChaCha20-Poly1305'te etiket şöyle hesaplanır. Her anahtar ve nonce çifti, keystream'in ilk bloğundan bir Poly1305 tek kullanımlık anahtarı `(r, s)` türetir:

```
tag = ( Σ (blok_i + 2^128) · r^(L−i+1)  mod (2^130 − 5) )  +  s   (mod 2^128)
```

Burada `blok_i`, AAD, şifreli metin ve uzunluk bloklarıdır. Denklem **şifreli metin bloklarında doğrusaldır.**

Saldırgan iki anahtarı da biliyorsa (K₁ ve K₂, her biri kendi seçtiği bir aday parolanın Argon2 çıktısı), iki etiket denklemini eşitleyip tek bir serbest bloğu modüler tersle çözer. Ortaya **her iki anahtarla da doğrulanan** tek bir (nonce, şifreli metin, etiket) çıkar.

`k` anahtar için `k−1` serbest blokla doğrusal bir sistem çözülür. Literatürde buna çoklu anahtar çakışması (multi-key collision) ya da partitioning oracle saldırısı deniyor (Len, Grubbs, Ristenpart, USENIX Security 2021).

Bu bir AEAD "kırılması" değildir. Standart AEAD güvenlik tanımı, **tek bir gizli anahtar** altında gizlilik ve bütünlük ister. "Şifreli metin tek bir anahtara bağlıdır" garantisi o tanımın parçası değildir.

### 2.2 Kavram kanıtı: bugünkü format için

`scratchpad/r2poc` (depo dışında, hiçbir şeyi değiştirmeden çalışan kod):

```
collision found after 2 tries in 2.06ms
chacha20poly1305 crate: AEAD valid under key A: true
chacha20poly1305 crate: AEAD valid under key B: true
unlock(password-of-alice ) -> OK, vault name = "Alice vault"
unlock(password-of-bob!  ) -> DIFFERENT error: vault content could not be (de)serialized: …
unlock(some-other-guess  ) -> DecryptionFailed (wrong password)
```

**Kanıtlanan:**

1. Tek bir `.lav` dosyası iki farklı parolayla AEAD doğrulamasından geçiyor.
2. Uygulama üç **ayırt edilebilir** sonuç veriyor: "açıldı", "bozuk içerik" ve "yanlış parola". Bu, partitioning oracle sinyalinin kaynağı.
3. **Ek bulgu:** CBOR çözücü, değerin arkasındaki fazla baytları **yok sayıyor.** A parolasıyla geçerli bir kasa açılabilmesinin sebebi bu.

### 2.3 Gerçek risk: yerel bir uygulamada oracle kim?

Oracle olabilmesi için saldırganın iki şeyi birden yapabilmesi gerekir:

- **(a)** Kullanıcının açtığı dosyayı değiştirebilmeli (senkron saldırganı).
- **(b)** Sonucu görebilmeli.

Yerel uygulamada sonuç yalnızca kullanıcıya gösterilir. Ancak bazı durumlar sonucu dışarı sızdırır:

- Kullanıcı "dosya bozuk" diye destek ister ya da saldırganla konuşur.
- Uygulama başarılı açılıştan sonra senkron klasörüne bir şey yazar (otomatik kayıt, ikon önbelleği). Saldırgan dosyanın değiştiğini görür.

**Çevrimdışı kaba kuvvete göre kazanç:** Dosyaya yazabilen senkron saldırganı onu **okuyabilir** de. Elinde gerçek kasa olduğu için çevrimdışı kaba kuvveti zaten tam hızda yapabilir. Oracle'ın maliyeti ise daha yüksektir: her sorgu `k` Argon2 hesaplaması ve bir kullanıcı etkileşimi gerektirir. **Parolayı kırmak açısından kazanç pratikte yok.**

**Gerçek risk** gizlilikte değil, bütünlükte ve karışıklıkta ("invisible salamander"):

- Saldırganın hazırladığı ve "ekip kasası, parola X" diye verdiği bir dosya, farklı parolalarla **farklı içerik** gösterebilir.
- İleride gelecek paylaşılan kasa ve içe aktarma özelliklerinde, farklı hatalar yeni yan kanallar açar.

**Önem: Düşük.** Ama düzeltmesi ucuz ve doğru bir hijyen önlemi.

### 2.4 Seçenekler

| Seçenek | Bağlayıcılık | Maliyet ve risk | Değerlendirme |
|---|---|---|---|
| **A. Header'da commitment** `C = HMAC-SHA256(HKDF(master,"LKAV v2 key commitment"), "LKAV-commit" ‖ header_C_hariç)`, çözmeden önce sabit sürede doğrulanır | ✅ İki farklı anahtar için aynı C'yi bulmak SHA-256 çakışmasıyla eşdeğer, yaklaşık 2¹²⁸ iş | Header +32 bayt. Mevcut bağımlılıklar yeterli (hkdf/hmac/sha2) | **Önerilen** |
| B. Sıfır blok "padding fix" (Albertini vd., USENIX Security 2022): plaintext'in başına 32 sıfır bayt koyup çözünce kontrol etmek | ✅ (ChaCha için makul varsayımlar altında) | Header değişmez, ama kontrol çözmeden sonra yapılır ve daha az standart bir argümana dayanır | İkinci tercih |
| C. CTX (etiketi `H(K,N,A,T)` ile değiştirmek) | ✅ | AEAD çıktısını değiştirir, el yapımı kompozisyon | Gereksiz risk |
| D. XChaCha20 + HMAC-SHA256 (encrypt-then-MAC, KDBX4'e benzer) | ✅ | Doğrulanmış AEAD'den uzaklaşır, kendi kompozisyonumuzu yazmamız gerekir | Daha büyük değişiklik |
| E. "Commit eden" hazır bir AEAD'e geçmek | — | RustCrypto'da olgun ve standart bir seçenek yok | Şimdilik yok |

### 2.5 Seçenek A'nın etkileri

- **Çevrimdışı kaba kuvvet (ölçüldü, bu makine):**
  - Argon2id varsayılan ayarlarla **124 ms**.
  - Bugünkü kontrol, yani 1 MiB üzerinde XChaCha20-Poly1305: **1,03 ms**.
  - HMAC commitment: **1,6 µs**.
  - Tahmin başına maliyet 125 ms'den 124 ms'ye iner, yani **en fazla yaklaşık %0,8 hızlanma**. Maliyeti Argon2 belirlediği için ihmal edilebilir.
  - **Kural:** C yalnızca Argon2 çıktısından türetilmeli. SHA-256(parola) ya da salt'tan türetilirse bu kritik bir hata olur.
- **Parola doğrulama oracle'ı:** Poly1305 etiketi zaten bir doğrulayıcı. C yeni bir bilgi sızdırmaz, çünkü gizli anahtarla üretilmiş bir PRF çıktısıdır.
- **Alan ayrımı:** Şifreleme anahtarı ve commitment anahtarı için ayrı HKDF `info` dizgileri kullanılır. HMAC girdisinin başında etiket olur ve header'ın tamamını (C alanı hariç) kapsar.
- **Anahtar dosyası bayrağı:** Header'ın içinde olduğu için bağlanır. Anahtar dosyası composite'i, dolayısıyla master'ı ve C'yi değiştirir.
- **Sürüm düşürme (downgrade):** C'siz eski format okunmaya devam ederse saldırgan C'siz bir dosya hazırlayıp korumayı atlatır. Format henüz yayınlanmadığı için **v1 okuyucusu tamamen kaldırılmalı.** İleride gerekirse R1'deki cihaz durumuna "minimum format sürümü" eklenebilir.
- **Hata davranışı:**
  - C uyuşmazsa: `DecryptionFailed`, yani yanlış parolayla aynı hata.
  - C tutar ama AEAD başarısız olursa: kurcalanmış veya bozuk dosya.
  - C tutar, AEAD geçer ama çözme başarısız olursa: gerçek bozulma ya da bir hata. Artık bir oracle sinyali değildir.
- **Ek sıkılaştırma (R2'nin parçası olarak):** CBOR çözümü şifresiz içeriğin **tamamını** tüketmeli, fazla bayt varsa reddetmeli.
- **Yeni riskler:**
  - Kendi kompozisyonumuzda uygulama hatası yapma ihtimali. KAT (bilinen değer) testleriyle azaltılır.
  - Header 32 bayt büyür.
  - KDF değişmez.

### 2.6 Format ve uyumluluk

- Header 78 bayttan 110 bayta çıkar. `version` 2 olur. v1 reddedilir.
- Yayınlanmış dosya olmadığı için geçiş kodu gerekmez. Bu aynı zamanda saldırı yüzeyini küçültür.
- **R1 ve R2 tek bir format revizyonunda birlikte yapılmalı.** Böylece tek bir geçiş olur.

### 2.7 Uygulanırsa gerekli testler

1. **PoC'nin regresyon testine dönüşmesi:** Header en fazla bir anahtarın C'sini taşıyabilir. Bu yüzden aynı yöntemle üretilen dosya **en fazla bir parolayla** (saldırganın C'yi yazdığı A ile) açılmalı. B ve C parolaları `DecryptionFailed` vermeli; B için "farklı hata" sinyali kaybolmalı.
2. **k=3 çoklu çakışma:** En fazla bir parola kabul edilmeli.
3. **C kurcalama:** Tek bit çevirme `DecryptionFailed` vermeli.
4. **C taşıma:** Bir dosyanın C'si başka bir dosyaya konursa reddedilmeli.
5. **v1 header:** Reddedilmeli (sürüm düşürme engeli).
6. **Fazla baytlı payload:** Reddedilmeli.
7. **KAT vektörleri:** Sabit parola ve salt'tan beklenen master, payload anahtarı ve C değerleri. Türetme kazara değişirse yakalanır.
8. **Alan ayrımı:** C ve şifreleme anahtarı farklı olmalı. KDF parametresi değişince C de değişmeli.
9. **Kod incelemesi ve test:** Karşılaştırma `subtle` ile yapılmalı. C, Argon2'den önce hesaplanamıyor olmalı.
10. **Ölçüm:** Doğrulama maliyetinin Argon2'ye göre ihmal edilebilir olduğu kaydedilmeli (bilgi amaçlı).
11. **Fuzz:** v2 header hedefi eklenmeli.
12. **Aynı hata:** Yanlış parola, yanlış anahtar dosyası, eksik anahtar dosyası (bayrak 1), bayrak 0 iken verilen anahtar dosyası ve bozuk etiket aynı hatayı vermeli. Commitment ve etiket doğruyken CBOR hatası "bozuk dosya" olarak gösterilebilir (bkz. bölüm 3).
13. **Commitment uzunluğu:** Tam 32 bayt olmalı, kırpılmamalı.

---

## 3. Bağımsız inceleme ile karşılaştırma

Bağımsız inceleme, benim önerilerimi ve PoC'mi görmeden yapıldı. **Kendi çakışma dosyasını da üretti:** 158 baytlık bir `.lav` dosyası iki parolayla da AEAD'den geçti ve ikisinde de `Serialization` hatası verdi, üçüncü parolada `DecryptionFailed`. Yani R2 iki ayrı yöntemle, iki kez kanıtlandı.

| Konu | Benim analizim | Bağımsız inceleme | Sonuç |
|---|---|---|---|
| Dosya içi sayaç tek başına yeterli mi | Hayır | Hayır | **Uzlaşı** |
| Referans nerede tutulmalı | `%LOCALAPPDATA%` | `%LOCALAPPDATA%` | **Uzlaşı** |
| Rollback tespit mekanizması | Tek sayaç + son 16 hash | Cihaz başına version vector | **Version vector benimsendi** (daha güçlü) |
| Eski parolaya dönüş (en kötü senaryo) | Yalnızca kilit açıldıktan sonra fark edilirdi | Emekli `(salt, commitment)` listesiyle **kilit açılmadan önce** durdurulur | **Benimsendi** |
| Çok cihaz sınırı | Fork consistency | Aynı (SUNDR) | **Uzlaşı** |
| R2 teknik nedeni | Poly1305 doğrusallığı | Aynı, k anahtar için k×k sistem | **Uzlaşı** |
| R2'nin gerçek riski | Düşük, kaba kuvvete katkısı yok | Aynı. "Yaklaşık log₂(k) bit/açılış, pratikte sıfır" | **Uzlaşı** |
| R2 çözümü | HKDF/HMAC commitment header'da, çözmeden önce kontrol | Aynı yapı, 32 bayttan kısa olmamalı | **Uzlaşı** |
| Kaba kuvvet etkisi | Ölçüldü: ≤ %0,8 | Bugün bile bilinen düz metin (CBOR'da ilk alan) tek bloklık ucuz bir kontrol sağlıyor, ek hızlanma < 10⁻⁵ | **Uzlaşı.** Onun argümanı daha da güçlü |
| v1 desteği | Kaldırılmalı | Kaldırılmalı, geri dönüş yolu bırakılmamalı | **Uzlaşı** |
| Padding fix'in ChaCha için gücü | Emin değilim | Emin değil | **İkimiz de doğrulayamadık** |

**Bağımsız incelemenin eklediği yeni bulgular** (kodla doğrulandı, düşük önem, henüz düzeltilmedi):

1. **Bayrak 0 iken anahtar dosyası:** Bayrak 0 olduğu hâlde bir anahtar dosyası verilirse bu dosya sessizce anahtara karıştırılıyor (`vault.rs` `unlock`). Kullanıcı "doğru parolayı yazdım ama açılmıyor" der. Reddedilmeli.
2. **Bugünkü hata ayrımı:** Core, "parola etiket kontrolünü geçti mi" bilgisini farklı hata tipleriyle sızdırıyor. Bu, THREAT_MODEL ilke 3'e aykırı. Commitment gelene kadar arayüz `Serialization` ve `DecryptionFailed` hatalarını kullanıcıya aynı mesajla göstermeli.

   Commitment geldikten sonra bu ayrım bir oracle sinyali olmaktan çıkar. Commitment doğru çıktıktan sonra yaşanan bir çözme hatası ancak doğru anahtarla oluşabilir, yani gerçek bir bozulmadır. O noktada "dosya bozuk" mesajı doğru ve güvenlidir.

## 4. Karar önerisi

**Önerim: R1 ve R2'yi tek bir format revizyonunda (v2) birlikte uygulamak.**

Gerekçe:

- İkisi aynı yerlere dokunuyor: header ve payload şeması.
- R1'in en değerli parçası (eski parolaya dönüşü kilit açmadan durdurmak) R2'nin commitment değerine ihtiyaç duyuyor.
- Format henüz yayınlanmadığı için bugün uyumluluk maliyeti sıfır. Yayından sonra her ikisi de geçiş kodu, yani yeni bir saldırı yüzeyi gerektirir.

| | R2 (anahtar bağlayıcılık) | R1 (rollback) |
|---|---|---|
| Kanıtlanmış risk | Evet, PoC iki kez çalıştı. Pratik zararı düşük | Senaryo net. Bugün hiçbir koruma yok (bağımsız incelemenin kod tespiti) |
| Önem | Düşük, ama ucuz hijyen | **Orta** (senkron klasörü kullananlar için) |
| Kriptografik değişiklik | Header +32 bayt, yeni HKDF etiketi, v1 kaldırılır | Kriptografi değişmez, payload şeması değişir |
| İş miktarı | Küçük | Orta (yerel durum, karar mantığı, birleştirme) |
| Bağımlılık | — | Emekli kimlik kontrolü için R2 gerekli |

**Önerilen sıra:**

1. **Hemen yapılabilecek, format değiştirmeyen sıkılaştırmalar** (onayınızla):
   - Fazla baytlı payload'ı reddetmek.
   - Bayrak 0 iken verilen anahtar dosyasını reddetmek.
2. **Format v2:**
   - R2 commitment
   - v1'i kaldırmak
   - payload'a `vault_id`, `vv`, `last_writer` ve `saved_at` eklemek
   - KAT testleri
   - PoC'yi regresyon testine dönüştürmek
3. **R1 karar mantığı ve yerel durum:** Masaüstü uygulamasıyla birlikte (Faz 2). Yerel durum ve uyarılar arayüz gerektiriyor.
4. **Birleştirme (merge):** Ayrı bir iş olarak, önce testleri yazılarak.

**Bu belge kapsamında yapılmayanlar:**

- R1 ve R2 için hiçbir kod değişikliği yapılmadı.
- R1 tasarımı kâğıt üzerinde. Simülasyonu ya da testi yok.
- TPM NV erişiminin Windows'ta yönetici yetkisi gerektirip gerektirmediği doğrulanmadı.
- Padding fix'in ChaCha20-Poly1305 için kesin gücü doğrulanmadı.
- Rust için olgun bir "committing AEAD" kütüphanesi olup olmadığı doğrulanmadı.
