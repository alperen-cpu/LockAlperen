# `.lav` Dosya Formatı — Sürüm 2

LockAlperen kasaları tek bir `.lav` dosyasında saklanır. Dosya iki bölümden oluşur:

```
┌──────────────────────────────┐
│ HEADER   (110 bayt, şifresiz)│  ← ilk 78 bayt key commitment ile, tamamı AEAD AAD ile doğrulanır
├──────────────────────────────┤
│ PAYLOAD  (şifreli + 16 bayt  │  ← XChaCha20-Poly1305
│           Poly1305 etiketi)  │
└──────────────────────────────┘
```

## Header

Tüm tamsayılar **little-endian**.

| Ofset | Boyut | Alan | Değer |
|---:|---:|---|---|
| 0 | 4 | magic | `"LKAV"` |
| 4 | 2 | version | `2` (başka her değer reddedilir, v1 dahil) |
| 6 | 1 | cipher | `1` = XChaCha20-Poly1305 |
| 7 | 1 | kdf | `1` = Argon2id (v0x13) |
| 8 | 2 | flags | bit 0 = anahtar dosyası gerekli; diğer bitler 0 olmalı |
| 10 | 4 | memory_kib | Argon2 bellek (KiB), 19 456 – 1 048 576 (19 MiB – 1 GiB) |
| 14 | 4 | iterations | Argon2 geçiş sayısı, 2 – 20 |
| 18 | 4 | parallelism | Argon2 şerit sayısı, 1 – 16 |
| 22 | 32 | salt | Rastgele; yalnızca parola değişince yenilenir |
| 54 | 24 | nonce | Rastgele; **her kayıtta** yenilenir |
| 78 | 32 | commitment | Anahtar bağlayıcılık değeri (aşağıda). Tam 32 bayt, kırpılmaz |

Bilinmeyen sürüm, algoritma ya da bayrak görülürse dosya reddedilir. KDF parametreleri
aralık dışındaysa da reddedilir. Böylece kötü niyetli bir dosya ne KDF'yi zayıflatabilir
ne de açılırken gigabaytlarca bellek tüketebilir.

## Anahtar türetme

```
composite   = SHA-256(UTF-8(NFC(parola))) [ || SHA-256(anahtar dosyası baytları) ]
master      = Argon2id(composite, salt, memory_kib, iterations, parallelism) → 32 bayt
payload_key = HKDF-SHA256(ikm = master, salt = yok,
                          info = "LKAV v1 payload encryption key") → 32 bayt
commit_key  = HKDF-SHA256(ikm = master, salt = yok,
                          info = "LKAV v2 key commitment") → 32 bayt
commitment  = HMAC-SHA256(commit_key, "LKAV-commit v2" || header[0..78])
```

`payload_key` için `info` dizgisi bilinçli olarak v1'deki gibi bırakıldı (anahtar şemasında
gereksiz değişiklik yok). v1 dosyaları zaten header sürümüyle reddedilir.

### Key commitment (v2)

- `commitment`, header'ın commitment dışındaki **bütün** alanlarını kapsar: magic, version,
  cipher, kdf, flags, Argon2 parametreleri, salt ve nonce.
- Yalnızca Argon2id çıktısından türetilen, amaca özel ayrı bir anahtarla (`commit_key`) hesaplanır.
  Argon2 çalışmadan hesaplanamaz.
- Açılışta sıra: header ayrıştırma → anahtar dosyası/bayrak kontrolü → Argon2id → **commitment
  sabit sürede karşılaştırılır** → ancak eşleşirse AEAD çözme → CBOR çözme.
  Kodda payload anahtarı yalnızca `DerivedKeys::verified_payload_key` üzerinden alınabilir.
- Uyuşmazlık yanlış parolayla aynı hatayı verir (`DecryptionFailed`).
- Amaç: aynı şifreli metnin birden fazla anahtar altında AEAD doğrulamasından geçmesini
  (Poly1305 çoklu anahtar çakışması / "partitioning oracle") etkisiz kılmak. Header en fazla
  bir anahtarın commitment değerini taşıyabilir.

Varsayılan parametreler: 64 MiB, 3 geçiş, 4 şerit. Parola Unicode NFC ile normalleştirilir;
anahtar dosyası yoksa en az 8 karakter olmalıdır.

## Payload

```
ciphertext = XChaCha20-Poly1305(key = payload_key, nonce = header.nonce,
                                aad = header'ın 110 baytının tamamı (commitment dahil),
                                plaintext = CBOR(VaultData))
```

`VaultData` (CBOR, alan adlarıyla):

```
VaultData { schema: 1, name, root: uuid, groups: [Group], entries: [Entry], created, modified,
            recycle_bin?: uuid }
Group     { id, parent?, name, icon?, created, modified }
Entry     { id, group, title, username, password, url, notes, totp?, tags: [str],
            fields: [ { name, value, protected } ], attachments: [ { name, data: bytes } ],
            favorite, expires?, icon?: { png: bytes, fetched }, created, modified,
            history: [EntryVersion] }
```

`icon` yalnızca uygulamanın yeniden kodladığı 64×64 PNG'yi tutar, indirilen ham resmi değil.
Zaman damgaları Unix saniyesidir. Her kayıtta en fazla 20 geçmiş sürümü tutulur.

`recycle_bin` (2026-11, isteğe bağlı): Geri Dönüşüm Kutusu klasörünün kimliği. İlk silmede
kökün altında oluşturulur. Yoksa (eski dosya) `None` okunur; eski uygulama sürümleri alanı yok
sayar ve kutuyu sıradan bir klasör olarak gösterir. Bu yüzden `schema` artırılmadı.
`repair_structure`, var olmayan bir klasörü ya da kökü gösteren değeri temizler.

Payload tam olarak **tek** bir CBOR değeri olmalıdır. Sonunda fazladan bayt varsa dosya reddedilir.

## Kaydetme

0. `<dosya>.lock` üzerinde özel bir OS kilidi alınır, en fazla 10 sn beklenir (sonra `SaveBusy`).
   - **Windows:** Kilit dosyası `FILE_SHARE_DELETE` olmadan açılır; tutulduğu sürece silinemez ve
     üzerine rename yapılamaz.
   - **Unix:** `flock` + kilitli dosya ile yoldaki dosyanın (dev, ino) eşleşmesi kontrol edilir.
   - Dosya bu kasanın en son okuduğu ya da yazdığı dosya değilse kayıt reddedilir:
     `FileChangedOnDisk`. Yol karşılaştırması `canonicalize` ile yapılır.
1. Rastgele adlı `<dosya>.<16 hex>.tmp` dosyası `create_new` ile oluşturulur, yazılır ve `fsync`
   ile diske işlenir.
2. **Yedek:**
   - Adım 0'da **doğrulanan baytlar** (yeniden okunmuş dosya değil) `<dosya>.bak.<16 hex>.tmp`
     dosyasına yazılır ve `fsync` edilir.
   - Bu dosya `<dosya>.bak` adına taşınır ve dizin flush'lanır.
   - Ana parola değiştiyse eski parolalı `.bak` kopyalanmaz, **silinir** ve dizin flush'lanır.
3. Kilit hâlâ bizde mi ve dosya hâlâ doğrulanan baytları mı içeriyor diye yeniden kontrol edilir.
   Kilit gitmişse `LockLost`, dosya değişmişse `FileChangedOnDisk` döner. Bu durumda ana dosya
   **değişmez**.
4. `.tmp` dosyası atomik olarak `<dosya>` adına taşınır (OneDrive veya antivirüs dosyayı kısa süre
   tutuyorsa birkaç kez yeniden denenir). Dizin flush'lanır. Çökmeden kalan eski `.tmp` dosyaları
   silinir.

**Garantiler (testli: `vault_save_tests.rs` T1–T8):**
- 4. adımdan önce ana dosyaya dokunulmaz.
- `.bak`, ana dosya değişmeden önce `fsync` edilmiş olur.
- Yedeğe yalnızca doğrulanmış sürüm girer.
- Herhangi bir adımda çökme olursa ana dosya ya eski ya da yeni sürümdür.
- Eski parolalı yedek, yeni parolalı bir kasanın yanında kalmaz.

**Sınırlar:**
- `fsync` ve dizin flush garantileri için `docs/FIX_DESIGN_2026-11.md` §4.5'e bakın.
- Windows'ta dizin flush'ının rename'i diske yazdırdığı doğrulanmadı.
- Unix'te kilit kontrolü ile rename arasında küçük bir pencere kalır (§4.4).

## Hata gösterimi

Parola, anahtar dosyası, header ve içerikle ilgili bütün açılış hataları kullanıcıya **tek bir genel
mesajla** gösterilir (`Error::user_message`, `UNLOCK_FAILED_MESSAGE`). Ayrıntılı hata türleri yalnızca
testler ve tanılama içindir. İşletim sistemi düzeyindeki G/Ç hataları (dosya bulunamadı vb.) ve
dosya boyutu sınırı kendi mesajlarını korur, çünkü parolaya bağlı değildirler.

## v1'in kaldırılması ve etkileri

- v1 okuyucusu **tamamen kaldırıldı**. Commitment kontrolünü atlayan bir geri dönüş yolu yoktur:
  `version != 2` olan her dosya Argon2 çalışmadan `UnsupportedVersion` ile reddedilir.
- **Etki:** v1 ile kaydedilmiş bir kasa bu sürümle açılamaz ve otomatik dönüştürülmez.
  Format yayınlanmadığı için bilinen bir kullanıcı dosyası yoktur. Elinde v1 dosyası olan
  biri (geliştirme ya da test kopyası) dosyayı bir önceki commit'le (`c1c606a`) açıp içeriği
  dışa aktarmalı, sonra yeni sürümde yeniden oluşturmalıdır.
- v1 `.bak` dosyaları da açılamaz. Bu kasıtlıdır.
- İleride v2'den v3'e geçiş gerekirse geçiş, v2 dosyası **tam doğrulandıktan sonra** ve yalnızca
  açık bir kullanıcı eylemiyle yapılmalıdır. Hiçbir zaman "eski sürümü daha az kontrolle oku"
  biçiminde olmamalıdır.

## Uyumluluk kuralları

- Header yapısını değiştiren her değişiklik `version` değerini artırır.
- Payload'a yeni ve isteğe bağlı alanlar eklemek `schema` değerini artırmayı gerektirmez.
  Alanların anlamını değiştiren her değişiklik ise `schema` değerini artırır.
