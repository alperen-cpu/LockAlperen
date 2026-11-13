# `.lav` Dosya Formatı — Sürüm 1

LockAlperen kasaları tek bir `.lav` dosyasında saklanır. Dosya iki bölümden oluşur:

```
┌──────────────────────────────┐
│ HEADER   (78 bayt, şifresiz) │  ← AEAD "associated data" olarak doğrulanır
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
| 4 | 2 | version | `1` |
| 6 | 1 | cipher | `1` = XChaCha20-Poly1305 |
| 7 | 1 | kdf | `1` = Argon2id (v0x13) |
| 8 | 2 | flags | bit 0 = anahtar dosyası gerekli; diğer bitler 0 olmalı |
| 10 | 4 | memory_kib | Argon2 bellek (KiB), 19 456 – 1 048 576 (19 MiB – 1 GiB) |
| 14 | 4 | iterations | Argon2 geçiş sayısı, 2 – 20 |
| 18 | 4 | parallelism | Argon2 şerit sayısı, 1 – 16 |
| 22 | 32 | salt | Rastgele; yalnızca parola değişince yenilenir |
| 54 | 24 | nonce | Rastgele; **her kayıtta** yenilenir |

Bilinmeyen sürüm, algoritma ya da bayrak görülürse dosya reddedilir. KDF parametreleri
aralık dışındaysa da reddedilir. Böylece kötü niyetli bir dosya ne KDF'yi zayıflatabilir
ne de açılırken gigabaytlarca bellek tüketebilir.

## Anahtar türetme

```
composite   = SHA-256(UTF-8(NFC(parola))) [ || SHA-256(anahtar dosyası baytları) ]
master      = Argon2id(composite, salt, memory_kib, iterations, parallelism) → 32 bayt
payload_key = HKDF-SHA256(ikm = master, salt = yok,
                          info = "LKAV v1 payload encryption key") → 32 bayt
```

Varsayılan parametreler: 64 MiB, 3 geçiş, 4 şerit. Parola Unicode NFC ile normalleştirilir;
anahtar dosyası yoksa en az 8 karakter olmalıdır.

## Payload

```
ciphertext = XChaCha20-Poly1305(key = payload_key, nonce = header.nonce,
                                aad = header'ın 78 baytının tamamı,
                                plaintext = CBOR(VaultData))
```

`VaultData` (CBOR, alan adlarıyla):

```
VaultData { schema: 1, name, root: uuid, groups: [Group], entries: [Entry], created, modified }
Group     { id, parent?, name, icon?, created, modified }
Entry     { id, group, title, username, password, url, notes, totp?, tags: [str],
            fields: [ { name, value, protected } ], attachments: [ { name, data: bytes } ],
            favorite, expires?, icon?: { png: bytes, fetched }, created, modified,
            history: [EntryVersion] }
```

`icon` yalnızca uygulamanın yeniden kodladığı 64×64 PNG'yi tutar, indirilen ham resmi değil.
Zaman damgaları Unix saniyesidir. Her kayıtta en fazla 20 geçmiş sürümü tutulur.

## Kaydetme

0. `<dosya>.lock` üzerinde özel bir OS kilidi alınır. Dosya bu kasanın en son okuduğu ya da
   yazdığı dosya değilse (başka bir örnek, senkron istemcisi) kayıt reddedilir: `FileChangedOnDisk`.
1. Rastgele adlı `<dosya>.<16 hex>.tmp` dosyası `create_new` ile oluşturulur, yazılır ve `fsync` ile diske işlenir.
2. Mevcut dosya `<dosya>.bak` olarak kopyalanır. Ana parola değiştiyse eski parolalı `.bak`
   kopyalanmaz, **silinir**.
3. `.tmp` dosyası atomik olarak `<dosya>` adına taşınır (OneDrive veya antivirüs dosyayı
   kısa süre tutuyorsa birkaç kez yeniden denenir). Çökmeden kalan eski `.tmp` dosyaları silinir.

Kaydetme yarıda kesilse bile ya eski ya da yeni dosya sağlam kalır.

## Uyumluluk kuralları

- Header yapısını değiştiren her değişiklik `version` değerini artırır.
- Payload'a yeni ve isteğe bağlı alanlar eklemek `schema` değerini artırmayı gerektirmez.
  Alanların anlamını değiştiren her değişiklik ise `schema` değerini artırır.
