# Tehdit Modeli

LockAlperen, tek kullanıcının kendi Windows bilgisayarında çalışan, yerel ve çevrimdışı
bir parola yöneticisidir.

## Korunan varlıklar

- Kasa içeriği: parolalar, notlar, TOTP gizli anahtarları, ekler
- Ana parola ve anahtar dosyası

## Koruduğumuz durumlar ✅

| Tehdit | Önlem |
|---|---|
| `.lav` dosyası çalınır (bulut hesabı, kayıp disk, yedek) | Argon2id + XChaCha20-Poly1305. Güvenlik yalnızca ana parolanın gücüne bağlıdır |
| Dosya kurcalanır (KDF'yi zayıflatma, içerik değiştirme) | Header AEAD ile doğrulanır, KDF parametrelerinin alt sınırı vardır |
| Kötü niyetli dosya kaynak tüketir | KDF parametrelerinin üst sınırı vardır |
| Kaydetme sırasında çökme ya da elektrik kesintisi | Atomik yazma ve `.bak` yedeği |
| Kopyalanan parola panoda kalır | Pano belirli bir süre sonra temizlenir *(uygulama katmanı)* |
| Bilgisayar açık bırakılır | Boşta kalınca ve Windows kilitlenince kasa kilitlenir *(uygulama katmanı)* |
| Bellek dökümünde sırların uzun süre kalması | Anahtarlar, kasa verisi ve ara tamponlar bırakılırken sıfırlanır (`zeroize`, `SecretString`) |
| Sırların log ya da hata mesajına düşmesi | `Debug` çıktısı gizli alanları `***` gösterir |
| Açık bırakılan oturumda kasanın ele geçirilmesi | Ana parola değişimi mevcut parolayı zorunlu tutar |
| Parola değiştikten sonra eski yedeğin açılması | Eski parolalı `.bak` silinir |
| Ekran paylaşımı ve pano geçmişi | Pencere ekran yakalamadan hariç tutulur, pano geçmişi kapatılır *(uygulama katmanı)* |
| Favicon üzerinden yerel ağ taraması veya kötü niyetli resim | Yalnızca HTTPS, yerel adresler yasak, resim yeniden kodlanır (`lav-favicon`) |

## Kapsam dışı ❌

- **Ele geçirilmiş bilgisayar:** Keylogger, yönetici yetkisiyle çalışan zararlı yazılım ya da
  süreç belleğini okuyan saldırgan. Kasa açıkken hiçbir yerel parola yöneticisi buna karşı
  koruma sağlayamaz.
- **Zayıf ana parola:** Argon2 kaba kuvvet saldırısını yavaşlatır ama engelleyemez.
- **Fiziksel ya da donanım yan kanal saldırıları.**
- **Bulut senkronu:** Dosyayı OneDrive gibi bir yere koymak kullanıcının tercihidir.
  Dosya zaten şifreli olduğu için ek bir risk getirmez.

## İlkeler

1. Kendi kriptografi algoritmamızı yazmıyoruz; yalnızca RustCrypto kütüphanelerini kullanıyoruz.
2. Çekirdekte `unsafe` kod yok (`#![forbid(unsafe_code)]`).
3. Yanlış parola ile bozuk dosya aynı hatayı verir. Saldırgana ipucu vermeyiz.
4. Çekirdek ağa hiç çıkmaz. Uygulamanın ağa çıktığı yerler yalnızca kullanıcının kapatabileceği
   site ikonu indirme ile ileride gelecek HIBP k-anonymity kontrolüdür (yalnızca SHA-1 özetinin
   ilk 5 karakteri gönderilir). Ayrıntı: [SECURITY.md](../SECURITY.md).
