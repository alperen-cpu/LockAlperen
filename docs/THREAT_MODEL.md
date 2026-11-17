# Tehdit Modeli

LockAlperen, tek kullanıcının kendi Windows bilgisayarında çalışan yerel bir parola yöneticisidir.
Sunucusu ve hesabı yoktur; kasa hiçbir yere gönderilmez. Ağa yalnızca site ikonu indirmek ve
yeni sürümü denetlemek için çıkar (aşağıda "İlkeler").

## Korunan varlıklar

- Kasa içeriği: parolalar, notlar, TOTP gizli anahtarları, ekler
- Ana parola ve anahtar dosyası

## Koruduğumuz durumlar ✅

| Tehdit | Önlem |
|---|---|
| `.lav` dosyası çalınır (bulut hesabı, kayıp disk, yedek) | Argon2id + XChaCha20-Poly1305. Güvenlik yalnızca ana parolanın gücüne bağlıdır |
| Dosya kurcalanır (KDF'yi zayıflatma, içerik değiştirme) | Header AEAD ile doğrulanır, KDF parametrelerinin alt sınırı vardır |
| Kötü niyetli dosya kaynak tüketir | KDF parametrelerinin üst sınırı vardır |
| Kaydetme sırasında çökme ya da elektrik kesintisi | Atomik yazma; yedek ana dosyadan önce `fsync` edilir; dizin flush. Çökme her adımda test edildi; **gerçek güç kesintisi test edilmedi** |
| Kopyalanan parola panoda kalır | Pano belirli bir süre sonra temizlenir *(uygulama katmanı)* |
| Bilgisayar açık bırakılır | Boşta kalınca ve Windows kilitlenince kasa kilitlenir *(uygulama katmanı)* |
| Bellek dökümünde sırların uzun süre kalması | Anahtarlar, kasa verisi ve ara tamponlar heap'te bırakılırken sıfırlanır (`zeroize`, `SecretString`). Kütüphanelerin yığında bıraktığı kopyalar için **en iyi çaba** yığın temizliği vardır: bir garanti değildir, yalnızca release derlemesinde ölçülmüştür |
| Sırların log ya da hata mesajına düşmesi | `Debug` çıktısı gizli alanları `***` gösterir |
| Açık bırakılan oturumda kasanın ele geçirilmesi | Ana parola değişimi mevcut parolayı zorunlu tutar |
| Parola değiştikten sonra eski yedeğin açılması | Eski parolalı `.bak` silinir |
| Ekran paylaşımı ve pano geçmişi | Pencere ekran yakalamadan hariç tutulur, pano geçmişi kapatılır *(uygulama katmanı)* |
| Kayıttaki adres üzerinden program başlatma (`file:`, `ms-msdt:` gibi protokol işleyicileri; içe aktarılan kasadan gelebilir) | Yalnızca `http`/`https` açılır, adresi Rust okur (`src/browser.rs`, testli) |
| Favicon üzerinden yerel ağ taraması veya kötü niyetli resim | Yalnızca HTTPS, yerel adresler yasak, resim yeniden kodlanır (`lav-favicon`) |
| Sahte ya da eski güncelleme (MITM, kurcalanmış `latest.json`) | Yalnızca HTTPS; kurulum dosyası gömülü anahtarla imza doğrulanmadan çalıştırılmaz; imza sürüme bağlı, sürüm düşürme yok; indirme adresi bu reponun Releases'ı ([UPDATES.md](UPDATES.md)). **Kapsam dışı:** imza anahtarı ve parolasının birlikte çalınması |

## Kapsam dışı ❌

- **Ele geçirilmiş bilgisayar:** Keylogger, yönetici yetkisiyle çalışan zararlı yazılım ya da
  süreç belleğini okuyan saldırgan. Kasa açıkken hiçbir yerel parola yöneticisi buna karşı
  koruma sağlayamaz.
- **Zayıf ana parola:** Argon2 kaba kuvvet saldırısını yavaşlatır ama engelleyemez.
- **Fiziksel ya da donanım yan kanal saldırıları.**
- **Bulut senkronu ve ağ sürücüleri:** Dosya şifreli olduğu için gizlilik açısından ek risk
  yoktur. Bütünlük ve eşzamanlılık açısından ise sınırlar vardır: aşağıdaki "Bilinen
  sınırlamalar" bölümüne bakın.

## Bilinen sınırlamalar: OneDrive ve ağ sürücüleri

### OneDrive (ve benzeri senkron istemcileri)

- **Geri alma (rollback) tespit edilmez.** Klasöre yazabilen biri ya da OneDrive sürüm geçmişi,
  eski ama geçerli bir kasa sürümünü geri koyabilir. Bu sürüm sorunsuz açılır. Tespit tasarımı
  yalnızca prototip aşamasındadır (`prototypes/r1-rollback`) ve üretimde **değildir**.
- **Makineler arası kilit yoktur.** Kilit yalnızca aynı bilgisayardaki örnekleri dışlar. İki
  bilgisayardaki düzenlemeler şöyle sonuçlanır:
  - Değişiklik kayıttan önce diske ulaştıysa: `FileChangedOnDisk`.
  - Ulaşmadıysa: OneDrive'ın çakışma kopyası (`kasa-PC2.lav` gibi).
  - Birleştirme özelliği yoktur.
- **Kilit dosyası (`<kasa>.lock`) senkron klasöründedir** ve OneDrive tarafından eşitlenir.
  Tutulduğu sürece Windows'ta silinemez ve değiştirilemez. OneDrive'ın bu durumda senkron uyarısı
  ya da çakışma kopyası üretip üretmediği **test edilmedi**.
- **Kayıt sırasındaki pencere:** Dosya, son kontrol ile rename arasındaki çok kısa aralıkta
  OneDrive tarafından değiştirilirse bu değişiklik ezilebilir. Kontrolden önceki değişiklikler
  yakalanır.
- **İsteğe bağlı dosyalar (Files On-Demand) / yer tutucular:** Dosya yerelde değilse okuma
  indirmeyi tetikler. Çevrimdışı ya da `ERROR_CLOUD_*` durumları **test edilmedi** ve yeniden
  denenmez.
- **Başka makinenin geçici dosyaları:** `<kasa>.<16 hex>.tmp` biçimindeki dosyalar eşitlenirse
  başarılı bir kayıttan sonra temizlenebilir. Bu durum TEORİKTİR.
- **Sürüm geçmişi:** Eski parolayla şifrelenmiş eski sürümler bulutta kalabilir.

### Ağ sürücüleri (SMB / NFS)

- Kilit semantiği (`LockFileEx` ya da SMB üzerinden `flock`, NFS'te `flock` emülasyonu), rename
  atomikliği ve `fsync` davranışı sunucuya bağlıdır ve **test edilmedi**.
- **Dizin flush:**
  - "Desteklenmiyor" hataları (Windows'ta 1 ve 50) yok sayılır, yani kalıcılık garantisi yoktur.
  - Diğer hatalar (örneğin erişim reddi) kaydı başarısız yapar. Bu, bazı paylaşımlarda kaydı
    engelleyebilir.
- Aynı paylaşımı kullanan iki bilgisayar arasında kilit garantisi yoktur.
- **Öneri:** Kasa yerel diskte tutulmalı. Ağ sürücüsü şu an **desteklenen bir yapılandırma
  değildir.**

### Güç kesintisi

`fsync`, dizin flush ve NTFS rename'inin günlüğe yazılması fiziksel olarak test edilmedi.
Windows'ta dizin `FlushFileBuffers`'ının rename'i kalıcı yaptığı belgelenmemiştir. Disk
önbelleğinin "flush'ları yok say" ayarı bu garantileri boşa çıkarabilir. Ayrıntı:
`docs/FIX_DESIGN_2026-11.md` §4.5.

## İlkeler

1. Kendi kriptografi algoritmamızı yazmıyoruz; yalnızca RustCrypto kütüphanelerini kullanıyoruz.
2. Çekirdekte `unsafe` kod yok (`#![forbid(unsafe_code)]`).
3. Yanlış parola ile bozuk dosya kullanıcıya aynı hatayı verir (`Error::user_message`). Saldırgana
   ipucu vermeyiz. v2'den itibaren key commitment, bir dosyanın birden fazla parolayla doğrulanmasını
   da engeller.
4. Çekirdek ağa hiç çıkmaz. Uygulamanın ağa çıktığı iki yer var: site ikonu indirme (doğrudan
   sitenin kendisinden; şu an kapatılamıyor) ve GitHub Releases üzerinden sürüm denetimi
   (Ayarlar'dan kapatılabilir). Sızıntı kontrolü (HIBP) yoktur. Ayrıntı:
   [SECURITY.md](../SECURITY.md), [UPDATES.md](UPDATES.md).
