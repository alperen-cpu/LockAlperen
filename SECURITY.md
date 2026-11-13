# Güvenlik

LockAlperen yerel çalışan bir parola yöneticisidir: sunucusu, hesabı ve telemetrisi yoktur.
**Son kapsamlı denetim:** [docs/SECURITY_AUDIT_2026-11.md](docs/SECURITY_AUDIT_2026-11.md)
(19 bulgu, 17'si testle doğrulanıp düzeltildi; açık kalan riskler ve yapılamayan testler orada).

Bu belge neye karşı koruduğumuzu, KeePass ailesinde çıkmış açıklara karşı durumumuzu ve
henüz açık kalan konuları dürüstçe listeler. Ayrıntılı kriptografi için [docs/FORMAT.md](docs/FORMAT.md),
tehdit modeli için [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Kısa özet (BT / güvenlik ekibi için)

| Soru | Cevap |
|---|---|
| Şifreleme | XChaCha20-Poly1305 (AEAD), anahtar Argon2id (64 MiB, 3 geçiş) + HKDF-SHA256 ile türetilir |
| Kriptografi kodu | Kendi yazdığımız algoritma yok; yalnızca [RustCrypto](https://github.com/RustCrypto) kütüphaneleri |
| Bellek güvenliği | Rust; çekirdekte `unsafe` kod yasak (`#![forbid(unsafe_code)]`) |
| Ağ erişimi | Çekirdek (`lav-core`) ağa hiç dokunmaz. Tek ağ işlemi, kullanıcının kapatabileceği site ikonu (favicon) indirmedir |
| Veri nerede | Tek bir şifreli `.lav` dosyasında, kullanıcının seçtiği yerde |
| Bağımlılık taraması | Her commit'te ve haftalık olarak CI'da `cargo audit` (RustSec) ve `cargo deny` (lisans, kaynak, advisory) çalışır |
| Test | Her bulgu için regresyon testi, canlı süreç belleği taraması, serbest bırakılan blokları tarayan allocator testi, fuzz testi |
| Kaynak kodu | Açık (MIT) |

## KeePass ailesinde çıkmış açıklar: bizde durum

| Açık | Ne oldu | LockAlperen'de durum |
|---|---|---|
| **CVE-2023-32784** (KeePass 2.x) | Parola kutusunun yazarken bıraktığı ara metinler yüzünden ana parola bellek dökümünden okunabiliyordu | ✅ Çekirdekte parola, anahtarlar, şifresiz içerik ve ara tamponlar işi bitince bellekten siliniyor (`zeroize`). Bellekte büyürken eski kopyasını geride bırakacak tamponlar önceden doğru boyutta açılıyor. ⚠️ Arayüz (WebView) tarafı için aşağıdaki "Uygulama katmanı" maddelerine bakın |
| **CVE-2023-24055** (KeePass 2.x) | Yapılandırma dosyasına yazabilen biri bir "tetikleyici" ekleyip kasayı sessizce düz metin olarak dışa aktarabiliyordu | ✅ Tasarım gereği tetikleyici ve eklenti sistemi yok. Güvenliği etkileyen ayarlar şifreli kasanın içinde tutulacak; düz metin config hiçbir dışa aktarmayı başlatamaz. Dışa aktarma her seferinde ana parolayı yeniden soracak |
| **CVE-2016-5119** (KeePass ≤ 2.33) | Güncelleme kontrolü HTTP üzerindendi; araya giren biri (MITM) sahte güncelleme sunabiliyordu | ✅ Uygulama ağ üzerinden kendini güncellemez. İleride güncelleme gelirse yalnızca HTTPS ve imza doğrulamalı olacak |
| **CVE-2022-0725** | Hassas bilgiler log dosyalarına düşüyordu | ✅ **Bu inceleme sırasında bizde de bulundu ve düzeltildi.** Kayıt yapıları `Debug` ile parolayı yazdırabiliyordu. Artık parola, notlar, TOTP, gizli alanlar ve ekler `SecretString`/`SecretBytes` tipinde; log ve hata çıktılarında yalnızca `***` görünür. Bunu doğrulayan testler var |
| **CVE-2019-20184** (KeePass 2.4.1) | CSV dışa aktarmada formül enjeksiyonu (`=cmd…`) | ⏳ CSV dışa aktarma henüz yok. Eklendiğinde `= + - @ \t \r` ile başlayan hücreler kaçışlanacak |
| **CVE-2023-35866** (KeePassXC ≤ 2.7.5) | Açık bir oturumda ana parola, mevcut parola sorulmadan değiştirilebiliyordu | ✅ **Düzeltildi.** `change_credentials` artık mevcut parolayı ve anahtar dosyasını zorunlu tutuyor ve sabit sürede doğruluyor |
| KeeFarce / KeeThief (CVE değil, saldırı aracı) | Çalışan KeePass sürecine kod enjekte edip kasayı dışa aktarıyordu | ⏳ Uygulama katmanında: işlem DACL'ı ile aynı kullanıcının diğer süreçlerinin belleğimizi okuması engellenecek. Yönetici yetkisindeki zararlı yazılıma karşı hiçbir yerel parola yöneticisi tam koruma sağlayamaz |
| Eski KDBX varsayılanları | KDBX 3'te varsayılan AES-KDF 60 000 tur gibi zayıf ayarlar | ✅ Varsayılan Argon2id 64 MiB. Dosyada yazan KDF ayarları için alt ve üst sınır var; içe aktarılan KeePass kasası **bizim** ayarlarımızla yeniden şifrelenir |

## Bu incelemede kendi kodumuzda bulup düzelttiklerimiz

1. **Parolanın log'a sızması:** Yukarıdaki CVE-2022-0725 satırı. Gizli alanlar artık `SecretString`/`SecretBytes` tipinde.
2. **Alan değişince eski parolanın bellekte kalması:** `entry.password = yeni` yapıldığında eski `String` silinmeden serbest bırakılıyordu. `SecretString` artık bırakılırken kendini siliyor.
3. **Şifreleme öncesi tamponda iz kalması:** CBOR'a çevrilen şifresiz içerik büyüyen bir `Vec`'e yazılıyordu; her yeniden boyutlanmada eski kopya bellekte kalıyordu. Artık önce boyut ölçülüp tampon tam o boyutta açılıyor. Çözme tarafında ciborium'un ara tamponu da siliniyor.
4. **Eski parolalı `.bak` dosyası:** Ana parola değiştirildikten sonra yedek dosyası **eski parolayla** açılabiliyordu. Bu, parolası ele geçmiş birinin yedekten içeri girmesi demekti. Artık parola değişince eski yedek silinip yeniden oluşturuluyor (test var).
5. **Parola değiştirirken kimlik doğrulama yoktu:** Yukarıdaki CVE-2023-35866 satırı.
6. **Zayıf ana parola:** Anahtar dosyası yoksa ana parola en az 8 karakter olmak zorunda. Boş anahtar dosyası reddediliyor.
7. **Kötü niyetli büyük dosyalar:** Kasa dosyası 512 MiB'ı, anahtar dosyası 16 MiB'ı geçemez.
8. **Türkçe karakter ile kilitlenme riski:** Ana parola Unicode NFC ile normalleştiriliyor. "ş" farklı klavyelerden farklı kodlarla gelse bile aynı anahtar üretiliyor.

## Site ikonları (favicon): gizlilik ve güvenlik

İkonlar `lav-favicon` modülü ile indirilir. Çekirdekten ayrıdır.

- **Üçüncü taraf servis yok.** Google veya DuckDuckGo ikon servisleri kullanılmaz. İkon doğrudan kaydın kendi sitesinden alınır. Böylece hangi sitelerde hesabınız olduğu toplu olarak kimseye gitmez.
- **Yalnızca HTTPS.** Çerez, referrer ve sıkıştırma kullanılmaz. Boyut sınırı 512 KB, zaman aşımı 6 sn, en fazla 3 yönlendirme var. Her yönlendirme yeniden denetlenir.
- **Bu bilgisayara ve link-local adreslere hiçbir zaman istek atılmaz.** `localhost`, `127.0.0.1`, `::1`, IPv6 içine gömülü biçimleri (NAT64, 6to4) ve bulut metadata adresi `169.254.169.254` reddedilir. Çözülen IP adresi sabitlenir, böylece DNS rebinding saldırısı çalışmaz.
- **Şirket içi (intranet) adresler varsayılan olarak kapalıdır**, ayardan açılabilir.
- **Ortamdaki proxy ayarları (`HTTPS_PROXY`) kullanılmaz.** Proxy kullanılsaydı, adresi proxy kendisi çözeceği için IP kontrolleri atlanırdı.
- **İndirilen resim arayüze hiç ulaşmaz.** Bellek güvenli bir çözücüyle boyut ve bellek sınırları altında açılır, 64×64 **yeni bir PNG** olarak yeniden kodlanır. Arayüz yalnızca bu PNG'yi görür. SVG kabul edilmez.
- İkon şifreli kasanın içinde saklanır ve bir kez indirilir.
- ⚠️ **Şirket ağında dikkat:** İkon indirildiğinde şirket proxy'si veya DNS kayıtları hangi siteye gidildiğini görür. İsterseniz ayarlardan tamamen kapatılabilecek.

## Uygulama katmanı: Faz 2'de zorunlu sıkılaştırmalar

Bunlar masaüstü uygulaması yazılırken yapılacaklar ve sürüm çıkmadan önce kontrol edilecek:

- [ ] **Pano:** Kopyalanan parolalar Windows pano geçmişine (Win+V) ve bulut panosuna düşmeyecek. Bunun için `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` ve `CanUploadToCloudClipboard=0` biçimleri işaretlenecek. Pano süre dolunca temizlenecek, ama yalnızca hâlâ bizim koyduğumuz içerik duruyorsa.
- [ ] **Ekran paylaşımı:** Pencereye `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` uygulanacak. Teams/Zoom ekran paylaşımında ve ekran görüntülerinde kasa görünmeyecek.
- [ ] **Süreç belleğine erişim:** İşlem DACL'ı ile aynı kullanıcının diğer süreçlerinin belleğimizi okuması engellenecek (KeeFarce tipi saldırılara karşı).
- [ ] **DLL ele geçirme:** Başlangıçta `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` çağrılacak.
- [ ] **Ana parola girişi (CVE-2023-32784 dersi):** Parola arayüzde durum (state) olarak tutulmayacak, alındığı anda Rust tarafına gönderilip kutu temizlenecek. ⚠️ WebView/JavaScript dizgileri silinemez. Bu bilinen bir sınır ve süre en kısada tutulacak.
- [ ] **Otomatik kilit:** Boşta kalınca, Windows kilitlenince, oturum değişince ve uyku moduna geçilince kasa kilitlenecek. Kilitte anahtar ve içerik bellekten silinecek.
- [ ] **Hassas bellek sayfaları:** Anahtar sayfaları `VirtualLock` ile kilitlenip pagefile'a yazılmaları engellenecek.
- [ ] **Dışa aktarma:** Her seferinde ana parola yeniden sorulacak. CSV hücreleri kaçışlanacak.
- [ ] **Otomatik yazma (auto-type):** Yalnızca hedef pencere doğrulandıktan sonra yazılacak.
- [ ] **Tauri yapılandırması:** Sıkı CSP olacak, uzak içerik yüklenmeyecek, yalnızca gerekli komutlar açık olacak, WebView'de geliştirici araçları kapalı olacak.
- [ ] **Dağıtım:** `.exe` kod imzalı olacak ve yeniden üretilebilir derleme hedeflenecek.

## Kalan riskler (dürüstçe)

- **Ele geçirilmiş bilgisayar:** Keylogger ya da yönetici yetkili zararlı yazılım, kasa açıkken her yerel parola yöneticisini yener.
- **Zayıf ana parola:** Argon2 kaba kuvveti yavaşlatır ama engelleyemez. Uzun bir parola cümlesi önerilir.
- **Bulut sürüm geçmişi:** OneDrive gibi servisler dosyanın eski sürümlerini saklar. Eski parolayla şifrelenmiş eski bir sürüm orada kalabilir.
- **Geri alma (rollback):** Dosyaya yazabilen biri, kendi doğrulamasından geçen **eski** bir kasa sürümünü geri koyabilir. İleride son açılan sürümü yerelde kaydedip uyarı vereceğiz.
- **Bağımsız denetim:** Kod henüz bağımsız bir güvenlik denetiminden geçmedi.

## Açık bildirme

Bir güvenlik açığı bulursanız lütfen herkese açık bir issue açmak yerine depo sahibine özel olarak bildirin.
