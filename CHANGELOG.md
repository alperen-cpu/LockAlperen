# Sürüm Notları

## [0.4.2] - 2026-11-17: klasör simgeleri, listeleme stilleri

- **Klasör simgeleri:** Klasör araçlarındaki "Simge" düğmesiyle 48 Font Awesome simgesinden biri
  seçilebilir (ev, iş, banka, e-posta, sunucu, oyun…). Simgeler uygulamaya gömülü; ağdan bir şey
  indirilmez. Dosya formatı değişmedi (klasörlerin `icon` alanı baştan beri vardı).
- **Listeleme stilleri:** Liste, kompakt liste, kartlar ve tablo. Tabloda sütun başlığına tıklayınca
  sıralama. Seçim hatırlanır.
- Kilit açma ekranındaki "Argon2id · 64 MiB · 3 geçiş" satırı kaldırıldı.

## [0.4.1] - 2026-11-17: arayüz yerleşimi tasarımla aynı, ayarlar tam sayfa

- **Arayüz tasarıma uyduruldu:** Kilit açma ekranında ortada tek kart, son kasalar altında.
  Üst çubukta arama ortada, kasa adı logonun altında. Liste başlığı ve "Yeni kayıt" düğmesi.
  Kayıt alanlarında etiket solda, "Kopyala / Göster / Aç" düğmeleri sağda. Dar pencerede klasör
  çipleri ve yüzen "Yeni kayıt" düğmesi.
- **Ayarlar tam sayfa:** Güvenlik, Otomatik yazma, Görünüm, Pencere ve tepsi, Güncellemeler,
  İçe ve dışa aktarma. KeePass'ten içe aktarma artık "İçe ve dışa aktarma" bölümünde.

## [0.4.0] - 2026-11-17: yeni arayüz, koyu tema, duyarlı düzen

- **Yeni arayüz:** Ferah, açık tema varsayılan; yuvarlak düğmeler, kenar çizgisi yerine hafif
  gölgeler, daha geniş boşluklar. Kayıt ayrıntısı tek, sakin bir kart.
- **Koyu tema:** Ayarlar → Görünüm: "Windows ile aynı" (varsayılan), "Açık" ya da "Koyu".
- **Duyarlı düzen:** Geniş pencerede klasörler, liste ve ayrıntı yan yana. Daha dar pencerede
  klasörler soldan açılan bir çekmecede (☰). En dar pencerede liste ya da ayrıntı, geri düğmesiyle.
  Pencere 380 piksele kadar daraltılabilir.
- **Siteyi aç:** `javascript:`, `mailto:` gibi değerler artık bağlantı gibi görünmüyor ve
  açılmaya çalışılmıyor; `localhost:8080` gibi portlu adresler açılmaya devam ediyor.

## [0.3.1] - 2026-11-17: kilitli simge, esnek site açma

- **Kilitli simge:** Kasa kilitliyken görev çubuğu ve tepsi simgesinin sağ altında kırmızı bir
  kilit görünür (KeePass gibi); kilit açılınca simge normale döner. Win+L, uyku, otomatik kilit,
  Ctrl+L ve tepsiden kilitlemenin hepsinde çalışır. Tepsi ipucu da durumu söyler.
- **Siteyi aç daha esnek:** `localhost:8080`, `intranet:8443/giris`, `site.com:8443` gibi portlu
  adresler ve `kullanici@site.com` gibi kullanıcı bilgisi içeren adresler artık açılıyor (0.3.0'da
  "http(s) adresi değil" diye reddediliyordu). Kullanıcı bilgisi tarayıcıya gönderilmez.
  Tarayıcı yerine program başlatabilecek şemalar (`file:`, `cmd://`, `ms-msdt:` vb.) yine
  açılmaz.

## [0.3.0] - 2026-11-17: tepsi, otomatik yazma kısayolu, klasör taşıma

- **Sistem tepsisi:** Kapat düğmesi pencereyi tepsiye gizler (Ayarlar'dan kapatılabilir). Tepsi
  menüsünde göster, kilitle, kilitle ve çık var. Kilit kuralları gizliyken de geçerli.
- **Tek örnek:** Uygulama ikinci kez açılınca mevcut pencere öne gelir.
- **Otomatik yazma kısayolu:** Varsayılan `Ctrl+Alt+A`, Ayarlar'dan değiştirilebilir ya da
  kapatılabilir. Öndeki pencereye uyan tek kaydın kullanıcı adını ve parolasını yazar. Birden
  fazla kayıt uyarsa, hiç uymazsa ya da tuşlar bırakılmazsa hiçbir şey yazmaz.
- **Klasör taşıma ve sürükle-bırak:** Klasörler girintili ağaç olarak görünür; klasörler ve
  kayıtlar sürüklenip başka klasöre bırakılabilir ya da "Taşı" menüsüyle taşınabilir. Bir klasör
  kendi içine ya da alt klasörüne taşınamaz.
- **Siteyi aç:** Kaydın web sitesi tek tıkla tarayıcıda açılır. Yalnızca `http`/`https` adresleri
  açılır.

## [0.2.0] - 2026-11-16: uygulama içi güncelleme

- **Güncelleme:** Uygulama açılışta yeni sürümü denetler (Ayarlar'dan kapatılabilir) ve onay
  alınca kurulu sürümün üzerine kurar. Kasa dosyaları ve ayarlar korunur. Kurulum dosyası
  gömülü anahtarla imza doğrulanmadan çalıştırılmaz. Ayrıntı: [docs/UPDATES.md](docs/UPDATES.md).
- **Sürüm yayınlama:** `v*` etiketi GitHub Actions'ta imzalı kurulum, `latest.json` ve taslak
  bir Release üretir. Sürüm numarası `node scripts/set-version.mjs` ile değiştirilir.
- Ayarlar'da kullanılan sürüm görünür.

## [0.2.0] - 2026-11-16: kasa formatı v2

### ⚠️ Kırıcı değişiklik: format v1 kaldırıldı

- `.lav` dosya formatı **sürüm 2** oldu. Header 78 bayttan 110 bayta çıktı ve 32 baytlık bir
  key commitment alanı eklendi.
- **v1 dosyaları açılmaz** ve otomatik olarak dönüştürülmez. Açmaya çalışınca
  `UnsupportedVersion(1)` hatası döner ve kullanıcıya genel "açılamadı" mesajı gösterilir.
  Commitment kontrolünü atlayan bir geri dönüş yolu bilinçli olarak yoktur (sürüm düşürme
  koruması).
- v1 ile yazılmış `.bak` dosyaları da açılmaz.
- **Geçiş:** Format daha önce yayınlanmadığı için kullanıcı dosyası beklenmiyor. Elinde v1
  dosyası olan biri (geliştirme ya da test kopyası) dosyayı `c1c606a` commit'iyle açıp içeriği
  dışa aktarmalı, sonra bu sürümde yeniden oluşturmalı.
- Ayrıntı: [docs/FORMAT.md](docs/FORMAT.md).

### Güvenlik

- **Key commitment (R2):** Bir dosya en fazla bir anahtarla doğrulanabilir. Commitment,
  `HKDF(Argon2id çıktısı)`'ndan türetilen ayrı bir anahtarla `HMAC-SHA256` olarak hesaplanır,
  header'ın bütün güvenlik alanlarını kapsar ve şifre çözmeden önce sabit sürede doğrulanır.
  Argon2id, XChaCha20-Poly1305 ve payload anahtar türetmesi değişmedi.
- **Kilit açma sıkılaştırması:**
  - Şifresi çözülmüş içerikten sonra fazla bayt varsa dosya reddedilir.
  - Kasa anahtar dosyası kullanmıyorsa verilen anahtar dosyası reddedilir.
  - Kimlik bilgisi ve içerikle ilgili bütün açılış hataları kullanıcıya tek bir genel mesajla
    gösterilir.
- **Bellek:**
  - Türetilmiş anahtarlar tek bir heap ayırmasında tutulur ve bırakılırken silinir.
  - Şifre çözme yalnızca commitment'ı doğrulanmış bir anahtarla yapılabilir (tür düzeyinde).
  - Parolanın NFC normalleştirmesi heap'te silinmemiş kopya bırakmaz.
  - Kütüphanelerin yığında bıraktığı kopyalar için **en iyi çaba** yığın temizliği var
    (garanti değil).
- **Kaydetme:**
  - Kilit dosyası Windows'ta tutulurken silinemez. Unix'te kilit kaybı tespit edilir
    (`LockLost`). Kilit en fazla 10 sn beklenir (`SaveBusy`).
  - Yedek, doğrulanmış sürümden yazılır ve ana dosya değiştirilmeden önce diske işlenir.
  - Commit'ten önce dosya ve kilit yeniden kontrol edilir.

### Yeni hata türleri

`UnexpectedKeyFile`, `Encode`, `SaveBusy`, `LockLost`. Ayrıca `Error::is_unlock_failure` ve
`Error::user_message` eklendi.

### Bilinen sınırlamalar (bu sürümde)

- **Geri alma (rollback) tespit edilmez.** Tasarım yalnızca prototip (`prototypes/r1-rollback`),
  üretimde değil.
- **OneDrive:**
  - Makineler arası kilit yok.
  - Kilit dosyası senkron klasöründe.
  - Çakışma kopyaları için birleştirme yok.
  - Files On-Demand davranışı test edilmedi.
- **Ağ sürücüleri (SMB/NFS)** test edilmedi ve desteklenen bir yapılandırma değil.
- **Güç kesintisi** fiziksel olarak test edilmedi.
- **Bellek temizliği:** Yığın temizliği yalnızca Windows'ta ölçüldü: release derlemesinde
  GNU araç zinciriyle (yerel), debug derlemesinde MSVC ile (CI). MSVC release ve Linux için
  ölçüm yok.
- Ayrıntı: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) "Bilinen sınırlamalar".

### Test durumu

- **Windows 10, rustc 1.100, GNU araç zinciri, yerel:** bütün workspace testleri geçti.
- **CI, ubuntu-latest:** bütün workspace testleri geçti (135 geçti, 0 başarısız, 11 yok
  sayıldı). Unix'e özel T2 (kilit kaybı → `LockLost`) dahil.
- **CI, windows-latest (MSVC araç zinciri):** bütün workspace testleri geçti (140 geçti,
  0 başarısız, 11 yok sayıldı). Windows'a özel T1 ve T8 dahil.
- CI çalışmaları: [43474412721](https://github.com/alperen-cpu/LockAlperen/actions/runs/43474412721)
  (push) ve [43479266434](https://github.com/alperen-cpu/LockAlperen/actions/runs/43479266434)
  (PR #1), ikisi de commit `b27f4d1` üzerinde. Test sayıları push çalışmasından; iki çalışmada da
  bütün işler (fuzz ve supply-chain dahil) geçti.
- Bellek testleri (`lav-memtest`, 4 test) CI'da Windows/MSVC **debug** derlemesinde de geçti.
  Release derlemesinde yalnızca yerelde Windows/GNU ile ölçüldü. Linux için bellek testi yok
  (`lav-memtest` yalnızca Windows'ta derleniyor).
