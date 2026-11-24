# Sürüm Notları

## [0.10.0] - 2026-11-24: tarayıcı eklentisi, güvenlik düzeltmeleri

- **Tarayıcı eklentisi (Chromium, yalnızca doldurma, Linux):** `apps/browser-extension`. Ayarlar ›
  Tarayıcı eklentisi'nden açılır; eşleştirme iki tarafta görünen 6 haneli kodla yapılır. Kayıtlar
  yalnızca tam köken eşleşmesiyle önerilir; bir kayıt bir sitede ilk kez doldurulurken masaüstü
  onay ister. Eklenti ana parolayı hiçbir zaman sormaz. Ayrıntılar: `apps/browser-extension/README.md`.
- **Linux'ta üst çubuktaki simge kilitlenince değişmiyordu:** Ubuntu'nun AppIndicator eklentisi
  (GNOME Shell 50) yeni simgeyi alıyor ama eskisini çizmeye devam ediyordu. Simge artık durum
  değişince yeni bir simgeyle değiştiriliyor.
- **Güvenlik (rakip karşılaştırması ve pentest, `docs/SECURITY_COMPARISON_2026-11.md`):**
  - Kasa, `.bak`, ayarlar, son kasalar, Drive deposu, dışa aktarmalar, kaydedilen ekler, anahtar
    dosyası ve otomatik başlatma dosyası artık yalnızca kullanıcıya açık (0600, klasörler 0700).
    Önceden Ubuntu'nun umask'ıyla gruba yazılabilir, herkese okunabilirdi.
  - Kaydedilen ekin önerilen adı temizleniyor (`../`, yol ayırıcıları, kontrol ve yön değiştirme
    karakterleri). KeePassXC 2.7.12'deki açıkla aynı sınıf.
  - `url` 2.5.9 (RUSTSEC-2026-0592) ve `cookie` 0.18.3 (RUSTSEC-2026-0594, Tauri üzerinden).

## [0.9.0] - 2026-11-19: Linux (Ubuntu masaüstü)

- **Linux desteği:** Ubuntu 22.04 ve sonrası için `.deb` ve AppImage. İkisi de uygulama içinden
  güncellenir (`.deb` güncellemesi yönetici parolası ister).
- Linux'ta otomatik kilit (boşta kalma, ekran kilidi, uyku, kapanma, kullanıcı değiştirme), pano
  (pano yöneticilerine "gizli" işaretiyle), Google erişim anahtarı için sistem anahtarlığı, oturum
  açılışında başlatma ve süreç sıkılaştırması (ptrace/core dump kapalı).
- Linux'ta henüz olmayanlar: otomatik yazma, global kısayollar, ekran görüntüsünden gizleme.
- Sürüm iş akışı Windows ve Linux paketlerini birlikte imzalayıp tek taslak sürümde yayımlar.

## [0.8.0] - 2026-11-18: Google Drive yedeği

- **Google Drive yedeği:** Ayarlar › Google Drive. Google hesabınızı bağlayın; kasa `LockAlperen
  yedekleri` klasörüne yüklenir. Elle ("Bu kasayı şimdi yedekle") ya da açık kasalar değişince
  otomatik (dakikada bir denetlenir). Drive'daki yedekleri listeleyip bilgisayara indirebilirsiniz.
  - Drive'a yalnızca **şifreli kasa dosyası** gider; ana parola ve içerik gitmez.
  - Uygulama Drive'da yalnızca kendi oluşturduğu dosyaları görebilir (`drive.file` izni).
  - Giriş tarayıcıda yapılır (PKCE); Google erişim anahtarı Windows (DPAPI) ile şifreli saklanır.
  - Bir kerelik kurulum: Google Cloud'da kendi "Masaüstü uygulaması" OAuth istemcinizi oluşturup
    kimliğini ve gizli anahtarını girmeniz gerekir (adımlar uygulamada).

## [0.7.0] - 2026-11-18: birden fazla kasa, birleştirme, KeePass'e dışa aktarma, otomatik yazma dizileri ve daha fazlası

KeePass'teki özelliklerin büyük kısmı geldi.

- **Birden fazla kasa (sekmeler):** Üst çubuktaki **+** ile başka bir kasayı yeni sekmede
  açın (en fazla 8). Kilitleme bütün sekmeleri kilitler; aynı kasa iki sekmede açılamaz.
  Kısayolla otomatik yazma açık bütün kasalara bakar.
- **Başka bir kasayla birleştir** (KeePass "Synchronize"): Ayarlar › İçe ve dışa aktarma.
  Başka cihazdaki ya da yedekteki `.lav` dosyası bu kasaya katılır. Aynı kayıt iki yerde
  değiştiyse yenisi kalır, eskisi geçmişe girer. Bir tarafta kalıcı silinenler silinir; bunun
  için kasa artık kalıcı silinenlerin kimliğini tutuyor.
- **KeePass olarak dışa aktar (KDBX 4):** Klasörler, ekler, etiketler, son kullanma, otomatik
  yazma ve renkler dahil; dosyaya ayrı bir parola verilir. KeePass'e geri dönüş yolu.
- **Yazdırılabilir sayfa (acil durum):** Kayıtlar klasörlere göre bir HTML sayfasına yazılır
  (parolalar isteğe bağlı).
- **Kayda özel otomatik yazma:** Düzenle › Gelişmiş. Dizi (`{USERNAME}{ENTER}{DELAY 1500}
  {PASSWORD}{ENTER}` gibi; `{TOTP}`, `{S:Alan}`, `{TITLE}`, `{URL}`, `{NOTES}`, `{SPACE}`), hedef
  pencere kuralı (`*Banka*Giriş*`) ve kayıtta otomatik yazmayı kapatma.
- **Alan referansları:** Bir kaydın parolası ya da kullanıcı adı başka bir kaydınkine bağlanabilir
  (KeePass `{REF:…}`). Kaynak değişince bağlı kayıt da güncel olur; kopyalama ve otomatik yazma
  gerçek değeri kullanır.
- **Kayıt renkleri:** Listede yazı ve arka plan rengi.
- **Gelişmiş arama:** Arama kutusunun yanındaki **Alanlar** ile nerelere bakılacağı seçilir:
  başlık, kullanıcı adı, site, etiketler, notlar, özel alanlar (gizli değerler ve parolalar
  hiçbir zaman aranmaz).
- **Etiketler ve "Süresi dolacaklar":** Sol menüde etiketler listelenir; tıklayınca o etiketli
  kayıtlar görünür. "Süresi dolacaklar" süresi geçmiş ya da 7/30/90/365 gün içinde dolacak
  kayıtları en yakından başlayarak gösterir.
- **Parola üretici profilleri ve desen:** Hazır profiller (onaltılık anahtarlar, MAC adresi, PIN)
  ve kendi kaydettiğiniz profiller; desenle üretme (`uu-d{4}` gibi).
- **Kasa ayarları** (Ayarlar › Kasa): ad ve açıklama, kayıt başına geçmiş sayısı, eski geçmişi
  temizleme, şifreleme gücü (Argon2id bellek/geçiş; hazır ayarlar), anahtar dosyası oluşturma,
  ekleme, değiştirme ve kaldırma.
- **KeePass'ten içe aktarma** artık otomatik yazma ayarlarını ve renkleri de alıyor.
- **Dosya formatı:** Kasaya ve kayıtlara isteğe bağlı yeni alanlar eklendi (`docs/FORMAT.md`).
  Eski kasalar açılır. Eski bir uygulama sürümü bu kasayı açar ama onunla kaydedilirse yeni
  alanlar (renkler, otomatik yazma ayarı, silinme kayıtları) düşer.

## [0.6.0] - 2026-11-18: otomatik yazma siteyi açar, parola sütunu, üzerindeyken Ctrl+C, boyutlanan panel, onay penceresi

- **Otomatik yaz önce siteyi açar:** Kaydın web sitesi varsa "Otomatik yaz" siteyi varsayılan
  tarayıcıda yeni sekmede açar; sayfa yüklenip başlığı kayda uyunca kullanıcı adını ve parolayı
  yazar (en fazla 25 sn bekler). Başlık uymazsa eskisi gibi hiçbir şey yazılmaz. Sitesi olmayan
  kayıtlarda davranış aynı: 10 sn içinde hedef pencereye geçilir.
- **Tabloda parola ve son kullanma sütunları:** Parola tabloda yalnızca nokta olarak görünür
  (tablo için parola arayüze gönderilmez). Son kullanma tarihine göre sıralanabilir; süresi geçenler uyarı
  renginde.
- **Üzerindeyken Ctrl+C:** Fare bir kullanıcı adının ya da parolanın üzerindeyken (tablo, liste
  ya da ayrıntı paneli) Ctrl+C o değeri kopyalar. Fare bir değerin üzerinde değilse seçili kaydın
  parolasını kopyalar (KeePass'teki gibi). Seçili metin varsa normal kopyalama yapılır.
- **Yeni kısayollar (KeePass'teki gibi):** Ctrl+B kullanıcı adını kopyalar, Ctrl+U siteyi açar,
  Ctrl+E ya da Enter kaydı düzenler, Delete kaydı siler (önce sorar). Bütün kısayollar
  Ayarlar › Klavye kısayolları'nda.
- **Ayrıntı paneli boyutlandırılabilir:** Liste ile ayrıntı paneli arasındaki çubuk sürüklenerek
  panel genişletilip daraltılır; çift tıklayınca eski haline döner. Çubuk seçiliyken ← / → ile de
  ayarlanır. Genişlik hatırlanır.
- **Silme onayı pencerede:** Klasör silme, kayıt silme ve Geri Dönüşüm Kutusu'nu boşaltma artık
  "tekrar tıklayın" yazısı yerine ne silineceğini (alt klasör ve kayıt sayısı) gösteren bir onay
  penceresi açar. Kalıcı silmelerde düğme kırmızıdır; Enter tek başına silmez ("Vazgeç" seçili gelir).
- **Ayarlar metinleri:** "Küçültünce tepsiye gizle" ayarı "Küçültünce görev çubuğunda gösterme"
  oldu; açıklamalar simgenin nerede durduğunu (saatin yanı) anlatıyor.

## [0.5.0] - 2026-11-17: Geri Dönüşüm Kutusu, kayıt çoğaltma, son kullanma tarihi, KeePass seçenekleri

- **Kaydı çoğalt (KeePass'teki gibi, Ctrl+K):** Ayrıntıdaki "Çoğalt" düğmesi kaydın bir
  kopyasını aynı klasörde "… - Kopya" adıyla oluşturur. Parola, notlar, TOTP, özel alanlar, ekler
  ve etiketler kopyalanır; **geçmiş (eski parolalar) kopyalanmaz.**
- **Son kullanma tarihi (KeePass "Expires"):** Düzenleyicide tarih seçilebilir (1/3/6/12 ay hızlı
  seçimi). Ayrıntıda tarih, süresi geçmişse "Süresi doldu" olarak görünür; parola sağlığı zaten
  süresi dolanları sayıyordu. KeePass'ten aktarılan tarihler artık düzenlenebilir. Dosya formatı
  değişmedi (`expires` alanı baştan beri vardı).
- **Geri Dönüşüm Kutusu (KeePass'teki gibi):** Silinen kayıt ya da klasör önce "Geri Dönüşüm
  Kutusu" klasörüne taşınır (ilk silmede oluşur). Oradan "Geri yükle" ile ya da sürükleyerek geri
  alınır. Kutunun içinden silmek ve "Boşalt" kalıcıdır, iki kez onay ister. Kutudaki kayıtlar "Tüm
  kayıtlar", TOTP, parola sağlığı ve otomatik yazmaya girmez. **Dosya formatı:** kasaya isteğe
  bağlı `recycle_bin` alanı eklendi (`schema` aynı; eski dosyalar açılır, eski sürümler kutuyu
  sıradan klasör olarak gösterir).
- **KeePass Seçenekleri'nden gelen ayarlar** (hepsi varsayılan olarak kapalı, bugünkü davranış
  değişmez; KeePass'te varsayılan açık olan "yeni kayda parola üret" ve "Ctrl+Alt+K" hariç):
  - Güvenlik: küçültünce kilitle; süre dolunca kilitlemek yerine kapat; açınca süresi dolan ya da
    7 gün içinde dolacak kayıtları bildir.
  - Pencere: küçültünce tepsiye gizle; kopyaladıktan sonra küçült; kilitleyince küçült; her zaman
    üstte; küçültülmüş başlat; Windows açılışında başlat (yalnızca kullanıcının `Run` anahtarı);
    pencereyi gösterme kısayolu (Ctrl+Alt+K ya da Ctrl+Alt+Shift+W, KeePass açıksa çakışır ve
    Ayarlar uyarır).
  - Parola üretici: yeni kayda otomatik parola, varsayılan uzunluk (8–128) ve karakter türleri.

## [0.4.3] - 2026-11-17: pano süresi, Win+L kilidi ayarı, görev çubuğunda kilit, temalı başlık çubuğu

- **Pano süresi seçilebilir:** Ayarlar → Güvenlik: 5–90 saniye (varsayılan 12). "Asla" yok.
- **Bilgisayar kilitlenince kasayı da kilitle:** Win+L, uyku ve oturum kapatmada kilitleme artık
  açılıp kapatılabilir (varsayılan açık; kapatınca uyarı gösterilir).
- **Görev çubuğunda kilit:** Kasa kilitliyken görev çubuğu düğmesinde de kırmızı kilit rozeti
  görünür (KeePass gibi).
- **Başlık çubuğu:** Pencerenin başlık çubuğu uygulamanın açık ya da koyu temasıyla aynı renkte
  (Windows 11).
- **Kartlar:** Uzun başlıklar ve kullanıcı adları kartın dışına taşmıyor.
- Ayarlar'daki "Pencere ve tepsi" bölümü "Pencere" oldu; açıklaması sadeleşti.

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
