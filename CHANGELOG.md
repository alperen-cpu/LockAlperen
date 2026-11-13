# Sürüm Notları

## [Yayınlanmamış]: kasa formatı v2

### ⚠️ Kırıcı değişiklik: format v1 kaldırıldı

- `.lav` dosya formatı **sürüm 2** oldu. Header 78 bayttan 110 bayta çıktı ve 32 baytlık bir
  key commitment alanı eklendi.
- **v1 dosyaları açılmaz** ve otomatik olarak dönüştürülmez. Açmaya çalışınca
  `UnsupportedVersion(1)` hatası döner ve kullanıcıya genel "açılamadı" mesajı gösterilir.
  Commitment kontrolünü atlayan bir geri dönüş yolu bilinçli olarak yoktur (sürüm düşürme
  koruması).
- v1 ile yazılmış `.bak` dosyaları da açılmaz.
- **Geçiş:** Format daha önce yayınlanmadığı için kullanıcı dosyası beklenmiyor. Elinde v1
  dosyası olan biri (geliştirme ya da test kopyası) dosyayı `f3ef659` commit'iyle açıp içeriği
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
- **Bellek temizliği:** Yığın temizliği yalnızca Windows'ta (rustc 1.100, GNU araç zinciri)
  ve release derlemesinde ölçüldü. Linux ve MSVC araç zinciri için ölçüm yok.
- Ayrıntı: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) "Bilinen sınırlamalar".

### Test durumu

- **Windows 10, rustc 1.100, GNU araç zinciri, yerel:** bütün workspace testleri geçti.
- **Linux:** testler **çalıştırılmadı.** CI işi eklendi ama sonucu henüz görülmedi; yalnızca
  derleme ve clippy denetimi yapıldı.
- **CI'daki MSVC araç zinciri:** sonuç henüz görülmedi.
