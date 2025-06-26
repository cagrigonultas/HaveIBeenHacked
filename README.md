# 🛡️ Have I Been Hacked?

**Have I Been Hacked?** – Windows kullanıcıları için tasarlanmış, zararlı yazılım ve IP tespiti yapan kullanımı kolay bir güvenlik kontrol aracıdır.

---
### 🚀 Temel Özellikler

- ✔️ Aktif işlemleri tarar, imzasız veya şüpheli öğeleri puanlayarak tespit eder.  
- ✔️ VirusTotal API’si ile SHA256 hash kontrolü yapar.  
- ✔️ AbuseIPDB ile dış bağlantılardaki IP adreslerinin güvenliğini kontrol eder.  
- ✔️ Detaylı veya sade (son kullanıcıya yönelik) raporlar üretir.  
- ✔️ Geçici olarak interneti kesip açabilir (isteğe bağlı).  
- ✔️ Sezgisel grafik arayüz ve ilerleme göstergeleri içerir.

---
### 🎥 Uygulama Tanıtım Videosu

[![YouTube Video Önizleme](https://img.youtube.com/vi/h2NBEB0Arbw/0.jpg)](https://www.youtube.com/watch?v=h2NBEB0Arbw)

> 🔗 Videoyu izlemek için görsele tıklayın.

---
## 📦 Gerekli Kurulumlar (`requirements.txt`)
---
## 🎯 Amaç

Bu araç, özellikle teknik bilgisi olmayan kullanıcıların sisteminde şüpheli işlemleri kolayca tarayabilmesini sağlar. Gelişmiş kullanıcılar için detaylı analiz ve rapor desteği de sunar.

---

## 🖱️ Arayüz Butonları ve İşlevleri

| Buton                      | Görevi                                                                 |
|---------------------------|------------------------------------------------------------------------|
| 🔍 **Tarama Başlat**       | Şüpheli işlemleri ve zararlı dosya hash’lerini tespit eder             |
| 🧪 **VirusTotal Güncelle** | Tespit edilen hash'leri VirusTotal ile sorgular, sonuçları puanlar     |
| 🌐 **IP Analizi Yap**      | Aktif IP bağlantılarını AbuseIPDB ile kontrol eder                     |
| 📄 **Detaylı Rapor**       | Tüm verilerle kapsamlı bir analiz raporu üretir                        |
| 👤 **Son Kullanıcı Raporu**| Yalnızca kara listeye giren işlemler hakkında sade bir rapor sunar     |
| ❌ **İnterneti Kes**        | Ağ bağlantısını geçici olarak kapatır                                  |
| ✅ **İnterneti Aç**         | Ağ bağlantısını yeniden sağlar                                        |


---

## 📌 Bilgilendirme

- Uygulama yalnızca Windows ortamında çalışmak üzere geliştirilmiştir.
- Son kullanıcıysanız “Son Kullanıcı Raporu” sizin için sade bir biçimde düzenlenmiştir. Detaylı rapor meraklılar ve analistler içindir.
- Internet erişimi kesme/açma işlemi yönetici yetkisi gerektirir. Uygulama başlatılırken yetki isteği kabul edilmelidir.
- VirusTotal Güncelleme kısmı günde 1 kere çalışacak şekilde ayarlıdır. Bunun sebebi ücretsiz sürümde kısıtlamaların olmasıdır. Premium API sahibi hesaplar bu kısıtı kaldırabilir.
- API anahtarları mutlaka doğru girilmelidir. Yanlış girilmesi durumunda sonuçlar yanıltıcı olabilir.
## 🛡️ Windows Defender “Virüs Algılandı” Uyarısı

Bazı antivirüs yazılımları (özellikle **Windows Defender**) bu uygulamayı yanlışlıkla zararlı olarak algılayabilir.  
Bu bir **false positive**’tir. Kaynak kodlar GitHub’da açıkça paylaşıldığından, uygulamanın zararlı olmadığı doğrulanabilir.

### ⚠️ Windows Defender’da Dosyaya İzin Verme

1. **Başlat Menüsü → Windows Güvenliği** uygulamasını açın.  
2. Sol menüden **Virüs ve tehdit koruması** sekmesine tıklayın.  
3. **Koruma geçmişi** bölümüne girin (sayfanın altında).  
4. Listede `have_i_been_hacked.exe` uyarısını bulun ve açın.  
5. **Eylemler** menüsünü açın → **İzin ver** seçeneğine tıklayın.  

> 🔐 Bu adım yalnızca güvenilir yazılımlar için yapılmalıdır.  
> “Have I Been Hacked?” uygulaması açık kaynaklıdır ve kötü amaçlı işlem içermez.

## ⚠️ “Bilinmeyen Yayıncı” Uyarısı Hakkında

Windows, bu uygulamayı ilk kez çalıştırırken aşağıdaki gibi bir uyarı verebilir:

**Windows bilgisayarınızı korudu**

Bu uyarı, yazılımın zararlı olduğu anlamına gelmez. Sadece dijital imza (sertifika) bulunmadığı için gösterilir.

### 🔧 Ne Yapmalıyım?

1. “**Ek Bilgi**” seçeneğine tıklayın.  
2. “**Yine de çalıştır**” butonuna basın.  
3. Uygulama açılacaktır.


🛡️ İlk Kurulumda API Key Girmeniz Gerekiyor
- Uygulama ilk kez çalıştırıldığında sizden iki API anahtarı istenecektir:
  ## 🔑 API Anahtarları Nasıl Alınır?

Uygulamayı kullanmadan önce iki adet ücretsiz API anahtarına ihtiyacınız var:

### 1. VirusTotal API Key

1. [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) adresine gidin. (Yeni sekmede açılması önerilir.)
2. Ücretsiz bir hesap oluşturun veya giriş yapın.
3. Sağ üstten profilinize tıklayın → *API Key* bölümüne gidin.
4. Buradaki anahtarı kopyalayın.

### 2. AbuseIPDB API Key

1. [https://www.abuseipdb.com/register](https://www.abuseipdb.com/register) adresinden kayıt olun veya giriş yapın. (Yeni sekmede açılması önerilir.)
2. Sağ üstten *API* bölümüne girin.
3. Ücretsiz bir API Key oluşturun ve kopyalayın.

### 🔧 Anahtarları Uygulamaya Tanıtma

İlk kez uygulamayı açtığınızda bu anahtarlar sizden GUI üzerinden istenecek. Girdiğiniz anahtarlar otomatik olarak `apikeys.json` adlı dosyaya kaydedilecek ve bir daha sormayacak.

> NOT: Anahtarlarınızı kimseyle paylaşmayın! Sadece sizin sisteminizde çalışmalıdır.


🔐 Bu anahtarlar sadece sizin bilgisayarınızda saklanır ve başkalarıyla paylaşılmaz.

---
## 🧰 Kurulum

Bu uygulama doğrudan çalıştırılabilir `.exe` dosyası olarak paketlenmiştir. 

> 📥 **Uygulamanın son sürümünü indirmek için**:  
👉 [Releases sekmesine tıklayın](https://github.com/cagrigonultas/HaveIBeenHacked/releases) (exe dosyasını ve .ico dosyasını indirmek yeterlidir. Aynı klasörde olmalarına dikkat edilmeli)

---

## 📦 İçindekiler

```bash
have_i_been_hacked.py      # Ana Python kodu (geliştiriciler için)
have_i_been_hacked.spec    # PyInstaller yapılandırma dosyası
have_i_been_hacked.ico     # Özel simge dosyası
README.md                  # Bu dosya
requirements.txt           # Gerekli kütüphaneler

