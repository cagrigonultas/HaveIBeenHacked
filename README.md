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
## 🔐 API Anahtarları

> 🔑 Aşağıdaki alanlara kendi API anahtarlarınızı girmeniz gerekir.

- `API_KEY`: [VirusTotal](https://www.virustotal.com/) API Key  
- `ABUSE_API_KEY`: [AbuseIPDB](https://www.abuseipdb.com/) API Key
---
## 📌 Bilgilendirme

- Uygulama yalnızca Windows ortamında çalışmak üzere geliştirilmiştir.
- Son kullanıcıysanız “Son Kullanıcı Raporu” sizin için sade bir biçimde düzenlenmiştir. Detaylı rapor meraklılar ve analistler içindir.
- Internet erişimi kesme/açma işlemi yönetici yetkisi gerektirir. Uygulama başlatılırken yetki isteği kabul edilmelidir.
---
## 🧰 Kurulum

Bu uygulama doğrudan çalıştırılabilir `.exe` dosyası olarak paketlenmiştir. 

> 📥 **Uygulamanın son sürümünü indirmek için**:  
👉 [Releases sekmesine tıklayın](https://github.com/cagrigonultas/HaveIBeenHacked/releases)

---

## 📦 İçindekiler

```bash
have_i_been_hacked.py      # Ana Python kodu (geliştiriciler için)
have_i_been_hacked.spec    # PyInstaller yapılandırma dosyası
have_i_been_hacked.ico     # Özel simge dosyası
README.md                  # Bu dosya
requirements.txt           # Gerekli kütüphaneler

