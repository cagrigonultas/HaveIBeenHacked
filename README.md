# 🛡️ Have I Been Hacked?

**Have I Been Hacked?** – Windows kullanıcıları için tasarlanmış, zararlı yazılım ve IP tespiti yapan kullanımı kolay bir güvenlik kontrol aracıdır.

---

## 🎯 Amaç

Bu araç, özellikle teknik bilgisi olmayan kullanıcıların sisteminde şüpheli işlemleri kolayca tarayabilmesini sağlar. Gelişmiş kullanıcılar için detaylı analiz ve rapor desteği de sunar.

---

## ⚙️ Özellikler

- ✅ Çalışan işlemleri tarar ve şüpheli olanları analiz eder.
- 🧪 VirusTotal API'si ile dosya hash'lerini doğrular.
- 🌐 AbuseIPDB API'si ile IP bağlantılarını kontrol eder.
- 📄 Detaylı rapor ve 👤 sadeleştirilmiş son kullanıcı raporu üretir.
- 🔌 Tek tuşla interneti kesip yeniden bağlayabilir.
- 🪪 Yönetici yetkisiyle çalışır.

---

## 🧰 Kurulum

Bu uygulama doğrudan çalıştırılabilir `.exe` dosyası olarak paketlenmiştir. Python kurulumu gerekmez.

> 📥 **Uygulamanın son sürümünü indirmek için**:  
👉 [Releases sekmesine tıklayın](https://github.com/<cagrigonultas>/HaveIBeenHacked/releases)

---

## 📦 İçindekiler

```bash
have_i_been_hacked.py      # Ana Python kodu (geliştiriciler için)
have_i_been_hacked.spec    # PyInstaller yapılandırma dosyası
have_i_been_hacked.ico     # Özel simge dosyası
README.md                  # Bu dosya
requirements.txt           # Gerekli kütüphaneler
dist/                      # EXE çıktısı burada (sürümde ayrı paylaşılır)
